#!/bin/sh
set -eu

config="${SB_XRAY_CONFIG:-/config/generated/xray.json}"
lkg="${SB_XRAY_LKG_CONFIG:-/data/last-known-good/xray.json}"
poll_seconds="${SB_XRAY_CONFIG_POLL_SECONDS:-10}"
configured_startup_timeout_seconds="${SB_XRAY_STARTUP_TIMEOUT_SECONDS:-}"
prevalidated_marker="${SB_XRAY_PREVALIDATED_MARKER:-/run/sb-gateway/xray-prevalidated.sha256}"
selectors_ready="${SB_XRAY_READY_FILE:-/run/sb-gateway/xray-selectors-ready}"
rm -f "$selectors_ready"

while [ ! -s "$config" ]; do
  if [ -s "$lkg" ]; then
    mkdir -p "$(dirname "$config")"
    cp "$lkg" "$config"
    chmod 0600 "$config"
    break
  fi
  # Setup mode is healthy: the panel provisions the first active Xray config.
  sleep "$poll_seconds"
done

skip_validation=0
if [ -s "$prevalidated_marker" ]; then
  expected_digest="$(sed -n '1p' "$prevalidated_marker")"
  actual_digest="$(sha256sum "$config" | awk '{print $1}')"
  rm -f "$prevalidated_marker"
  if [ "$expected_digest" = "$actual_digest" ]; then
    skip_validation=1
  fi
else
  rm -f "$prevalidated_marker"
fi

# A normal Apply already validated this exact config and gets the shortest
# interruption budget. Cold container/runtime starts need more room for large
# RouterOS/ARM64 configs. The prevalidation marker is one-shot, so a timed-out
# fast attempt automatically retries through the cold recovery budget.
if [ -n "$configured_startup_timeout_seconds" ]; then
  startup_timeout_seconds="$configured_startup_timeout_seconds"
elif [ "$skip_validation" -eq 1 ]; then
  startup_timeout_seconds=15
else
  startup_timeout_seconds=30
fi
case "$startup_timeout_seconds" in
  ''|*[!0-9]*|0)
    printf '%s\n' "SB_XRAY_STARTUP_TIMEOUT_SECONDS must be an integer from 1 to 30" >&2
    exit 78
    ;;
esac
if [ "$startup_timeout_seconds" -gt 30 ]; then
  printf '%s\n' "SB_XRAY_STARTUP_TIMEOUT_SECONDS must be an integer from 1 to 30" >&2
  exit 78
fi
if [ "$skip_validation" -ne 1 ]; then
  xray run -test -config "$config"
fi

# RouterOS-native WireGuard exits use deterministic loopback source identities.
# RouterOS policy-routes only these identities to the selected interface, so a
# failed WireGuard table cannot leak through the ordinary WAN.
/bin/sh /opt/sb-gateway/scripts/configure-wireguard-egress.sh "$config"

# Public ingress replies must always return through the RouterOS-facing veth.
container_ip="${SB_CONTAINER_IP:-}"
if [ -z "$container_ip" ] && [ -n "${SB_CONTAINER_ADDRESS:-}" ]; then
  container_ip="${SB_CONTAINER_ADDRESS%%/*}"
fi
case "$container_ip" in
  *[!0-9.]*|'')
    printf '%s\n' \
      "actual SB_CONTAINER_IP or SB_CONTAINER_ADDRESS is required for the return route" >&2
    exit 78
    ;;
esac
routeros_gateway="${SB_ROUTEROS_GATEWAY:-}"
case "$routeros_gateway" in
  *[!0-9.]*|'')
    printf '%s\n' "actual SB_ROUTEROS_GATEWAY is required for the return route" >&2
    exit 78
    ;;
esac
return_dev="$(
  ip -4 route get "$routeros_gateway" 2>/dev/null \
    | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
)"
case "$return_dev" in
  ''|*[!A-Za-z0-9_.:-]*)
    printf '%s\n' "unable to resolve the RouterOS-facing veth" >&2
    exit 78
    ;;
esac
while ip rule del priority 1000 from "$container_ip/32" lookup main \
  >/dev/null 2>&1; do
  :
done
while ip rule del priority 1000 from "$container_ip/32" table 1001 \
  >/dev/null 2>&1; do
  :
done
ip route flush table 1001 >/dev/null 2>&1 || true
ip route add table 1001 "$routeros_gateway/32" \
  dev "$return_dev" src "$container_ip"
ip route add table 1001 default via "$routeros_gateway" dev "$return_dev"
ip rule add priority 1000 from "$container_ip/32" table 1001

xray_api_server="${SB_XRAY_API_SERVER:-127.0.0.1:10085}"
# Core readiness and selector restoration share one outage budget. A broken
# phase must not turn into several sequential minute-long black-hole windows
# while RouterOS is still forwarding clients.
startup_started="$(date +%s)"
startup_deadline=$((startup_started + startup_timeout_seconds))
process_log="${SB_XRAY_PROCESS_LOG:-/logs/xray-process.log}"
process_log_limit_bytes="${SB_XRAY_PROCESS_LOG_LIMIT_BYTES:-4194304}"
case "$process_log_limit_bytes" in
  ''|*[!0-9]*|0) process_log_limit_bytes=4194304 ;;
esac
mkdir -p "$(dirname "$process_log")"
process_log_bytes="$(wc -c <"$process_log" 2>/dev/null || printf '0')"
if [ "$process_log_bytes" -ge "$process_log_limit_bytes" ]; then
  rm -f "$process_log.2"
  if [ -f "$process_log.1" ]; then
    mv "$process_log.1" "$process_log.2"
  fi
  mv "$process_log" "$process_log.1"
fi
xray_gomemlimit="${SB_XRAY_GOMEMLIMIT:-192MiB}"
GOMEMLIMIT="$xray_gomemlimit" xray run -config "$config" >>"$process_log" 2>&1 &
xray_pid=$!

stop_xray() {
  rm -f "$selectors_ready"
  /bin/sh /opt/sb-gateway/scripts/configure-transparent-routing.sh cleanup \
    >/dev/null 2>&1 || true
  kill -TERM "$xray_pid" 2>/dev/null || true
  wait "$xray_pid" 2>/dev/null || true
  exit 143
}
trap stop_xray HUP INT TERM

xray_api_ready=0
while [ "$xray_api_ready" -ne 1 ]; do
  kill -0 "$xray_pid" 2>/dev/null || {
    wait "$xray_pid"
    exit $?
  }
  if [ "$xray_api_ready" -ne 1 ] && sb-gateway tcp-ready --address "$xray_api_server" --timeout 200ms >/dev/null 2>&1; then
    xray_api_ready=1
  fi
  startup_now="$(date +%s)"
  if [ "$startup_now" -ge "$startup_deadline" ]; then
    if [ "$xray_api_ready" -ne 1 ]; then
      printf '%s\n' "Xray RoutingService did not become ready within the shared startup deadline" >&2
    fi
    kill -TERM "$xray_pid" 2>/dev/null || true
    wait "$xray_pid" 2>/dev/null || true
    /bin/sh /opt/sb-gateway/scripts/configure-transparent-routing.sh cleanup \
      >/dev/null 2>&1 || true
    exit 78
  fi
  sleep 0.1
done
core_ready_at="$(date +%s)"
printf '%s\n' "Xray core ready after $((core_ready_at - startup_started))s"

startup_now="$(date +%s)"
selector_timeout_seconds=$((startup_deadline - startup_now))
if [ "$selector_timeout_seconds" -le 0 ]; then
  printf '%s\n' "Xray startup deadline expired before selector restoration" >&2
  kill -TERM "$xray_pid" 2>/dev/null || true
  wait "$xray_pid" 2>/dev/null || true
  /bin/sh /opt/sb-gateway/scripts/configure-transparent-routing.sh cleanup \
    >/dev/null 2>&1 || true
  exit 78
fi
if [ "$selector_timeout_seconds" -gt 5 ]; then
  selector_timeout_seconds=5
fi

# Restore confirmed working leaves before admitting transparent client traffic.
# Explicit priority reorders retain their configured order. The native helper
# confirms each actual override and propagates failures without a shell pipe.
if ! sb-gateway xray-balancers --apply --timeout "${selector_timeout_seconds}s" --config "$config"; then
  printf '%s\n' "Xray startup selection failed" >&2
  kill -TERM "$xray_pid" 2>/dev/null || true
  wait "$xray_pid" 2>/dev/null || true
  exit 78
fi
selectors_ready_at="$(date +%s)"
printf '%s\n' "Xray startup selectors restored after $((selectors_ready_at - startup_started))s"

if ! /bin/sh /opt/sb-gateway/scripts/configure-transparent-routing.sh apply; then
  printf '%s\n' "transparent RouterOS to Xray routing failed" >&2
  kill -TERM "$xray_pid" 2>/dev/null || true
  wait "$xray_pid" 2>/dev/null || true
  /bin/sh /opt/sb-gateway/scripts/configure-transparent-routing.sh cleanup \
    >/dev/null 2>&1 || true
  exit 78
fi
startup_finished="$(date +%s)"
if [ "$startup_finished" -gt "$startup_deadline" ]; then
  printf '%s\n' "Xray transparent routing exceeded the shared startup deadline" >&2
  kill -TERM "$xray_pid" 2>/dev/null || true
  wait "$xray_pid" 2>/dev/null || true
  /bin/sh /opt/sb-gateway/scripts/configure-transparent-routing.sh cleanup \
    >/dev/null 2>&1 || true
  exit 78
fi
printf '%s\n' "Xray traffic admitted after $((startup_finished - startup_started))s (budget ${startup_timeout_seconds}s)"
mkdir -p "$(dirname "$selectors_ready")"
printf '%s\n' "$xray_pid" >"$selectors_ready"

xray_status=0
wait "$xray_pid" || xray_status=$?
rm -f "$selectors_ready"
/bin/sh /opt/sb-gateway/scripts/configure-transparent-routing.sh cleanup \
  >/dev/null 2>&1 || true
exit "$xray_status"
