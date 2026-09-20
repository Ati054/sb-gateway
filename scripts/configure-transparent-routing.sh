#!/bin/sh
set -eu

action="${1:-apply}"
route_table="${SB_TRANSPARENT_ROUTE_TABLE:-1002}"
rule_priority="${SB_TRANSPARENT_RULE_PRIORITY:-1100}"
nft_table="sb_gateway_transparent"
telemetry_table="sb_gateway_client_telemetry"
exclusions_file="${SB_TRANSPARENT_EXCLUSIONS_FILE:-/config/generated/transparent-exclusions.txt}"
telemetry_file="${SB_CLIENT_TELEMETRY_NFT_FILE:-/config/generated/client-telemetry.nft}"
tproxy_port="${SB_TPROXY_PORT:-12345}"
tproxy_mark="${SB_TPROXY_MARK:-1}"

case "$route_table:$rule_priority" in
  ''|:*|*:|*:*:*|*[!0-9:]*)
    printf '%s\n' "transparent route table or rule priority has an invalid format" >&2
    exit 78
    ;;
esac
case "$tproxy_port:$tproxy_mark" in
  ''|:*|*:|*:*:*|*[!0-9:]*)
    printf '%s\n' "TPROXY port or mark has an invalid format" >&2
    exit 78
    ;;
esac

routeros_gateway="${SB_ROUTEROS_GATEWAY:-}"
case "$routeros_gateway" in
  *[!0-9.]*|'')
    printf '%s\n' "actual SB_ROUTEROS_GATEWAY is required for transparent routing" >&2
    exit 78
    ;;
esac

uplink_dev="$(
  ip -4 route get "$routeros_gateway" 2>/dev/null \
    | awk '{ for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }'
)"
case "$uplink_dev" in
  ''|*[!A-Za-z0-9_.:-]*)
    printf '%s\n' "unable to resolve the RouterOS-facing interface" >&2
    exit 78
    ;;
esac

delete_policy_rules() {
  while ip rule del priority "$rule_priority" fwmark "$tproxy_mark" table "$route_table" \
      >/dev/null 2>&1; do
    :
  done
}

cleanup() {
  delete_policy_rules
  ip route flush table "$route_table" >/dev/null 2>&1 || true
  nft delete table inet "$nft_table" >/dev/null 2>&1 || true
  nft delete table inet "$telemetry_table" >/dev/null 2>&1 || true
}

if [ "$action" = "cleanup" ]; then
  cleanup
  exit 0
fi
if [ "$action" != "apply" ]; then
  printf '%s\n' "usage: configure-transparent-routing.sh [apply|cleanup]" >&2
  exit 64
fi

# Routed packets arrive from RouterOS with their original LAN source. Linux
# must accept them into a transparent local socket, and reverse-path filtering
# must not reject their asymmetric return path. Write procfs directly so
# a hot update does not depend on the optional procps package being present in
# an already installed RouterOS container image.
write_ipv4_setting() {
  setting_path="$1"
  setting_value="$2"
  [ -w "/proc/sys/net/ipv4/$setting_path" ] || {
    printf '%s\n' "IPv4 setting is not writable: $setting_path" >&2
    exit 77
  }
  printf '%s\n' "$setting_value" >"/proc/sys/net/ipv4/$setting_path"
}

write_ipv4_setting ip_forward 1
write_ipv4_setting conf/all/rp_filter 0
write_ipv4_setting conf/default/rp_filter 0
write_ipv4_setting "conf/${uplink_dev}/rp_filter" 0

cleanup

configure_tproxy() {
  mkdir -p /run/sb-gateway
  nft_probe="$(mktemp /run/sb-gateway/tproxy-check.XXXXXX)"
  cat >"$nft_probe" <<EOF
table inet sb_gateway_tproxy_probe {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    meta l4proto tcp tproxy to :$tproxy_port accept
    meta l4proto udp tproxy to :$tproxy_port accept
  }
}
EOF
  if ! nft -c -f "$nft_probe" >/dev/null 2>&1; then
    rm -f "$nft_probe"
    return 1
  fi
  rm -f "$nft_probe"

  exclude_elements=""
  if [ -s "$exclusions_file" ]; then
    while IFS= read -r cidr; do
      [ -n "$cidr" ] || continue
      case "$cidr" in
        *[!0-9A-Fa-f:./]*) return 1 ;;
        *:*) continue ;;
      esac
      if [ -z "$exclude_elements" ]; then
        exclude_elements="$cidr"
      else
        exclude_elements="$exclude_elements, $cidr"
      fi
    done < "$exclusions_file"
  fi
  exclude_rule=""
  if [ -n "$exclude_elements" ]; then
    exclude_rule="iifname \"$uplink_dev\" ip daddr { $exclude_elements } return"
  fi

  nft_candidate="$(mktemp /run/sb-gateway/tproxy-table.XXXXXX)"
  cat >"$nft_candidate" <<EOF
table inet $nft_table {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "$uplink_dev" fib daddr type local return
    $exclude_rule
    iifname "$uplink_dev" meta l4proto tcp tproxy to :$tproxy_port meta mark set $tproxy_mark accept
    iifname "$uplink_dev" meta l4proto udp tproxy to :$tproxy_port meta mark set $tproxy_mark accept
  }
  chain input {
    type filter hook input priority filter; policy accept;
    meta mark != $tproxy_mark tcp dport $tproxy_port drop
    meta mark != $tproxy_mark udp dport $tproxy_port drop
  }
}
EOF
  if ! ip route replace local default dev lo table "$route_table"; then
    rm -f "$nft_candidate"
    return 1
  fi
  if ! ip rule add priority "$rule_priority" fwmark "$tproxy_mark" table "$route_table"; then
    rm -f "$nft_candidate"
    return 1
  fi
  if ! nft -f "$nft_candidate"; then
    rm -f "$nft_candidate"
    return 1
  fi
  rm -f "$nft_candidate"
  return 0
}

if ! configure_tproxy; then
  cleanup
  printf '%s\n' "kernel TPROXY setup failed; RouterOS traffic remains fail-open on WAN" >&2
  exit 77
fi

# Client telemetry is deliberately isolated from the diversion table.  It has
# an accept policy and counter-only rules, so a missing or incompatible
# telemetry candidate can never prevent transparent routing from starting.
if [ -s "$telemetry_file" ] && ! nft -f "$telemetry_file"; then
  nft delete table inet "$telemetry_table" >/dev/null 2>&1 || true
  printf '%s\n' "client telemetry unavailable; routing remains active" >&2
fi

printf '%s\n' \
  "transparent routing active: mode=tproxy iif=$uplink_dev table=$route_table port=$tproxy_port"
