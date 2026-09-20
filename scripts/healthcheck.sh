#!/bin/sh
set -eu

# OCI health describes the setup/control plane. RouterOS separately polls the
# 9080 ready marker before it diverts any managed-client traffic.
# Keep both probes inside RouterOS' ten-second HEALTHCHECK budget, but do not
# serialize them: under saturated ARM64/TCG scheduling two otherwise healthy
# endpoints can each need more than the old three-second allowance.
curl --silent --show-error --fail --max-time 7 \
  http://127.0.0.1:8080/api/health/live >/dev/null &
api_probe_pid=$!
curl --insecure --silent --show-error --fail --max-time 7 \
  https://127.0.0.1:9443/ >/dev/null &
https_probe_pid=$!

probe_status=0
wait "$api_probe_pid" || probe_status=1
wait "$https_probe_pid" || probe_status=1
if [ "$probe_status" -ne 0 ]; then
  exit "$probe_status"
fi

for persistent_mount in /config /data /logs /state; do
  mount_options="$(awk -v target="${persistent_mount}" '$2 == target { print $4; exit }' /proc/mounts)"
  case ",${mount_options}," in
    *,rw,*) ;;
    *)
      echo "persistent mount is not read-write: ${persistent_mount}" >&2
      exit 1
      ;;
  esac
done
