#!/bin/sh
set -eu

config="${1:-${SB_XRAY_CONFIG:-/config/generated/xray.json}}"
state_dir="/run/sb-gateway"
state_file="$state_dir/wireguard-egress-addresses"
desired_file="$state_dir/wireguard-egress-addresses.next"
mkdir -p "$state_dir"

sb-gateway wireguard-egress-plan --config "$config" >"$desired_file"

if [ -s "$state_file" ]; then
  while read -r address priority; do
    [ -n "$address" ] || continue
    if ! grep -Fqx "$address $priority" "$desired_file"; then
      while ip rule del priority "$priority" from "$address/32" lookup main >/dev/null 2>&1; do :; done
      ip address del "$address/32" dev lo >/dev/null 2>&1 || true
    fi
  done <"$state_file"
fi

while read -r address priority; do
  [ -n "$address" ] || continue
  if ! ip -o address show dev lo | awk '{print $4}' | grep -Fqx "$address/32"; then
    ip address add "$address/32" dev lo
  fi
  while ip rule del priority "$priority" from "$address/32" lookup main >/dev/null 2>&1; do :; done
  ip rule add priority "$priority" from "$address/32" lookup main
done <"$desired_file"

mv "$desired_file" "$state_file"
chmod 0600 "$state_file"
