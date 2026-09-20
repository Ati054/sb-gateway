#!/bin/sh
set -eu

root="${1:-$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)}"

for script in "$root"/entrypoint.sh "$root"/scripts/*.sh; do
  sh -n "$script"
done

grep -Fq '52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120' "$root/Dockerfile"
grep -Fq 'XRAY_GO_IMAGE=golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125' "$root/Dockerfile"
grep -Fq 'FROM --platform=$BUILDPLATFORM ${XRAY_GO_IMAGE} AS xray-build' "$root/Dockerfile"
grep -Fq 'patch -p1 --fuzz=0 < /tmp/xray-vision-padding-overflow.patch' "$root/Dockerfile"
grep -Fq 'go test ./proxy' "$root/Dockerfile"
grep -Fq 'io.sb-gateway.dependency.xray.vision-padding-overflow-compat="true"' "$root/Dockerfile"
grep -Fq 'xray run -test -config /tmp/xray-build-validation.json' "$root/Dockerfile"
if grep -Fq 'COPY tests ' "$root/Dockerfile" \
  || grep -Eq '^COPY[[:space:]]+templates[[:space:]]+\./templates' "$root/Dockerfile" \
  || grep -Eq '^![^[:space:]]*tests' "$root/.dockerignore"; then
  printf '%s\n' "test material can enter the production image build" >&2
  exit 1
fi
grep -Fq 'auto-restart-interval=10s' "$root/routeros/install.rsc"
grep -Fq 'memory-high=$containerMemoryHigh memory-max=$containerMemoryMax' "$root/routeros/install.rsc"
grep -Fq ':set containerMemoryHigh "224M"' "$root/routeros/install.rsc"
grep -Fq ':set containerMemoryMax "256M"' "$root/routeros/install.rsc"
grep -Fq ':global "SB_CONTAINER_MEMORY_HIGH" "224M"' "$root/routeros/variables.example.rsc"
grep -Fq ':global "SB_CONTAINER_MEMORY_MAX" "256M"' "$root/routeros/variables.example.rsc"
grep -Fq 'comment="SB-GATEWAY diversion-gate"' "$root/routeros/install.rsc"
grep -Fq 'connection-mark="sb-managed"' "$root/routeros/watchdog.rsc"
grep -Fq 'SB_MANAGED_CLIENTS failed open' "$root/routeros/watchdog.rsc"
grep -Fq 'listen 9443 ssl' "$root/templates/nginx.conf.j2"
grep -Fq '${DEFAULT_PUBLIC_SERVER}' "$root/templates/nginx.conf.j2"
grep -Fq 'sb-gateway rulesets --prepare' "$root/Dockerfile"
grep -Fq 'exec /usr/local/bin/sb-gateway appliance' "$root/entrypoint.sh"
grep -Fq 'FROM ${RUNTIME_IMAGE} AS runtime' "$root/Dockerfile"
if grep -Eq '(PYTHON_IMAGE|pip install|supervisord|uvicorn)' "$root/Dockerfile" \
  || sed -n '/ AS runtime$/,$p' "$root/Dockerfile" \
    | grep -Eq '^[[:space:]]*COPY[[:space:]]+app([[:space:]]|/)'; then
  printf '%s\n' "legacy Python runtime detected in Dockerfile" >&2
  exit 1
fi

if grep -R -nE '/(ip|ipv6)/firewall/(filter|mangle|nat)/remove \[find\]$' "$root/routeros"; then
  printf '%s\n' "unscoped RouterOS firewall wipe detected" >&2
  exit 1
fi

printf '%s\n' "runtime static checks passed"
