#!/bin/sh
set -eu

umask 077
export SB_GATEWAY_API_HOST="${SB_GATEWAY_API_HOST:-127.0.0.1}"
export SB_GATEWAY_API_PORT="${SB_GATEWAY_API_PORT:-8080}"
export SB_GATEWAY_STATE_DIR="${SB_GATEWAY_STATE_DIR:-/state/control-plane}"
export SB_GATEWAY_DATA_DIR="${SB_GATEWAY_DATA_DIR:-/data}"
export SB_GATEWAY_SECRETS_DIR="${SB_GATEWAY_SECRETS_DIR:-/config/secrets}"
export SB_XRAY_CONFIG="${SB_XRAY_CONFIG:-/config/generated/xray.json}"
export SB_RUNTIME_CANDIDATE_DIR="${SB_RUNTIME_CANDIDATE_DIR:-/state/runtime-candidates}"

mkdir -p \
  /config/certs /config/generated /config/secrets /config/rulesets \
  /data/backups /data/last-known-good \
  /logs/nginx "${SB_GATEWAY_STATE_DIR}" /run/sb-gateway \
  /run/sb-gateway/nginx-client-body
chmod 0700 /config/secrets "${SB_GATEWAY_STATE_DIR}" /data/backups /data/last-known-good
chmod 0755 /run/sb-gateway
chmod 0700 /run/sb-gateway/nginx-client-body
chmod 0750 /logs/nginx
chown www-data:www-data /logs/nginx /run/sb-gateway/nginx-client-body

# A recovery request is fully authenticated and staged by the Web UI before
# RouterOS restarts the container.  Apply it before any runtime process reads
# persistent state or generates first-boot defaults.
if [ -f /config/.sb-gateway-recovery-pending.json ]; then
  /usr/local/bin/sb-gateway recovery-apply-pending
fi

# First boot must expose the management UI without requiring secrets that the
# wizard itself provisions. Values are generated locally, never logged, and
# written atomically with mode 0600.
generate_hex_secret() {
  destination="$1"
  bytes="$2"
  if [ ! -s "$destination" ]; then
    temporary="${destination}.tmp.$$"
    mkdir -p "$(dirname "$destination")"
    openssl rand -hex "$bytes" > "$temporary"
    chmod 0600 "$temporary"
    mv "$temporary" "$destination"
  fi
}

generate_path_secret() {
  destination="$1"
  if [ ! -s "$destination" ]; then
    temporary="${destination}.tmp.$$"
    {
      printf '/'
      openssl rand -hex 24
    } > "$temporary"
    chmod 0600 "$temporary"
    mv "$temporary" "$destination"
  fi
}

restore_lkg_nginx() {
  # CandidateStore commits the verified runtime under its persistent state
  # root. Keep startup pointed at the same file so an image/container restart
  # cannot silently fall back to the management-only bootstrap listener.
  lkg="${SB_NGINX_LKG_CONFIG:-${SB_RUNTIME_CANDIDATE_DIR}/runtime-lkg/nginx.conf}"
  selected_config="${SB_XRAY_CONFIG:-/config/generated/xray.json}"
  runtime_config="${SB_NGINX_RUNTIME_CONFIG:-/run/sb-gateway/nginx.conf}"
  candidate="${runtime_config}.lkg.$$"

  [ -s "$lkg" ] && [ -s "$selected_config" ] || return 1
  # Runtime configuration is generated code. Never revive a structurally old
  # last-known-good file after an image upgrade; render the active model with
  # the current template instead.
  grep -Eq '^# sb-gateway-nginx-schema: (2|3)$' "$lkg" || return 1
  if ! cp "$lkg" "$candidate"; then
    printf '%s\n' "entrypoint: unable to stage last-known-good nginx config" >&2
    return 1
  fi
  if ! chmod 0600 "$candidate"; then
    rm -f "$candidate"
    printf '%s\n' "entrypoint: unable to secure staged last-known-good nginx config" >&2
    return 1
  fi
  if nginx -t -c "$candidate" -p / >/dev/null 2>&1; then
    if mv "$candidate" "$runtime_config"; then
      return 0
    fi
    rm -f "$candidate"
    printf '%s\n' "entrypoint: unable to activate last-known-good nginx config" >&2
    return 1
  fi
  rm -f "$candidate"
  printf '%s\n' "entrypoint: last-known-good nginx config is invalid; using setup config" >&2
  return 1
}

generate_hex_secret /config/secrets/management-api-token 32
generate_hex_secret /config/secrets/session-signing-key 32
generate_path_secret /config/secrets/ws-path
generate_path_secret /config/secrets/httpupgrade-path
if [ ! -s /config/secrets/grpc-service ]; then
  grpc_tmp="/config/secrets/grpc-service.tmp.$$"
  {
    printf 'grpc-'
    openssl rand -hex 24
  } > "$grpc_tmp"
  chmod 0600 "$grpc_tmp"
  mv "$grpc_tmp" /config/secrets/grpc-service
fi

bootstrap_ip="${SB_CONTAINER_IP:-}"
if [ -z "$bootstrap_ip" ] && [ -n "${SB_CONTAINER_ADDRESS:-}" ]; then
  bootstrap_ip="${SB_CONTAINER_ADDRESS%%/*}"
fi
case "$bootstrap_ip" in
  *[!0-9.]*|'')
    printf '%s\n' \
      "actual SB_CONTAINER_IP or SB_CONTAINER_ADDRESS is required for the bootstrap certificate" >&2
    exit 78
    ;;
esac

bootstrap_valid=1
openssl x509 -in /config/certs/bootstrap.pem -noout -checkend 86400 >/dev/null 2>&1 \
  || bootstrap_valid=0
openssl x509 -in /config/certs/bootstrap.pem -noout -checkip "$bootstrap_ip" >/dev/null 2>&1 \
  || bootstrap_valid=0
openssl pkey -in /config/certs/bootstrap.key -noout >/dev/null 2>&1 \
  || bootstrap_valid=0
bootstrap_cert_digest="$(
  openssl x509 -in /config/certs/bootstrap.pem -pubkey -noout 2>/dev/null \
    | openssl pkey -pubin -outform DER 2>/dev/null \
    | sha256sum | awk '{print $1}'
)"
bootstrap_key_digest="$(
  openssl pkey -in /config/certs/bootstrap.key -pubout -outform DER 2>/dev/null \
    | sha256sum | awk '{print $1}'
)"
[ -n "$bootstrap_cert_digest" ] \
  && [ "$bootstrap_cert_digest" = "$bootstrap_key_digest" ] \
  || bootstrap_valid=0
if [ "$bootstrap_valid" -ne 1 ]; then
  rm -f /config/certs/bootstrap.pem /config/certs/bootstrap.key
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 30 \
    -subj "/CN=sb-gateway.local" \
    -addext "subjectAltName=DNS:sb-gateway.local,IP:${bootstrap_ip}" \
    -keyout /config/certs/bootstrap.key \
    -out /config/certs/bootstrap.pem >/dev/null 2>&1
  chmod 0600 /config/certs/bootstrap.pem /config/certs/bootstrap.key
fi

# Secrets are flat files owned by the control plane.  A recursive walk is both
# unnecessary and very expensive on RouterOS external storage, where it can
# hold the whole container startup before the Go appliance is reached.
for secret_file in /config/secrets/*; do
  [ -f "$secret_file" ] || continue
  chmod 0600 "$secret_file"
done
rm -f /run/sb-gateway/router-ready
# Xray is the only supported core.  Remove the exact legacy generated file
# left by releases that still rendered sing-box; user configuration and other
# generated artifacts are not touched.
rm -f /config/generated/sing-box.json
# The complete reviewed fallback set is prepared at image build time.  Startup
# only installs files that do not exist yet; it never parses large downloaded
# rule sets before the management API becomes available.  The native
# worker validates, merges and refreshes them after startup.
for seed in /opt/sb-gateway/rulesets-seed/*.json; do
  [ -f "$seed" ] || continue
  destination="/config/rulesets/${seed##*/}"
  if [ ! -e "$destination" ]; then
    temporary="${destination}.tmp.$$"
    cp "$seed" "$temporary"
    chmod 0600 "$temporary"
    mv "$temporary" "$destination"
  fi
done

/opt/sb-gateway/scripts/preflight.sh
if ! restore_lkg_nginx; then
  /opt/sb-gateway/scripts/render-runtime.sh
fi
nginx -t -c /run/sb-gateway/nginx.conf

exec /usr/local/bin/sb-gateway appliance
