#!/bin/sh
set -eu

read_secret() {
  tr -d '\r\n' < "$1"
}

tls_pair_matches() {
  cert_digest="$(
    openssl x509 -in "$1" -pubkey -noout 2>/dev/null \
      | openssl pkey -pubin -outform DER 2>/dev/null \
      | sha256sum | awk '{print $1}'
  )"
  key_digest="$(
    openssl pkey -in "$2" -pubout -outform DER 2>/dev/null \
      | sha256sum | awk '{print $1}'
  )"
  [ -n "$cert_digest" ] && [ "$cert_digest" = "$key_digest" ]
}

valid_host() {
  case "$1" in
    ''|*[!A-Za-z0-9.-]*|.*|*..*|*.) return 1 ;;
  esac
}

valid_path() {
  case "$1" in
    /*) ;;
    *) return 1 ;;
  esac
  case "$1" in
    *[!A-Za-z0-9_./~-]*) return 1 ;;
  esac
}

ROUTEROS_GATEWAY="${SB_ROUTEROS_GATEWAY:-}"
case "$ROUTEROS_GATEWAY" in
  *[!0-9.]*|'')
    printf '%s\n' \
      "actual SB_ROUTEROS_GATEWAY is required; no example runtime fallback is permitted" >&2
    exit 78
    ;;
esac
if [ -s /config/certs/origin.pem ] && [ -s /config/certs/origin.key ] \
   && openssl x509 -in /config/certs/origin.pem -noout -checkend 0 >/dev/null 2>&1 \
   && openssl pkey -in /config/certs/origin.key -noout >/dev/null 2>&1 \
   && tls_pair_matches /config/certs/origin.pem /config/certs/origin.key \
   && [ -s "${SB_XRAY_CONFIG:-/config/generated/xray.json}" ]; then
  WS_HOST="${SB_WS_HOST:-ws.example.invalid}"
  GRPC_HOST="${SB_GRPC_HOST:-grpc.example.invalid}"
  STATUS_HOST="${SB_STATUS_HOST:-status.example.invalid}"
  PUBLIC_TLS_CERT="${SB_PUBLIC_TLS_CERT:-/config/certs/origin.pem}"
  PUBLIC_TLS_KEY="${SB_PUBLIC_TLS_KEY:-/config/certs/origin.key}"
else
  # Setup mode: management stays available, while all public names are inert.
  WS_HOST="websocket-disabled.invalid"
  GRPC_HOST="grpc-disabled.invalid"
  STATUS_HOST="status-disabled.invalid"
  PUBLIC_TLS_CERT="/config/certs/bootstrap.pem"
  PUBLIC_TLS_KEY="/config/certs/bootstrap.key"
fi
MANAGEMENT_TLS_CERT="${SB_MANAGEMENT_TLS_CERT:-$PUBLIC_TLS_CERT}"
MANAGEMENT_TLS_KEY="${SB_MANAGEMENT_TLS_KEY:-$PUBLIC_TLS_KEY}"
WS_PATH="$(read_secret /config/secrets/ws-path)"
GRPC_SERVICE="$(read_secret /config/secrets/grpc-service)"
MANAGEMENT_TOKEN="$(read_secret /config/secrets/management-api-token)"

if [ "${SB_HTTPUPGRADE_ENABLED:-0}" = "1" ] \
   && [ "$PUBLIC_TLS_CERT" != "/config/certs/bootstrap.pem" ]; then
  HU_HOST="${SB_HU_HOST:-hu.example.invalid}"
  [ -s /config/secrets/httpupgrade-path ] || {
    printf '%s\n' "httpupgrade enabled but its path secret is missing" >&2
    exit 78
  }
  HU_PATH="$(read_secret /config/secrets/httpupgrade-path)"
else
  HU_HOST="httpupgrade-disabled.invalid"
  HU_PATH="/disabled-httpupgrade"
fi

for host in "$WS_HOST" "$GRPC_HOST" "$HU_HOST" "$STATUS_HOST"; do
  valid_host "$host" || {
    printf '%s\n' "invalid hostname: $host" >&2
    exit 78
  }
done
valid_path "$WS_PATH" || {
  printf '%s\n' "invalid websocket path secret" >&2
  exit 78
}
valid_path "$HU_PATH" || {
  printf '%s\n' "invalid HTTPUpgrade path secret" >&2
  exit 78
}
case "$GRPC_SERVICE" in
  ''|*[!A-Za-z0-9_.~-]*)
    printf '%s\n' "invalid gRPC service secret" >&2
    exit 78
    ;;
esac
case "$ROUTEROS_GATEWAY" in
  *[!0-9.]*|'')
    printf '%s\n' "invalid RouterOS IPv4 gateway" >&2
    exit 78
    ;;
esac

export WS_HOST GRPC_HOST HU_HOST STATUS_HOST ROUTEROS_GATEWAY
export PUBLIC_TLS_CERT PUBLIC_TLS_KEY MANAGEMENT_TLS_CERT MANAGEMENT_TLS_KEY
export WS_PATH GRPC_SERVICE HU_PATH MANAGEMENT_TOKEN

# Bootstrap exposes management and local health only. Public server fragments
# are rendered by the native control plane once a configuration exists. Still,
# every template token must be replaced here: a literal ${TOKEN} makes nginx
# reject first boot before the API can become healthy.
DECOY_ROOT="/opt/sb-gateway/templates/decoy"
DECOY_HTTP_SERVER=""
DEFAULT_PUBLIC_SERVER=""
REALITY_COVER_SERVER=""
DECOY_HTTPS_SERVER=""
WS_SERVER=""
GRPC_SERVER=""
HU_SERVER=""
XHTTP_SERVER=""
STATUS_SERVER=""
SUBSCRIPTION_SERVER=""
SHARED_STREAM=""
ORIGIN_MAPS=""
export SHARED_STREAM ORIGIN_MAPS
SUBSCRIPTION_RELAY_SOURCE="${SB_GATEWAY_SUBSCRIPTION_RELAY_SOURCE:-$ROUTEROS_GATEWAY}"
case "$SUBSCRIPTION_RELAY_SOURCE" in
  ''|*[!0-9./]*)
    printf '%s\n' "invalid private subscription relay IPv4 source" >&2
    exit 78
    ;;
esac
export DECOY_ROOT DECOY_HTTP_SERVER DEFAULT_PUBLIC_SERVER DECOY_HTTPS_SERVER
export REALITY_COVER_SERVER
export WS_SERVER GRPC_SERVER HU_SERVER XHTTP_SERVER STATUS_SERVER
export SUBSCRIPTION_SERVER SUBSCRIPTION_RELAY_SOURCE

envsubst '${SHARED_STREAM} ${ORIGIN_MAPS} ${DECOY_ROOT} ${DECOY_HTTP_SERVER} ${DEFAULT_PUBLIC_SERVER} ${REALITY_COVER_SERVER} ${DECOY_HTTPS_SERVER} ${WS_SERVER} ${GRPC_SERVER} ${HU_SERVER} ${XHTTP_SERVER} ${STATUS_SERVER} ${SUBSCRIPTION_SERVER} ${MANAGEMENT_TLS_CERT} ${MANAGEMENT_TLS_KEY} ${MANAGEMENT_TOKEN} ${ROUTEROS_GATEWAY} ${SUBSCRIPTION_RELAY_SOURCE}' \
  < /opt/sb-gateway/templates/nginx.conf.j2 \
  > /run/sb-gateway/nginx.conf
chmod 0600 /run/sb-gateway/nginx.conf
