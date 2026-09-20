#!/bin/sh
set -eu

fatal() {
  printf '%s\n' "preflight: $*" >&2
  exit 78
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

[ "$(uname -m)" = "aarch64" ] || [ "${SB_ALLOW_NON_ARM64:-0}" = "1" ] \
  || fatal "the production image must run on ARM64/aarch64"
for file in \
  /config/certs/bootstrap.pem \
  /config/certs/bootstrap.key \
  /config/secrets/management-api-token \
  /config/secrets/ws-path \
  /config/secrets/grpc-service \
  /config/secrets/httpupgrade-path
do
  [ -s "$file" ] || fatal "required file is missing or empty: $file"
done

if [ -e /config/certs/origin.pem ] || [ -e /config/certs/origin.key ]; then
  if ! { [ -s /config/certs/origin.pem ] \
      && [ -s /config/certs/origin.key ] \
      && openssl x509 -in /config/certs/origin.pem -noout -checkend 0 >/dev/null 2>&1 \
      && openssl pkey -in /config/certs/origin.key -noout >/dev/null 2>&1 \
      && tls_pair_matches /config/certs/origin.pem /config/certs/origin.key; }; then
    printf '%s\n' "preflight: origin TLS pair is incomplete, invalid, or expired; public ingress stays disabled while management uses bootstrap TLS" >&2
  fi
fi
openssl x509 -in /config/certs/bootstrap.pem -noout -checkend 0 >/dev/null \
  || fatal "temporary management certificate is invalid or expired"
openssl pkey -in /config/certs/bootstrap.key -noout >/dev/null \
  || fatal "temporary management private key is invalid"

token="$(tr -d '\r\n' < /config/secrets/management-api-token)"
case "$token" in
  *[!A-Za-z0-9_-]*|'') fatal "management-api-token must be base64url text" ;;
esac
[ "${#token}" -ge 32 ] || fatal "management-api-token must contain at least 32 characters"

[ -s /opt/sb-gateway/web/out/index.html ] || fatal "static Web UI export is absent"
xray version | grep -Fq "Xray 26.9.9" \
  || fatal "unexpected Xray version"
