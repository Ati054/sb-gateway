# syntax=docker/dockerfile:1.7

ARG GO_IMAGE=golang:1.26.4-alpine@sha256:3ad57304ad93bbec8548a0437ad9e06a455660655d9af011d58b993f6f615648
ARG XRAY_GO_IMAGE=golang:1.27.1-alpine@sha256:cf6fca6641884b8433441b2b0652976f975e1d0fdd26d177eaaf8596087f3125
ARG NODE_IMAGE=node:22-alpine@sha256:16e22a550f3863206a3f701448c45f7912c6896a62de43add43bb9c86130c3e2
ARG RUNTIME_IMAGE=alpine:3.23

FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS sb-gateway-build
ARG TARGETARCH
ARG SB_GATEWAY_VERSION=1.6.24
ARG SB_GATEWAY_REVISION=uncommitted
WORKDIR /src
COPY go.mod go.sum ./
COPY Dockerfile .dockerignore entrypoint.sh ./
COPY cmd ./cmd
COPY internal ./internal
COPY routeros ./routeros
COPY scripts ./scripts
RUN set -eux; \
    CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} /usr/local/go/bin/go build \
      -trimpath \
      -buildvcs=false \
      -ldflags="-s -w -buildid= -X main.version=${SB_GATEWAY_VERSION} -X main.revision=${SB_GATEWAY_REVISION}" \
      -o /out/sb-gateway ./cmd/sb-gateway
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} /usr/local/go/bin/go build \
      -trimpath -buildvcs=false -ldflags="-s -w -buildid=" -o /out/sb-acme ./cmd/sb-acme

FROM --platform=$BUILDPLATFORM ${XRAY_GO_IMAGE} AS xray-build
ARG TARGETARCH
# The server can use the current validated core. Xray's simplified Reverse
# regression is bridge-side; exported reverse clients are pinned separately.
ARG XRAY_VERSION=26.9.9
ARG XRAY_COMMIT=52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120
ARG XRAY_REALITY_COMMIT=8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8
RUN test "${TARGETARCH}" = "arm64"
RUN apk add --no-cache git patch
WORKDIR /src
COPY patches/xray-reality-x25519-compat.patch /tmp/xray-reality-x25519-compat.patch
COPY patches/xray-vision-padding-overflow.patch /tmp/xray-vision-padding-overflow.patch
COPY patches/xray-vless-failure-signal.patch /tmp/xray-vless-failure-signal.patch
RUN git init \
    && git remote add origin https://github.com/XTLS/Xray-core.git \
    && git fetch --depth=1 origin "${XRAY_COMMIT}" \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${XRAY_COMMIT}" \
    && patch -p1 --fuzz=0 < /tmp/xray-vision-padding-overflow.patch \
    && git apply --check /tmp/xray-vless-failure-signal.patch \
    && git apply /tmp/xray-vless-failure-signal.patch \
    && go test ./proxy ./proxy/vless/outbound
RUN set -eux; \
    git clone --filter=blob:none --no-checkout https://github.com/XTLS/REALITY.git /src/reality; \
    git -C /src/reality fetch --depth=1 origin "${XRAY_REALITY_COMMIT}"; \
    git -C /src/reality checkout --detach FETCH_HEAD; \
    test "$(git -C /src/reality rev-parse HEAD)" = "${XRAY_REALITY_COMMIT}"; \
    patch -d /src/reality -p1 --fuzz=0 < /tmp/xray-reality-x25519-compat.patch; \
    grep -F 'if peerPub2 == nil && peerPub == nil {' /src/reality/tls.go; \
    go mod edit -replace github.com/xtls/reality=/src/reality
RUN set -eux; \
    CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build \
      -trimpath \
      -buildvcs=false \
      -gcflags="all=-l=4" \
      -ldflags="-X github.com/xtls/xray-core/core.build=${XRAY_COMMIT} -s -w -buildid=" \
      -o /out/xray ./main

FROM --platform=linux/arm64 alpine:3.23 AS xray-check
ARG XRAY_VERSION=26.9.9
COPY --from=xray-build /out/xray /out/xray
RUN set -eux; \
    /out/xray version | tee /tmp/xray.version; \
    grep -F "Xray ${XRAY_VERSION}" /tmp/xray.version; \
    printf '%s\n' \
      '{"log":{"loglevel":"warning"},"inbounds":[{"tag":"build-validation","listen":"127.0.0.1","port":19099,"protocol":"http"}],"outbounds":[{"tag":"direct","protocol":"freedom"}]}' \
      >/tmp/xray-build-validation.json; \
    /out/xray run -test -config /tmp/xray-build-validation.json; \
    rm -f /tmp/xray-build-validation.json /tmp/xray.version

FROM --platform=$BUILDPLATFORM ${NODE_IMAGE} AS web-build
ARG SB_GATEWAY_REVISION=uncommitted
WORKDIR /src
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts
COPY app ./app
COPY public ./public
COPY build ./build
COPY worker ./worker
COPY next.config.ts vite.config.ts tsconfig.json postcss.config.mjs eslint.config.mjs ./
RUN test -n "${SB_GATEWAY_REVISION}" \
    && npm run build \
    && npm run build:static \
    && npm run lint \
    && test -f /src/out/index.html

FROM ${RUNTIME_IMAGE} AS runtime
RUN set -eux; \
    apk add --no-cache ca-certificates curl gettext iproute2 nginx nginx-mod-stream nftables openssl; \
    if ! grep -q '^www-data:' /etc/group; then addgroup -S www-data; fi; \
    if ! grep -q '^www-data:' /etc/passwd; then adduser -S -D -H -s /sbin/nologin -G www-data www-data; fi; \
    rm -f /etc/nginx/http.d/default.conf
ARG XRAY_VERSION=26.9.9
ARG XRAY_COMMIT=52a412d9e2f5c2a5142b1b4e2ab3771dacb8b120
ARG XRAY_REALITY_COMMIT=8cdf7bf9c7f09cb9814bf08c3eb877f68b85fba8
ARG SB_GATEWAY_VERSION=1.6.24
ARG SB_GATEWAY_REVISION=uncommitted
ARG SB_GATEWAY_SOURCE=local
LABEL org.opencontainers.image.title="sb-gateway" \
      org.opencontainers.image.description="ARM64 Xray proxy gateway and local Web UI for MikroTik RouterOS 7" \
      org.opencontainers.image.source="${SB_GATEWAY_SOURCE}" \
      org.opencontainers.image.version="${SB_GATEWAY_VERSION}" \
      org.opencontainers.image.revision="${SB_GATEWAY_REVISION}" \
      io.sb-gateway.lifecycle.version="1" \
      io.sb-gateway.config.schema="1" \
      io.sb-gateway.config.minimum-schema="1" \
      io.sb-gateway.dependency.xray.version="${XRAY_VERSION}" \
      io.sb-gateway.dependency.xray.revision="${XRAY_COMMIT}" \
      io.sb-gateway.dependency.xray.vision-padding-overflow-compat="true" \
      io.sb-gateway.dependency.reality.revision="${XRAY_REALITY_COMMIT}" \
      io.sb-gateway.dependency.reality.x25519-compat="true"
ENV SB_GATEWAY_VERSION=${SB_GATEWAY_VERSION} \
    SB_GATEWAY_REVISION=${SB_GATEWAY_REVISION} \
    SB_XRAY_VERSION=${XRAY_VERSION} \
    GOGC=150 \
    GOMEMLIMIT=128MiB \
    SB_XRAY_GOMEMLIMIT=192MiB \
    SB_GATEWAY_API_HOST=127.0.0.1 \
    SB_GATEWAY_API_PORT=8080 \
    SB_GATEWAY_STATE_DIR=/state/control-plane \
    SB_GATEWAY_DATA_DIR=/data \
    SB_GATEWAY_SECRETS_DIR=/config/secrets \
    SB_XRAY_CONFIG=/config/generated/xray.json
WORKDIR /opt/sb-gateway
COPY --from=xray-check /out/xray /usr/local/bin/xray
COPY --from=sb-gateway-build /out/sb-gateway /usr/local/bin/sb-gateway
COPY --from=sb-gateway-build /out/sb-acme /usr/local/bin/sb-acme
COPY --from=web-build /src/out /opt/sb-gateway/web/out
COPY rulesets ./rulesets
COPY templates/client-profile.json.j2 templates/nginx-api-decoy.inc templates/nginx-decoy.inc templates/nginx.conf.j2 templates/xray-source-model.json.j2 ./templates/
COPY templates/decoy ./templates/decoy
COPY scripts/configure-transparent-routing.sh scripts/configure-wireguard-egress.sh scripts/healthcheck.sh scripts/preflight.sh scripts/render-runtime.sh scripts/run-xray.sh ./scripts/
COPY entrypoint.sh ./
RUN chmod 0755 entrypoint.sh scripts/*.sh \
    && mkdir -p /config /data /logs /state /run/sb-gateway \
    && mkdir -p /opt/sb-gateway/rulesets-seed \
    && SB_RULESET_DIR=/opt/sb-gateway/rulesets-seed sb-gateway rulesets --prepare \
    && sb-gateway version | grep -F "sb-gateway ${SB_GATEWAY_VERSION}" \
    && xray version | grep -F "Xray ${XRAY_VERSION}"
EXPOSE 443/tcp 443/udp 2443/tcp 2444/tcp 2446/tcp 9443/tcp
VOLUME ["/config", "/data", "/logs", "/state"]
HEALTHCHECK --interval=10s --timeout=10s --start-period=60s --retries=3 \
  CMD ["/opt/sb-gateway/scripts/healthcheck.sh"]
ENTRYPOINT ["/opt/sb-gateway/entrypoint.sh"]
