# Exchange Card Routing

## Endpoint Review, 2026-10-07

The Bybit, Gate.io, OKX and Binance cards were checked against their official
REST/WebSocket documentation. Regression tests cover 49 representative hosts
through compiled Xray WAN rules and compiled policy-DNS rules for a managed
client. The traffic rules remain independent of URL path, TLS and WebSocket
ports; they do not restrict exchange APIs to port 443.

Bybit now also includes `api-testnet.manepa.jp`, `api.spark-fintech.com`,
`api-testnet.spark-fintech.com` and `stream.spark-fintech.com` in its API pack.
Gate.io adds `api-testnet.gateapi.io`. Existing API seed documents merge these
additions without losing their other rules; repeating the upgrade changes
nothing. The parent exchange cards include their API packs automatically.

Official sources:

- [Bybit REST endpoints](https://bybit-exchange.github.io/docs/v5/guide) and
  [WebSocket endpoints](https://bybit-exchange.github.io/docs/v5/ws/connect).
- [Gate.io REST](https://www.gate.com/docs/developers/apiv4/en/) and
  [WebSocket](https://www.gate.com/docs/developers/apiv4/ws/en/).
- [OKX API](https://my.okx.com/docs-v5/en/).
- [Binance REST](https://developers.binance.com/en/docs/products/spot/rest-api)
  and [WebSocket streams](https://developers.binance.com/docs/binance-spot-api-docs/web-socket-streams).

## DNS Dependency Fix

Previously, the traffic renderer expanded an exchange card's included API
packs, but DNS rules for direct services and explicit service overrides
referenced only the parent card. Domains present only in a dependency could
therefore use a different DNS route from the traffic route.

Both DNS paths now expand the same recursive catalog dependencies. Tests cover
policy-level and client-level rules, direct WAN, another selectable policy,
and rejection when an explicitly requested policy is unavailable. Client
identity, rule priority and fail-closed behavior are retained.

After installing the corrected build, Check/Apply regenerates the traffic and
DNS documents from the selected cards. An already running old resolver cannot
be corrected merely by changing the source catalog on disk.

## What a Timeout Proves

A timeout alone does not establish a missing card domain. Diagnose the
effective traffic and DNS route, upstream reachability, authentication and
connection timing separately. A third-party application's configuration or
heartbeat service is not part of an exchange card and must not be added
implicitly. Adding a domain to a card does not guarantee external reachability
or uninterrupted authenticated WebSocket sessions.
