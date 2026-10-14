# Changelog

## 1.6.58

- Added a default-enabled WAN ping switch for managed IPv4/IPv6 clients. Related ICMP errors remain allowed in either state; multicast and broadcast no longer depend on editable exclusions. Unsupported public IP protocols are blocked without affecting separate router VPNs or LAN traffic.
- Watchdog monitors the live dataplane without repeated Xray configuration tests. Check/Apply, startup validation and transactional GeoIP rollback remain active.
- Reverse connection indicators use online telemetry, name editing preserves focus, and startup waits up to 30 seconds for a selected Reverse with a working path. Independent XHTTP/REALITY profiles remain isolated; blocked internal tunnels are avoided without closing existing streams.
- HTTPS availability uses a shared five-second round, with additional sites after two seconds. URLTest failover ranks fresh successful measurements, and stalled REALITY probes release sockets.
- ACME issuance supports inactive profiles and preserves queued requests across unchanged saves. Activation uses Apply; interrupted issuance requires an explicit retry.
- Restored architecture-default Xray connection buffers. Apply once after upgrading to reconcile generated settings and RouterOS rules.
