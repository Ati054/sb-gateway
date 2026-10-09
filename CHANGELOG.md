# Changelog

## 1.6.48

- Go 1.27.2, golang.org/x/net 0.60.0 and shared-core compress 1.18.7 security updates.

- Apply restores an eligible saved node instead of treating an unconfirmed probe error as a confirmed outage. Health evidence cannot cross core, pool or DNS generations, and planned runtime restarts pause probes only while a bounded live guard is valid.
- Gateway and patched Xray share one executable while retaining independent processes and recovery. Health workers share immutable catalogs; reverse status uses the existing local API connection.
- Encrypted DNS reconnects within bounded deadlines and cancels work before restart. Unchanged RouterOS DNS settings retain their cache and connections.
- Managed IPv4 client queries to RouterOS-local TCP/UDP DNS follow each client's policy, internal zones and WAN exceptions. Recovery admits new DNS marking before expiring affected unmanaged DNS flows, closing the concurrent-query recovery race; separate port fields and legacy endpoints are supported.
- Smart-home service cards remain separate by ecosystem. Routing drafts persist across navigation and global Apply; an image upgrade offers a single manual Apply Update when required.
- Structural Xray restarts still interrupt established connections. Memory limits, connection buffers, policy modes and atomic GeoIP publication are unchanged.
