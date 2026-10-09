# Changelog

## 1.6.48

- Apply restores an eligible saved node instead of treating an unconfirmed probe error as a confirmed outage. Health evidence cannot cross core, pool or DNS generations, and planned runtime restarts pause probes only while a bounded live guard is valid.
- Gateway and patched Xray share one executable while retaining independent processes and recovery. Health workers share immutable catalogs; reverse status uses the existing local API connection.
- Encrypted DNS reconnects within bounded deadlines and cancels work before restart. Unchanged RouterOS DNS settings retain their cache and connections.
- Managed IPv4 client queries to RouterOS-local TCP/UDP DNS follow each client's policy, internal zones and WAN exceptions. Recovery expires only affected managed DNS flows, supporting separate port fields and legacy endpoints.
- Smart-home service cards remain separate by ecosystem. Routing drafts persist across navigation and global Apply; an image upgrade offers a single manual Apply Update when required.
- Structural Xray restarts still interrupt established connections. Memory limits, connection buffers, policy modes and atomic GeoIP publication are unchanged.
