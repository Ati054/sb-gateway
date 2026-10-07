# Changelog

## 1.6.45

- Managed GeoIP uses immutable content-addressed binary Xray assets instead of repeated inline CIDRs. Check, Apply, startup migration and hot refresh share the same asset directory; portable IPv4/IPv6 packs remain available to DNS and RouterOS.
- A failed hot update rolls back to the last confirmed GeoIP version. Obsolete databases are cleaned after confirmation, retaining active/LKG/Apply/rollback references and short-lived publication leases. Recovery archives include the required country sources and binary files.
- Both native RouterOS memory limits are editable with explicit restart confirmation and actual readback. Ordinary Apply and image commit do not silently reset limits or mutate a running container's boot policy.
- Includes startup/readiness, upload-cache, selector-history and exchange-card corrections. Known dependency audit findings and extended memory/recovery verification remain open; see the release notes.
