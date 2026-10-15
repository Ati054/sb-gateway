# Changelog

## 1.6.62

- Raised Nginx connection capacity and upgraded saved limits automatically at startup.
- Added periodic size-based rotation for Xray and Nginx diagnostic logs without restarting traffic services.
- Added startup warnings for unverified streaming limits in custom saved Nginx configurations.

## 1.6.61

- Kept DNS domain rules compatible with image rollback while sharing their in-memory membership.
- Updated Xray and REALITY to pinned upstream revisions through 2026-10-14.
- Fixed gRPC channel reconnection after a completed or canceled first request and improved Hysteria cancellation and cleanup.

## 1.6.60

- Shared large domain sets across routing and DNS rules and streamed catalog updates.
- Fixed large and idle gRPC/XHTTP uploads through Nginx.
- Derived process memory budgets from container limits, reserving space for temporary tasks.

## 1.6.59

- Fixed saving Settings with the default zero recovery cooldown.
- Split panel sections while preserving drafts and one Apply across navigation.
- Added browser regression checks and simplified installation guidance.
- Retained the public release history in source archives.

## 1.6.58

- Added a WAN ping switch; related ICMP errors and required multicast/broadcast remain allowed.
- Improved Reverse status, name editing, startup recovery and connection stability.
- Improved HTTPS availability checks, URLTest reserve selection and inactive-profile certificate issuance.
- Run Apply once after upgrading to reconcile settings and RouterOS rules.

## 1.6.49

- Reduced memory use and background CPU work.
- Container startup waits for the storage it actually uses; existing installations migrate automatically.
- Preserved selected routes across Apply and improved DNS recovery and smart-home service cards.
- Added independent container memory limits and safer offline recovery.
- URLTest uses HTTPS latency instead of download-speed probes.

## 1.6.35

- Added confirmed speed-degradation failover and paired comparisons before planned URLTest switches.
- Improved reserve selection and bounded background probe work.

## 1.6.34

- Improved failover, subscription updates, node-quality display and route editors.
- Reduced false rollbacks with large GeoIP rules and preserved selected routes during rule updates.
- Kept unrelated RouterOS logging rules and existing connections intact.

## 1.6.33

- Updated the server to Xray-core 26.9.30 and fixed concurrent selector, XHTTP and certificate updates.
- Added dynamic node groups, custom routing rules, country GeoIP routes and regional service cards.
- Improved Apply recovery and rejected conflicting draft mutations without late writes.

## 1.6.27

- Reduced false switches and delays when finding a working reserve.
- Improved retry of failed speed measurements and reduced memory accumulation during subscription updates.

## 1.6.26

- Added confirmed URLTest switches based on speed gain while retaining latency limits and anti-flap protection.
- Corrected the panel's HTTPS median threshold label.

## 1.6.25

- A single failed HTTPS test site no longer marks a VLESS node unavailable.
- Preserved RouterOS logging exclusions and fixed final-line handling in optional CDN feed updates.

## 1.6.24

- Added immediate confirmation probes after connection failures and a dedicated route-switch log.
- Improved bounded reserve searches and discarded stale health evidence after node changes.

## 1.6.22

- Continued searching untested reserves during complete outages.
- Safely cleaned obsolete subscription snapshots and retired handlers after confirmed selection.

## 1.6.21

- Added global route-monitor settings and aligned the quality table with priority order.
- Preserved existing configuration, secrets and node statistics across updates.

## 1.6.20

- Added recovery for an interrupted first Apply and serialized manual rollback with other management operations.

## 1.6.19

- Improved recovery after interrupted Apply and container updates without starting duplicate operations.
- Rejected invalid subscription responses while retaining the last working configuration.

## 1.6.18

- Fixed protected Apply finalization and distinguished confirmed rollback from an unknown operation result.
- Kept priority-route quality rows in their configured order.

## 1.6.17

- First public release: browser-managed routing, subscriptions, local and remote clients, certificates and container updates.
- Added protected Apply with backup and rollback for supported ARM64 RouterOS containers.
