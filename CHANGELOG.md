# Changelog

## 1.6.49

- Watchdog reuses the exact ready-core PID and process generation instead of scanning every process on each healthy cycle. Missing startup proof retains process discovery; API, listeners, routing and configuration checks are unchanged.

- RouterOS installers use a one-shot storage-aware boot worker instead of native container autostart. It waits for the root and the disks used by the actual enabled mounts, confirms readiness twice, then checks source folders once before requesting start. The mount layout is not hardcoded; disks are deduplicated within each poll. Waiting is limited to 150 checks with two-second gaps and never creates folders during boot. Runtime auto-restart and manual Stop after startup are preserved. New image-update workers use the same storage gate for candidate start and ordinary rollback; offline recovery keeps the broken predecessor stopped. Existing installations migrate automatically through saved RouterOS REST credentials after probation, without a manual script import. Legacy native autostart needs one controlled restart; already migrated containers do not restart. Both native running and healthy flags are recognized.

- The runtime image defaults to `GODEBUG=disablethp=1` for Linux Go heaps, including inherited Xray and CLI subprocesses. This avoids transparent huge-page heap inflation without changing host kernel settings, memory budgets, GC targets or connection buffers. The published 1.6.48 image is unchanged.
- Appliance shutdown has a 30-second deadline after cancellation. An unresponsive worker cannot indefinitely block PID 1 termination, including during a stalled planned restart. Forced shutdown does not wait for persistent diagnostic logging; no replacement worker is started alongside the stalled instance.

### Included Changes Since 1.6.35

- HTTPS-latency URLTest with two-confirmation planned switches, bounded parallel failover, median ordering and `Delta, %`; obsolete speed controls and the 600-second return pause are removed.
- Apply preserves eligible saved selections and rejects stale probe evidence across runtime generations; routing drafts persist across navigation and global Apply.
- Shared executable with separate processes, immutable health catalogs and atomic binary GeoIP assets with rollback and obsolete-file cleanup.
- DoH reconnect/deadline validation, policy-aware RouterOS-local DNS interception, race-free DNS recovery and separate smart-home service cards.
- Independently editable RouterOS memory thresholds, safe offline recovery, Go 1.27.2 and updated HTTP/2/compress dependencies. Existing memory budgets and connection buffers are retained.
