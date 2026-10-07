# Container Memory

RouterOS `memory-current` accounts for the whole container: gateway Go heap,
Xray, Nginx, file cache and socket buffers. It is not a Go heap measurement.
Short-lived increases during uploads, Check/Apply and database replacement
can include temporary objects and file cache; a later decrease alone does not
prove a leak or an OOM. Check native restart history and cgroup memory events.

## Native Limits

The installation defaults remain `memory-high=224M` and `memory-max=256M`.
Settings reads and edits both actual RouterOS values separately from Apply.
`memory-high` is a soft reclaim threshold; `memory-max` is a hard limit.
Existing limits are preserved during ordinary configuration and image updates.

Supported finite values are integer MiB, 16 <= high <= max <= 8192.
Missing or unlimited inventory is not replaced with template values. Lowering
the hard limit requires at least 16 MiB above current container usage, checked
again at execution; this snapshot cannot guarantee that later workloads fit.

**Apply and restart** requires explicit confirmation. A durable operation and
native one-shot worker exclude concurrent Apply, recovery and image updates.
Traffic diversion remains disabled until the watchdog confirms readiness.
Readback checks both limits, the same root and native control-plane health.
An unconfirmed operation is not automatically retried or reported as success.
Reopening Settings resumes reconciliation. Changing limits is not optimization.

## Allocation Optimizations

- Readiness and compact selector polling retain only their requested current
  fields, not complete daily samples or 30-day history.
- Daily histories compact in place and clear expired references. Existing
  retention behavior is preserved.
- Documents larger than 256 KiB bypass the small map cache, avoiding another
  retained graph and deep copy. This is not a document-size limit.
- Atomic-write equality checks use a bounded buffer rather than reading an
  extra full file copy.
- Image uploads synchronize 8 MiB windows and on Linux request eviction of
  completed file-cache pages. Advice is best effort, not a hard memory cap.
- DNS compilation validates IP arrays but retains only presence information;
  traffic routing still preserves all IPv4/IPv6 prefixes.
- Managed GeoIP traffic rules share immutable binary country assets rather
  than repeating inline CIDR arrays. See [GeoIP Assets](GEOIP-ASSETS.md) for
  publication, activation, rollback and obsolete-file cleanup.

Connection buffers and existing runtime settings are unchanged. No new 64 MiB
Go cap, production profiler, periodic forced GC or artificial memory reset is
introduced. The pre-existing `GOMEMLIMIT=128MiB`, `GOGC=150` and separate
`SB_XRAY_GOMEMLIMIT=192MiB` remain soft process budgets, not container limits.

## Operational Limits

Full statistics decode history when requested. Concurrent Apply, database
validation and archive extraction can still raise temporary memory usage.
Neither these optimizations nor a short functional test prove the absence of
long-term leaks or guarantee that every configuration fits inside 256 MiB.
Compare identical workloads and process/cgroup measurements before attributing
an increase to a specific component.

HomeProxy and stock Passwall2 launch their selected core with configuration
generation and optional auxiliary processes; their process layouts are not a
direct RAM benchmark for this gateway. sing-box URLTest keeps current selection
history separate from long-term panel statistics. The same separation guides
compact readiness here; changing cores alone is not a memory guarantee.

References: [HomeProxy](https://github.com/immortalwrt/homeproxy),
[Passwall2](https://github.com/Openwrt-Passwall/openwrt-passwall2),
[sing-box URLTest](https://github.com/SagerNet/sing-box/blob/testing/common/urltest/urltest.go),
[Go memory limits](https://go.dev/doc/gc-guide#Memory_limit).
