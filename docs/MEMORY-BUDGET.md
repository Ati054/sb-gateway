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

## Go Process Budgets

The packaged image enables `SB_MEMORY_BUDGET=1`. Gateway, the multicall Xray
core and transient helpers derive soft Go limits at process startup from
cgroup v2 `memory.high` and `memory.max`, including visible parent limits.
The working ceiling is the lower finite value of `memory.high` and 7/8 of
`memory.max`. Unlimited or missing values do not become enormous Go budgets.

The ceiling reserves up to 40 MiB (at most one quarter of the ceiling) for
non-Go memory. Two helper reserves are each at most 32 MiB or one eighth of
the ceiling. The remaining budget is split 65% Xray, 35% gateway. One reserve
covers configuration validation and the other ACME, so a long certificate
operation does not need to block Apply. Validation subprocesses within the
controller are serialized with a cancellable wait.

These are arithmetic headroom allocations, not preallocated RAM. Combining the
two helper slots would require serializing certificate issuance with validation;
DNS challenge propagation could then delay Check/Apply for the whole issuance.
Do not reclaim a helper slot without enforcing that exclusion across startup and
controller subprocesses and measuring the operational delay. Any reclaimed
budget would follow the same 65/35 split, not all go to Xray.

With high/max 224/256 MiB the planned soft limits are approximately 83.2 MiB
Xray, 44.8 MiB gateway and 28 MiB for each helper, plus 40 MiB non-Go reserve.
For 320/384 MiB they are 140.4, 75.6 and 32 MiB respectively, plus 40 MiB.
Container limits themselves are never raised by this calculation.

If neither cgroup value is available, the last finite RouterOS limits observed
by the memory Settings endpoint are read from `memory-budget-limits.json` in
the control-plane state directory. Before a scheduled change, this hint may
tighten but cannot assume an unconfirmed increase. Without either source the
fallback ceiling is 224 MiB. This fallback cannot discover a smaller limit
on its own: cgroup-unavailable installations must confirm memory Settings
before relying on it. Supported panel changes restart the container, so the
new processes recalculate automatically. Manual external limit changes also
require a restart to update the long-running processes' budgets.

`GOMEMLIMIT` (gateway) and `SB_XRAY_GOMEMLIMIT` (core) may lower their calculated
limits; they cannot raise them while automatic budgeting is enabled. Xray
validation/API commands use a helper budget rather than a second core budget.
ACME keeps its minimal environment and `GOMAXPROCS=1`; THP remains disabled.
Host-side developer commands are not automatically capped by this image setting.

`GOGC=150` still controls ordinary collection before a soft limit is reached.
GOMEMLIMIT is not a reservation, a combined RSS limit or a guarantee against
OOM: live objects can exceed it, and binary mappings, sockets and file cache
need separate headroom. Smaller budgets can increase GC CPU. Functional tests
and the formula do not establish capacity for a full LAN or sustained traffic;
compare CPU, latency, throughput and cgroup pressure under the same workload.

## Allocation Optimizations

- Large service domain rules use content-addressed GeoSite assets and share
  compiled Xray matchers. DNS shares membership independently of per-lane
  routing decisions; catalog text is parsed as a bounded stream.
  See [Shared Domain Sets](DOMAIN-SETS.md) for migration and verification.

- The shared-executable candidate retains separate gateway/core processes while
  deduplicating their compiled dependencies. See [Shared Executable](XRAY-MULTICALL.md)
  for dispatch, build requirements and verification status; binary size alone is
  not a full-container RAM measurement.
- Parallel probe lanes share one immutable parsed health-pool inventory per
  controller generation. Dynamic-handler ownership and probe state stay local
  to each lane. Atomic replacements invalidate the cache even when size and
  timestamp match; invalid input cannot replace the last parsed snapshot.
- Subscription name filters reuse one concurrency-safe variation-selector
  replacer and skip label normalization when neither name filter is present.
- Reverse-peer availability uses the controller's shared local gRPC connection
  and the existing Xray online-statistic method instead of an API subprocess.
  Missing, mismatched or failed responses do not establish peer availability.
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

Connection buffers remain at the architecture default. No periodic forced GC,
production profiler or artificial memory reset is introduced. Connection idle
timeouts are unchanged; reducing them requires evidence and long-session tests.

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
