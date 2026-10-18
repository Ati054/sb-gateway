# Container Memory

RouterOS `memory-current` accounts for the whole container: gateway Go heap,
Xray, Nginx, file cache and socket buffers. It is not a Go heap measurement.
Short-lived increases during uploads, Check/Apply and database replacement
can include temporary objects and file cache; a later decrease alone does not
prove a leak or an OOM. Check native restart history and cgroup memory events.

## Native Limits

New installations default to `memory-high=288M` and `memory-max=320M`.
Settings reads and edits both actual RouterOS values separately from Apply.
`memory-high` is a soft reclaim threshold; `memory-max` is a hard limit.
Existing limits are preserved during ordinary configuration and image updates.
An existing 224/256 MiB setting is not migrated automatically. Repeated reclaim
events together with DNS or local API delays are a reason to review the limits
in Settings and the router's available RAM. Higher limits do not preallocate RAM.

Supported finite values are integer MiB, 16 <= high <= max <= 8192.
Missing or unlimited inventory is not replaced with template values. Lowering
the hard limit requires at least 16 MiB above current container usage, checked
again at execution; this snapshot cannot guarantee that later workloads fit.
RouterOS may omit a false `stopped` flag. The panel accepts that representation
only with readable finite limits and positive live memory usage; an explicitly
stopped container, missing usage or zero usage cannot schedule a change.

**Apply and restart** requires explicit confirmation. A durable operation and
native one-shot worker exclude concurrent Apply, recovery and image updates.
Traffic diversion remains disabled until the watchdog confirms readiness.
Readback checks both limits, the same root and native control-plane health.
RouterOS paths with or without a surrounding slash identify the same root;
different roots, unhealthy containers and queued operations remain unconfirmed.
An unconfirmed operation is not automatically retried or reported as success.
Reopening Settings resumes reconciliation. Changing limits alone does not
guarantee capacity or improve the efficiency of a workload.

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

These are arithmetic headroom allocations, not preallocated RAM. The two helper
slots remain independent: certificate propagation must not monopolize validation.

With high/max 224/256 MiB the planned soft limits are approximately 83.2 MiB
Xray, 44.8 MiB gateway and 28 MiB for each helper, plus 40 MiB non-Go reserve.
For the default 288/320 MiB they are 114.4, 61.6 and 32 MiB respectively,
plus 40 MiB. The working ceiling is 280 MiB, below the native reclaim threshold.
For 320/384 MiB they are 140.4, 75.6 and 32 MiB respectively, plus 40 MiB.
Container limits themselves are never raised by this calculation.

### Idle ACME Loan

The packaged image enables `SB_MEMORY_BUDGET_ACME_LOAN=1`. The controller may
use the idle ACME helper allowance without changing Xray, native limits or the
permanent validation allowance.
At 224/256 MiB its idle soft limit becomes 72.8 MiB; at 256/320 MiB it becomes
85.2 MiB instead of 53.2 MiB. At 288/320 MiB it becomes 93.6 MiB instead of
61.6 MiB. An explicitly lower `GOMEMLIMIT` still wins. Set
`SB_MEMORY_BUDGET_ACME_LOAN=0` to retain the base controller budget.
Readable usage and a finite cgroup ceiling matching the startup plan are required;
fallback hints alone cannot enable lending. Otherwise the base limit stays.
The visible cgroup root must contain the controller itself. An empty limited
parent is also accepted when every empty ancestor has exactly one real child
leading to the controller (for example RouterOS `/init`). Sibling groups,
invisible task IDs and links in that chain are rejected. Traversal is bounded;
unavailable or ambiguous ownership disables lending. A leaf-only usage counter
cannot establish spare memory in a shared parent hierarchy.
The startup log distinguishes `gateway_base` from the temporary `acme_idle_loan`;
the borrowed allowance is not a third simultaneous helper reservation.

Before starting ACME, the controller recalls the loan and serializes ACME workers.
It verifies current cgroup usage leaves the helper allowance plus up to 16 MiB
extra margin below the ceiling. Only if necessary, this rare admission path makes
one explicit reclaim attempt and waits up to two further seconds for headroom.
Unknown usage rejects the worker without forcing GC; insufficient headroom also
rejects it safely after the bounded admission attempt. Cancellation,
start failure, worker failure and progress-pipe completion restore the idle
allowance. Validation does not wait on this ACME slot; Apply can proceed while
DNS challenge propagation waits. No periodic forced collection is added.

### Physical Headroom For The Idle Loan

The packaged image also enables `SB_MEMORY_PRESSURE_BUDGET=1`. Every two seconds
the controller checks its owned cgroup usage, clean unmapped file cache and its
own Go memory counters. The idle loan is reduced when other container memory,
including Xray and kernel socket buffers, consumes the available headroom. Mapped
code, dirty files and a 4-MiB file working set are not treated as disposable cache.
Up to 24 MiB below the working ceiling is kept out of the loan calculation.

Only the borrowed ACME allowance changes: the controller base floor, Xray budget,
two independent helper allowances and native limits remain unchanged. A live-heap
floor avoids asking GC to reclaim still-referenced objects. Unknown counters
recall the loan to its base floor; they do not grant more memory. After pressure
subsides, borrowing grows by at most 4 MiB per check, up to the existing idle cap.
An active ACME worker always retains its slot. Release rechecks physical headroom
instead of unconditionally restoring the full loan. Monitoring changes only the
soft Go limit, never calls `runtime.GC`/`FreeOSMemory`, and runs no subprocesses.

`SB_MEMORY_PRESSURE_BUDGET=0` disables this headroom monitor for controlled
comparisons; ordinary ACME admission/recall still applies. This is not an RSS
hard cap or a guarantee that every traffic load fits in the configured container.

Use [controller runtime counters](CONTROLLER-RUNTIME-DIAGNOSTICS.md) to distinguish
GC work from useful controller work; measure actual OS CPU separately.

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
production profiler or artificial memory reset is introduced. Ordinary traffic
and tunnel idle timeouts are unchanged. Only the internal DNS-lane Freedom
outbounds use a separate policy level (100) with a 30-second inactivity timer,
instead of retaining completed UDP exchanges for the ordinary 300 seconds.
This exceeds the resolver's maximum 15-second query budget; ongoing exchanges
refresh the timer. It does not shorten persistent DoH connections or change
TCP/UDP, VLESS or Reverse traffic policies. A pinned-core loopback regression
checks both idle-session release and continued activity on the same session.
The image build runs this regression together with the runtime renderer tests;
its Go test stage includes the maintained rendering templates.
Image startup regenerates older DNS forwarding policies from the committed
configuration through the existing validation and activation transaction. This
does not edit drafts or require an extra Apply; an already current policy is
left unchanged.

Policy DNS retains its bounded upstream worker and TCP-session counts. When
upstream workers are busy, UDP and accepted TCP sessions can still receive fresh
cached answers and local rejection decisions. This path uses the same lane,
question and routing validation, opens no upstream connection and does not serve
expired data as fresh. Uncached queries retain the overload response; no unbounded
queue or new goroutine pool is introduced.

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
