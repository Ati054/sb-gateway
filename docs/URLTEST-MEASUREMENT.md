# URLTest Measurement

This document describes source behavior and measurement boundaries. It does not
claim completed image or physical-router performance acceptance.

## Gateway Behavior

The gateway currently measures a new primary-origin HTTP request, including
connection setup, through its isolated probe selector. Keep-alive is disabled.
HTTPS probes explicitly use HTTP/1.1, matching the first request of the
same-connection experiment. Disabling forced HTTP/2 alone does not prevent
automatic ALPN negotiation with Go's default TLS dialer. Certificate and
hostname verification, expected status checks and the cold no-reuse boundary
remain enforced. The `gstatic-h1-head-v2` marker invalidates earlier planning
samples and pending confirmations while preserving the working selection and
historical full-request statistics. Historical statistics can therefore span
both measurement versions; they do not authorize a fresh planned switch.
URLTest ranks the median of up to three recent full-request samples. A planned
switch needs two independent comparisons in which both the latest full-request
pair and the short median beat the configured margin. A recovered latest pair
therefore cancels a pending switch even when the older median is still slow.
Both sample timestamps must advance between accepted confirmations. A split
pair can use a recent active sample at a one-slot budget, but that same active
sample cannot confirm a second win. Recalculation does not issue extra probes.
The window expires after two reserve intervals (at least 120 seconds); sparse
sampling never makes an old delay permanent. Availability and priority failback
retain their separate confirmation paths. Alternate-origin successes prove
availability only and never enter the latency ranking.

The threshold remains milliseconds of the full fresh HTTPS request. A setup-free
response duration is collected from connection readiness to first response byte
for diagnostics only; it does not silently reinterpret the threshold as RTT.
Successful-path probe counts are unchanged. Switch comparison logs identify the
measurement, effective margin, short-median delays and any fresh setup-free
response durations. Historical availability and full-request latency history
remain compatible and are not erased.

The fast availability lane dates a successful cold quality proof with its
original subsecond observation time. Whole-second history scheduling must not
trigger another availability request before the configured interval ends.
Explicit failure signals still force an immediate check; this does not add a
quality confirmation or change the interval/margin settings.

A short routine quality job also services an overdue active check before the
next controller sleep. This prevents a continuing one-slot survey from repeatedly
winning the wake-up tie and leaving the active route untested. Quality progress
is retained; a confirmed failure yields immediately to emergency handling rather
than waiting for the remaining survey. Active quality successes still satisfy
the availability interval, without an unnecessary second request.

An already confirmed active-path failure enters emergency reserve selection
before either the routine quality deadline or the active retry timer. It does
not spend another availability request on the confirmed failed active node.
Failures still awaiting independent confirmation retain the normal retry
interval and threshold; emergency handling retains the shared WAN/DNS checks
and reserve probe budgets.

## Paired Planning Modes

The internal `SB_URLTEST_PLANNING_MODE` setting accepts `legacy`, `warm-paired`
and `fresh-paired`. An explicit value takes precedence over
`SB_URLTEST_WARM_COMPARE`; when it is absent or empty, the old boolean keeps its
previous meaning. Unknown explicit values are rejected before the agent starts
its API connection and workers.

The image build defaults to `SB_URLTEST_PLANNING_MODE=fresh-paired`, with the
legacy warm-comparison boolean disabled. Its OCI label and runtime environment
record the selected mode. An explicit empty mode retains the legacy boolean
contract for custom builds. Validate the effective installed environment as well
as the label when preserved RouterOS environment lists are in use. Selecting a
mode alone does not establish completed image or physical-router acceptance.

`fresh-paired` uses marker `gstatic-fresh-paired-head-v1`. Each healthy planning
job sends one new primary-origin HEAD, including its connection setup, with
HTTP/1.1, normal certificate/hostname verification and the ordinary five-second
deadline. Reverse uses the same planning HEAD as ordinary nodes; its online
observation remains required. If HEAD is unsupported but the independent GET
availability check works, the route remains available and planning quality is
unknown. Alternate-origin or GET success never substitutes a planning sample.
Startup, priority, active availability and emergency entry points keep their
existing request contracts, including the Reverse GET availability probe.

Both paired modes share the bounded active/reserve scheduler, physical
preparation barrier, one-slot continuation, two independent confirmations and
configured interval/margin. Fresh mode has no second request or second-phase
barrier. With a 60-second configured interval, two accepted candidate observations
must be at least 60 seconds apart. Neither mode adds a cooldown or a third proof.
Virtual-clock regressions use the production health-loop fallback of 60 seconds
separately from the per-policy quality and liveness intervals. Combined cases
cover six independent policies sharing one slot through both confirmations,
both endpoint orders, early shared evidence and interrupted worker cleanup.
Only exact metric-qualified observations enter its planning history or cache.
Changing mode, primary target, endpoint fingerprints or core context discards
incompatible planning data and confirmations; a mode change preserves the
working route and full-request history.

The `warm_*` JSON fields remain legacy envelope names for either paired mode.
The envelope marker and each comparison's `measurement` identify its actual
semantics. Consumers must recognize the marker and require exact agreement;
warm and fresh delays are not interchangeable. Session planning is discarded
on restart. Existing historical median columns continue to show full-request
history rather than the current paired comparison.

The short median uses at most three recent admitted values per node. Successful
observations enter that history no more often than the configured quality
interval, using precise observation completion times. The first eligible value
is retained without selecting a minimum or calculating a separate burst median.
The rule is independent of whether the node is active or a reserve. Extra active
references remain fresh physical evidence for the current pair, but cannot evict
previous minutes from the median. Rejected admission never advances its clock.

Raw results, quality/availability failure and recovery counters, loss, scheduling
and physical-pair timestamps still process every independent observation. A
failure and its first successful recovery are not suppressed by the history
interval. Paired histories reset on failed or invalid primary evidence while
their processed watermark still rejects older results. A checkpoint keeps cold
raw evidence separately from admitted samples. Older checkpoints without the
cadence marker and quality-interval changes rebuild the short history and pending
planning proof, preserving the working route, raw status and long-term history.
Best/priority transitions also rebuild the appropriate planning history.

The median is not a history of paired differences or a guarantee of equal time
coverage: sparse reserves can still span longer than active observations. The
latest qualified raw pair must independently beat the configured margin. The
three-value limit, expiry, full-request metric, two confirmations, request
budgets and emergency handling remain unchanged; this is not a CPU benchmark or
proof that common WAN congestion can no longer cause a planned switch.

For a healthy full sweep over `N` nodes, fresh paired mode can require
`2 × (N − 1)` jobs/primary requests; warm paired mode can require twice as many
primary requests. Different policies and availability fallbacks add work.
Concurrency and per-job counts do not establish a global requests-per-minute
limit or a CPU improvement. Measure those outcomes separately.

## Experimental Same-Connection Comparison

Normal source builds keep the full-request behavior above. An experimental image
may explicitly enable `SB_URLTEST_WARM_COMPARE=1`; it is off by default and is not
a panel setting. This is a measurement experiment, not completed performance or
physical-router acceptance.

Only ordinary best/URLTest surveys request a second HEAD through the exact
TCP/TLS connection used by a successful first request. Each ordinary warm batch
admits at most one physical pair: the active node and one reserve. The configured
global work budget still applies; cold startup, priority and emergency widths
are unchanged. Both requests and the second-phase start barrier share the
original five-second request budget. A parallel pair starts its second requests
only after both first requests succeed. One
physical lane never waits for a nonexistent second worker. With one admitted
slot, a session-local scan continuation finishes one active/reserve pair before
rotating policies. Its second side uses the existing pair-continuation wake,
independent of the liveness interval. It spends the same two jobs; arming the
continuation alone is not a switch confirmation.
Its ten-second window starts at the actual warm observation. Peer completion
ends the scheduler continuation and retains an expiring, runtime-only token for
the selection checks. It cannot hold a physical slot. An error, expiry or a
route/context change discards the continuation or token. A failed cold peer or
expired budget before the
second request starts defers warm quality: the healthy node retains its previous
planning history and pending confirmation, and only the attempt clock advances.
This does not hide a later-delivered real network error. An actually started
second request that fails or reconnects supplies unknown planning quality, never
a cold availability failure. That unknown quality clears the affected warm
history and any active/pending warm confirmation; a stale result cannot overwrite
a newer success.

A one-slot pair can complete in either endpoint order. The initial active-first
survey uses its exact completed scan token rather than requiring an earlier
nomination. Finishing the active side after a fresh nominated reserve also counts
the first complete confirmation without repeating a request. A cached half
retains its actual start, completion time and parallel-wave identity and must
match the current qualified planning sample's timestamp, success and delay.
Overlapping phases from the same nonzero parallel wave remain comparable when
completion or delivery order is reversed; serial halves keep their order.
An incompatible wave, stale half or retained display value cannot authorize a
switch. The raw
pair and short-median margin checks, two confirmations, candidate interval and
separate emergency path remain unchanged.

Cold evidence remains separate: availability, emergency selection, priority
return, first startup selection and historical full-request latency keep their
existing behavior. Warm optimization has its own bounded three-sample history,
raw timestamps and measurement marker `gstatic-warm-head-v1`. The existing two
fresh confirmations and configured interval/margin still apply. Warm attempt
completion is rounded up for the whole-second warm scheduler; a shared
result also must satisfy the full candidate-to-candidate confirmation interval.
This can conservatively delay the next warm attempt by less than one second.
An otherwise valid shared pair captured before a policy's confirmation interval
cannot move that policy's next due time. It is replaced within the ordinary
budget, or deferred until the next turn when already attempted in this cycle.
Comparison diagnostics and Delta identify the experimental metric; historical medians
continue to describe full cold requests. Warm timing intentionally excludes
connection setup and first-response-only penalties and can still vary under
congestion.

Experimental comparison checkpoints use separate `warm_latency_comparisons`,
`warm_last_latency_comparisons` and `warm_optimization_last_result` fields,
guarded by `warm_planning_marker`. Legacy optimization/comparison fields are
empty while the experiment is active. Older agents therefore cannot consume a
warm confirmation or display its Delta as a cold result after rollback. A new
agent also discards session-bound warm planning on restart, retaining the
selected path and cold availability/history.

Reload an already open panel after changing the preview image. The container
version is read from the API; it does not establish that the browser has loaded
the matching JavaScript. An older frontend does not understand the separate
experimental comparison fields. The healthy-sweep regression verifies that all
23 reserves of a 24-node inventory publish comparison data even when no node
qualifies for a planned switch.

A failed, missing or incomplete warm observation withdraws fresh planning
evidence and pending confirmations without erasing the last qualified Delta
for the unchanged active route and endpoints. Failure of the active warm probe
therefore does not blank every reserve's last comparison. The next qualified
pair replaces its displayed value. Retained display comparisons are never
accepted as fresh switching evidence; active-route, endpoint, membership or
measurement-context changes still invalidate incompatible values.
Fresh experimental Delta also requires the actual latest warm phases to be
qualified and comparable. Different parallel waves or nonoverlapping parallel
phases cannot replace the retained last-good numbers. Serial phases remain
eligible in either endpoint order within the existing comparison window. This
qualification does not change the medians, ranking, probe budget or confirmations.

A warm quality job performs at most two primary requests; a cold-only quality job
performs one. Ordinary cold probes use HEAD; Reverse retains its existing cold
GET, followed by the same warm HEAD used for other best-mode nodes. Metric-specific
caches prevent their evidence from mixing. When best and priority consumers
independently request the same endpoint, this prototype may perform both jobs:
**three primary requests**, not a promised global bound of two. Same-metric consumers may reuse raw evidence within the
ordinary shared-wave rules. The configured budget counts admitted jobs;
concurrency alone is not a request-count limit. Existing availability fallback
requests remain a separate cost and do not enter warm ranking.

Pairing repeats the active baseline more often. With more than one node, a full
healthy sweep over `N` nodes can require `2 × (N − 1)` quality jobs and therefore
`4 × (N − 1)` primary requests. The sweep duration, request rate and history
publication frequency depend on request durations and other policies. Measure
CPU, serialization and traffic under load; a smaller worker count does not
guarantee unchanged total work.

Checkpoint encoding remains synchronous with the controller. It uses an encoder
directly on the restricted temporary file before Sync/Close/Rename, preserving
the compact JSON plus trailing newline format without Marshal's result copy or
potential body growth for that newline. This is not streaming JSON: the Go encoder
still buffers the complete value. It does not reduce checkpoint frequency or
the amount of history visited. Wire-compatibility and failed-encode tests cover
both cold and experimental checkpoint views and preserve the previous file on
an encoding failure.
The mature-checkpoint benchmark reports encoded payload bytes separately from
allocated bytes so these quantities cannot be confused with retained memory.
Maintenance failure regressions count one failed flush, retain pending state and
verify that the original health deadline does not wake early. Cancellation is
checked separately, without a machine-speed ceiling on disk writes.

### Isolated Native Checks

`TestCHRPairedHTTPSRuntime` is an opt-in test of a separate installed-core
instance, its temporary selectors and trusted local TLS origin. It does not
change the appliance's active routes. `SB_CHR_PAIR_WARM=1` exercises the warm
experiment; `SB_CHR_PAIR_VLESS=1` adds isolated VLESS over WebSocket/TLS with
synthetic users. Without the latter, the fixture uses direct outbounds.
`SB_CHR_PAIR_PLANNING_MODE=fresh-paired` selects the distinct full fresh mode;
the same enum precedence and validation apply. Reports identify the selected
measurement, ordinary per-job primary-request contract and physical phase
observations. The existing warm control remains available independently.
The `inventory` scenario accepts `SB_CHR_PAIR_NODES=7`, `10` or `24`, ten available
lanes, slow middle candidates and a fastest final candidate. It retains the
60-second confirmation interval. The separate `cohort-*` stress scenarios use
six seconds and must not be reported as production-cadence acceptance.

Opt-in HTTPS stage tracing records both physical requests of a warm job,
including their separate start/end boundaries. Count failed attempts and
availability fallbacks too. Compare observed request rates, rolling-minute
peaks, CPU and memory on equal-duration runs. An isolated native test verifies
the installed core and controller integration, not a physical WAN or an
external provider's performance.

The separate `cpu` scenario accepts the same inventory sizes and runs either
cold or warm probes against equal synthetic origins. It records the isolated
Xray process's own CPU accounting separately from aggregate cgroup CPU, and
collects a 120-second profile through a temporary localhost-only metrics
listener. `SB_CHR_PAIR_CPU_PROFILE` must name a new `/data/sb-chr-pair-*.pprof`
file; profiles are private test evidence, not release assets.
`SB_CHR_PAIR_CORE_MEMORY_MIB` explicitly fixes the child core's Go memory budget
between 32 and 192 MiB so it does not silently inherit the test driver's budget.
`SB_CHR_PAIR_CPU_TRAFFIC=1` adds a bounded, paced synthetic download through a
separate inbound for the selected policy. Traffic bytes and errors are reported
separately from health requests. Compare equal-duration runs and achieved
traffic rates; this test does not establish physical-router CPU or WAN speed.

For CPU comparisons, synthetic VLESS provider handlers run in a separate child
process with a fixed 64 MiB Go limit. Client, provider, test-driver and aggregate
cgroup CPU are distinct measurements. Driver CPU includes the traffic generator
and HTTPS origin; it must not be reported as controller-only CPU.
`SB_CHR_PAIR_DRIVER_CPU_PROFILE` optionally writes a second private profile;
the `fixture_role=controller` label covers Tick and probe goroutines it starts.
Shared runtime/GC work is not assigned exclusively to that label.

`SB_CHR_PAIR_CPU_MONITOR=0` supplies a traffic-only control.
`SB_CHR_PAIR_CPU_CLIENTS` accepts 1–16 paced streams, and
`SB_CHR_PAIR_CPU_CHUNK_DELAY_MS` accepts 1–250 ms between 32 KiB writes.
`SB_CHR_PAIR_CORE_BUFFER_KIB=4|16|32` changes only the isolated client's policy
pipe queue; it does not change Xray's regular buffer size or WebSocket buffers.
`SB_CHR_PAIR_CPU_MATURE=1` seeds generated 24-hour samples and 30 daily reservoirs
before measurement, reporting the checkpoint size. No production history is read.

`SB_CHR_PAIR_CPU_DYNAMIC=1` exercises subscription-style HandlerService add/remove
instead of preinstalled base leaves. The standalone fixture converts its
synthetic definitions through the installed core once before measurement, then
preserves opaque protobuf sender/proxy settings while replacing only the tag.
It measures core handler construction and API traffic, not production embedded
encoder compilation CPU. Reports include handler preparation counts and actual
HTTPS-carrying TLS connection counts, separately from bulk traffic connections.
`SB_CHR_PAIR_VLESS_VARIANT=ws|tls-vision` selects the isolated transport for CPU
comparison (TLS/WS by default, or raw TLS with Vision on both peers). Certificate
verification, origins, pacing and traffic volume remain comparable; this is not
a REALITY benchmark or a claim that different provider nodes cost the same CPU.

## Upstream Approaches

See [the upstream comparison](URLTEST-UPSTREAM-COMPARISON.md) for pinned
sing-box timing boundaries, reviewed proposals and the scope of the controller
tradeoff regressions. A new destination request does not necessarily include
the proxy transport setup in sing-box's reported duration.

[sing-box URLTest](https://sing-box.sagernet.org/configuration/outbound/urltest/)
defaults to a three-minute interval and a 50 ms tolerance. Its
[selector](https://github.com/SagerNet/sing-box/blob/testing/protocol/group/urltest.go)
starts from the current selection and requires a tolerance-sized advantage.
[HomeProxy](https://github.com/immortalwrt/homeproxy/blob/master/root/etc/homeproxy/scripts/generate_client.uc)
generates sing-box URLTest configuration rather than a separate selection engine.
[Mihomo unified delay](https://wiki.metacubex.one/en/config/general/#unified-delay)
reduces transport-handshake bias: its
[measurement implementation](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/adapter.go)
attempts a second HEAD request and uses its duration when successful. This mode
is optional, not the behavior of every Mihomo installation.

### Re:HomeProxy

The [Re:HomeProxy generator](https://github.com/1andrevich/homeproxy-hiddify/blob/master/root/etc/homeproxy/scripts/generate_client.uc)
also delegates URLTest to its selected core. It emits the probe URL, interval,
tolerance and optional interruption of existing connections, not its own
latency-selection algorithm. Reviewed backend source snapshots are
[hiddify-sing-box](https://github.com/hiddify/hiddify-sing-box/tree/3a1c923e306d5b39cde8f2c02ec9dd556ea112d3)
and [sing-box-extended](https://github.com/shtorm-7/sing-box-extended/blob/extended/protocol/group/urltest.go).
Both retain the current selection within tolerance, prevent overlapping sweeps
and bound batch concurrency to ten. Their default interval is three minutes and
their URLTest uses a 15-second TCP timeout; these are different from the
gateway's five-second availability rounds, not interchangeable failure policies.

sing-box-extended also has an explicitly enabled
[unified-delay option](https://github.com/shtorm-7/sing-box-extended/blob/extended/option/experimental.go)
and a second-request measurement path. The reviewed Re:HomeProxy generator does
not emit this option. Its availability in a core is not proof that a generated
configuration enables it. This source review does not identify the build or
configuration of any installed Re:HomeProxy instance.

These are latency selectors, not sustained-throughput measurements. The
[sing-box bandwidth-aware proposal](https://github.com/SagerNet/sing-box/issues/4397)
describes this limitation; it is not evidence that the proposal is shipped.

## Comparison Gate

These implementations do not prove the cause of an individual switch. A valid
comparison must measure the same origin, method and timing boundary on both
nodes, rotate probe order, and run both idle and mixed-load phases. Compare cold
and warmed measurements, reciprocal planned switches, failed requests, CPU and
probe counts. Warm requests must never reuse a connection after changing the
probe selector: that would measure the previous node. Keep availability deadlines
and failure confirmation unchanged during this experiment. A slower quality-scan
interval is not a mandatory post-failure recovery delay, and warmed latency is
not evidence that a new connection can be established.

## Health checkpoint deadline regression

The health-loop regression uses a virtual clock to check that a maintenance
checkpoint resumes the original probe deadline. It asserts the exact scheduled
duration rather than a wall-clock upper bound affected by filesystem flushes
and unrelated build load. Separate persistence tests still verify that the
checkpoint writes the latest state.
