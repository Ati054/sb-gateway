# Controller Runtime Counters

Authenticated `GET /api/v1/diagnostics/runtime` returns numeric Go runtime
counters for the controller process only. It does not force GC or expose heap
objects, stack profiles, configuration, environment or credentials. It performs
no background sampling and is independent of Check/Apply mutation locks.

The response includes the process PID, startup-generation timestamp, UTC sampling
time and a `metrics` object keyed by the standard Go metric names with units.
Available counters include:

- Current Go soft memory limit, GOGC, heap goal and last marked live heap.
- Cumulative heap allocation bytes, total and explicitly forced GC cycles.
- Estimated GC, mark-assist, idle-marking, scavenger and user CPU classes.
- Runtime memory classes, released heap bytes, goroutines and GOMAXPROCS.

Compare counter differences for the same PID and `started_at` generation over
matched workload windows. Container PID 1 can recur after a restart, which resets
cumulative counters. Heap live size is from the last completed
collection; it is not a continuous RSS measurement. Runtime memory minus released
heap approximates the memory controlled by Go's soft limit, not container usage.
Unsupported metric kinds are omitted rather than treated as zero.

Go CPU classes are runtime estimates, not OS CPU measurements. Compare those
classes with each other, subtract idle marking from total GC when studying
compulsory collection work, and measure actual process/container CPU separately.
Do not divide GC estimates by an unrelated OS CPU counter or infer GC cost solely
from stop-the-world pauses. See [Go runtime metrics](https://pkg.go.dev/runtime/metrics).

For capacity testing, retain completed bytes, latency and failures alongside CPU
and cgroup pressure. Include simultaneous devices, short requests, long-lived
connections, DNS, panel polling and Check/Apply. A CPU decrease accompanied by
lost work, disconnections or throughput loss is not an optimization. Emulated
ARM tests establish relative behavior, not native-router throughput or capacity.

## Lab-Only CPU Profiles

The normal image excludes the `sb_cpu_lab` build tag. An explicit diagnostic build
may use `SB_GATEWAY_GO_TAGS=xray_multicall,sb_cpu_lab` and then opt in at runtime
with `SB_LAB_CPU_PROFILE=1`. Only the appliance/controller role watches
`/run/sb-gateway/lab-cpu-profile-request`; core and API-helper aliases do not.
Without both opt-ins, no watcher or profiler runs. There is no HTTP profiler.

The request file contains a new alphanumeric/hyphen token, at most 48 characters,
not a pathname. A request produces one exclusive 0600 CPU profile in
`/logs/lab-cpu-profile/`; existing files are never overwritten. Duration defaults
to 60 seconds; `SB_LAB_CPU_PROFILE_SECONDS` may select 10 through 120 seconds.
Only a logged `completed` request is accepted as a complete artifact. Restarted
or interrupted captures must not be used as successful evidence. Keep profiles
and environment-specific analysis private and export-excluded. Profile matched
baseline/candidate windows equally and account for profiling overhead.

## Status Polling

Full authenticated status polling caches the encoded public selector document by
file identity, modification time and size, independently of the small generic
document cache. Retention is capped at 4 MiB; larger documents remain caller-owned
and are not retained. Atomic replacement invalidates the cache even when size and
mtime match. Missing or malformed state never serves a previous cached status.

History arrays stay encoded rather than being expanded into a second universal
object graph on every poll. Existing public fields and `daily_samples` remain
available, including the panel's 24-hour reset calculations; retired speed fields
are filtered as before. The compact selector endpoint retains its separate small
projection. Synthetic tests and benchmarks cover compatibility, bounded retention,
concurrent readers and invalidation; image-level load verification remains required.
