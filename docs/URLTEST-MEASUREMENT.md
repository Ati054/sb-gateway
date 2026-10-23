# URLTest Measurement

This document describes source behavior and measurement boundaries. It does not
claim completed image or physical-router performance acceptance.

## Gateway Behavior

The gateway currently measures a new primary-origin HTTP request, including
connection setup, through its isolated probe selector. Keep-alive is disabled.
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

## Upstream Approaches

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
