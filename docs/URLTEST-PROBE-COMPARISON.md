# Comparing URLTest Measurements

The operational quality metric is the complete HTTPS request through the selected
proxy, including connection setup and TLS. Ordinary nodes use HEAD; Reverse
qualification retains its availability request semantics. The diagnostic
response-only timing is not the ranking metric. Neither value measures bulk
throughput or ICMP RTT.

A repeated-request alternative performs a successful first HTTPS request, then
times a second request on the same HTTP connection. This resembles Mihomo's
optional `unified-delay` behavior, not a change to `tolerance`: tolerance remains
a required advantage between two measured delays. A successful second request
without confirmed connection reuse must not be labeled a warmed measurement.

The measurements answer different questions. Complete request timing includes
the cost of opening a new connection. Repeated timing reduces the effect of
transport setup, but can conceal expensive or unstable new connections. The
second request also adds origin work and traffic. Changing the metric silently
would change the practical meaning of an existing switch threshold.

## Comparison Procedure

- Keep the same HTTPS origin, method, headers, TLS verification, success status,
  deadline, nodes and switch threshold. Do not substitute an easier HTTP target.
- Alternate complete and repeated modes in ABBA order, with a fresh client per
  observation. Repeated mode keeps its connection only for that observation.
- Include idle, simultaneous client traffic and post-load recovery. Keep
  background panel polling and maintenance comparable. Do not compile alongside
  CPU measurements.
- Record first-request failures, second-request failures, actual reuse, request
  count, median, P95 and median absolute deviation. A failed warmup supplies no
  warmed latency; failed observations must not disappear from availability data.
- Retain OS process/container CPU, GC counter deltas, transferred work, DNS
  failures, readiness, cgroup pressure and per-process memory. Endpoint snapshots
  do not establish continuous memory peaks.
- Evaluate both steady deterioration and temporary setup spikes. Report planned
  speed changes separately from confirmed-outage failover. A simplified replay
  is not a test of the entire production scheduler.

## Cross-Implementation Controls

Pin executable versions and verify their published checksums. Record actual
request budgets and completed sampling rounds, not just configured intervals.
For example, sing-box v1.14.4 uses a 15-second TCP request budget and can skip a
scheduled test while its previous successful history is still fresh. Its
failed tests delete the stored history; a successful-history API readout is not
a complete failure journal. Collect request failures independently.

A common local proxy can keep the underlying routes identical when comparing
URLTest implementations. This does not compare each core's native VLESS,
multiplexing or QUIC implementation. Likewise, a common 204 origin does not
prove that every implementation applies the same HTTP-status acceptance rule.
Keep these boundaries explicit before changing a production metric or timeout.

Long loaded runs must compare transferred bytes and completed DNS/HTTP work as
well as elapsed time. Closed-loop generators can complete less work when
responses slow down; a lower CPU percentage alone is not an efficiency gain.
Account for monitoring processes and compare lightweight persistent sampling
against interactive collection when investigating measurement-related stalls.

Controlled tests in `internal/agent/health_response_timing_test.go` verify fresh
connections for current probes and actual TLS connection reuse for the repeated
measurement. They establish timing boundaries, not a preferred production mode
or physical-router capacity. No default measurement or threshold is changed by
these comparisons. Keep endpoint configuration and environment-specific results
in export-excluded private evidence.

References: [Mihomo URLTest implementation](https://github.com/MetaCubeX/mihomo/blob/Meta/adapter/adapter.go),
[Mihomo unified delay](https://wiki.metacubex.one/en/config/general/#unified-delay),
[sing-box v1.14.4 request timing](https://github.com/SagerNet/sing-box/blob/v1.14.4/common/urltest/urltest.go),
[sing-box v1.14.4 budgets](https://github.com/SagerNet/sing-box/blob/v1.14.4/constant/timeout.go),
[sing-box v1.14.4 scheduling and history](https://github.com/SagerNet/sing-box/blob/v1.14.4/protocol/group/urltest.go).
