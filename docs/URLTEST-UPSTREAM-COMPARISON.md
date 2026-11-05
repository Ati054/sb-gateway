# URLTest Upstream Comparison

Source review: 2026-11-02. This document distinguishes source behavior,
unmerged proposals and synthetic controller tests from network qualification.
It does not change the gateway's selection defaults or enable a new metric.

## Measurement boundaries

The reviewed sing-box revisions are
[stable 1.14.4](https://github.com/SagerNet/sing-box/blob/c005f35300ce76427dc285481ec5695f5b179cd2/common/urltest/urltest.go)
and [testing e5d91fa](https://github.com/SagerNet/sing-box/blob/e5d91fa79f6319d5de940d6c81d81f0fe53b9476/common/urltest/urltest.go).
Each final test opens a new destination connection and sends HEAD. The timer
starts before the outbound dial, but resets after it when the returned connection
still requires a write handshake. This is neither uniformly complete setup time
nor a second request over the same destination TLS connection. Multiplex-enabled
outbounds can first prepare a shared session with a separate request.

For ordinary non-multiplexed VLESS,
[the outbound](https://github.com/SagerNet/sing-box/blob/e5d91fa79f6319d5de940d6c81d81f0fe53b9476/protocol/vless/outbound.go)
prepares its outer transport before returning the pending VLESS connection.
Consequently, the reported duration can exclude outer TCP/TLS/REALITY setup.
[WebSocket early data](https://github.com/SagerNet/sing-box/blob/e5d91fa79f6319d5de940d6c81d81f0fe53b9476/transport/v2raywebsocket/client.go)
can defer Upgrade until the first write. Current code already dials TCP/TLS
before that branch: the older report in
[issue 4451](https://github.com/SagerNet/sing-box/issues/4451) must not be treated
as a description of every current handshake boundary.

The gateway measures through Xray's local HTTP proxy.
[Xray's CONNECT response](https://github.com/XTLS/Xray-core/blob/0afec66085a85191e9dd2a4a6646c7c9a94688d1/proxy/http/server.go)
precedes upstream dispatch. Neither that response nor the client's destination
TLS start identifies completed outer WS/REALITY setup. Moving an HTTP trace
timestamp therefore cannot faithfully reproduce sing-box's outbound-dial boundary.

The gateway's complete first request includes setup; its experimental strict
second request excludes setup. Both use HTTP/1.1 and certificate verification.
The post-connection response diagnostic is a third, explicitly different boundary.
No one of these short observations establishes sustained transfer capacity.

## Reviewed proposals

| Source | Reviewed status | Usefulness and limits |
| --- | --- | --- |
| [4376: AnyTLS warmup](https://github.com/SagerNet/sing-box/pull/4376) | Merged | Prepares an existing multiplexed session; does not introduce same-connection destination HEAD timing. |
| [4398: bandwidth-aware selection](https://github.com/SagerNet/sing-box/pull/4398) | Open, not merged | Separately scheduled bounded GETs can detect slow payload transfer that HEAD misses. Body-only rate excludes setup and first-response delay. |
| [1494: HTTP/2 PING](https://github.com/SagerNet/sing-box/issues/1494) | Feature proposal | A prepared-connection round trip is inexpensive but cannot qualify a new connection or bulk transfer. |
| [4436: raw TCP/UDP](https://github.com/SagerNet/sing-box/issues/4436) | Open proposal | Useful for non-HTTP destinations; a proxy dial return is not always remote target readiness. |
| [4256: stuck sweep ceiling](https://github.com/SagerNet/sing-box/pull/4256) | Open, not merged | Bounds waiting; stopping a waiter alone does not establish worker cancellation or bounded resource use. |
| [2994: concurrency and faster updates](https://github.com/SagerNet/sing-box/pull/2994) | Closed, not merged | Reduces wait for individual results; does not make differently timed observations comparable. |
| [3537: first available](https://github.com/SagerNet/sing-box/pull/3537) | Closed, not merged | Changes selection to configured preference; it does not improve latency comparison. |
| [4562: cost-based selection](https://github.com/SagerNet/sing-box/issues/4562) | Open proposal | Selects according to preference/cost within a delay limit; it does not separate access-link queues from endpoint degradation. |

### Bounded transfer review

The bandwidth proposal was reviewed at
[head 2578521](https://github.com/zydo/sing-box/tree/257852146839d9bb97ec19192c171c30e02afc6d).
Its defaults use 256 KiB per node, a reusable 32 KiB buffer, two workers per group,
and a cadence five times the latency interval. Twenty-four nodes consume 6 MiB
of application payload per sweep: 576 MiB/day at fifteen-minute intervals, or
1728 MiB/day at five-minute intervals, excluding protocol and in-flight overhead.

The reviewed code needs further qualification before adaptation. Ranking has no
sample-age guard; late abandoned workers can still publish within the same
network epoch. Releasing the sweep guard does not cancel its queued workers.
Candidate iteration applies tolerance against each temporary winner, so inventory
order can change the result. A positive but incomplete 2xx body can receive a
rate. Routine latency updates also replace the public throughput fields, despite
the proposal's separate update helper. These are source-review findings, not
results of executing the upstream integration suite.

Required checks include stale/late-result rejection, repeated stuck rounds,
candidate-order permutations, partial payloads, independent metric updates and
the actual CPU, traffic and DNS cost under a shared bottleneck. Bounded transfer
is a candidate diagnostic, not a validated remedy for a saturated common WAN.

## Gateway comparison coverage

`TestURLTestFreshAndWarmMeasurementTradeoffs` exercises the actual controller
with synthetic timestamped observations for slow setup with fast reuse,
persistent response delay and a single setup spike. It compares both existing
measurement modes while requiring independently spaced switch confirmations.
It demonstrates their different decisions; it does not run sing-box or qualify
network performance, throughput or a new hybrid selector.

A future paired-fresh experiment should share scheduling mechanics with the
same-connection experiment while preserving a distinct measurement identity.
One new primary request per endpoint would retain real start/end/wave evidence,
the short history, two confirmations and independent emergency handling.
Simply disabling the warm flag is not that adaptation: some bounded pair and
one-slot continuation mechanics currently belong only to the warm path. No such
new mode or combination score is enabled by this source review.
