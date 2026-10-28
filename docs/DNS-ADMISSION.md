# DNS admission and concurrency

## Current behavior

Policy DNS has one service-wide upstream-work limit, default 32, and a pending
queue of four unique requests per worker. `SB_POLICY_DNS_WORKERS` accepts 2–64. Incoming
TCP sessions have a separate limit. These are concurrency limits, not queries
per second. Cache hits and local answers bypass a saturated worker queue.

Waiting and resolution share the original request deadline. Increasing workers
also increases the pending queue. When multiple resolver profiles exist, one
profile may occupy at most half the active slots and half the unique queue.
Its queued queries wait for the profile allowance before acquiring global work capacity. This
leaves room for another profile when a single resolver stalls, without polling.
At the default, a single profile retains the previous 16-exchange allowance.
Several stalled profiles can still exhaust the global limit; this is bounded
isolation against one profile monopolizing work, not a per-profile guarantee.

Each UDP listener reuses one 65,535-byte receive buffer. An asynchronous handler
owns only the received packet length. Retained raw request bytes across unique
requests and duplicate waiters are capped at workers times 65,535 bytes, about
2 MiB at the default. This is an admission ceiling, not a reservation or a bound
on all DNS memory. Keys, responses, caches, goroutines, listener buffers and TLS
are additional. With multiple profiles, each profile may use at most half this
byte allowance. Large EDNS packets are accepted within these count and byte
bounds. Asynchronous outgoing HTTP request bodies retain separate ownership.

Duplicate queries share one exchange before admission to upstream work. Their
waiters consume neither active work nor unique pending slots. Waiters are bounded
globally at four times workers, with the same per-key participant ceiling
including the owner. One profile may use at most three times workers duplicate
waiters when multiple profiles exist. They retain their own deadline and transaction ID. Excess
requests receive SERVFAIL. The key preserves resolver profile and DNS wire contents
apart from the transaction ID. WAN and VLESS policies must remain separate even
when they use the same resolver address.

## Reference implementations

Source review dated 2026-10-27; linked development branches may change.

| Project | Relevant mechanism | Application here |
| --- | --- | --- |
| [AdGuard DNSProxy UDP server](https://github.com/AdguardTeam/dnsproxy/blob/master/proxy/serverudp.go) | Reuses a large listener buffer and copies only the received packet length for asynchronous handling; uses request admission. | Avoid retaining a maximum-sized packet for every queued question. |
| [sing-box DNS client](https://github.com/SagerNet/sing-box/blob/testing/dns/client.go) | Coordinates eligible concurrent lookups using a key that includes transport, subnet and network environment. | Coalesce only compatible requests; preserve routing and query semantics. |
| [Mihomo resolver](https://github.com/MetaCubeX/mihomo/blob/Meta/dns/resolver.go) | Uses singleflight to share concurrent resolver work. | Distinguish real upstream work from clients waiting for its result; do not copy a simpler key without our policy isolation. |
| [CoreDNS forward](https://coredns.io/plugins/forward/) | Configurable upstream concurrency; recommends exceeding expected upstream query rate multiplied by upstream latency. | Size from measured demand and resource cost, rather than memory alone. Its documented per-query memory estimate is specific to its implementation. |

These sources do not establish that another complete product has no resource
limits. A transport-local limit and a global request limit are different things.

## Remaining sizing work

Review concurrency using measured upstream demand and tail latency within
controller memory/CPU limits. Keep the explicit operator override. No automatic
memory-derived worker count is enabled. Cache and access decisions run before
coalescing; sharing a response never changes WAN/VLESS or fallback selection.

## Reproducible characterization

`go test ./internal/policydns -run 'TestDNSBurstCapacityAt16And32Workers|TestDNSSlowResolverPreservesAnotherProfilesSlot|TestMixedDNS|TestSharedDNS|TestDNSByte' -count=1`

The burst test holds submission ahead of resolution to exercise admission
overflow deterministically. Unique questions prevent coalescing from concealing
capacity. The mixed-resolver test holds one resolver while another is healthy;
it verifies progress through the reserved capacity. Duplicate and large-EDNS
tests cover waiter/byte bounds, transaction IDs and cancellation cleanup. The
mixed test fills the slow profile's active work and unique queue, joins duplicate
requests, and verifies that the fast profile retains its full parallel batch.

`go test ./internal/policydns -run '^$' -bench '^BenchmarkDNSAdmissionBurst$' -benchmem`

The benchmark uses a fixed synthetic upstream delay and the same retained UDP
packet ownership as serving. It compares batch completion and allocations, not real
network throughput, steady-state memory, TLS peaks or whole-container CPU.
Before changing defaults, measure queue delay/rejections, unique upstream work,
duplicate waiters, DNS latency, website traffic and resource use under sustained
mixed-path load. Verify cancellation, reload, access decisions, EDNS, large
packets and transaction IDs as well as the successful fast path.
