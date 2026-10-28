# Localizing Network Stalls

Preserve the failing request before changing DNS budgets, transport settings or
memory limits. A timeout identifies a missed deadline, not the failing component.
Use an isolated test client and keep captures and environment-specific results
outside the public source export.

## Packet Loss

Capture both directions at the client, the container interface and, for a virtual
router, its host TAP. Validate each capture against successful exchanges, retain
capture-drop counters and align clocks. Match DNS questions, IDs, addresses and
ports; record replies with unexpected source tuples too. A reply visible at
container egress but absent at the next observation point is not evidence of a
slow upstream resolver. Packet capture alone may precede checksum completion;
compare offload metadata before calling a captured checksum invalid.

Record before/after native interface counters, especially `tx-queue-drop`, and
host TAP/bridge drops. Check UDP receive-buffer errors separately. Cumulative
counters without a test-window delta cannot associate a drop with one request.
Queue replacement or interface restart can reset counters; never subtract
measurements across that boundary or interpret a negative delta as no loss.
The [RouterOS queue documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/328088/Queues)
distinguishes the hardware-only transmit ring from software queues. Compare
queue changes only as bounded, reversible lab experiments: larger queues can
increase delay, and virtual-device results do not prescribe physical-router
settings. Never silently replace an administrator's queue configuration.

## HTTPS Stalls

Retain the effective URL, redirects, local/remote tuple and timestamped connection
events alongside curl's timing fields. With redirects,
[curl adds application-connect timings across requests](https://curl.se/libcurl/c/CURLINFO_APPCONNECT_TIME.html);
the aggregate is not a packet-level measurement of one TLS handshake. Distinguish
connection setup, TLS, first response and incomplete response bodies. A received HTTP 200 does not
make a timed-out partial download successful.

Correlate TCP SYN, sequence/ACK progress, retransmissions and the first reset at
adjacent capture points. A reset emitted by a client after its own deadline is
not proof of an upstream reset. Compare the same origin and proxy node through
an independent client before attributing a stall to the gateway implementation.
Keep observer cost and completed workload comparable during loaded runs.

## Observer Controls

Compare whole-router CPU with container CPU and per-core utilization before
assuming spare processing capacity. They account for different workloads.
Calibrate persistent exec sessions and repeated SSH authentication with a bounded
idle control before treating a sampler as negligible. Use one SSH session for
repeated router counters. A detached diagnostic needs a bounded lifetime, verified
PID identity, an exit-status journal and explicit cleanup; closing a console must
not leave an untracked worker behind.
