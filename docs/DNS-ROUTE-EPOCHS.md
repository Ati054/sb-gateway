# DNS state after a confirmed outbound change

The appliance monitor and policy DNS service share an instance-owned route
registry. After a production selector update has been read back successfully,
the monitor publishes the actual selected runtime tag. A changed tag retires
only DNS resolver profiles whose tunnel detour uses that selector. A changed
selected node definition also rotates those profiles when its confirmed runtime
tag changes. Unchanged tags, probe selections and unrelated catalog updates do
not rotate DNS transports or cache namespaces.

Core identity includes its process ID and start ticks. A changed core retires all
profiles that tunnel through it; ordinary direct UDP upstreams retain their existing pool/cache path without a
route-generation subscription or additional profile mutex.
Registry storage follows the current admitted selector inventory and live DNS
dependencies, rather than retaining node inventories or a history of switches.
Monitor restarts invalidate the old publisher, while DNS restarts synchronously
subscribe to the latest confirmed observations. This registry is explicitly
wired by appliance mode; separately launched standalone agent and DNS processes
do not share it and require coordinated service reloads when their routes change.

Each affected profile receives a fresh transport and cache/coalescing generation.
Idle old connections drain. Healthy requests already using the old transport may
finish for their existing waiters, but their answers cannot populate the new
generation's cache, and new requests cannot join their flights. An admitted old
plan still waiting for upstream capacity fails closed if its generation has
retired. A failed retired request cannot use stale answers from the old cache.
An A-to-B-to-A route sequence receives three distinct generations.

Retirement does not acquire the service runtime write lock or wait for network
requests. DNS deadlines, admission and byte limits, coalescing waiter limits,
fallback permissions and URLTest decisions are unchanged. Logical cache
invalidation uses generation keys; unreachable entries remain subject to the
existing bounded LRU capacity rather than a synchronous full-cache scan.

This supplements the existing artifact lifecycle. An Apply that changes the DNS
artifact still restarts the DNS component. An exact unchanged artifact keeps its
warm service, and a confirmed unchanged selected route preserves its transports
and cache. A selector update with an error or unconfirmed readback does not
publish a new epoch; a later successful readback can reconcile the actual route.

Focused deterministic regressions cover a held HTTP/2 reply concurrent with a new
generation, current-cache isolation, queued old plans, unrelated WAN state,
A-to-B-to-A changes, core process reuse, stale publishers and failed selector
updates. These source regressions do not by themselves qualify external traffic
performance or identify the cause of a network timeout.
