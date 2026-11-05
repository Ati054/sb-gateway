# Health History Aggregates

The agent reuses process-local 24-hour, 7-day and 30-day aggregate results for
unchanged node histories. New evidence invalidates that node's results; rolling
24-hour expiry, pruned days, UTC rollover, fingerprint resets and process reload
are handled explicitly. A failed selector transaction does not make the cache
depend on statistics that were never publicly committed. Selection retains its
existing publication order.

The persisted history format, retention and sample limits are unchanged.
Routine history changes are coalesced over a ten-second checkpoint interval,
before constructing or encoding the large projection. The controller keeps the
latest state in memory; there is no asynchronous queue of older snapshots.
Maintenance writes resume the original probe deadline, rather than starting an
extra probe cycle. An orderly agent shutdown attempts to flush pending history.

Traffic readiness is published immediately in its separate small snapshot.
Startup membership, Apply reconciliation snapshots, selector changes, first
durable working selection, runtime errors and changes to failure evidence also
force a full checkpoint. A missing failure count and an explicit zero are
equivalent for this decision; inserting zero after a successful probe is routine work.
Positive failure counts and recovery from a positive count remain immediate.

The panel's routine history and display comparisons can trail the in-memory
controller until the next checkpoint. Selection and availability checks use
live evidence and retain their configured intervals, thresholds and HTTP
measurement semantics. A checkpoint write failure preserves pending state and
does not create a busy retry loop while waiting for the next health deadline.

Synthetic equivalence tests, publication/deadline regressions and a multi-node
retained-history benchmark accompany these changes. Full-image correctness and
CPU checks remain required; isolated CPU comparisons do not predict a physical
router's utilization.

After a successful full checkpoint, the agent also attempts to publish a small
`selector-status.json` containing the existing current-status API whitelist.
It excludes raw samples and day reservoirs and does not change probe cadence,
history retention, critical-change detection or the separate readiness proof.
This adds a small serialization/write at the existing checkpoint boundary;
it is not a zero-cost change to the producer. The disposable cache is replaced
atomically without another forced disk flush; durable history and readiness
writes retain their existing synchronization.

Compact polling uses this optional companion only when its version and source
file identity/change stamp match the opened history snapshot. A replacement,
missing, invalid or incompatible companion falls back to current full history.
The companion is reconstructed, excluded from recovery archives, and never
supplies availability or switching evidence. Its write failure does not reject
an otherwise successful readiness/history publication.

On Linux the retained-history publication benchmark reports process user+system
`cpu-ns/op` separately from wall-clock `ns/op`, which also includes storage
waits. Compare both producer costs as well as polling allocations.
