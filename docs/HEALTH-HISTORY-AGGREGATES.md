# Health History Aggregates

The agent reuses process-local 24-hour, 7-day and 30-day aggregate results for
unchanged node histories. New evidence invalidates that node's results; rolling
24-hour expiry, pruned days, UTC rollover, fingerprint resets and process reload
are handled explicitly. A failed selector transaction does not make the cache
depend on statistics that were never publicly committed. Selection retains its
existing publication order.

The persisted history format, retention, sample limits and publication cadence
are unchanged. This optimization avoids redundant sorting; it does not implement
delayed history writes or claim that large-file serialization is eliminated.
Synthetic equivalence tests and a multi-node retained-history benchmark accompany
the change. Full-image correctness and CPU checks remain required.
