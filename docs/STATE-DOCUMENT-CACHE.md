# Parsed State Cache

The controller's general JSON document cache retains at most 16 small parsed
documents with LRU eviction, each no larger than 256 KiB. The total encoded
input budget remains 1 MiB, equal to the former four-document maximum. This is
not a decoded-heap or RSS limit. Callers receive independent copies; cloning
immutable cached graphs does not hold the shared repository lock. Larger
documents bypass this cache without evicting other entries. Selector response
caching is separate.

A hit requires the same file identity, size and modification time. An atomic
replacement invalidates a cached document even when it preserves the previous
size and timestamp. Both reads and controller writes record the file identity.
This applies to drafts, committed pointers and auxiliary state without changing
their on-disk format or their authoritative commit points.

Windows captures file identities through an open handle, before a path can be
replaced; a deferred path lookup is not a stable cache key. Subscription idle
snapshots use the same rule. Other platforms retain their direct stat path.

`TestReadJSONCacheInvalidatesAtomicReplacement` covers caches warmed by reads
and writes. Mixed-working-set, recency, ownership and total-byte tests accompany
the cache benchmark. Whole-controller CPU and memory checks remain necessary
before predicting router performance.

The subscription scheduler and compact provider-status endpoint use a separate
projection containing only `provider` and `refreshed_at`. Its encoded admission
ceiling is 64 KiB, independently of the source node-file size. Node graphs are
not retained in this projection. Missing, changed or invalid source files are
checked on each read; unchanged file generations reuse detached metadata.
Refresh intervals, due-time rules and subscription application are unchanged.
Concurrent readers, caller mutation, source deletion/corruption and same-size,
same-time atomic replacements are covered by maintained tests.
