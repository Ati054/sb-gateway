# Parsed State Cache

The controller's general JSON document cache retains at most four parsed
documents, each no larger than 256 KiB. Callers receive independent copies.
Larger documents bypass this cache; selector response caching is separate.

A hit requires the same file identity, size and modification time. An atomic
replacement invalidates a cached document even when it preserves the previous
size and timestamp. Both reads and controller writes record the file identity.
This applies to drafts, committed pointers and auxiliary state without changing
their on-disk format or their authoritative commit points.

`TestReadJSONCacheInvalidatesAtomicReplacement` covers caches warmed by reads
and writes.
