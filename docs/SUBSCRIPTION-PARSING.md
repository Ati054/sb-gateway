# Streaming subscription parsing

The parser walks raw URI lists and the supported standard/URL-safe base64
encodings without retaining a second complete decoded string or an array of all
links. Encoding and UTF-8 validation precede emission. Two bounded passes retain
compact identity/ID indexes, preserving source order, stable identifiers and
credential-sensitive disambiguation. Invalid supported links can be skipped;
their statistics remain distinct from emitted nodes.

The walker accepts zero as no node-count quota. Positive quotas count supported
URI lines, including lines that later fail node validation; exceeding a quota
rejects the import rather than publishing a truncated list. The legacy
collecting wrapper retains its positive-quota API for bounded callers.

Encoded/decoded byte bounds, per-link bounds and working-index bounds are
independent of node quotas. Production catalog import uses an 8 MiB response
bound, a 64 KiB link bound and a 64 MiB working-index bound. Parsing is
cancellable. A later node, quota or resource error can follow earlier callbacks,
so callers build unpublished staging data and abort it on any error.

Synthetic regressions cover raw/base64 equivalence, malformed tails, UTF-8,
duplicates, identity ordering, cancellation and independent resource limits.
Parser success establishes neither server connectivity nor runtime capacity.
