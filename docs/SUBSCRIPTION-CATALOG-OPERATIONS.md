# Complete subscription catalogs: operation and compatibility

Subscriptions have no implicit node-count ceiling. A positive provider
`max_nodes` remains an explicit quota; byte, record, working-index and disk
bounds remain separate. An import rejected or interrupted before publication retains the previous
published inventory. Private definitions and credentials are looked up on disk
when needed instead of copying the complete catalog into every runtime pool.

Runtime preparation additionally accounts for retained metadata, duplicate-ID
hashes and policy memberships before allocating large maps or encoding a pool.
The conservative working estimate is at most 64 MiB and normally half of
the controller's soft Go budget, with a 4 MiB floor. This is not an exact heap
limit. A selected runtime set that exceeds it is rejected with the previously
committed runtime retained; the complete refreshed catalog remains cached and
can be used with a narrower selection. Import is not truncated to fit runtime
planning.

The catalog itself uses immutable generations and checksummed references.
Current configuration, active/last-known-good/previous node snapshots, pending
transactions, the generated runtime pool and compatibility pins define the
retained graph. Open file leases additionally veto deletion. Ordinary retention
has a 24-hour grace period. Its background worker starts after one minute and
then runs hourly, with nonblocking admission and a 20-second context budget.
It does not run as part of successful Apply. Failed imports attempt a scoped
cleanup of only their unpublished generation; uncertain or busy cases remain
for later retention.

Recovery exports include only reachable catalog generations and required node
snapshots. The encrypted envelope remains version 2; archives containing catalog
payloads use inner manifest version 3. Ordinary files keep the 16 MiB per-file
and 64 MiB aggregate bounds. Catalog files have a separate 512 MiB per-file and
2 GiB aggregate bound. Restore verifies all referenced generations before
staging a transaction. Older images cannot consume the new inner manifest.

Backup and restore check filesystem headroom before staging and preserve a
64 MiB reserve, with additional space for staging and archive overhead. Large
linear reads use consumed-range cache drop-behind; private output files sync in
8 MiB windows. These are I/O controls, not RAM reservations or guarantees of
zero page cache. Concurrent writers and ordinary write failures still require
safe cancellation and cleanup.

Images declare support using the explicit OCI label
`io.sb-gateway.data.subscription-catalog.schema=1`. Local upload and offline
recovery read it from the checked image configuration; registry inspection
verifies manifest/config digests and platform. Version numbers do not imply
support. An incompatible target cannot be scheduled against catalog data.
Before publishing the new format, a checked legacy predecessor receives its
own complete compatibility mounts; the running container's mounts stay in
place. See [image compatibility](CATALOG-IMAGE-COMPATIBILITY.md) and
[runtime preparation](SUBSCRIPTION-CATALOG-RUNTIME.md).

Synthetic tests cover parsing, immutable storage, lookup, lazy preparation,
reference retention and compatibility guards. Image-update script execution,
resource behavior and real-provider transfers require separate CHR testing;
unit fixtures do not establish those results.

A deterministic runtime-planning memory rejection is reported as
`runtime_update.state=blocked` with a `catalog_planning_budget` reason. The full
catalog and committed runtime remain unchanged; the same active revision,
provider node generation and applied node snapshot are not prepared again under
an equal or smaller budget. Changing the active configuration, source generation
or another provider's applied snapshot permits a new attempt. A larger controller
planning budget also permits reconsideration: the in-process idle cache uses a
30-second budget-check TTL, and a process restart starts with an empty idle cache.
Ordinary transient failures keep their 30-second retry.

Refresh admission and all download channels share the configured 2–30 second
network deadline. A successful HTTP response is parsed and imported under a
separate two-minute local budget, following the original request's cancellation
and source guard. An invalid provider response can try the next channel while
the original network budget remains; local staging, compatibility, publication
or cancellation errors never trigger another provider request. The authenticated
refresh response allows three minutes for network, import and publication
headroom. These limits are separate from runtime activation and Apply.
