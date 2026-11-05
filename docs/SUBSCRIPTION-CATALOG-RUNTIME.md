# Disk-backed subscription runtime

An imported subscription catalogue is immutable private storage. Its checked
reference names a content generation and file checksums; it never supplies a
filesystem path. Node definitions and credentials are read one record at a time.
Legacy inline catalogues and version 4 health-pool files remain readable.

The version 5 runtime compiler walks credential-free matching metadata before
constructing Xray outbounds. It preserves the complete ordered candidate set of
every enabled policy, including policies without an assigned client. Country,
city, region and explicit group selections use the same canonical matching and
first-claim order as the legacy compiler. The working shortlist does not truncate
the catalogue or the eligible reserves.

Provider definitions used through health selectors are absent from the startup
Xray graph and from the health-pool JSON. The pool stores checked catalogue
references, candidate IDs and one shared typed metadata index. The health worker
loads a definition only when an active or probe handler requires it. A shared
cache is bounded to 32 definitions and 2 MiB of rendered bodies; larger individual
definitions bypass the cache. The health worker caches checked readers for up
to eight catalogue generations. The controller may open an uncached transient
reader when all cache entries are leased. Record-size and catalogue byte limits remain independent of node
count. These bounds do not imply constant total memory for arbitrary policy,
history or metadata sizes.

The panel selects subscription nodes through policy candidates. Its exception
service destinations refer to the current policy, and custom routes choose WAN
or VLESS. A policy's `final` reference is validated as another policy or `direct`;
the panel does not expose an arbitrary node destination there. Legacy renderer
fixtures containing direct node references do not establish a separate supported
panel pinning mode.

Direct leaf dependencies in legacy service/final routes are materialized for traffic and
DNS routing. Configuration-owned Reverse, RouterOS WireGuard and independent
subscription-refresh reserves retain their separate static/live-session behavior.
Reverse leaves are never replaced by synthetic direct handlers. Endpoint bypass
and loop-prevention rules follow the same eligible dependency closure. Editing
that closure can therefore change the corresponding routing artifacts.

Probe listener allocation still uses the full enabled inventory count, bounded
by the configured probe budget. Selecting fewer candidates does not reduce the
listener geometry or change its ports. An explicit all-node policy retains every
eligible ID and its compact metadata; it does not eagerly render every private
outbound definition.

Cold-start reconciliation uses the same catalogue-aware metadata planner to
check that inventory. Compact catalogue references are not counted as ordinary
inline nodes. The image compatibility proof is checked before catalogue metadata
is opened; provider definitions and UUIDs are not decoded to calculate listener
geometry. The same expected geometry checks both the persisted runtime and a
replacement candidate, including listener tags, ports, loopback binding, protocol
and per-policy probe budget. A matching version 5 probe contract does not by
itself require another render or publication. An obsolete contract is rebuilt from the committed
node snapshot, leaving unapplied source updates and draft settings unchanged.
Unavailable or corrupt committed catalogue references and unproven image
compatibility stop reconstruction rather than substituting another inventory.

Version 5 endpoint evidence uses the explicit `connection-node-secrets-v1`
fingerprint kind. The controller hashes normalized connection settings and
credential content while excluding display labels and selection/location data.
Changing an endpoint or credentials invalidates incompatible evidence. A new
disk generation caused only by cosmetic changes does not change handler identity.
Version 4 retains its original raw-Xray-body fingerprint and handler-tag algorithm.

The catalogue root comes from trusted process configuration, never the health
pool: `subscription-catalogs` below `SB_GATEWAY_SECRETS_DIR` (normally
`/config/secrets/subscription-catalogs`). The
controller and health worker must use the same root. Missing, mismatched or corrupt
definitions fail closed; another source or direct WAN is not substituted.

Source regressions cover full versus narrow selection, canonical group order,
listener geometry, scoped IDs and local record secrets, shared metadata, bounded
lazy definition lookup, generation/fingerprint separation and legacy handler tags.
These source checks are not a claim of completed CHR or production qualification;
release validation must also exercise full catalogue ingestion, refresh, Apply,
rollback, startup restoration, and sustained traffic under the target limits.
Startup regressions include small and mixed inventories, disabled records,
unchanged version 5 contracts, repair followed by an unchanged second start,
and rejection of missing or corrupt committed generations before publication.

Changing the on-disk catalogue format also requires a matching old-image rollback
handoff and reachable-generation recovery export. Those lifecycle boundaries are
part of release qualification; a passing parser or lazy-lookup test alone does
not qualify an image for deployment.

Image capability and interrupted preparation rules are described in
[catalogue compatibility](SUBSCRIPTION-CATALOG-COMPATIBILITY.md).
