# Catalog data and image compatibility

Disk catalog references and lazy runtime pools require a catalog-aware image.
They must not replace authoritative legacy state during image probation. Before
the first incompatible publication, the controller must prove a completed image
transition and either an absent predecessor or a checked, stopped predecessor.
An absent active revision is accepted only when no prior runtime artifacts exist.

A legacy predecessor receives a full private snapshot of configuration, state,
credentials, matching generated runtime and last-known-good files. There is no
500- or 1000-node projection. Snapshot directories live beneath existing mounted
roots; catalog scratch, catalog payloads, compatibility recursion and image/recovery
archives are excluded. Published baselines are retained while their image exists.
Current container mounts are not changed. The predecessor remains stopped and
gets a separate owned mount list, confirmed by fresh authenticated readback.

The data snapshot includes the product's `last-known-good` tree. Other files in
the data mount are neither copied nor removed; upload archives, diagnostics and
unrelated artifacts do not consume the compatibility snapshot budget. Config
snapshots retain credentials, generated runtime and rule assets. Authoritative
state and complete legacy node inventories retain their original integrity and
source-epoch checks.

Reconstructible worker histories use a stable point-in-time copy of their opened
file. The copy is checked, but an atomic replacement of the live history does
not invalidate the baseline. Initial-size bounds prevent an append from extending
copying indefinitely. An unstable or invalid worker cache may be omitted without
changing its live source; this exception does not apply to configuration,
subscription node snapshots, generations or apply metadata. Snapshot errors name
only a generic stage and failure class, without private paths or file contents.
Recognized atomic-writer scratch names use the same precise classification as
recovery only within managed control-plane destinations, and are skipped before
file metadata is read. Their normal rename or disappearance cannot interrupt
copying. Scratch-looking secret references, configuration and last-known-good
files retain their normal checks, as do ordinary `.tmp` files and nonmatching
dotfiles. A basename alone never makes an authoritative secret disposable.
Secret references and last-known-good payloads also retain supported names such
as `.pending-key` or a `.catalog-compat` path component. Staging exclusions apply
to owned staging locations, not arbitrary matching names inside those protected
payloads. The separate new-format subscription catalog store remains excluded
from the legacy-image snapshot.
Protection follows the configured secrets directory relative to the captured
configuration root, including supported names such as `/config/private`.
Collection rejects a namespace outside that root or redirected by a symlink;
it does not silently fall back to `/config/secrets`.
Secret namespaces colliding with the reserved `generated`, `rulesets` or
compatibility staging roots are rejected before collection. Their content is
not silently treated as generated output, asset cache or scratch data.

Catalog-aware encrypted recovery currently requires the default `secrets`
namespace relative to the configuration root. With a custom namespace, catalog
archive export, schema-3 restore staging and boot restoration are rejected before
publishing or applying a restore. Legacy recovery inventories and local image
compatibility snapshots still preserve supported custom secret directories.
Namespace-aware catalog archive portability remains unsupported.
When the secrets directory is unset for boot recovery, its default is resolved
from the final configuration directory, including a command-line root override.
An explicitly configured custom directory does not silently use that default.

Container REST proofs normalize the current `envlists` field and the legacy
`envlist` alias from a nonempty string list or JSON array. If both fields are
present, both must be valid and name the same lists. Malformed or conflicting
aliases reject the proof; they do not silently select another environment.
Equivalent spellings retain the same normalized image fingerprint. These REST
checks do not change the image worker's RouterOS command compatibility behavior.

The preparation journal is incomplete until copied-file hashes, source epoch,
container identity and mount readback agree. Partial, ambiguous, canceled or
out-of-space preparation blocks incompatible publication. An unknown prior v5
image is not assumed compatible: a persisted producer-root capability must prove
support. Image-update workers choose rollback mounts for the target image and
reject unverified target-image catalog capabilities before creating a candidate.

An interrupted copy before mount attachment can be retried only after fresh
source-epoch, container and mount checks prove that no contract or mount refers
to its exact owned staging ID. A private ownership marker and bounded file-tree
checks protect that scoped removal. A preparing journal alone never authorizes
deleting a stage that may already be attached. Completed baselines are not
overwritten. Copies use bounded buffers, shared disk admission and 8 MiB
sync/cache-advice windows; final file and directory durability checks remain.

After an image or configuration change, an unattached preparation with no
recorded file manifest can be retired only by the same fresh global-reference
and local-ownership proof. Its files are not reused. The new producer and epoch
receive a new descriptor before copying starts. Recorded manifests, attached
mounts, completed baselines and unknown ownership are never retired by this
retry path.
Image-update admission can finish an interrupted, unpublished legacy preparation
before its normal backup check. This requires a recognized legacy preparation,
no catalog references or competing operation, a legacy runtime pool and a
verified catalog-capable update target. An unrecorded copy follows the checked
unused-stage retry described above. A recorded manifest may instead resume the
same handoff after its complete copied-file and authoritative-source checks,
private stage ownership, exact source epoch, producer/predecessor identity and
recomputed staging identifier all match. It is never retired or rebuilt.
Only exact owned partial mount rows are completed; an already attached
predecessor requires all four matching rows. Other containers, foreign paths,
unknown contracts and changed critical inputs veto continuation before any
mount or contract write. An existing contract must describe this exact completed
handoff. After completion, admission repeats the ordinary strict reference scan.
Retention and recovery remain strict while the preparation is pending; unknown
or catalog-aware preparations do not receive this lifecycle exception.
Global mount-reference checks also examine POSIX-normalized relative, `.` and
`..` spellings of the exact staging path. Empty, non-string or unresolved mount
sources cannot prove a stage unused. A matching list or contract remains a veto;
a different stage ID that merely shares a prefix is not the same stage.

The import publication barrier runs under the mutation and configuration locks:
it admits the original source epoch, prepares compatibility, then rechecks the
source, active revision and applied snapshot before publishing a catalog pointer.
A real Apply repeats the physical producer/previous-image proof before preparing
v5 artifacts or writing an operation journal. Preview and plan do not prepare
compatibility. Committed v5 startup checks the existing proof without changing
mounts or receipts; an absent proof prevents starting that persisted runtime.

Runtime reconstruction has a separate read-only validator. During a successor's
probation it requires the prepared producer capability, an exact owned transfer
receipt with verified incoming schema, a stopped matching predecessor and the
original shared-mount fingerprint. It can rebuild an existing v5 runtime without
authorizing new catalog publication. New pointers and producer-proof refresh
remain gated until the image transition completes.
Before deleting the transfer receipt, the worker persists and reads back an
owned arrival receipt bound to the successor/predecessor IDs, roots, verified
schema and original mount list. Startup can use that receipt across a power loss
between image commit and controller producer-proof refresh. It is not an
authorization to mutate catalog state during probation.
If the producer marker is published but the matching auxiliary rename is
interrupted, the completed arrival plus exact IDs, roots, predecessor capability
and original mount fingerprint permits read-only startup and strict publication
retry. A live transfer or probation receipt cannot authorize that promotion.

Draft-only bootstrap imports can record an explicit no-active/no-prior-runtime
receipt without reaching RouterOS. A real first Apply must additionally bind the
physical producer before preparing v5 and before creating its pending journal;
otherwise a power loss after the first commit would leave no startup proof.
An unexpected retained predecessor at this empty-bootstrap boundary is rejected
rather than assigned an invented legacy baseline.

An older image archive cannot safely consume the current catalog by merely
sharing current mounts. Retained-image promotion and offline recovery must use
the matching checked handoff, or be rejected. Recovery archives must separately
export all reachable catalog generations with explicit streaming and disk limits.

Synthetic filesystem and mocked REST tests describe the intended boundary. Until
controller hooks, verified image capability metadata, recovery export and actual
CHR lifecycle tests pass together, this compatibility path is not release-qualified.
Scheduler admission regressions use an authenticated TLS REST image/mount proof;
virtual-time cases release and cancel queued workers even if an assertion fails.
