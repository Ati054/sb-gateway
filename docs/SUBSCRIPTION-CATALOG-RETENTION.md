# Subscription catalog retention

Catalog generations are immutable private directories identified by a checked
content reference. Retention is separate from accepting a subscription: a failed
import must not replace the last complete source inventory or its metadata.
Storage bounds for one builder are not a reservation or a quota for all retained
generations together.

The reference graph consists of the current source inventory, committed and
rollback node snapshots, generated runtime pool references, settled operation
state and prepared compatibility pins for an older container. A stopped previous
container can still require a generation; the absence of an open file descriptor
does not prove that a generation is disposable. Missing, malformed or pending
reference state postpones cleanup instead of guessing.

Readers hold a shared manifest file lease for their entire lifetime. Removal
requires an exclusive nonblocking lease, including when a reader belongs to a
different process or is outside a controller cache. Idle cache entries must be
closed before removal; active users remain protected. Unsupported lease platforms
or filesystems reject the operation explicitly.

`subscriptioncatalog.RemoveGeneration` is a scoped storage primitive. Its caller
must prove that the exact generation is unreferenced. The primitive verifies the
reference, complete seven-file layout, private regular files, anchored filesystem
identities and checksums before deleting anything. It removes only those known
files and the empty generation directory; it never recursively deletes a parent.
Cancellation before the first unlink leaves the generation intact. Cancellation
after that boundary no longer interrupts scoped deletion; unrelated filesystem
errors still surface.

Ordinary retention must allow at least 24 hours for unreferenced completed
generations and exclude preparation directories. Cleanup of one exact
caller-owned, unpublished generation after a rejected import may omit that age
grace, but must use the same complete reference proof and reader leases. A cleanup
failure leaves extra storage to inspect or retry; it is not permission to delete
referenced or busy generations.

Recovery archives include generations reachable from persisted reference state.
A retired reader's temporary file lease blocks deletion but does not, by itself,
add unrelated cached generations to the recovery archive.

Package-level synthetic tests cover independent and cross-process leases,
foreign/corrupt/symlink entries and both sides of the cancellation boundary.
These checks do not establish aggregate disk headroom, device performance or
successful recovery of a particular deployment.
