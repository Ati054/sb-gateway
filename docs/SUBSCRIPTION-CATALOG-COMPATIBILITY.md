# Catalogue capability across image updates

The health pool's version describes runtime data, not the installed image's
catalogue capability. A catalogue-aware image may still use a legacy pool until
the first catalogue refresh and Apply. Versions 3, 4 and 5 therefore do not select
the predecessor's image capability by themselves.

For a successor transition the controller reads an authenticated owned prepared
schema 1 image contract and a completed image-arrival receipt. They must agree
with the actual running current and stopped predecessor IDs and roots, the live
interface, mount lists and environment namespace. Four enabled current mount rows
and their sources are bound by the fresh inventory. Inventory, contract and
receipt are read again; changing, malformed or missing positive evidence vetoes
the transition. A receipt proves the target image; the matching contract must
also prove predecessor capability. No historical fingerprint is reconstructed
from current data, and no version number is treated as capability evidence.

An already prepared unchanged physical descriptor keeps its existing fast path.
Ordinary refreshes and Apply do not repeat arrival inventories merely to reuse
that descriptor. A genuine legacy predecessor still requires its private legacy
baseline. Unknown version 5 state remains blocked.

A legacy pool can already coexist with full catalogue sources after refresh but
before Apply. Losing an image contract does not make those sources legacy data.
Before any new legacy snapshot, preparation journal or incomplete-stage
retirement, the complete authoritative reference graph must prove there are no
catalogue references. Otherwise the transition is blocked: a legacy snapshot
intentionally excludes private catalogue generations and would be incomplete.
Exact pending-journal scans are read-only absence proofs; they do not declare a
preparing journal prepared. Unrecorded retirement may still handle a changed
producer or epoch after its separate unused-stage and ownership checks, while
recorded baseline resume retains its original epoch and checksum requirements.

For the completed-arrival recovery path, an interrupted unrecorded preparation
can be retired only with an exact typed
journal, an explicitly empty reference list, no recorded files or attached mount
list, unchanged producer/epoch, and an identifier recomputed from the original
canonical preparation inputs. A full checked reference graph must prove that no
catalogue is authoritative. Global RouterOS references and local ownership must
also veto use of the incomplete stage before retirement. Recorded or attached
baselines do not enter this recovery path; older frozen baselines are preserved.

Marker publication precedes the final auxiliary descriptor. If that final write
is interrupted, the next attempt can verify the completed arrival and promoted
contract again. It does not relabel a preparing journal as prepared to bypass
normal reference checks. Reference retention, recovery export and pruning keep
their normal strict graph requirements.

Sanitized regression tests cover all supported pool versions, completed and
promoted receipt states, missing/malformed and changing evidence, environment
and mount binding, journal/identifier tampering, legacy-pool reference vetoes and
unchanged prepared fast paths. Release-specific qualification is separate.
