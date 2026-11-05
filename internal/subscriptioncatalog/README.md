# Immutable subscription catalogs

This package stores the complete normalized node inventory on disk without a
node-count ceiling. Callers assign runtime-scoped IDs, compute identity keys, and
validate the opaque Node, Secrets and public Metadata JSON. An explicit caller
node quota is separate from this package's byte and working-memory limits.

`NewBuilder` creates private staging files. Append writes one framed record and
one metadata record at a time, plus four fixed 48-byte index entries. Seal sorts
bounded chunks and merges them with a bounded fan-in; it does not retain a map or
slice of all records. Defaults are an 8 MiB record, 512-byte ID, 512 MiB combined
canonical records and metadata, 1 GiB temporary-plus-final disk budget, 1 MiB
sort working chunk and 16 merge inputs. The disk budget counts logical file
bytes; filesystem metadata and allocation rounding are additional. Existing
generations do not count toward this build. The caller manages total storage.
The limit is not a reservation or an aggregate quota. Two simultaneous builders,
or a retained raw staging catalog and a final catalog, can each consume their
own budget. The caller must account for all builders, retained generations,
source staging, filesystem overhead and other application files together, and
preserve rollback/pending references during any separately scoped retention.

Builders also check available filesystem space before the first payload write
and approximately every 1 MiB of new writes, including index sorting, buffered
merges and the manifest. Each check requires 64 MiB of disk headroom plus the
upcoming write quantum; larger writes include their full size. Checks use the
anchored root's logical path and fail if that path was replaced. Insufficient
space returns ErrNoSpace; capacity that cannot be verified returns ErrIO. This
disk headroom does not reserve RAM or filesystem bytes and cannot guarantee
against concurrent writers. Ordinary write, sync and publication failures still
prevent a partial catalog from becoming visible.

On Linux, builders use one shared 8 MiB write window across records, metadata,
sort runs, merges and the manifest. At a boundary, owned dirty ranges are synced
before best-effort `FADV_DONTNEED`; a sync failure aborts publication. Pending
closed runs are reopened through the anchored staging directory, and tracking
does not retain every run name or file descriptor for the whole build. The final
tail is flushed before publication. This controls large linear I/O accumulation;
it is not a promise of zero page cache or a replacement for cgroup memory limits.

Large SHA verification and framed walks use 8 MiB read drop-behind, including
linear sort input and a shared window across merge inputs. Small metadata and
ordinary binary-search/Get reads retain their cache. Non-Linux platforms keep
the sync and error semantics but use a documented no-op advisory fallback; they
do not provide the Linux cache-release behavior.

A successful Seal publishes a complete directory by atomic rename after syncing
its files and directory. Its generation is a lowercase SHA256 over schema,
count, record/metadata digests and index digests, including secret content.
Generations contain only fixed filenames. Ref contains checksums and sizes, not
paths. Directories are 0700 and files 0600; symlinks and nonregular files are
rejected. Opened directory and file identities are checked against their initial
filesystem entries, including permissions, before use. Filesystem errors omit
record content, identifiers and paths.

Defer Abort immediately after creating a builder. Failed or canceled builds
cannot publish a partial generation. Abort removes only that builder's staging
directory. Published generations are retained unless the caller proves them
unreferenced and explicitly calls RemoveGeneration. This package does not infer
active, rollback or pending references. A failed directory sync after rename may
leave a complete unreferenced generation, never a partially written publication.

Inspect checks the small manifest and content identity. Open additionally streams
and verifies every file checksum once before exposing a Reader. Get and
LookupUnique use binary search and concurrent-safe ReadAt, decoding one private
record. Duplicate IDs reject Seal; duplicate identity matches return ErrAmbiguous
instead of choosing a record. Zero identity keys are absent from their indexes.
Keys serialize as 64 lowercase hexadecimal characters.

Bulk identity reconciliation uses an explicit `NewBulkLookupSession`. It keeps
at most 64 merged, page-aligned consumed record ranges and an 8 MiB outstanding
range budget, flushing best-effort advice at either boundary. Reads are chunked
so a large record cannot bypass admission. Outward page alignment is specific to
this maintenance role and can evict pages also used by concurrent ordinary reads.
Index files and ordinary Get/LookupUnique paths are unchanged. `CheckUnique`
checks identity-index uniqueness without reading or decoding a private record.
The caller retains the Reader/cache lease for the session lifetime. Session Flush
and Close only release cache ranges; they neither sync nor close the Reader.

WalkMetadata reads only the separate metadata file and never decodes Node or
Secrets. It depends on caller-approved metadata fields rather than inspecting
private definitions. Walk streams full records when explicitly requested.
Callbacks run without reader locks and their errors pass through unchanged.
The caller owns Reader.Close; a concurrent close interrupts subsequent reads.
Every Reader holds a shared manifest file lease until Close. RemoveGeneration
requires a nonblocking exclusive lease, including across processes, validates the
complete seven-file layout and checksums, and removes only those owned files and
the empty generation directory. An active reader returns ErrBusy. Unsupported
lease platforms or filesystems fail explicitly. Cancellation before the first
unlink leaves the generation intact; after that boundary deletion finishes.

Synthetic tests cover complete 1k/5k/10k inventories, multipass external merges,
metadata isolation, large records, immutable coexistence and reordered IDs,
duplicate/ambiguous keys, concurrent reads, bounded failures/cancellation,
checksum corruption and filesystem guards. These tests are package-level
verification; they do not establish full controller, runtime, or ARM performance.
