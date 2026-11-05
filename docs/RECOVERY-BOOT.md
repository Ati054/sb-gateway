# Boot-time recovery

The restart restore stage accepts explicit inner manifest version 2 and version 3.
Version 2 retains the ordinary 16 MiB per-file and 64 MiB aggregate limits. Version 3
adds only the seven catalogue files below
`config/secrets/subscription-catalogs/<generation>/`: `manifest.json`,
`records.bin`, `metadata.bin`, `id.idx`, `stable.idx`, `endpoint.idx`, and
`logical.idx`. Each catalogue file is limited to 512 MiB and their total to 2 GiB.
Other files keep the ordinary limits. Unknown schemas, noncanonical paths,
duplicate destinations and other files within that reserved prefix are rejected.

Before replacing the first live file, recovery validates every staged path,
size and digest, complete catalogue generations, and consistency with persisted
catalogue references. Catalogue records are verified as opaque bytes; recovery
does not expand private node definitions. Reference documents are scanned using
streaming JSON tokens. Checked catalogue readers pin generations during copying.

Storage admission checks the destination roots against the actual total payload
plus 64 MiB headroom and 8 MiB overhead. Copies recheck free space periodically,
use 64 KiB buffers, and verify the individual file again before atomic rename.
Owned output is synced in 8 MiB windows; consumed bulk input pages receive a
best-effort cache hint. Small shared inputs receive no eviction hint. There is
no global page-cache flush.

Recovery is retryable across interruption, rather than a transaction spanning
all destination files. A pre-existing invalid late file is rejected during
preflight without replacing earlier files. A new I/O failure or power loss after
copying starts can leave some files restored. The pending marker and complete
staging directory remain until every copy succeeds, so the next boot repeats
the complete verified operation. The pending marker is removed after successful
copies; staging cleanup follows. A successful parser or staging test alone does
not establish that the boot restore path supports a large catalogue.

Source regression coverage includes actual catalogue files larger than 16 MiB,
final private-record readback after boot restore, schema 2 compatibility, late
corrupt/incomplete/inconsistent payload rejection before overwrites, selective
byte budgets, storage-write failure propagation, and actual file I/O windows.
These checks do not substitute for release-specific filesystem and device tests.
