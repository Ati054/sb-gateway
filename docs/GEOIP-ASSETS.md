# Managed GeoIP Assets

Retention inputs must contain exactly one complete JSON object. Empty,
truncated or concatenated documents abort cleanup before any asset deletion.

Managed country traffic rules use Xray binary references instead of repeating
the complete CIDR list in each source/inbound rule. Portable `geoip-XX.json`
packs remain the source for DNS IP-condition validation, RouterOS WAN-outage
rules and restore. The traffic compiler preserves every canonical IPv4/IPv6
prefix; it does not substitute DNS's presence-only flag.

## Publication and Activation

Assets live in `SB_RULESET_DIR` (default `/config/rulesets`), on the persistent
configuration mount. Their names are `sb-geoip-<cc>-<sha256>.dat`, where SHA256
covers the entire deterministic country protobuf. Routing uses the basename
`ext:sb-geoip-<cc>-<sha256>.dat:<cc>`. Startup, Check/Apply validators and API
helpers all set `XRAY_LOCATION_ASSET` to the same controlled directory.

A writer validates the bounded JSON pack, writes and fsyncs a private temporary
file, publishes with an atomic no-overwrite hard link, verifies the published
bytes and syncs the directory. Only then may refresh replace the portable JSON
pack. Existing content-addressed files are never rewritten. Damaged assets,
symlinks, invalid countries, noncanonical prefixes and mixed domain/IP packs
fail closed. Filesystem hard-link support is required; failure leaves the old
portable pack/routing untouched.

The existing RoutingService transaction compiles a complete replacement table
while the old table serves traffic. It then replaces the table and verifies
rule count/order. The bundled core retains balancer overrides, and established
flows retain their original route. No Xray restart is requested for a pack
refresh. Failed or ambiguous activation/readback rolls back to the last
confirmed GeoIP references for that core, not merely the startup country list.
Only a small reference map is retained, not a duplicate full routing table.
The existing startup-proof and Apply-journal exclusion remain in effect.

Selected legacy inline rules (including already tagged inline rules) are
rendered/validated from the committed model and node snapshot before startup.
Missing or checksum-invalid binary references also require this reconciliation;
a missing asset cannot silently pass the migration gate.
Configuration and last-known-good routing retain their own immutable assets;
the current portable JSON pack is reconciled by the ordinary refresh worker.
Recovery archives now include country JSON sources and managed binary assets,
so restored last-known-good references have their required files.

## Bounded Cleanup

After confirmed activation and during unchanged monitor passes, cleanup retains
references from the active generated config, last-known-good config, current
candidate/transaction rollback artifacts, and the live core's last confirmed
country references. Other managed `.dat` files are removed; user files and
portable JSON sources are never deleted by this collector.

An unpublished Check/Apply render has a ten-minute publication lease, renewed
when its asset is verified. This covers the short render-to-candidate window
without holding an extra full config graph in memory. Cleanup runs no more than
once per minute, after the existing monitor refresh cadence, and defers during
Apply. A missing optional candidate/LKG root is allowed; unsafe or malformed
retention inputs abort deletion. Superseded startup/LKG versions remain only
until those configurations are replaced. This is not indefinite generation
history, and a switch never deletes a file still needed for rollback/restart.

## Verification

Unit/race regressions cover protobuf wire format, every prefix in a 25,094-prefix
pack, concurrent publication, corrupt/symlink rejection, portable-pack retention
on asset failure, last-confirmed rollback, restoration dependencies, and cleanup
of orphaned assets while preserving active/LKG/Apply/rollback/leased files.

These regression contracts do not guarantee whole-container memory usage or
physical-router recovery time. Environment-specific acceptance receipts and
hardware runners are not included in the public source distribution.
