# Shared Domain Sets

Large service-pack domain rules (64 entries or more) use immutable native
GeoSite assets instead of repeating domain arrays in each Xray route. Manual
conditions and mixed rule-set overrides retain their existing inline behavior.
Exact names, suffixes, keywords and regular expressions keep their original
semantics. Invalid expressions reject publication rather than being silently
discarded by a GeoSite loader.

Assets are named `sb-geosite-<sha256>.dat`. The content hash changes the Xray
matcher-cache key on updates; an older active/LKG generation keeps its old
file. Publication, bounded verification, candidate leases, retention cleanup
and encrypted recovery use the existing managed geodata asset machinery.
Startup and Apply verify referenced assets before launching or validating a core.

Policy DNS schema 2 stores large exact/suffix sets once in `domain_sets`.
Rules refer to their content IDs. Each resolver generation compiles one shared
membership index, while every lane owns its own rule-order/server/reject
decisions. First-match order, suffix boundaries and source/user isolation are
unchanged. No process-global history cache retains old generations. Old schema
1 remains readable; image startup transactionally rebuilds committed runtime
artifacts without changing the saved draft or requiring another Apply.

Trusted catalog updates parse bounded HTTP readers line by line, including
GeoIP text. Parent responses close before following includes. Limits remain
4 MiB per source, 96 included files and 250,000 distinct domain values; invalid
UTF-8, read errors and malformed rules preserve the last published pack. The
legacy string-fetch adapter remains available for existing callers/tests.

## Verification

Run Go tests for `internal/domainset`, `internal/geoipasset`, `internal/rulesets`,
`internal/policydns`, `internal/runtimeconfig` and `internal/controlplane`.
The `xray_multicall` command tests exercise the pinned core's native GeoSite
decoder and confirm that a repeated large matcher reuses its compiled data.
DNS tests cover overlapping sets, exact/suffix precedence, independent lane
decisions, missing sets, immutable updates and safe cleanup.

`go test ./internal/policydns -run '^$' -bench BenchmarkDNSMembershipCompilation
-benchmem` compares eight lanes sharing 10,000 suffixes with separate tables.
This component benchmark is not a full-container memory or CPU measurement.
Before releasing, test schema migration, repeated Apply, DNS over TCP/UDP,
actual matched and unmatched traffic, rollback/restart and sustained VLESS
transfers on CHR. Keep lab topology, measurements and credentials private.
