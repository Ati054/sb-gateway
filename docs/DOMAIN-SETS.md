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

Persisted policy DNS keeps schema 1 and complete inline domain conditions, so
predecessor workers cannot silently lose rules during an image rollback.
The new worker decodes one lane at a time and interns large exact/suffix sets
before reading its siblings. Each resolver generation compiles one shared
membership index, while every lane owns its own rule-order/server/reject
decisions. First-match order, suffix boundaries and source/user isolation are
unchanged. No process-global history cache retains old generations. The interim
schema 2 reference format remains readable. A `domain_index_version` marker lets
startup transactionally rebuild committed runtime
artifacts without changing the saved draft or requiring another Apply.
Resolver documents are bounded at 32 MiB; listener readiness reads only lane
addresses and does not rebuild the membership index.

Clients with identical effective DNS policies share one loopback listener and
Xray forwarding outbound. Equality includes the final resolver, ordered domain
conditions, resolver tags and reject actions. Source, authenticated-user and
inbound selection still happens before that listener, with first-match routing
preserved. Disjoint host-only source rules can share an Xray route to the same
listener; compaction never crosses overlapping sources, network prefixes,
user/inbound constraints or the fallback rule. Distinct resolver tags remain
isolated even when they point at the same address. Persisted schema 1 remains
readable by predecessor workers during rollback.
A `lane_layout_version` marker triggers a transactional rebuild of committed
artifacts at startup, so existing installations receive this layout without
changing saved settings or requiring Apply.

Packaged `xray_multicall` builds reuse the pinned Xray `MphMatcherGroup` for
the DNS membership index. Its compact arena and numeric hash tables avoid
per-domain string/slice pointers in retained memory. A numeric membership array
preserves all set IDs and duplicate memberships. Matching returns all exact
matches, followed by suffixes from nearest to furthest, before each lane applies
its own rule precedence. Leading-dot legacy exact names remain literal rather
than acquiring Xray's subdomain behavior. Compilation uses the group directly,
not the value-matcher builder that explicitly forces garbage collection.
Successful lookups allocate Xray's result slice; misses do not. Non-multicall
development builds retain the map implementation without an Xray dependency.
If MPH construction fails (for example, on a hash collision between legacy
noncanonical names), the index falls back to the previous map implementation
rather than rejecting a previously accepted configuration. That exceptional
generation does not receive the MPH memory savings.
This does not change Xray's routing matcher or the persisted configuration.

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
Compiler tests also cover shared client policies, IPv4/IPv6 host compaction,
overlapping sources and preservation of ordered access decisions.

`go test ./internal/policydns -run '^$' -bench BenchmarkDNSMembershipCompilation
-benchmem` compares eight lanes sharing 10,000 suffixes with separate tables.
This component benchmark is not a full-container memory or CPU measurement.

`go test ./internal/domainset -run '^$' -bench BenchmarkDomain -benchmem`
compares lookup latency, retained heap and GC-scannable heap for a map and a
sorted compact-array prototype on a synthetic 100,000-name catalog. Add
`-modfile=<prepared-multicall.mod> -tags=xray_multicall` to include the actual
packaged MPH adapter in the same comparison. The array prototype is test-only.
Storage results include forced collections only in the benchmark, never in
production.
`go test ./internal/domainset -run '^$' -fuzz FuzzIndexMatchesReference
-fuzztime=45s` checks membership and callback order against that reference.
Run the domainset and policydns tests with `-race` and with both build variants.
These are component checks; they do not establish a whole-router CPU reduction
or CHR acceptance.

Before releasing, test schema migration, repeated Apply, DNS over TCP/UDP,
actual matched and unmatched traffic, rollback/restart and sustained VLESS
transfers on CHR. Keep lab topology, measurements and credentials private.
