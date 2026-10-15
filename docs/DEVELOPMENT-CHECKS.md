# Development Checks

## Public Release History

`docs/PUBLIC-CHANGELOG.md` is the reviewed, user-facing version history. The
public export copies it to `CHANGELOG.md` in full and verifies that its first
release matches `package.json`. Add a new entry when preparing a release;
do not discard older entries or substitute the internal development journal.
The public-tree check rejects missing or duplicate versions and a mismatched
copy. Detailed private acceptance evidence remains outside this history.
The release-contract test also retains the known public version headings;
adding a release must not silently remove older entries. Stable and numbered
RC headings use the same parser.
The export copies the reviewed file byte-for-byte, including line endings,
so Windows archives and Linux verification compare the same content.

## Memory Budget Checks

Domain-set verification and native Xray matcher checks are documented in
[Shared Domain Sets](DOMAIN-SETS.md). Keep shared membership independent of
per-lane actions and test both matched and unmatched traffic before publishing.

`go test ./internal/memorybudget ./cmd/sb-gateway ./internal/controlplane`
covers finite/unlimited and nested cgroup limits, role allocation, explicit
lower overrides, safe persisted hints, helper dispatch and unchanged Apply/ACME
contracts. The budgeting opt-in is set by the image, not by host test commands.
Exercise at least 128/256/384 MiB cgroups before releasing a budget change.
Also measure sustained traffic, concurrent ACME/Apply, cgroup events and GC CPU;
an arithmetic sum below memory.high is not an RSS or long-term stability proof.

## Console Forms

Run `npm test`, `npm run lint` and `npm run build:static` after moving console
components. `tests/console-modules.test.mjs` rejects cyclic section imports and
another oversized route entry. Source-contract checks include every console
module, including RU/EN translations and transport serializers.

After the static build, `npm run test:browser` runs the real bundled UI against
an isolated synthetic API. It requires a developer-installed Playwright and
Chromium. `SB_PLAYWRIGHT_MODULE` may point to an existing Playwright `index.mjs`;
`SB_BROWSER_CHANNEL=chrome` selects an installed Chrome instead. These are test
tools, not container dependencies. The fixture never accesses RouterOS or an
external service and uses no real accounts, subscriptions or keys.

The browser matrix covers both languages, LAN/WireGuard/PPP device edits,
VLESS subscription formats, routing DNS and Reverse names, navigation before
autosave completes, failed writes preserving input, Settings with the default
zero recovery cooldown, and one explicit Apply followed by a reload. It also
checks desktop/mobile rendering. A mocked Apply proves the frontend request
contract only; it does not replace protected Apply and dataplane tests on CHR.

`settings-validation.test.mjs` covers all Settings recovery-field boundaries.
Zero recovery cooldown is valid, including in an otherwise untouched default
configuration; it must not disable saving unrelated settings.

## Managed IP Protocols

`go test ./routeros ./internal/runtimeconfig` covers the default-enabled WAN
echo toggle, mandatory multicast/broadcast exclusions, independent related
ICMP error rules and removal of new owned rules during a legacy rollback.
`go test ./internal/routeros` additionally validates that legacy cleanup keeps
the required full-candidate header and section order accepted by SSH transport.
Release verification must exercise IPv4/IPv6 echo enabled and disabled,
related PMTUD errors in both states, unrequested ICMP errors and unsupported
GRE/ESP, multicast with the editable exclusions removed, repeated Apply and
rollback. Keep packet captures and environment-specific results private.

Watchdog probes the live dataplane and does not run `xray -test`. The controller
validates candidate configurations with `XRAY_LOCATION_ASSET` set from
`SB_RULESET_DIR` (default `/config/rulesets`); startup validation is retained.
`TestDeepProbeDoesNotLaunchXrayValidation` covers routing-only file changes and
confirms that missing live TCP/UDP listeners still fail readiness. With
`SB_TEST_XRAY` pointing to the pinned core,
`TestPinnedXrayGeoIPCandidateValidation` validates a synthetic content-addressed
GeoIP database and verifies that a missing asset rejects activation without
publishing the candidate or restarting processes. It requires no external
network access and does not alter the running core or generated configuration.

The release-hygiene workflow has an independent Go quality job:

- `go vet ./...`;
- Staticcheck v0.8.1, `-checks='SA*' ./...`;
- Analysis tools use the pinned `golang.org/x/tools` v0.51.0 importer for Go 1.27.2 export-format compatibility. Install them with `sh scripts/install-analysis-tools.sh "$(go env GOPATH)/bin"`; this does not change runtime dependencies.
- `CGO_ENABLED=1 go test -race ./... -count=1 -timeout=15m`;
- govulncheck v1.8.0, `govulncheck ./...`.

Its Go version matches the gateway build toolchain pinned in `Dockerfile`;
update both pins and the laboratory packaging image together. All three use
Go 1.27.2; earlier Go 1.27.1 and 1.26.4 images have known standard-library
vulnerabilities that a source scan under a newer host Go cannot detect.
Ubuntu's C compiler is required only for race
instrumentation. Production gateway binaries remain `CGO_ENABLED=0`. Analysis
tools are development dependencies, not additional container components.

All Staticcheck correctness checks are blocking, including allocation checks.
Style (`ST*`), simplification (`S*`) and unused-code (`U1000`) checks are not
blocking in this job. The full default scan has existing findings in those
categories; it is not reported as passing. No correctness finding is suppressed.
UDP DNS pools store pointers to fixed-size buffers, avoiding slice-header
boxing on pool returns without changing request lifetime or worker limits.
Fresh DNS TLS fixtures construct trusted upstreams before starting handler
goroutines; they do not mutate live TLS settings. Untrusted-certificate cases
still use the public production constructor and require certificate rejection.
The ACME telemetry subprocess fixture measures the reporter call itself, not
the race runtime's one-second exit delay. A five-second parent context bounds
stuck children. The reporter threshold remains 750 ms; race detection and its
normal exit behavior are not disabled.

govulncheck distinguishes reachable symbols from merely required modules.
A passing source scan is not a security certificate for a release image: also
inspect the actual built binaries, their embedded Go version and dependencies.
It does not cover npm, Alpine packages or configuration/exposure vulnerabilities.
For a binary audit, extract the gateway, ACME worker and Xray executables from
the exact candidate image without starting it. Record their hashes and embedded
build metadata, then run `govulncheck -mode=binary` on each executable. Private
hardware runners and environment-specific receipts are not published.
Public network fixtures use documentation or benchmark address spaces rather
than identifying a deployment.
References: [Staticcheck](https://staticcheck.dev/docs/getting-started/) and
[Go vulnerability management](https://go.dev/doc/security/vuln/).

The pinned stripped binaries have no symbol table usable by govulncheck 1.8.0:
binary findings fall back to module-wide precision. Preserve these findings;
do not report them as a passing symbol scan. Resolve them against the exact
patched Xray build stage and the publisher's advisory before release. In
particular, the gRPC publisher lists 1.84.0 as fixed for
[GHSA-2v4p-qf9q-27wj](https://github.com/grpc/grpc-go/security/advisories/GHSA-2v4p-qf9q-27wj),
Database results may change; compare every returned finding against the
publisher's fixed-version ranges and the exact binary metadata.
The opt-in `TestXrayAPIRejectsMissingAuthority` sends three HTTP/2 requests
without both authority/Host headers to an isolated real core. Each must return
HTTP 400/gRPC 13 and a subsequent ordinary selector command must succeed.
This isolated regression never contacts live selectors.
A source scan or this regression does not certify every dependency or exposure.

Review reported dependency paths against the exact pinned Xray source and
ARM64 import closure, not an unrelated upstream version. A narrow source review
is not a clean binary scan or a scanner exception. Preserve nonzero audit
results; a different core requires a new review.

Configuration drafts remain untyped JSON objects so invalid drafts and older
fields can be retained. Consumers must validate before runtime publication;
typed boundary decoders must reject malformed values rather than silently
defaulting them. Validation/runtime agreement is already tested for enabled
defaults, transport settings, DNS controls and configuration-owned exits.
These tests are important but do not provide compile-time coverage for every
string key. This change does not convert the complete schema or split large
files. Add focused validation-to-rendering contracts when changing a field.

The pinned core includes `xray-reverse-backpressure-selection.patch`.
Run `go test ./common/mux ./app/reverse ./proxy/vless/inbound` in the patched
Xray source. The blocked-receiver fixture requires an independent tunnel to
deliver a response while its sibling is blocked, then checks selection away
from that sibling and its reuse after recovery without closing either tunnel.
Sole/all-blocked fallback, drain priority, closed-worker exclusion and write-error
cleanup and isolation between separate profile pickers must remain intact.
Repeat the focused tests under `-race`; benchmark
`BenchmarkSBReverseDownlinkTracking` with allocation reporting before release.
Both image build stages exercise these packages. These deterministic core tests
do not establish public-WAN throughput, real failover timing or release-image
acceptance on CHR; record those checks separately before claiming them complete.

Reverse regressions cover converted/pruned selector membership, zero online
counters with a live portal, and local API failures without node penalties.
`TestReverseRecoveryUsesActiveRequestContract` requires the same GET/deadline
for Reverse quality qualification and active availability. HEAD-only and slow
GET responses must not qualify a return; a healthy primary needs one request.
HTTP trace regressions isolate CONNECT rejection, silent TLS, missing headers
and stalled bodies; classification and cancellation must survive error wrapping.
Startup regressions also require native RPC override/readback for every ordinary
selector with no CLI binary available, plus a bounded readiness budget rather
than a fixed startup delay.
Pool-only reload fixtures use the readiness marker, not host process-name scans;
an unrelated running Reverse client must not invalidate their cached generation.
The opt-in `TestStartupReverseWaitPinnedCoreReconnect` uses an isolated core,
ephemeral ports and a temporary external-client JSON exchange. Set
`SB_TEST_XRAY`, `SB_TEST_REVERSE_ADDRESS` and `SB_TEST_REVERSE_EXCHANGE`;
run the exchanged client separately. `SB_TEST_REVERSE_TRANSPORT` accepts
`tcp` (REALITY + Vision) or `xhttp` (REALITY). The fixture permits only its
explicit IP/port target, verifies real data transfer and repeats restoration
after core restart. It does not alter existing route-sheet configuration.
The client fixture uses exported TCP defaults: keepalive idle 30 seconds,
interval 10 seconds, and unacknowledged-data timeout 60000 milliseconds.
`SB_TEST_REVERSE_BURST=1` additionally alternates 320 availability and quality
requests per startup with pauses for mux worker rotation. Both request kinds
must remain healthy across rotation and the subsequent core restart.
An online counter alone is not a passing data-path or restart test.

`SB_TEST_REVERSE_FAULTS=1` requires a trusted external HTTPS origin at
`SB_TEST_REVERSE_TARGET` (explicit IP/port), with `/data` returning 204 and
`/mode/slow`, `/mode/silent`, `/mode/normal`, `/mode/stop` controlling the
fixture. Slow mode delays only probe headers for four seconds; `/data` must
remain immediate in both slow and silent modes. The test keeps
concurrent data requests running, reproduces two rejections with the former
2/3-second budgets,
then requires both production availability and Reverse recovery probes to
accept the same delayed response. Availability shares a five-second round
deadline across its origins, hedging after two seconds; recovery uses a
five-second primary request. After the first active timeout, the controller
starts all three origins immediately in the confirming round, under the same
five-second budget. Recovery resets the failure count and restores the ordinary
one-request fast path. `health_confirmation_test.go` checks controller dispatch,
immediate origin fanout, canceled-worker joining and Apply-generation rejection;
non-timeout failure classes must not enable this confirming fanout.
Silent mode delays headers for thirty seconds;
two complete failure rounds are timed against the former sequential schedule.
Healthy HTTP-schedule comparisons record process CPU ticks for twenty probes
per schedule, excluding identical selector/API observations
(test process plus isolated core only, excluding the external client/host).
Stop mode terminates the external client and restarts it after twelve seconds;
the test requires rejection of the
dead path, recovery, and restoration after an isolated core restart. Install
only the fixture CA through `SSL_CERT_FILE`; never disable TLS verification.
This is a controlled deadline comparison, not proof of a production root cause
or an automatic failover/Apply test. IP-based origins do not cover DNS latency.
Fault mode uses a local TLS 1.3 camouflage endpoint rather than a public site.

`SB_TEST_REVERSE_BULK=1` additionally compares one and four concurrent HTTPS
downloads with availability checks, using `/bulk` and `/bulk/paced` on that
same owned origin. Each response is 8 MiB, streamed from a 64 KiB buffer;
paced responses pause 10 ms per block. Runs are bounded and canceled workers
are joined. Any data error, empty transfer or failed concurrent probe fails
the run; failed runs must not be averaged into a release pass. Bytes from the
deliberately canceled last transfers count toward throughput, not completed
responses or errors; requiring an entire 8 MiB per
stream inside the window would impose an arbitrary minimum aggregate speed.
Report payload throughput, test-plus-core CPU ticks per delivered MiB and
probe failures; do not equate this local transfer or application-level pacing
with public-WAN RTT, loss, queueing, upload performance, or real failover timing.
The isolated core leaves the connection buffer at its architecture default
unless buffer comparison is explicitly enabled. No shared network
qdisc is changed.

`SB_TEST_REVERSE_BUFFER_COMPARE=1` with bulk mode compares isolated core
buffers in the order 4, 128, 128, 4 KiB, restarting and restoring the real
Reverse connection before each run. It requires bulk mode without burst mode,
skips the long fault scenarios and uses one post-run path proof. Only the core
buffer changes; the external
client keeps its architecture default. Repeated opposing-order results are
needed before attributing a throughput change to buffering. This does not
measure peak memory per connection or justify a production buffer change by
itself.

The loopback-only origin is `tests/fixtures/reverse-https-origin`. Build it with
`go build ./tests/fixtures/reverse-https-origin`, then run the binary with an
owned temporary directory and the external Xray binary as arguments. The
fixture uses the project's Go toolchain and needs no Python runtime.
Supply `cert.pem` and `key.pem` in that directory (IP SAN `127.0.0.1`, valid
on both hosts); the fixture writes `origin.port`. Use
`https://127.0.0.1:PORT/probe` as the target and trust that certificate in the
test process. Copy the exchanged client configuration to the directory as
`client.json` only after allowing its exact test endpoint through lab filters.
The fixture validates and starts that client, handles its stop/restart scenario,
and terminates only its owned child on exit. It neither edits route sheets nor
opens the HTTPS origin to external clients. Keep generated keys and logs local.

Keep bug fixes, features and release metadata in separate focused commits with
descriptive subjects. Do not rewrite existing release history just to rename it.

## Public Export Boundary

Public source export retains only the current stable or numbered RC changelog
section. User conversations, attachments, incident logs, owner test reports,
private topology and hardware acceptance receipts must never enter public
history, source archives or release descriptions. Generic regression tests and
operational documentation remain public. Replacement deletes are constrained
to their resolved output root. Hardware-specific image/logging fixtures and
benchmark launchers are excluded alongside the private acceptance reports.
Inspect archive contents and the complete public
history as well as the worktree; filename/secret checks alone are insufficient.
Run `node --test tests/release-contract.test.mjs` and verify the actual exported
tree with `scripts/verify-public-tree.sh` before publication. Update an existing
public checkout without importing private local history or rewriting public history.
