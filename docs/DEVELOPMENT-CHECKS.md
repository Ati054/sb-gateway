# Development Checks

## Survey baseline coverage

Run `go test ./internal/agent -run 'TestSurvey' -count=1 -v` for the virtual-time
24-node survey and unchanged-active restart regression. It exercises the real
controller and wake schedule with parallel primary responses of one and 4.5
seconds, in URLTest and priority modes. Every reserve must acquire a close-time
comparison after the restart; shared cycle bounds, total quality requests and
rolling-minute request peaks are checked. This is a deterministic scheduling
test, not a network throughput or hardware CPU benchmark. One-slot allowance,
failed primary, shared underlay failure and pending optimization cases verify
that baseline refresh cannot create a tight retry loop or starve reserve work.

Also run `go test ./internal/agent -run 'TestSingleQualityLaneBounds|TestIncompleteNomination|TestSharedSingleSlotCompletes' -count=1 -v`.
The single-lane regression uses 24 members, a configured batch of ten, slow
successful observations and a persisted restart. It bounds each actual batch
to two sequential probes and requires refreshed Delta pairs for all reserves.
The shared-slot test preserves both equal intervals and mixed 3/30/60-second
intervals. An incomplete nomination must not consume the first valid win, while
reusing an already accepted pair must not earn the second confirmation.

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

## Probe Budget Checks

Availability-budget regressions use a primary handler that waits for cancellation
and a fallback slower than the primary budget, with scheduling headroom inside
the round deadline. Repeat these tests under the race detector; millisecond-scale
deadline margins must not turn host scheduling jitter into transport failures.
Test timing overrides do not change production probe budgets.

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

## Log Retention And Ingress Capacity

Xray's local failure hints are best-effort: their delivery test resets limiter
state between runs and allows bounded retries when a short local socket deadline
expires under build load. Immediate duplicate suppression and the absence of
probe-generated hints must still be checked without delivery retries. Runtime
hint deadlines and independent HTTPS confirmation remain unchanged.

`go test ./internal/diagnosticlog ./internal/controlplane ./internal/runtimeconfig`
covers append-inode preservation, bounded legacy/current archives, interrupted
reopen recovery, missing files, cancellation and link rejection. Repeat focused
rotation and startup tests under `-race`. Rotation errors must preserve the
original log and must not request a runtime restart.
The live renamed-descriptor recovery test requires Linux and is skipped on
Windows, whose open-file rename semantics differ. Append, archive bounds and
link-rejection tests remain portable; exercise real Nginx reopen on Linux.

Saved schema-2/3 configurations receive capacity minima on image startup.
Test comments, whitespace, quoted directive lookalikes, absent defaults,
larger custom values and repeated startup. External main/events includes and
ambiguous directives must produce a warning without a partial rewrite.

Run in an isolated Linux container with Nginx plus stream and a file-descriptor
limit of at least 16384:

```sh
SB_SHARED_LIVE_NGINX=1 go test ./internal/runtimeconfig -run TestNginxCapacityAndLogReopenLive -v
```

The test reproduces the old 1024-slot ceiling, holds 512 simultaneous real
stream/TLS/Upgrade connections using the migrated configuration, then verifies
echo data survives Nginx log rotation, the master PID is unchanged, new errors
reach reopened logs and retained archives stay bounded. This verifies proxy
capacity, not 512 real users or capacity of every target router under sustained
VLESS traffic.

## Saved Nginx Streaming Limits

Startup migrates canonical gRPC/XHTTP locations, then audits saved inline
directives independently of whitespace, comments and directive order. Missing
unlimited request bodies or a body timeout below 300 seconds produce a warning
without preventing startup or rewriting a noncanonical transport location.
The audit observes inline scope inheritance; it does not expand external
includes or replace `nginx -t`. Warning text must not disclose paths or secrets.
Run the following and repeat under `-race`; lexer seeds also run as ordinary
tests. Check malformed input, quoted delimiters, sibling isolation, both schemas
and idempotent canonical migration.

```sh
go test ./internal/runtimeconfig ./internal/controlplane -run 'Test.*(Streaming|StartupNginx)'
```

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
- Analysis tools use the pinned `golang.org/x/tools` v0.51.0 importer for Go 1.27.x export-format compatibility. Install them with `sh scripts/install-analysis-tools.sh "$(go env GOPATH)/bin"`; this does not change runtime dependencies.
- `CGO_ENABLED=1 go test -race ./... -count=1 -timeout=15m`;
- govulncheck v1.8.0, `govulncheck ./...`.

Its Go version matches the gateway build toolchain pinned in `Dockerfile`;
update both pins and the laboratory packaging image together. All three use
Go 1.27.3; earlier Go 1.27.1 and 1.26.4 images have known standard-library
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

`health_timeout_retention_test.go` exercises permitted VLESS retention after
confirmed HTTPS timeouts in both priority and URLTest modes, without promoting
failed health or changing service permissions. It also checks fresh-reserve
failover, live Reverse session revalidation, membership removal, explicit
network/TLS failures and rejection of non-VLESS exits. A retained route is not
evidence that the remote transport or the surrounding network is healthy.
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

## Pinned Core Upgrade

The server source pins upstream Xray v26.10.29 at
`0afec66085a85191e9dd2a4a6646c7c9a94688d1`, with REALITY
`83f621788ca88b83179810b12baa7ae518aacb83` and Go 1.27.3.
Promotion still requires renderer, Reverse and external data-plane acceptance;
a source pin change does not certify an image. The build asserts both the
upstream and multicall-selected `x509roots/fallback` version
`v0.0.0-20261020153306-9f2b28d4331a` and the final executable's Go toolchain.
See [upstream's trust-store update](https://github.com/XTLS/Xray-core/pull/7212)
and [Go 1.27.3](https://go.dev/doc/devel/release#go1.27.3).
Exported Reverse bridge versions remain independently pinned.

The v26.10.29 upgrade also changes asset/Lua path helpers, GeoData update
validation and inbound module initialization order. Verify the generated
external GeoIP/GeoSite references with `XRAY_LOCATION_ASSET=/config/rulesets`,
API routing updates, WebSocket normal closure and cold-start traffic admission.
Keep the private comparison and image acceptance pending until the new core
has completed them; earlier-core measurements are only a baseline.

The v26.10.17 rebase preserves upstream Hysteria write/close cancellation and
adds retirement callbacks without replacing its new per-stream locks. The VLESS
failure hint patch follows the new import layout; Vision's Go 1.27.3+ changes
remain intact. Build toolchains are pinned independently. Patch application,
renderer validation and transport lifetime tests must pass before promotion.
The multicall library patch also moves upstream's CLI tests into `maincmd`;
new upstream test files must retain the same package as the importable CLI and
invoke `Main`. The core build runs the upstream CLI configuration-command tests
as well as the gateway multicall-dispatch checks.

The upstream gRPC dialer now uses the shared channel's reconnect context, not
the first stream's context. `xray-grpc-context-regression.patch` adds tests only:
single and multi streams must work after a canceled first request and after a
server disconnect/restart with the same cached channel. Run these tests with
the retirement tests under the race detector. The Hysteria retirement patch
preserves upstream instance shutdown cleanup and permanently closes each retired
client only after its acquired streams finish. Nginx body limits apply to inbound
transports; they do not explain an outbound subscription's throughput.

The snapshot also honors Hysteria request cancellation and cleans up clients
outside the manager's shared lock. The local retirement tests use its cancellable
per-client lock rather than reintroducing a mutex. Changes to REALITY use the
corresponding pinned dependency and preserve the narrow X25519 compatibility
patch. TUN, Lua and MASQUE remain disabled unless explicitly configured; updating
their implementation does not enable them in generated gateway rules.

## URLTest Comparison

See [URLTest measurement](URLTEST-MEASUREMENT.md) for upstream measurement
boundaries and the cold/warm, idle/load comparison gate. This is an investigation
procedure, not a change to the configured switch threshold or failure deadline.

Emergency ranking regressions must include a fast latest primary request whose
older short median is worse, and recovery streaks below the planned threshold.
The current availability probe still has to succeed; a failed preferred reserve
must release the next confirmed path. Keep stale/future observation times,
fallback-only successes, priority ordering, bounded waiting, generation changes
and cancellation covered. Check that `reserve_selection` diagnostics distinguish
unfinished probes from failures, contain no endpoint data and are absent from
persisted health history. These tests do not establish why a particular external
server or production connection timed out.
Exercise the fallback selector and blocked recovery too, with stale availability
flags and a current failed response. A full controller tick must preserve the
primary observation and its timestamp after successful availability-only checks
both with and without a returned latency, at batch sizes one and three. An
unknown primary latency must not gain a ranking from another origin's response.

## Public Export Boundary

Public source export retains the reviewed user-facing changelog history and only
the current release-notes document. User conversations, attachments, incident logs, owner test reports,
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
