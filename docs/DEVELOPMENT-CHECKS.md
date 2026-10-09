# Development Checks

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
