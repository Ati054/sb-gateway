# Shared Executable

The ARM64 container links the gateway and the complete pinned, patched Xray CLI
into one executable. `/usr/local/bin/xray` is a symlink to `sb-gateway`. Dispatch
uses the executable alias, not a shared command name: `sb-gateway api` remains
the control-plane server and `xray api` remains the core CLI.

The appliance and core still run as independent processes with separate heaps,
signals, restart supervision and existing environment settings. Nginx and the
on-demand ACME worker remain independent. Process isolation does not guarantee
survival of a container-wide OOM.

`xray-library-main.patch` exports the existing upstream entry point without
replacing its config parsing, validation, signal handling or startup cleanup.
The complete CLI is invoked only in the core process. Existing API services,
ports, runtime generation proofs and atomic image update contracts are unchanged.

## Build

Ordinary gateway Go tests use the standalone build and do not import Xray.
For the shared build, apply every Dockerfile Xray patch, including the CLI patch,
and the REALITY compatibility patch to the pinned source trees. From the project
root, run `scripts/prepare-xray-multicall.sh` with those two absolute source paths
and a new, ignored output `.mod` path. Build/test with that `-modfile` and the
`xray_multicall` build tag. The generated module files must not be committed.
Docker performs this preparation within its build stage.
Architecture-independent offline seed JSON is prepared on the build platform
and copied into the image. Cross-architecture user-mode emulation is not a
replacement for artifact checks on the target instruction set.
The build-only validation stage executes the actual ARM64 executable directly
on an ARM64 builder, or through an explicit build-platform QEMU on other hosts.
It checks both role identities, API help and upstream configuration validation.
The emulator is not shipped in the runtime image; target-system acceptance
remains required before publication.

`SB_TEST_MULTICALL_BINARY` enables `TestMulticallArtifactCLI` against a built
native executable: alias/command separation, upstream configuration flags and
environment, invalid configuration rejection, distinct process identity and
graceful shutdown. Set `SB_TEST_XRAY` to its `xray` alias to exercise real-core
selector integration tests. `TestMulticallArtifactRulesets` repeatedly prepares
and validates every offline seed using the built executable. Late-recovery
tests make the service recover after the failed batch completes rather than
depending on scheduler timing.
Mass-outage fixtures reserve core listener ports until every independent probe
endpoint is bound, and report the core startup log on readiness failure.

Selector restoration retains a confirmed saved leaf when an independent bad
probe is still below the confirmed-outage threshold. A pending failure must not
become a failover merely because Apply restarts the core. Confirmed outages,
removed members, explicit priority reorders and policy-mode changes still
invalidate restoration. Startup regressions cover both selection modes; the
opt-in real-core restart test checks the first admitted TCP connection after a
persisted pending failure. These checks do not identify a live switch reason
without the corresponding route-health event.

The active-path availability lane validates the health-pool/core-ready generation
before and after its probe, just like background and emergency lanes. Apply or
shutdown interruptions discard that probe without advancing the node's failure
streak. Real timeouts within an unchanged generation retain the normal immediate
confirmation and emergency failover behavior; no post-Apply cooldown is added.
When the core or health contract changes, a pending active-node failure streak
starts afresh and emits `probe-suppressed` with reason `runtime-changed`. A
confirmed outage remains confirmed. Tests require two genuine timeouts in one
unchanged generation to retain fast failover, and reject combining pre-restart
and post-restart failures into that confirmation.

During a planned structural runtime restart, URLTest pauses network proofs only
while the live Apply guard is valid. The guard requires a live owner, a heartbeat
no older than 90 seconds and an operation age no greater than 30 minutes.
Malformed, expired or abandoned guards do not suppress failover. Pending failure
confirmation is invalidated on resume; confirmed outages remain confirmed.
Hot route-list updates do not set this guard, so selector activation and its
acknowledgement remain live. DNS publication is also part of the proof generation:
a DNS-only restart must not turn a local resolver gap into remote-node evidence.

Structural Xray restarts still close its established connections. These health
guards prevent misclassification of planned disruption, not disruption itself.
Changing an encrypted DNS endpoint changes Xray's fixed upstream listener and
can therefore require a structural restart.

Both roles must be distributed from the same immutable image. No dynamic Go
library loader, external shared-library ABI or separately updated core executable
is introduced. Keep the `xray` alias when invoking its version/config/API commands.

## Verification Status

The implementation is a candidate until image-level verification completes.
Required checks include both CLI identities, command separation, Check/Apply and
rollback, routing/database hot updates, selector restoration, mass outages and
core-failure recovery. Component prototypes alone are not an image acceptance
test or proof of reduced full-container memory usage or absence of long-term leaks.
