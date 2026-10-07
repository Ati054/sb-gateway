package routeros

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// RenderOfflineImageRecovery reuses the image worker without a running panel.
// The operator stops the broken container first. Persistent directories are
// not copied or removed. A failed candidate keeps the predecessor stopped.
func RenderOfflineImageRecovery(spec ImageUpdateSpec, archiveSize int64, identity string) (string, error) {
	spec, err := validateImageUpdateSpec(spec)
	if err != nil {
		return "", err
	}
	if spec.CandidateSource != "local-file" || archiveSize <= 0 || archiveSize > 2<<30 {
		return "", errors.New("offline recovery requires a bounded local archive")
	}
	if !regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,63}$`).MatchString(identity) {
		return "", errors.New("offline recovery router identity is invalid")
	}
	spec.KeepPrevious, spec.StoppedPredecessor = true, true
	worker := renderImageUpdateWorker(spec)
	if !validFixedManagedScript(imageUpdateWorker, worker) {
		return "", errors.New("offline recovery worker is invalid")
	}
	quote := func(value string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\n", `\n`).Replace(value) + `"`
	}
	rootPrefix := "/" + spec.StorageRoot + "/root-"
	lines := []string{
		"# SB-GATEWAY offline image recovery; persistent directories are preserved.",
		"{",
		`:if ([/system/identity/get name] != ` + quote(identity) + `) do={ :error "SB-GATEWAY recovery router identity mismatch" }`,
		`:local current [/container/find where comment="SB-GATEWAY container"]`,
		`:if ([:len $current] != 1) do={ :error "SB-GATEWAY recovery current container is ambiguous" }`,
		`:if ([/container/get $current stopped] != true) do={ :error "SB-GATEWAY stop the broken container before recovery" }`,
		`:if (([:len [/container/get $current mountlists]] = 0) || ([:len [/container/get $current envlist]] = 0)) do={ :error "SB-GATEWAY recovery persistent settings are missing" }`,
		`:local currentRoot [/container/get $current root-dir]`,
		`:if (([:pick $currentRoot 0 ` + fmt.Sprint(len(rootPrefix)) + `] != ` + quote(rootPrefix) + `) && ($currentRoot != ` + quote("/"+spec.StorageRoot+"/root") + `)) do={ :error "SB-GATEWAY recovery root does not match current container" }`,
		`:if ([:typeof [:find $currentRoot "/" ` + fmt.Sprint(len(rootPrefix)) + `]] = "num") do={ :error "SB-GATEWAY recovery current root is nested" }`,
		`:if ($currentRoot = ` + quote("/"+spec.CandidateRoot) + `) do={ :error "SB-GATEWAY recovery requires a different image version" }`,
		`:local liveIf [/interface/veth/find where name=[/container/get $current interface]]`,
		`:if ([:len $liveIf] != 1) do={ :error "SB-GATEWAY recovery live veth is ambiguous" }`,
		`:if ([:pick [:tostr [/interface/veth/get $liveIf address]] 0 ` + fmt.Sprint(len(spec.ContainerAddress)+1) + `] != ` + quote(spec.ContainerAddress+"/") + `) do={ :error "SB-GATEWAY recovery container address mismatch" }`,
		`:if (([:len [/system/scheduler/find where name="SB-GATEWAY-image-update"]] > 0) || ([:len [/system/script/job/find where script="SB-GATEWAY-image-update-worker"]] > 0) || ([:len [/system/scheduler/find where name~"^SB-GATEWAY-safe-rollback-"]] > 0) || ([:len [/system/script/job/find where script~"^SB-GATEWAY-(apply|rollback)-"]] > 0)) do={ :error "SB-GATEWAY recovery conflicts with an active transaction" }`,
		`:if (([:len [/container/find where comment="SB-GATEWAY container candidate"]] > 0) || ([:len [/container/find where comment="SB-GATEWAY container rollback"]] > 0) || ([:len [/interface/veth/find where name="veth-sb-update"]] > 0) || ([:len [/interface/veth/find where name="veth-sb-swap"]] > 0)) do={ :error "SB-GATEWAY recovery conflicts with an unfinished image update" }`,
		`:if (([:len [/system/script/find where name="SB-GATEWAY-image-update-transfer"]] > 0) || ([:len [/container/find where comment="SB-GATEWAY container failed"]] > 0)) do={ :error "SB-GATEWAY recovery conflicts with image transfer metadata" }`,
		`:if (([:len [/file/find where name=` + quote(spec.CandidateRoot) + `]] > 0) || ([:len [/file/find where name=` + quote("/"+spec.CandidateRoot) + `]] > 0)) do={ :error "SB-GATEWAY recovery candidate root already exists" }`,
		`:local archive [/file/find where name=` + quote(spec.CandidateReference) + `]`,
		`:if ([:len $archive] != 1) do={ :error "SB-GATEWAY recovery archive is missing or ambiguous" }`,
		`:if ([/file/get $archive size] != ` + fmt.Sprint(archiveSize) + `) do={ :error "SB-GATEWAY recovery archive size mismatch" }`,
		`:local script [/system/script/find where name="SB-GATEWAY-image-update-worker"]`,
		`:if ([:len $script] > 1) do={ :error "SB-GATEWAY recovery worker is ambiguous" }`,
		`:if ([:len $script] = 1) do={ :if ([/system/script/get $script comment] != "SB-GATEWAY managed script SB-GATEWAY-image-update-worker") do={ :error "SB-GATEWAY recovery worker is not owned" } }`,
		`:local gate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]`,
		`:if ([:len $gate] > 1) do={ :error "SB-GATEWAY recovery diversion gate is ambiguous" }`,
		`:local workerSource ` + quote(worker),
		`:if ([:len $script] = 0) do={ /system/script/add name="SB-GATEWAY-image-update-worker" policy=read,write,test,policy comment="SB-GATEWAY managed script SB-GATEWAY-image-update-worker" source=$workerSource } else={ /system/script/set $script source=$workerSource }`,
		`:if ([:len $gate] = 1) do={ /ip/firewall/mangle/disable $gate }`,
		`/container/set $current start-on-boot=no`,
		`:do { /container/set $current restart-policy=no } on-error={ /container/set $current auto-restart-interval=0s }`,
		`/system/scheduler/add name="SB-GATEWAY-image-update" interval=5s on-event="/system/script/run SB-GATEWAY-image-update-worker" policy=read,write,test,policy comment="SB-GATEWAY autonomous image update" disabled=no`,
		`:put "SB-GATEWAY offline recovery scheduled; inspect container health and image-update log"`,
		"}",
	}
	return strings.Join(lines, "\n") + "\n", nil
}
