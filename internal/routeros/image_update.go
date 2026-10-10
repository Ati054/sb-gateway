package routeros

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	routerosassets "github.com/sb-gateway/sb-gateway/routeros"
)

const (
	imageUpdateWorker    = "SB-GATEWAY-image-update-worker"
	imageUpdateScheduler = "SB-GATEWAY-image-update"
	imageUpdateTransfer  = "SB-GATEWAY-image-update-transfer"
)

var (
	imageVersionPattern  = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$`)
	localImagePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{3,220}\.tar$`)
	registryImagePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/:+-]{2,220}@sha256:[a-f0-9]{64}$`)
)

type ImageUpdateSpec struct {
	Version            string
	StorageRoot        string
	CandidateRoot      string
	CandidateSource    string
	CandidateReference string
	ContainerAddress   string
	KeepPrevious       bool
	// Offline recovery must not restart an already broken predecessor.
	StoppedPredecessor bool
}

// SetContainerMemoryLimits changes the limits of one already-owned container.
// RouterOS 7.24.2 restarts a running container on this change. Callers must
// validate ownership and must not use this from read-only status reconciliation.
func (client *Client) SetContainerMemoryLimits(ctx context.Context, id string, memoryHigh, memoryMax int64) error {
	if !regexp.MustCompile(`^\*[0-9A-Fa-f]+$`).MatchString(id) {
		return errors.New("RouterOS container identifier is invalid")
	}
	if memoryHigh < 16<<20 || memoryMax < memoryHigh || memoryMax > 8<<30 {
		return errors.New("RouterOS container memory limits are invalid")
	}
	_, err := client.request(ctx, http.MethodPatch, "/rest/container/"+routerOSResourceID(id), map[string]any{
		"memory-high": memoryHigh,
		"memory-max":  memoryMax,
	})
	return err
}

// ScheduleImageUpdate installs an idempotent RouterOS-owned state machine and
// only then arms its scheduler. Extraction, health probation and rollback keep
// running even while the container control plane is unavailable.
func (client *Client) ScheduleImageUpdate(ctx context.Context, spec ImageUpdateSpec) (map[string]any, error) {
	validated, err := validateImageUpdateSpec(spec)
	if err != nil {
		return nil, err
	}
	if _, err := client.installFixedManagedScript(ctx, imageUpdateWorker, renderImageUpdateWorker(validated)); err != nil {
		return nil, err
	}
	const comment = "SB-GATEWAY autonomous image update"
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment")
	if err != nil {
		return nil, err
	}
	var existingID string
	for _, row := range rows {
		if text(row["name"]) != imageUpdateScheduler {
			continue
		}
		if existingID != "" {
			return nil, errors.New("image update scheduler is ambiguous")
		}
		if text(row["comment"]) != comment {
			return nil, errors.New("refusing to replace an unowned image update scheduler")
		}
		existingID = text(row[".id"])
		if existingID == "" {
			return nil, errors.New("image update scheduler identifier is unavailable")
		}
	}
	if existingID != "" {
		if _, err := client.request(ctx, http.MethodDelete, "/rest/system/scheduler/"+routerOSResourceID(existingID), nil); err != nil {
			return nil, err
		}
	}
	if _, err := client.request(ctx, http.MethodPut, "/rest/system/scheduler", map[string]any{
		"name": imageUpdateScheduler, "interval": "5s", "on-event": "/system/script/run " + imageUpdateWorker,
		"policy": "read,write,test,policy", "comment": comment, "disabled": "false",
	}); err != nil {
		return nil, err
	}
	return map[string]any{"scheduled": true, "delay_seconds": 10, "scheduler": imageUpdateScheduler}, nil
}

func validateImageUpdateSpec(spec ImageUpdateSpec) (ImageUpdateSpec, error) {
	spec.Version = strings.TrimSpace(spec.Version)
	root, err := validateLifecycleStorageRoot(spec.StorageRoot)
	if err != nil {
		return ImageUpdateSpec{}, err
	}
	spec.StorageRoot = root
	spec.CandidateRoot = strings.Trim(strings.TrimSpace(spec.CandidateRoot), "/")
	wantRoot := root + "/root-" + spec.Version
	if !imageVersionPattern.MatchString(spec.Version) || spec.CandidateRoot != wantRoot {
		return ImageUpdateSpec{}, errors.New("image update version or candidate root is invalid")
	}
	spec.CandidateReference = strings.TrimSpace(spec.CandidateReference)
	switch spec.CandidateSource {
	case "local-file":
		if !localImagePattern.MatchString(spec.CandidateReference) || !strings.HasPrefix(spec.CandidateReference, root+"/data/lifecycle-uploads/") {
			return ImageUpdateSpec{}, errors.New("local image reference is outside the managed upload directory")
		}
	case "registry":
		if !registryImagePattern.MatchString(spec.CandidateReference) {
			return ImageUpdateSpec{}, errors.New("registry image reference must use an immutable sha256 digest")
		}
	default:
		return ImageUpdateSpec{}, errors.New("image update source is invalid")
	}
	ip := net.ParseIP(strings.TrimSpace(spec.ContainerAddress))
	if ip == nil || ip.To4() == nil {
		return ImageUpdateSpec{}, errors.New("container health address must be IPv4")
	}
	spec.ContainerAddress = ip.String()
	return spec, nil
}

func renderImageUpdateWorker(spec ImageUpdateSpec) string {
	quote := func(value string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\n", `\n`).Replace(value) + `"`
	}
	// Re-arm cleanup, never initial extraction, if the job dies between deleting
	// terminal metadata and deleting its scheduler.
	terminalEvent := `:local t [/system/script/find where name="` + imageUpdateTransfer + `"]; :if ([:len $t] > 1) do={ :error "SB-GATEWAY terminal transfer is ambiguous" }; :if ([:len $t] = 1) do={ :if ([/system/script/get $t comment] != "SB-GATEWAY image transfer metadata") do={ :error "SB-GATEWAY terminal transfer is not owned" }; :local r [:deserialize from=json value=[/system/script/get $t source]]; :if ((($r->"phase") != "restored") || (($r->"candidate-root") != "/` + spec.CandidateRoot + `") || (($r->"reference") != "` + spec.CandidateReference + `")) do={ :error "SB-GATEWAY terminal transfer does not match" }; /system/script/remove $t }; /system/scheduler/remove [find where name="` + imageUpdateScheduler + `" and comment="SB-GATEWAY autonomous image update"]`
	startPrevious := func(id string) string {
		if spec.StoppedPredecessor {
			return `/container/set ` + id + ` start-on-boot=no; :do { /container/set ` + id + ` restart-policy=no } on-error={ /container/set ` + id + ` auto-restart-interval=0s }`
		}
		return `/container/set ` + id + ` start-on-boot=no; :if ([$storageReady ` + id + `] != true) do={ :error "SB-GATEWAY rollback storage is not ready" }; /container/start ` + id
	}
	retainPrevious := "false"
	startupDisabled := "false"
	if spec.StoppedPredecessor {
		startupDisabled = "true"
	}
	if spec.KeepPrevious {
		retainPrevious = "true"
	}
	addImage := `file="` + spec.CandidateReference + `"`
	cleanupArchive := `/file/remove [find where name="` + spec.CandidateReference + `"]`
	if spec.CandidateSource == "registry" {
		addImage = `remote-image="` + spec.CandidateReference + `"`
		cleanupArchive = ""
	}
	// A stale retained copy must never prevent emergency restoration of the
	// current transaction. Validate it only before a new update or commit cleanup.
	previousGuard := strings.Join([]string{
		`:if ([:len $previous] > 1) do={ :error "SB-GATEWAY previous image is ambiguous" }`,
		`:if ([:len $previousIf] > 0) do={ :if (([:len $previousIf] != 1) || ([/interface/veth/get $previousIf comment] != "SB-GATEWAY previous image hold")) do={ :error "SB-GATEWAY previous image interface is not owned" } }`,
		`:if ([:len $previous] = 1) do={`,
		`  :local previousRoot [/container/get $previous root-dir]`,
		`  :if (([:pick $previousRoot 0 ` + fmt.Sprint(len("/"+spec.StorageRoot+"/root-")) + `] != "/` + spec.StorageRoot + `/root-") && ($previousRoot != "/` + spec.StorageRoot + `/root")) do={ :error "SB-GATEWAY previous image root is not owned" }`,
		`  :if ([:typeof [:find $previousRoot "/" ` + fmt.Sprint(len("/"+spec.StorageRoot+"/root-")) + `]] = "num") do={ :error "SB-GATEWAY previous image root is nested" }`,
		`  :if ($previousRoot = "/` + spec.CandidateRoot + `") do={ :error "SB-GATEWAY candidate version is retained as previous image" }`,
		`  :if ([/container/get $previous stopped] != true) do={ :error "SB-GATEWAY previous image is not stopped" }`,
		`  :if ([:len $current] = 1) do={ :if ($previousRoot = [/container/get $current root-dir]) do={ :error "SB-GATEWAY previous image aliases current root" } }`,
		`  :foreach other in=[/container/find] do={ :if (($other != $previous) && ([/container/get $other root-dir] = $previousRoot)) do={ :error "SB-GATEWAY previous image root is shared" } }`,
		`}`,
	}, "\n")
	lines := []string{
		"# SB-GATEWAY autonomous one-image switch",
		`:local jobs [/system/script/job/find where script="` + imageUpdateWorker + `"]`,
		`:if ([:len [/system/script/job/find where script="SB-GATEWAY-container-startup"]] > 0) do={ :return true }`,
		`:if ([:len $jobs] > 1) do={ :return true }`,
		`:local current [/container/find where comment="SB-GATEWAY container"]`,
		`:local candidate [/container/find where comment="SB-GATEWAY container candidate"]`,
		`:local rollback [/container/find where comment="SB-GATEWAY container rollback"]`,
		`:local failed [/container/find where comment="SB-GATEWAY container failed"]`,
		`:local previous [/container/find where comment="SB-GATEWAY container previous"]`,
		`:local previousIf [/interface/veth/find where name="veth-sb-previous"]`,
		`:local retainPrevious ` + retainPrevious,
		`:local scheduler [/system/scheduler/find where name="` + imageUpdateScheduler + `"]`,
		`:local hold [/interface/veth/find where comment="SB-GATEWAY image update hold"]`,
		`:local swap [/interface/veth/find where comment="SB-GATEWAY image update swap"]`,
		`:local candidateRoot "/` + spec.CandidateRoot + `"`,
		`:local transfer [/system/script/find where name="` + imageUpdateTransfer + `"]`,
		`:local receipt`,
		`:local phase ""`,
		`:local healthURL "http://` + spec.ContainerAddress + `:9080/healthz"`,
		`:local trafficURL "http://` + spec.ContainerAddress + `:9080/traffic-ready"`,
		`:global sbGatewayImageProbation`,
		`:global sbGatewayImageMisses`,
		`:if (([:len $current] > 1) || ([:len $candidate] > 1) || ([:len $rollback] > 1) || ([:len $scheduler] > 1) || ([:len $hold] > 1) || ([:len $swap] > 1)) do={ :error "SB-GATEWAY image update state is ambiguous" }`,
		`:if (([:len $failed] > 1) || ([:len $transfer] > 1)) do={ :error "SB-GATEWAY image transfer state is ambiguous" }`,
		`:if ([:len $hold] = 1) do={ :if ([/interface/veth/get $hold name] != "veth-sb-update") do={ :error "SB-GATEWAY hold interface does not match" } }`,
		`:if ([:len $swap] = 1) do={ :if ([/interface/veth/get $swap name] != "veth-sb-swap") do={ :error "SB-GATEWAY swap interface does not match" } }`,
		`:local startupProbe [/system/script/find where name="SB-GATEWAY-storage-ready"]`,
		`:local startupBoot [/system/script/find where name="SB-GATEWAY-container-startup"]`,
		`:local startupSchedule [/system/scheduler/find where name="SB-GATEWAY-container-startup"]`,
		`:local installStartup true`,
		`:if (([:len $startupProbe] = 1) && ([:len $startupBoot] = 1) && ([:len $startupSchedule] = 1)) do={`,
		`  :if (([/system/script/get $startupProbe comment] = "SB-GATEWAY storage readiness") && ([/system/script/get $startupBoot comment] = "SB-GATEWAY storage-aware startup") && ([/system/scheduler/get $startupSchedule comment] = "SB-GATEWAY storage-aware startup scheduler") && ([/system/script/get $startupProbe source] = ` + quote(routerosassets.ContainerStorageReadySource()) + `) && ([/system/script/get $startupBoot source] = ` + quote(routerosassets.ContainerBootSource()) + `) && ([/system/scheduler/get $startupSchedule interval] = 0s) && ([/system/scheduler/get $startupSchedule start-time] = "startup") && ([/system/scheduler/get $startupSchedule on-event] = "/system/script/run SB-GATEWAY-container-startup")) do={ :set installStartup false }`,
		`}`,
		`:if ($installStartup = true) do={ :local setup [:parse ` + quote(routerosassets.ContainerStartupInstallSource()) + `]; $setup ` + startupDisabled + ` }`,
		`:if (` + startupDisabled + ` = true) do={ /system/scheduler/disable [find where name="SB-GATEWAY-container-startup" and comment="SB-GATEWAY storage-aware startup scheduler"] }`,
		`:local storageReady [:parse [/system/script/get [find where name="SB-GATEWAY-storage-ready" and comment="SB-GATEWAY storage readiness"] source]]`,
		// The inert JSON receipt survives interrupted detach/attach and role swaps.
		// An interrupted forward transfer restores the predecessor rather than
		// guessing whether the candidate was started before the job disappeared.
		`:if ([:len $transfer] = 1) do={`,
		`  :if ([/system/script/get $transfer comment] != "SB-GATEWAY image transfer metadata") do={ :error "SB-GATEWAY image transfer metadata is not owned" }`,
		`  :set receipt [:deserialize from=json value=[/system/script/get $transfer source]]`,
		`  :set phase ($receipt->"phase")`,
		`  :if (([:typeof $receipt] != "array") || (($receipt->"candidate-root") != $candidateRoot) || (($receipt->"reference") != "` + spec.CandidateReference + `") || (($phase != "transfer") && ($phase != "probation") && ($phase != "commit") && ($phase != "rollback") && ($phase != "restored"))) do={ :error "SB-GATEWAY image transfer metadata does not match" }`,
		`  :local oldRoot ($receipt->"previous-root")`,
		`  :if (([:typeof $oldRoot] != "str") || ($oldRoot = $candidateRoot) || (([:pick $oldRoot 0 ` + fmt.Sprint(len("/"+spec.StorageRoot+"/root-")) + `] != "/` + spec.StorageRoot + `/root-") && ($oldRoot != "/` + spec.StorageRoot + `/root"))) do={ :error "SB-GATEWAY image transfer previous root is invalid" }`,
		`  :if ([:typeof [:find $oldRoot "/" ` + fmt.Sprint(len("/"+spec.StorageRoot+"/root-")) + `]] = "num") do={ :error "SB-GATEWAY image transfer previous root is nested" }`,
		`  :local savedMountlists ($receipt->"mountlists")`,
		`  :local savedIf ($receipt->"live-if")`,
		`  :if ([:typeof $savedIf] = "array") do={ :if ([:len $savedIf] != 1) do={ :error "SB-GATEWAY image transfer live interface is ambiguous" }; :foreach value in=$savedIf do={ :set savedIf $value } }`,
		`  :if (([:typeof $savedMountlists] != "array") || ([:len $savedMountlists] = 0) || ([:typeof $savedIf] != "str") || ([:typeof ($receipt->"previous-start-on-boot")] != "bool")) do={ :error "SB-GATEWAY image transfer persistent settings are invalid" }`,
		`  :foreach list in=$savedMountlists do={ :if (([:typeof $list] != "str") || ([:len $list] = 0) || ([:len [/container/mounts/find where list=$list]] = 0)) do={ :error "SB-GATEWAY image transfer mountlist is missing" } }`,
		`  :local savedVeth [/interface/veth/find where name=$savedIf]`,
		`  :if ([:len $savedVeth] != 1) do={ :error "SB-GATEWAY image transfer live interface is missing" }`,
		`  :if ([:pick [:tostr [/interface/veth/get $savedVeth address]] 0 ` + fmt.Sprint(len(spec.ContainerAddress)+1) + `] != "` + spec.ContainerAddress + `/") do={ :error "SB-GATEWAY image transfer live address does not match" }`,
		`  :local old [/container/find where root-dir=$oldRoot]`,
		`  :local next [/container/find where root-dir=$candidateRoot]`,
		`  :if (([:len $old] > 1) || ([:len $next] > 1) || (([:len $old] = 0) && ($phase != "commit")) || (([:len $next] = 0) && ($phase != "rollback") && ($phase != "restored"))) do={ :error "SB-GATEWAY image transfer roots are ambiguous" }`,
		`  :foreach item in=$old do={ :local role [/container/get $item comment]; :if (($role != "SB-GATEWAY container") && ($role != "SB-GATEWAY container rollback") && ($role != "SB-GATEWAY container previous")) do={ :error "SB-GATEWAY image transfer predecessor is not owned" } }`,
		`  :foreach item in=$next do={ :local role [/container/get $item comment]; :if (($role != "SB-GATEWAY container") && ($role != "SB-GATEWAY container candidate") && ($role != "SB-GATEWAY container failed")) do={ :error "SB-GATEWAY image transfer candidate is not owned" } }`,
		`  :foreach item in=[/container/find] do={ :if (($item != $old) && ($item != $next)) do={ :if ([/container/get $item interface] = $savedIf) do={ :error "SB-GATEWAY image transfer live interface is shared" }; :local role [/container/get $item comment]; :if (($role = "SB-GATEWAY container") || ($role = "SB-GATEWAY container candidate") || ($role = "SB-GATEWAY container rollback") || ($role = "SB-GATEWAY container failed")) do={ :error "SB-GATEWAY image transfer role belongs to another root" } } }`,
		`  :if (($phase = "transfer") || ($phase = "rollback") || ($phase = "restored")) do={`,
		`    :if ($phase = "restored") do={ :if (([:len $next] != 0) || ([/container/get $old comment] != "SB-GATEWAY container") || ([/container/get $old interface] != $savedIf) || ([:serialize to=json value=[/container/get $old mountlists]] != [:serialize to=json value=$savedMountlists])) do={ :error "SB-GATEWAY terminal restored state does not match" } }`,
		`    :if ($phase != "restored") do={`,
		`    :set ($receipt->"phase") "rollback"`,
		`    /system/script/set $transfer source=[:serialize to=json value=$receipt]`,
		`    :local recoveryGate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]`,
		`    :if ([:len $recoveryGate] > 1) do={ :error "SB-GATEWAY recovery diversion gate is ambiguous" }`,
		`    :if ([:len $recoveryGate] = 1) do={ /ip/firewall/mangle/disable $recoveryGate }`,
		`    :foreach item in=$next do={ :do { /container/set $item restart-policy=no } on-error={ /container/set $item auto-restart-interval=0s }; /container/set $item start-on-boot=no }`,
		`    :foreach item in=$old do={ :do { /container/stop $item } on-error={} }`,
		`    :foreach item in=$next do={ :do { /container/stop $item } on-error={} }`,
		`    :local stopTry 0`,
		`    :local stopped false`,
		`    :while (($stopped = false) && ($stopTry < 60)) do={`,
		`      :set stopped true`,
		`      :foreach item in=$old do={ :if ([/container/get $item stopped] != true) do={ :set stopped false } }`,
		`      :foreach item in=$next do={ :if ([/container/get $item stopped] != true) do={ :set stopped false } }`,
		`      :if ($stopped = false) do={ :set stopTry ($stopTry + 1); :delay 2s }`,
		`    }`,
		`    :if ($stopped = false) do={ :error "SB-GATEWAY image transfer containers did not stop" }`,
		`    :foreach item in=$next do={ /container/set $item mountlists=""; /container/remove $item }`,
		`    :set rollback $old`,
		`    /container/set $rollback mountlists=$savedMountlists`,
		`    /container/set $rollback interface=$savedIf comment="SB-GATEWAY container"`,
		`    ` + startPrevious("$rollback"),
		`    }`,
		`    :if ([:len $swap] = 1) do={ /interface/veth/remove $swap }`,
		`    :if ([:len $hold] = 1) do={ /interface/veth/remove $hold }`,
		`    :set ($receipt->"phase") "restored"`,
		`    /system/script/set $transfer source=[:serialize to=json value=$receipt]`,
		`    :if ([:len $scheduler] = 1) do={ /system/scheduler/set $scheduler on-event=` + quote(terminalEvent) + ` }`,
		`    /system/script/remove $transfer`,
		`    :if ([:len $scheduler] = 1) do={ /system/scheduler/remove $scheduler }`,
		`    :set sbGatewayImageProbation`,
		`    :set sbGatewayImageMisses`,
		`    :log warning "SB-GATEWAY: image transfer restored predecessor; persistent mounts restored"`,
		`    :return true`,
		`  }`,
		`}`,
		`:if ([:len $failed] > 0) do={ :error "SB-GATEWAY failed image has no recoverable transfer metadata" }`,

		// Completed cleanup: the candidate already owns the canonical role.
		`:if (([:len $current] = 1) && ([:len $candidate] = 0) && ([:len $rollback] = 0)) do={`,
		`  :if ([/container/get $current root-dir] = $candidateRoot) do={`,
		`    /system/scheduler/enable [find where name="SB-GATEWAY-container-startup" and comment="SB-GATEWAY storage-aware startup scheduler"]`,
		`    :if ([:len $hold] = 1) do={ /interface/veth/remove $hold }`,
		`    :if ([:len $swap] = 1) do={ /interface/veth/remove $swap }`,
		`    :if ([:len $transfer] = 1) do={ /system/script/remove $transfer }`,
		`    :if ([:len $scheduler] = 1) do={ /system/scheduler/remove $scheduler }`,
		`    :return true`,
		`  }`,
		`}`,

		// Interrupted before role swap: discard only the exact candidate.
		`:if (([:len $current] = 1) && ([:len $candidate] = 1) && ([:len $rollback] = 0)) do={`,
		`  :local recoveryMountlists [/container/get $current mountlists]`,
		`  :if ([:len $recoveryMountlists] = 0) do={ :set recoveryMountlists [/container/get $candidate mountlists] }`,
		`  :do { /container/stop $candidate } on-error={}`,
		`  :local candidateStopped false`,
		`  :local stopTry 0`,
		`  :while (($candidateStopped = false) && ($stopTry < 30)) do={`,
		`    :do { :if ([/container/get $candidate running] = false) do={ :set candidateStopped true } } on-error={}`,
		`    :do { :if ([/container/get $candidate status] = "stopped") do={ :set candidateStopped true } } on-error={}`,
		`    :do { :if ([/container/get $candidate stopped] = true) do={ :set candidateStopped true } } on-error={}`,
		`    :if ($candidateStopped = false) do={ :set stopTry ($stopTry + 1); :delay 2s }`,
		`  }`,
		`  :if ($candidateStopped = false) do={ :error "SB-GATEWAY interrupted candidate did not stop" }`,
		`  /container/set $candidate mountlists=""`,
		`  :if (([:len [/container/get $current mountlists]] = 0) && ([:len $recoveryMountlists] > 0)) do={ /container/set $current mountlists=$recoveryMountlists }`,
		`  /container/remove $candidate`,
		`  :if ([:len $hold] = 1) do={ /interface/veth/remove $hold }`,
		`  :if ([:len $swap] = 1) do={ /interface/veth/remove $swap }`,
		`  :do { :if ([/container/get $current stopped] = true) do={ ` + startPrevious("$current") + ` } } on-error={}`,
		`  :if ([:len $scheduler] = 1) do={ /system/scheduler/remove $scheduler }`,
		`  :log warning "SB-GATEWAY: interrupted image extraction was cleaned up"`,
		`  :return true`,
		`}`,

		// Probation: three consecutive healthy scheduler passes commit; any
		// container restart or sixty misses restore the old image. Large GeoIP
		// configs can need a longer cold Xray start on single-core RouterOS.
		`:if (([:len $current] = 1) && ([:len $candidate] = 0) && ([:len $rollback] = 1)) do={`,
		`  :local healthy false`,
		`  :do { :local probe ([/tool/fetch url=$healthURL output=user as-value]->"data"); :if ([:typeof [:find $probe "\"ready\":true"]] = "num") do={ :set healthy true } } on-error={}`,
		`  :local trafficReady false`,
		`  :do { :local trafficProbe ([/tool/fetch url=$trafficURL output=user as-value]->"data"); :if ([:typeof [:find $trafficProbe "\"traffic_ready\":true"]] = "num") do={ :set trafficReady true } } on-error={}`,
		`  :local probationGate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]`,
		`  :if ([:len $probationGate] = 1) do={ :if ($trafficReady = true) do={ /ip/firewall/mangle/enable $probationGate } else={ /ip/firewall/mangle/disable $probationGate } }`,
		`  :local restartCount 0`,
		`  :do { :set restartCount [/container/get $current restart-count] } on-error={}`,
		`  :if ([:typeof $sbGatewayImageProbation] = "nil") do={ :set sbGatewayImageProbation 0 }`,
		`  :if ([:typeof $sbGatewayImageMisses] = "nil") do={ :set sbGatewayImageMisses 0 }`,
		`  :if (($healthy = true) && ($restartCount = 0)) do={ :set sbGatewayImageProbation ($sbGatewayImageProbation + 1); :set sbGatewayImageMisses 0 } else={ :set sbGatewayImageProbation 0; :set sbGatewayImageMisses ($sbGatewayImageMisses + 1) }`,
		`  :if ($sbGatewayImageProbation >= 3) do={`,
		`    :if ([:len $transfer] = 1) do={ :set ($receipt->"phase") "commit"; /system/script/set $transfer source=[:serialize to=json value=$receipt] }`,
		`    :if ([/container/get $current start-on-boot] != false) do={ :error "SB-GATEWAY candidate boot policy changed during probation" }`,
		previousGuard,
		`    :if ([:len $previous] = 1) do={ /container/remove $previous }`,
		`    :if ($retainPrevious = true) do={`,
		`      :if ([:len $previousIf] = 0) do={ /interface/veth/add name="veth-sb-previous" address=192.0.2.9/30 gateway=192.0.2.10 comment="SB-GATEWAY previous image hold" }`,
		`      :do { /container/set $rollback restart-policy=no } on-error={ /container/set $rollback auto-restart-interval=0s }`,
		`      /container/set $rollback interface="veth-sb-previous" start-on-boot=no comment="SB-GATEWAY container previous"`,
		`    } else={`,
		`      /container/remove $rollback`,
		`      :if ([:len $previousIf] = 1) do={ /interface/veth/remove $previousIf }`,
		`    }`,
		`    :if ([:len $hold] = 1) do={ /interface/veth/remove $hold }`,
		`    :if ([:len $swap] = 1) do={ /interface/veth/remove $swap }`,
		`    /system/scheduler/enable [find where name="SB-GATEWAY-container-startup" and comment="SB-GATEWAY storage-aware startup scheduler"]`,
		`    :if ([:len $transfer] = 1) do={ /system/script/remove $transfer }`,
		`    :if ([:len $scheduler] = 1) do={ /system/scheduler/remove $scheduler }`,
		`    :set sbGatewayImageProbation`,
		`    :set sbGatewayImageMisses`,
		`    :log info "SB-GATEWAY: image update committed after probation"`,
		`    :return true`,
		`  }`,
		`  :if (($sbGatewayImageMisses < 60) && ($restartCount = 0)) do={ :return true }`,
		`  :if ([:len $probationGate] = 1) do={ /ip/firewall/mangle/disable $probationGate }`,
		`  :if ([:len $transfer] = 1) do={`,
		`    :set ($receipt->"phase") "rollback"`,
		`    /system/script/set $transfer source=[:serialize to=json value=$receipt]`,
		`    :return true`,
		`  }`,
		`  :local failed $current`,
		`  :local failedMountlists [/container/get $failed mountlists]`,
		`  :if ([:len $failedMountlists] = 0) do={ :set failedMountlists [/container/get $rollback mountlists] }`,
		`  :if ([:len $failedMountlists] = 0) do={ :error "SB-GATEWAY rollback mountlists are missing" }`,
		`  :do { /container/stop $failed } on-error={}`,
		`  :local failedStopped false`,
		`  :local failedStopTry 0`,
		`  :while (($failedStopped = false) && ($failedStopTry < 60)) do={`,
		`    :do { :if ([/container/get $failed running] = false) do={ :set failedStopped true } } on-error={}`,
		`    :do { :if ([/container/get $failed status] = "stopped") do={ :set failedStopped true } } on-error={}`,
		`    :do { :if ([/container/get $failed stopped] = true) do={ :set failedStopped true } } on-error={}`,
		`    :if ($failedStopped = false) do={ :set failedStopTry ($failedStopTry + 1); :delay 2s }`,
		`  }`,
		`  :if ($failedStopped = false) do={ :error "SB-GATEWAY failed candidate did not stop for rollback" }`,
		`  :local liveIf [/container/get $failed interface]`,
		`  /container/set $failed mountlists=""`,
		`  /container/set $rollback mountlists=$failedMountlists`,
		`  :if ([:len $swap] = 0) do={ /interface/veth/add name="veth-sb-swap" address=192.0.2.5/30 gateway=192.0.2.6 comment="SB-GATEWAY image update swap"; :set swap [/interface/veth/find where comment="SB-GATEWAY image update swap"] }`,
		`  /container/set $rollback interface="veth-sb-swap"`,
		`  /container/set $failed interface="veth-sb-update" comment="SB-GATEWAY container failed"`,
		`  /container/set $rollback interface=$liveIf comment="SB-GATEWAY container"`,
		`  /interface/veth/remove $swap`,
		`  ` + startPrevious("$rollback"),
		`  /container/remove $failed`,
		`  :if ([:len $hold] = 1) do={ /interface/veth/remove $hold }`,
		`  :if ([:len $scheduler] = 1) do={ /system/scheduler/remove $scheduler }`,
		`  :set sbGatewayImageProbation`,
		`  :set sbGatewayImageMisses`,
		`  :log error "SB-GATEWAY: image update rolled back after failed probation"`,
		`  :return true`,
		`}`,

		`:if (([:len $current] != 1) || ([:len $candidate] != 0) || ([:len $rollback] != 0)) do={ :error "SB-GATEWAY image update state is not recoverable" }`,
		previousGuard,
		`:if ([:len $previous] = 1) do={ /container/set $previous mountlists="" }`,
		`:if ([:len $hold] = 0) do={ /interface/veth/add name="veth-sb-update" address=192.0.2.1/30 gateway=192.0.2.2 comment="SB-GATEWAY image update hold"; :set hold [/interface/veth/find where comment="SB-GATEWAY image update hold"] }`,
		`:local liveIf [:tostr [/container/get $current interface]]`,
		`:local mountlists [/container/get $current mountlists]`,
		`:local envlist [/container/get $current envlist]`,
		`:local dns [/container/get $current dns]`,
		`:local logging [/container/get $current logging]`,
		`:local memoryHigh [/container/get $current memory-high]`,
		`:local memoryMax [/container/get $current memory-max]`,
		`/container/add ` + addImage + ` root-dir=$candidateRoot interface="veth-sb-update" envlist=$envlist dns=$dns logging=$logging start-on-boot=no memory-high=$memoryHigh memory-max=$memoryMax comment="SB-GATEWAY container candidate"`,
		`:set candidate [/container/find where comment="SB-GATEWAY container candidate"]`,
		`:if ([:len $candidate] != 1) do={ :error "SB-GATEWAY candidate was not created" }`,
		`:local extracted false`,
		`:local extractTry 0`,
		`:while (($extracted = false) && ($extractTry < 180)) do={`,
		`  :do { :if ([/container/get $candidate status] = "stopped") do={ :set extracted true } } on-error={}`,
		`  :do { :if ([/container/get $candidate stopped] = true) do={ :set extracted true } } on-error={}`,
		`  :if ($extracted = false) do={ :set extractTry ($extractTry + 1); :delay 2s }`,
		`}`,
		`:if ($extracted = false) do={ :error "SB-GATEWAY candidate extraction timed out" }`,
		`:if (([:typeof $mountlists] != "array") || ([:len $mountlists] = 0)) do={ :error "SB-GATEWAY persistent mountlists are missing" }`,
		`:set receipt {"candidate-root"=$candidateRoot;"previous-root"=[/container/get $current root-dir];"reference"="` + spec.CandidateReference + `";"mountlists"=$mountlists;"live-if"=$liveIf;"previous-start-on-boot"=[/container/get $current start-on-boot];"phase"="transfer"}`,
		`/system/script/add name="` + imageUpdateTransfer + `" policy=read comment="SB-GATEWAY image transfer metadata" source=[:serialize to=json value=$receipt]`,
		`:set transfer [/system/script/find where name="` + imageUpdateTransfer + `"]`,
		`:if ([:len $transfer] != 1) do={ :error "SB-GATEWAY image transfer metadata was not created" }`,
		`:local readback [:deserialize from=json value=[/system/script/get $transfer source]]`,
		`:if ([:serialize to=json value=$readback] != [:serialize to=json value=$receipt]) do={ :error "SB-GATEWAY image transfer metadata readback failed" }`,
		`:do { /container/set $candidate restart-policy=always restart-interval=10s } on-error={ /container/set $candidate auto-restart-interval=10s }`,
		`:local gate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]`,
		`:if ([:len $gate] = 1) do={ /ip/firewall/mangle/disable $gate }`,
		`/ip/firewall/connection/remove [find where connection-mark="sb-managed"]`,
		`:if ([/container/get $current stopped] != true) do={ /container/stop $current }`,
		`:local currentStopped false`,
		`:local currentStopTry 0`,
		`:while (($currentStopped = false) && ($currentStopTry < 60)) do={`,
		`  :do { :if ([/container/get $current running] = false) do={ :set currentStopped true } } on-error={}`,
		`  :do { :if ([/container/get $current status] = "stopped") do={ :set currentStopped true } } on-error={}`,
		`  :do { :if ([/container/get $current stopped] = true) do={ :set currentStopped true } } on-error={}`,
		`  :if ($currentStopped = false) do={ :set currentStopTry ($currentStopTry + 1); :delay 2s }`,
		`}`,
		`:if ($currentStopped = false) do={ :error "SB-GATEWAY current container did not stop; diversion remains fail-open" }`,
		`/container/set $current start-on-boot=no`,
		`:do {`,
		`  /container/set $current mountlists=""`,
		`  /container/set $candidate mountlists=$mountlists`,
		`} on-error={`,
		`  :do { /container/set $candidate mountlists="" } on-error={}`,
		`  :do { /container/set $current mountlists=$mountlists } on-error={}`,
		`  :do { ` + startPrevious("$current") + ` } on-error={}`,
		`  :error "SB-GATEWAY persistent mount ownership transfer failed; diversion remains fail-open"`,
		`}`,
		`:if ([:len $swap] = 0) do={ /interface/veth/add name="veth-sb-swap" address=192.0.2.5/30 gateway=192.0.2.6 comment="SB-GATEWAY image update swap"; :set swap [/interface/veth/find where comment="SB-GATEWAY image update swap"] }`,
		`/container/set $candidate interface="veth-sb-swap"`,
		`/container/set $current interface="veth-sb-update" comment="SB-GATEWAY container rollback"`,
		`/container/set $candidate interface=$liveIf comment="SB-GATEWAY container"`,
		`/interface/veth/remove $swap`,
		// RouterOS 7.24.2 restarts a running container when start-on-boot changes.
		// Set it while stopped, after the canonical mounts/interface transfer.
		`/container/set $candidate start-on-boot=no`,
		`:if ([$storageReady $candidate] != true) do={ :error "SB-GATEWAY candidate storage is not ready" }`,
		`/container/start $candidate`,
		`:set ($receipt->"phase") "probation"`,
		`/system/script/set $transfer source=[:serialize to=json value=$receipt]`,
		`:set sbGatewayImageProbation 0`,
		`:set sbGatewayImageMisses 0`,
		cleanupArchive,
		`:log warning "SB-GATEWAY: candidate image started; health probation active"`,
	}
	filtered := lines[:0]
	for _, line := range lines {
		if strings.TrimSpace(line) != "" {
			filtered = append(filtered, line)
		}
	}
	return strings.Join(filtered, "\n")
}
