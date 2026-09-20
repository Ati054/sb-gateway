package routeros

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
)

const (
	imageUpdateWorker    = "SB-GATEWAY-image-update-worker"
	imageUpdateScheduler = "SB-GATEWAY-image-update"
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
}

// SetContainerMemoryLimits raises the runtime limits of one already-owned
// container after a successful self-update. RouterOS accepts these properties
// on a running container without restarting it; callers must resolve and
// validate ownership before passing the resource ID.
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
	retainPrevious := "false"
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
		`:if ([:len $jobs] > 1) do={ :return true }`,
		`:local current [/container/find where comment="SB-GATEWAY container"]`,
		`:local candidate [/container/find where comment="SB-GATEWAY container candidate"]`,
		`:local rollback [/container/find where comment="SB-GATEWAY container rollback"]`,
		`:local previous [/container/find where comment="SB-GATEWAY container previous"]`,
		`:local previousIf [/interface/veth/find where name="veth-sb-previous"]`,
		`:local retainPrevious ` + retainPrevious,
		`:local scheduler [/system/scheduler/find where name="` + imageUpdateScheduler + `"]`,
		`:local hold [/interface/veth/find where comment="SB-GATEWAY image update hold"]`,
		`:local swap [/interface/veth/find where comment="SB-GATEWAY image update swap"]`,
		`:local candidateRoot "/` + spec.CandidateRoot + `"`,
		`:local healthURL "http://` + spec.ContainerAddress + `:9080/healthz"`,
		`:local trafficURL "http://` + spec.ContainerAddress + `:9080/traffic-ready"`,
		`:global sbGatewayImageProbation`,
		`:global sbGatewayImageMisses`,
		`:if (([:len $current] > 1) || ([:len $candidate] > 1) || ([:len $rollback] > 1) || ([:len $scheduler] > 1) || ([:len $hold] > 1) || ([:len $swap] > 1)) do={ :error "SB-GATEWAY image update state is ambiguous" }`,

		// Completed cleanup: the candidate already owns the canonical role.
		`:if (([:len $current] = 1) && ([:len $candidate] = 0) && ([:len $rollback] = 0)) do={`,
		`  :if ([/container/get $current root-dir] = $candidateRoot) do={`,
		`    :if ([:len $hold] = 1) do={ /interface/veth/remove $hold }`,
		`    :if ([:len $swap] = 1) do={ /interface/veth/remove $swap }`,
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
		`  :do { :if ([/container/get $current stopped] = true) do={ /container/start $current } } on-error={}`,
		`  :if ([:len $scheduler] = 1) do={ /system/scheduler/remove $scheduler }`,
		`  :log warning "SB-GATEWAY: interrupted image extraction was cleaned up"`,
		`  :return true`,
		`}`,

		// Probation: three consecutive healthy scheduler passes commit; any
		// container restart or twelve misses restore the old image.
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
		`    :if ([:len $scheduler] = 1) do={ /system/scheduler/remove $scheduler }`,
		`    :set sbGatewayImageProbation`,
		`    :set sbGatewayImageMisses`,
		`    :log info "SB-GATEWAY: image update committed after probation"`,
		`    :return true`,
		`  }`,
		`  :if (($sbGatewayImageMisses < 12) && ($restartCount = 0)) do={ :return true }`,
		`  :local failed $current`,
		`  :local failedMountlists [/container/get $failed mountlists]`,
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
		`  /container/start $rollback`,
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
		`:local liveIf [/container/get $current interface]`,
		`:local mountlists [/container/get $current mountlists]`,
		`:local envlist [/container/get $current envlist]`,
		`:local dns [/container/get $current dns]`,
		`:local logging [/container/get $current logging]`,
		`:local memoryHigh [/container/get $current memory-high]`,
		`:local memoryMax [/container/get $current memory-max]`,
		`:if ($memoryHigh < 234881024) do={ :set memoryHigh 234881024 }`,
		`:if ($memoryMax < 268435456) do={ :set memoryMax 268435456 }`,
		`/container/add ` + addImage + ` root-dir=$candidateRoot interface="veth-sb-update" envlist=$envlist dns=$dns logging=$logging start-on-boot=yes memory-high=$memoryHigh memory-max=$memoryMax comment="SB-GATEWAY container candidate"`,
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
		`:do { /container/set $candidate restart-policy=always restart-interval=10s } on-error={ /container/set $candidate auto-restart-interval=10s }`,
		`:local gate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]`,
		`:if ([:len $gate] = 1) do={ /ip/firewall/mangle/disable $gate }`,
		`/ip/firewall/connection/remove [find where connection-mark="sb-managed"]`,
		`/container/stop $current`,
		`:local currentStopped false`,
		`:local currentStopTry 0`,
		`:while (($currentStopped = false) && ($currentStopTry < 60)) do={`,
		`  :do { :if ([/container/get $current running] = false) do={ :set currentStopped true } } on-error={}`,
		`  :do { :if ([/container/get $current status] = "stopped") do={ :set currentStopped true } } on-error={}`,
		`  :do { :if ([/container/get $current stopped] = true) do={ :set currentStopped true } } on-error={}`,
		`  :if ($currentStopped = false) do={ :set currentStopTry ($currentStopTry + 1); :delay 2s }`,
		`}`,
		`:if ($currentStopped = false) do={ :error "SB-GATEWAY current container did not stop; diversion remains fail-open" }`,
		`:do {`,
		`  /container/set $current mountlists=""`,
		`  /container/set $candidate mountlists=$mountlists`,
		`} on-error={`,
		`  :do { /container/set $candidate mountlists="" } on-error={}`,
		`  :do { /container/set $current mountlists=$mountlists } on-error={}`,
		`  :do { /container/start $current } on-error={}`,
		`  :error "SB-GATEWAY persistent mount ownership transfer failed; diversion remains fail-open"`,
		`}`,
		`:if ([:len $swap] = 0) do={ /interface/veth/add name="veth-sb-swap" address=192.0.2.5/30 gateway=192.0.2.6 comment="SB-GATEWAY image update swap"; :set swap [/interface/veth/find where comment="SB-GATEWAY image update swap"] }`,
		`/container/set $candidate interface="veth-sb-swap"`,
		`/container/set $current interface="veth-sb-update" comment="SB-GATEWAY container rollback"`,
		`/container/set $candidate interface=$liveIf comment="SB-GATEWAY container"`,
		`/interface/veth/remove $swap`,
		`/container/start $candidate`,
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
