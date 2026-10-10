package routeros

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	routerosassets "github.com/sb-gateway/sb-gateway/routeros"
)

const (
	containerStartupWorker  = "SB-GATEWAY-startup-migration-worker"
	containerStartupOnce    = "SB-GATEWAY-startup-migration-once"
	containerStartupComment = "SB-GATEWAY one-shot startup migration"
)

// ReconcileContainerStartup also supports images installed by an older updater.
// RouterOS owns the one-shot stop/change/start after image probation ends.
func (client *Client) ReconcileContainerStartup(ctx context.Context) (bool, error) {
	schedulers, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment,interval,start-time,on-event,disabled")
	if err != nil {
		return false, err
	}
	for _, row := range schedulers {
		name := text(row["name"])
		if name == imageUpdateScheduler || name == ContainerMemoryScheduler || name == recoveryRestartScheduler || name == fullUninstallScheduler || strings.HasPrefix(name, "SB-GATEWAY-safe-rollback-") {
			return false, ErrImageUpdateInProgress
		}
	}
	containers, err := client.list(ctx, "/rest/container?.proplist=.id,comment,root-dir,start-on-boot")
	if err != nil {
		return false, err
	}
	var target map[string]any
	for _, row := range containers {
		if text(row["comment"]) != "SB-GATEWAY container" {
			continue
		}
		if target != nil {
			return false, errors.New("startup migration container is ambiguous")
		}
		target = row
	}
	if target == nil {
		return false, errors.New("startup migration container is missing")
	}
	root := strings.Trim(text(target["root-dir"]), "/")
	if !lifecycleStorageRootPattern.MatchString(root) || strings.Contains(root, "..") {
		return false, errors.New("startup migration root is invalid")
	}
	bootFlag := fmt.Sprint(target["start-on-boot"])
	if bootFlag != "true" && bootFlag != "false" {
		return false, errors.New("startup migration boot policy is unavailable")
	}
	scripts, err := client.list(ctx, "/rest/system/script?.proplist=.id,name,comment")
	if err != nil {
		return false, err
	}
	for _, row := range scripts {
		if text(row["name"]) == imageUpdateTransfer {
			return false, ErrImageUpdateInProgress
		}
	}
	ready, err := ownedStartupObject(scripts, "SB-GATEWAY-storage-ready", "SB-GATEWAY storage readiness")
	if err != nil {
		return false, err
	}
	boot, err := ownedStartupObject(scripts, "SB-GATEWAY-container-startup", "SB-GATEWAY storage-aware startup")
	if err != nil {
		return false, err
	}
	schedule, err := ownedStartupObject(schedulers, "SB-GATEWAY-container-startup", "SB-GATEWAY storage-aware startup scheduler")
	if err != nil {
		return false, err
	}
	pending, err := ownedStartupObject(schedulers, containerStartupOnce, containerStartupComment)
	if err != nil {
		return false, err
	}
	worker, err := ownedStartupObject(scripts, containerStartupWorker, "SB-GATEWAY managed script "+containerStartupWorker)
	if err != nil {
		return false, err
	}
	if pending != nil {
		if worker == nil || text(pending["on-event"]) != "/system/script/run "+containerStartupWorker || fmt.Sprint(pending["disabled"]) != "false" {
			return false, errors.New("startup migration pending schedule is invalid")
		}
		return false, nil // Includes a lost scheduling acknowledgement; never re-arm.
	}
	if bootFlag == "false" && ready != nil && boot != nil && schedule != nil &&
		(text(schedule["interval"]) == "0s" || text(schedule["interval"]) == "00:00:00") && text(schedule["start-time"]) == "startup" && text(schedule["on-event"]) == "/system/script/run SB-GATEWAY-container-startup" {
		// Fetch only the two boot bodies, not every historical Apply script.
		readySource, err := client.startupScriptSource(ctx, ready)
		if err != nil {
			return false, err
		}
		bootSource, err := client.startupScriptSource(ctx, boot)
		if err != nil {
			return false, err
		}
		if readySource == normalizeStartupSource(routerosassets.ContainerStorageReadySource()) && bootSource == normalizeStartupSource(routerosassets.ContainerBootSource()) {
			return false, nil // Preserve an explicitly disabled, already installed boot scheduler.
		}
	}
	jobs, err := client.list(ctx, "/rest/system/script/job?.proplist=script")
	if err != nil {
		return false, err
	}
	for _, job := range jobs {
		if name := text(job["script"]); name == containerStartupWorker || name == "SB-GATEWAY-container-startup" || strings.HasPrefix(name, "SB-GATEWAY-apply-") || strings.HasPrefix(name, "SB-GATEWAY-rollback-") {
			return false, ErrImageUpdateInProgress
		}
	}
	source := renderContainerStartupMigration(root)
	id, err := client.installFixedManagedScript(ctx, containerStartupWorker, source)
	if err != nil {
		return false, err
	}
	readback, err := client.request(ctx, http.MethodGet, "/rest/system/script/"+routerOSResourceID(id)+"?.proplist=source", nil)
	if err != nil {
		return false, err
	}
	if normalizeStartupSource(text(readback["source"])) != source {
		return false, errors.New("startup migration worker readback differs")
	}
	_, err = client.request(ctx, http.MethodPut, "/rest/system/scheduler", map[string]any{
		"name": containerStartupOnce, "interval": "10s", "on-event": "/system/script/run " + containerStartupWorker,
		"policy": "read,write,test,policy", "comment": containerStartupComment, "disabled": "false",
	})
	return err == nil, err
}

func (client *Client) startupScriptSource(ctx context.Context, script map[string]any) (string, error) {
	row, err := client.request(ctx, http.MethodGet, "/rest/system/script/"+routerOSResourceID(text(script[".id"]))+"?.proplist=source", nil)
	return normalizeStartupSource(text(row["source"])), err
}

func normalizeStartupSource(source string) string {
	return strings.TrimSpace(strings.ReplaceAll(source, "\r\n", "\n"))
}

// StartupMigrationPending includes the boot job after the one-shot was consumed.
func (client *Client) StartupMigrationPending(ctx context.Context) (bool, error) {
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment")
	if err != nil {
		return false, err
	}
	pending, err := ownedStartupObject(rows, containerStartupOnce, containerStartupComment)
	if err != nil {
		return false, err
	}
	if pending != nil {
		return true, nil
	}
	jobs, err := client.list(ctx, "/rest/system/script/job?.proplist=script")
	if err != nil {
		return false, err
	}
	for _, job := range jobs {
		if name := text(job["script"]); name == containerStartupWorker || name == "SB-GATEWAY-container-startup" {
			return true, nil
		}
	}
	return false, nil
}

func ownedStartupObject(rows []map[string]any, name, comment string) (map[string]any, error) {
	var found map[string]any
	for _, row := range rows {
		if text(row["name"]) != name {
			continue
		}
		if found != nil || text(row["comment"]) != comment || text(row[".id"]) == "" {
			return nil, fmt.Errorf("startup object %s is ambiguous or unowned", name)
		}
		found = row
	}
	return found, nil
}

func renderContainerStartupMigration(root string) string {
	quote := func(value string) string {
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "\n", `\n`).Replace(value) + `"`
	}
	return strings.Join([]string{
		"# SB-GATEWAY one-shot storage startup migration",
		`:local migrate do={`,
		`:if ([:len [/system/script/job/find where script="` + containerStartupWorker + `"]] > 1) do={ :return true }`,
		`:local once [/system/scheduler/find where name="` + containerStartupOnce + `"]; :if ([:len $once] != 1) do={ :error "Startup migration schedule is ambiguous" }; :if ([/system/scheduler/get $once comment] != "` + containerStartupComment + `") do={ :error "Startup migration schedule is not owned" }`,
		`:if (([:len [/system/scheduler/find where name="SB-GATEWAY-image-update"]] > 0) || ([:len [/system/script/find where name="SB-GATEWAY-image-update-transfer"]] > 0) || ([:len [/system/scheduler/find where name="SB-GATEWAY-container-memory-once"]] > 0) || ([:len [/system/scheduler/find where name="SB-GATEWAY-recovery-restart-once"]] > 0) || ([:len [/system/scheduler/find where name="` + fullUninstallScheduler + `"]] > 0) || ([:len [/system/scheduler/find where name~"^SB-GATEWAY-safe-rollback-"]] > 0) || ([:len [/system/script/job/find where script~"^SB-GATEWAY-(apply|rollback)-"]] > 0) || ([:len [/system/script/job/find where script="SB-GATEWAY-container-startup"]] > 0)) do={ :return true }`,
		`:local target [/container/find where comment="SB-GATEWAY container"]; :if ([:len $target] != 1) do={ :error "Startup migration container is ambiguous" }`,
		`:if ([/container/get $target root-dir] != "/` + root + `") do={ /system/scheduler/remove $once; :error "Startup migration root changed" }`,
		`:if (([/container/get $target running] != true) && ([/container/get $target healthy] != true)) do={ :return true }`,
		`:local watchdog [/system/scheduler/find where name="SB-GATEWAY-health-watchdog" and comment="SB-GATEWAY health scheduler" and disabled=no]; :if ([:len $watchdog] != 1) do={ :error "Startup migration needs an active watchdog" }`,
		`:local gate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]; :if ([:len $gate] != 1) do={ :error "Startup migration gate is ambiguous" }; :if ([/ip/firewall/mangle/get $gate disabled] = true) do={ :return true }`,
		`:local ready [:parse ` + quote(routerosassets.ContainerStorageReadySource()) + `]; :if ([$ready $target] != true) do={ :return true }`,
		`:local setup [:parse ` + quote(routerosassets.ContainerStartupInstallSource()) + `]; $setup false`,
		`:local boot [/system/scheduler/find where name="SB-GATEWAY-container-startup" and comment="SB-GATEWAY storage-aware startup scheduler"]; :if ([:len $boot] != 1) do={ :error "Startup migration boot schedule is missing" }`,
		// Enable boot recovery before changing the native flag, including power loss.
		`/system/scheduler/enable $boot`,
		`/system/scheduler/remove $once`,
		`:if ([/container/get $target start-on-boot] = false) do={ :log info "SB-GATEWAY: storage startup scripts reconciled"; :return true }`,
		`/ip/firewall/mangle/disable $gate`,
		`/container/stop $target`,
		`:local attempt 0; :while (([/container/get $target stopped] != true) && ($attempt < 30)) do={ :delay 1s; :set attempt ($attempt + 1) }`,
		`:if ([/container/get $target stopped] != true) do={ :error "Startup migration stop deadline expired; boot policy unchanged" }`,
		`:do { /container/set $target start-on-boot=no } on-error={ /container/start $target; :error "Startup migration boot policy change failed" }`,
		`:if ([/container/get $target start-on-boot] != false) do={ /container/start $target; :error "Startup migration boot policy readback failed" }`,
		`/system/script/run SB-GATEWAY-container-startup`,
		`:log info "SB-GATEWAY: storage-aware startup migration completed; watchdog must confirm readiness"`,
		`}`,
		`:local result [$migrate]`,
	}, "\n")
}
