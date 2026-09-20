package routeros

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const (
	fullUninstallWorker    = "SB-GATEWAY-uninstall-worker"
	fullUninstallScheduler = "SB-GATEWAY-uninstall-once"
	maxFixedScriptBytes    = 64 << 10
)

var lifecycleStorageRootPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{2,190}$`)

func validFixedManagedScript(name, source string) bool {
	var prefix string
	switch name {
	case recoveryRestartWorker:
		prefix = "# SB-GATEWAY one-shot recovery restart\n"
	case fullUninstallWorker:
		prefix = "# SB-GATEWAY exact-scope full uninstall\n"
	case imageUpdateWorker:
		prefix = "# SB-GATEWAY autonomous one-image switch\n"
	default:
		return false
	}
	return len(source) >= len(prefix) && len(source) <= maxFixedScriptBytes && strings.HasPrefix(source, prefix) && !strings.ContainsRune(source, '\x00')
}

// ScheduleFullUninstall arms a fixed project-owned worker after all user input
// has been reduced to one validated external-storage path. The scheduler is
// created last, so an interrupted request leaves only an inert script.
func (client *Client) ScheduleFullUninstall(ctx context.Context, storageRoot string) (map[string]any, error) {
	root, err := validateLifecycleStorageRoot(storageRoot)
	if err != nil {
		return nil, err
	}
	worker := renderFullUninstallWorker(root)
	if _, err := client.installFixedManagedScript(ctx, fullUninstallWorker, worker); err != nil {
		return nil, err
	}
	comment := "SB-GATEWAY autonomous full uninstall"
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment")
	if err != nil {
		return nil, err
	}
	var existingID string
	for _, row := range rows {
		if text(row["name"]) != fullUninstallScheduler {
			continue
		}
		if existingID != "" {
			return nil, errors.New("full uninstall scheduler is ambiguous")
		}
		if text(row["comment"]) != comment {
			return nil, errors.New("refusing to replace an unowned full uninstall scheduler")
		}
		existingID = text(row[".id"])
		if existingID == "" {
			return nil, errors.New("full uninstall scheduler identifier is unavailable")
		}
	}
	if existingID != "" {
		if _, err := client.request(ctx, http.MethodDelete, "/rest/system/scheduler/"+routerOSResourceID(existingID), nil); err != nil {
			return nil, err
		}
	}
	if _, err := client.request(ctx, http.MethodPut, "/rest/system/scheduler", map[string]any{
		"name": fullUninstallScheduler, "interval": "10s", "on-event": "/system/script/run " + fullUninstallWorker,
		"policy": "read,write,test,policy", "comment": comment, "disabled": "false",
	}); err != nil {
		return nil, err
	}
	return map[string]any{"scheduled": true, "delay_seconds": 10, "scheduler": fullUninstallScheduler}, nil
}

func validateLifecycleStorageRoot(value string) (string, error) {
	root := strings.Trim(strings.TrimSpace(value), "/")
	lower := strings.ToLower(root)
	if !lifecycleStorageRootPattern.MatchString(root) || !strings.Contains(root, "/") || strings.HasPrefix(lower, "flash") {
		return "", errors.New("managed storage root is unsafe")
	}
	for _, part := range strings.Split(root, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("managed storage root is unsafe")
		}
	}
	return root, nil
}

func renderFullUninstallWorker(root string) string {
	lines := []string{
		"# SB-GATEWAY exact-scope full uninstall",
		`:local sbScheduler [/system/scheduler/find where name="` + fullUninstallScheduler + `"]`,
		`:if ([:len $sbScheduler] = 1) do={ /system/scheduler/remove $sbScheduler }`,
		`:local storageEntry [/file/find where name="` + root + `"]`,
		`:if ([:len $storageEntry] != 1) do={ :error "SB-GATEWAY exact project storage directory is missing or ambiguous" }`,
		`:local gate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]`,
		`:if ([:len $gate] = 1) do={ /ip/firewall/mangle/disable $gate }`,
		`/ip/firewall/connection/remove [find where connection-mark="sb-managed"]`,
		`:foreach state in=[/system/script/find where comment~"^SB-GATEWAY WG egress peer state "] do={`,
		`  :local stateData [/system/script/get $state source]`,
		`  :local separator [:find $stateData "|"]`,
		`  :if (($separator = nil) || ($separator < 2)) do={ :error "SB-GATEWAY WireGuard peer restore state is invalid" }`,
		`  :local peerKey [:pick $stateData 1 $separator]`,
		`  :local originalAllowed [:pick $stateData ($separator + 1) [:len $stateData]]`,
		`  :local peer [/interface/wireguard/peers/find where public-key=$peerKey]`,
		`  :if ([:len $peer] != 1) do={ :error "SB-GATEWAY WireGuard peer restore target is missing or ambiguous" }`,
		`  /interface/wireguard/peers/set $peer allowed-address=$originalAllowed`,
		`}`,
		`/system/scheduler/remove [find where comment~"^SB-GATEWAY "]`,
		`/ip/firewall/mangle/remove [find where comment~"^SB-GATEWAY "]`,
		`/ip/firewall/filter/remove [find where comment~"^SB-GATEWAY "]`,
		`/ip/firewall/nat/remove [find where comment~"^SB-GATEWAY "]`,
		`/ip/firewall/address-list/remove [find where list="SB_PUBLIC_ABUSE"]`,
		`/ip/firewall/address-list/remove [find where comment~"^SB-GATEWAY "]`,
		`:do { /ipv6/firewall/filter/remove [find where comment~"^SB-GATEWAY "] } on-error={}`,
		`:do { /ipv6/firewall/address-list/remove [find where comment~"^SB-GATEWAY "] } on-error={}`,
		`/ip/route/remove [find where comment~"^SB-GATEWAY "]`,
		`:do { /interface/list/member/remove [find where comment~"^SB-GATEWAY "] } on-error={}`,
		`:foreach containerId in=[/container/find where comment="SB-GATEWAY container" || comment="SB-GATEWAY container previous"] do={`,
		`  :local containerRoot [/container/get $containerId root-dir]`,
		`  :if (([:pick $containerRoot 0 ` + fmt.Sprint(len("/"+root+"/root-")) + `] != "/` + root + `/root-") && ($containerRoot != "/` + root + `/root")) do={ :error "SB-GATEWAY container root is outside managed storage" }`,
		`  :if ([:typeof [:find $containerRoot "/" ` + fmt.Sprint(len("/"+root+"/root-")) + `]] != "nil") do={ :error "SB-GATEWAY container root is nested" }`,
		`  :do { /container/stop $containerId } on-error={}`,
		`  :local stopped false`,
		`  :local stopAttempt 0`,
		`  :while (($stopped = false) && ($stopAttempt < 60)) do={`,
		`    :do { :if ([/container/get $containerId running] = false) do={ :set stopped true } } on-error={}`,
		`    :do { :if ([/container/get $containerId stopped] = true) do={ :set stopped true } } on-error={}`,
		`    :do { :if ([/container/get $containerId status] = "stopped") do={ :set stopped true } } on-error={}`,
		`    :if ($stopped = false) do={ :set stopAttempt ($stopAttempt + 1); :delay 2s }`,
		`  }`,
		`  :if ($stopped = false) do={ :error "SB-GATEWAY container did not stop; storage was preserved" }`,
		`  /container/remove $containerId`,
		`}`,
		`/container/envs/remove [find where comment~"^SB-GATEWAY "]`,
		`/container/mounts/remove [find where comment~"^SB-GATEWAY "]`,
		`/ip/address/remove [find where comment~"^SB-GATEWAY "]`,
		`/interface/bridge/port/remove [find where comment~"^SB-GATEWAY "]`,
		`/interface/veth/remove [find where comment~"^SB-GATEWAY "]`,
		`/interface/bridge/remove [find where comment~"^SB-GATEWAY "]`,
		`/interface/list/remove [find where comment~"^SB-GATEWAY "]`,
		`/routing/table/remove [find where comment="SB-GATEWAY routing table"]`,
		`/user/remove [find where comment="SB-GATEWAY control-plane REST user"]`,
		`/user/group/remove [find where comment="SB-GATEWAY REST group"]`,
		`/file/remove [find where name~"^sb-gateway-(before-|pre-)"]`,
		`/file/remove $storageEntry`,
		`:log warning "SB-GATEWAY: full uninstall complete; foreign RouterOS objects were preserved"`,
		`:foreach scriptId in=[/system/script/find where comment~"^SB-GATEWAY "] do={ /system/script/remove $scriptId }`,
	}
	return strings.Join(lines, "\n")
}
