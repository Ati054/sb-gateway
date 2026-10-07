package routeros

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const containerMemoryWorker = "SB-GATEWAY-container-memory-worker"
const ContainerMemoryScheduler = "SB-GATEWAY-container-memory-once"

func ValidContainerMemoryLimits(high, maximum int64) bool {
	return high >= 16<<20 && high <= maximum && maximum <= 8<<30
}

// ScheduleContainerMemoryUpdate keeps the operation on RouterOS when changing
// limits restarts the HTTP server. The one-shot is consumed before mutation.
func (client *Client) ScheduleContainerMemoryUpdate(ctx context.Context, root string, oldHigh, oldMax, high, maximum int64) (map[string]any, error) {
	root = strings.Trim(root, "/")
	if !lifecycleStorageRootPattern.MatchString(root) || strings.Contains(root, "..") || !ValidContainerMemoryLimits(high, maximum) || oldHigh < 0 || oldMax < 0 {
		return nil, errors.New("container memory settings are invalid")
	}
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment")
	if err != nil {
		return nil, err
	}
	for _, row := range rows {
		name := text(row["name"])
		if name == ContainerMemoryScheduler || name == imageUpdateScheduler || name == recoveryRestartScheduler || name == fullUninstallScheduler || strings.HasPrefix(name, "SB-GATEWAY-safe-rollback-") {
			return nil, errors.New("another RouterOS lifecycle operation is active")
		}
	}
	if _, err := client.installFixedManagedScript(ctx, containerMemoryWorker, renderContainerMemoryWorker(root, oldHigh, oldMax, high, maximum)); err != nil {
		return nil, err
	}
	if _, err := client.request(ctx, http.MethodPut, "/rest/system/scheduler", map[string]any{
		"name": ContainerMemoryScheduler, "interval": "10s", "on-event": "/system/script/run " + containerMemoryWorker,
		"policy": "read,write,test,policy", "comment": "SB-GATEWAY one-shot container memory update", "disabled": "false",
	}); err != nil {
		return nil, err
	}
	return map[string]any{"scheduled": true, "delay_seconds": 10}, nil
}

func renderContainerMemoryWorker(root string, oldHigh, oldMax, high, maximum int64) string {
	return strings.Join([]string{
		"# SB-GATEWAY one-shot container memory update",
		`:local jobs [/system/script/job/find where script="` + containerMemoryWorker + `"]; :if ([:len $jobs] > 1) do={ :error "Memory worker already running" }`,
		`:local scheduler [/system/scheduler/find where name="` + ContainerMemoryScheduler + `" and comment="SB-GATEWAY one-shot container memory update"]; :if ([:len $scheduler] != 1) do={ :error "Memory scheduler ownership changed" }`,
		`/system/scheduler/disable $scheduler`,
		`/system/scheduler/remove $scheduler`,
		`:local target [/container/find where comment="SB-GATEWAY container"]; :if ([:len $target] != 1) do={ :error "Managed container is missing or ambiguous" }`,
		`:if ([/container/get $target root-dir] != "/` + root + `") do={ :error "Managed container root changed" }`,
		`:if ([/container/get $target stopped] = true) do={ :error "Managed container is not running" }`,
		`:local autoRestart false; :do { :set autoRestart ([/container/get $target restart-policy] = "always") } on-error={ :set autoRestart ([/container/get $target auto-restart-interval] > 0s) }; :if ($autoRestart != true) do={ :error "Automatic container restart must be enabled" }`,
		`:if (([:len [/system/scheduler/find where name="SB-GATEWAY-image-update"]] > 0) || ([:len [/system/scheduler/find where name~"^SB-GATEWAY-safe-rollback-"]] > 0) || ([:len [/system/script/job/find where script~"^SB-GATEWAY-(apply|rollback)-"]] > 0)) do={ :error "Memory update conflicts with a transaction" }`,
		fmt.Sprintf(`:if (([/container/get $target memory-high] != %d) || ([/container/get $target memory-max] != %d)) do={ :error "Container memory limits changed since confirmation" }`, oldHigh, oldMax),
		fmt.Sprintf(`:if ((%d < %d) && (%d < ([/container/get $target memory-current] + 16777216))) do={ :error "Reduced hard limit is below current usage plus headroom" }`, maximum, oldMax, maximum),
		`:local watchdog [/system/scheduler/find where name="SB-GATEWAY-health-watchdog" and comment="SB-GATEWAY health scheduler" and disabled=no]; :if ([:len $watchdog] != 1) do={ :error "Active managed watchdog is required" }`,
		`:local gate [/ip/firewall/mangle/find where comment="SB-GATEWAY diversion-gate"]; :if ([:len $gate] != 1) do={ :error "Diversion gate is missing or ambiguous" }`,
		`/ip/firewall/mangle/disable $gate`,
		fmt.Sprintf(`/container/set $target memory-high=%d memory-max=%d`, high, maximum),
		fmt.Sprintf(`:if (([/container/get $target memory-high] != %d) || ([/container/get $target memory-max] != %d)) do={ :error "Container memory readback failed" }`, high, maximum),
		`:log warning "SB-GATEWAY: container memory limits changed; watchdog must confirm traffic readiness"`,
	}, "\n")
}
