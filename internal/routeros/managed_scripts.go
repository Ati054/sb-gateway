package routeros

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	routerosassets "github.com/sb-gateway/sb-gateway/routeros"
)

type installedScriptSpec struct {
	name, comment, source string
	optional              bool
}

var ErrImageUpdateInProgress = errors.New("RouterOS image update is still in progress")

// SyncInstalledScripts refreshes only existing, exactly owned RouterOS script
// bodies. It never runs a script, re-imports an installer, creates a missing
// optional component, or changes watchdog settings and scheduler timing.
func (client *Client) SyncInstalledScripts(ctx context.Context) (int, error) {
	schedulers, err := client.list(ctx, "/rest/system/scheduler?.proplist=name")
	if err != nil {
		return 0, err
	}
	for _, scheduler := range schedulers {
		if text(scheduler["name"]) == imageUpdateScheduler {
			return 0, ErrImageUpdateInProgress // Wait for probation or rollback.
		}
	}
	rows, err := client.list(ctx, "/rest/system/script?.proplist=.id,name,comment")
	if err != nil {
		return 0, err
	}
	specs := []installedScriptSpec{
		{"SB-GATEWAY-health-watchdog", "SB-GATEWAY health watchdog", routerosassets.HealthWatchdogSource(), false},
		{"SB-GATEWAY-startup-fail-open", "SB-GATEWAY startup fail-open", routerosassets.StartupFailOpenSource(), false},
		{"SB-GATEWAY-cloudflare-update", "SB-GATEWAY Cloudflare updater", routerosassets.CloudflareUpdateSource(), true},
	}
	changed := 0
	for _, spec := range specs {
		var id string
		for _, row := range rows {
			if text(row["name"]) != spec.name {
				continue
			}
			if id != "" {
				return changed, fmt.Errorf("RouterOS script %s is ambiguous", spec.name)
			}
			if text(row["comment"]) != spec.comment {
				return changed, fmt.Errorf("refusing to update unowned RouterOS script %s", spec.name)
			}
			id = text(row[".id"])
			if id == "" {
				return changed, errors.New("owned RouterOS script identifier is missing")
			}
		}
		if id == "" {
			if spec.optional {
				continue
			}
			return changed, fmt.Errorf("required RouterOS script %s is missing", spec.name)
		}
		item, err := client.request(ctx, http.MethodGet, "/rest/system/script/"+routerOSResourceID(id)+"?.proplist=source", nil)
		if err != nil {
			return changed, err
		}
		current := strings.TrimSpace(strings.ReplaceAll(text(item["source"]), "\r\n", "\n"))
		if current == spec.source {
			continue
		}
		if _, err := client.request(ctx, http.MethodPatch, "/rest/system/script/"+routerOSResourceID(id), map[string]any{"source": spec.source}); err != nil {
			return changed, err
		}
		readback, err := client.request(ctx, http.MethodGet, "/rest/system/script/"+routerOSResourceID(id)+"?.proplist=source", nil)
		if err != nil {
			return changed, err
		}
		if strings.TrimSpace(strings.ReplaceAll(text(readback["source"]), "\r\n", "\n")) != spec.source {
			return changed, fmt.Errorf("RouterOS script %s source readback differs", spec.name)
		}
		changed++
	}
	return changed, nil
}

// SetCloudflareUpdaterEnabled changes only the exact optional project-owned
// scheduler. Missing scripts/schedulers remain missing by user choice.
func (client *Client) SetCloudflareUpdaterEnabled(ctx context.Context, enabled bool) (bool, error) {
	const name = "SB-GATEWAY-cloudflare-update"
	const comment = "SB-GATEWAY Cloudflare scheduler"
	scripts, err := client.list(ctx, "/rest/system/script?.proplist=name,comment")
	if err != nil {
		return false, err
	}
	installed := false
	for _, script := range scripts {
		if text(script["name"]) != name {
			continue
		}
		if installed || text(script["comment"]) != "SB-GATEWAY Cloudflare updater" {
			return false, errors.New("Cloudflare updater script is ambiguous or unowned")
		}
		installed = true
	}
	if !installed && enabled {
		return false, nil
	}
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment,disabled")
	if err != nil {
		return false, err
	}
	var id, current string
	for _, row := range rows {
		if text(row["name"]) != name {
			continue
		}
		if id != "" {
			return false, errors.New("Cloudflare scheduler is ambiguous")
		}
		if text(row["comment"]) != comment {
			return false, errors.New("refusing to change an unowned Cloudflare scheduler")
		}
		id, current = text(row[".id"]), fmt.Sprint(row["disabled"])
		if id == "" {
			return false, errors.New("Cloudflare scheduler identifier is missing")
		}
	}
	if id == "" {
		return false, nil
	}
	wantDisabled := !enabled
	if strings.EqualFold(current, fmt.Sprint(wantDisabled)) {
		return false, nil
	}
	if _, err := client.request(ctx, http.MethodPatch, "/rest/system/scheduler/"+routerOSResourceID(id), map[string]any{"disabled": fmt.Sprint(wantDisabled)}); err != nil {
		return false, err
	}
	readback, err := client.request(ctx, http.MethodGet, "/rest/system/scheduler/"+routerOSResourceID(id)+"?.proplist=disabled", nil)
	if err != nil {
		return false, err
	}
	if !strings.EqualFold(fmt.Sprint(readback["disabled"]), fmt.Sprint(wantDisabled)) {
		return false, errors.New("Cloudflare scheduler readback differs")
	}
	return true, nil
}
