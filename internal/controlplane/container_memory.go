package controlplane

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

const containerMemoryOperation = "container-memory-operation"

func (server *Server) containerMemoryStatus(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	config, err := server.repository.loadActive()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	ctx, cancel := context.WithTimeout(request.Context(), 10*time.Second)
	defer cancel()
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		server.writeErrorResponse(response, request, 502, "routeros_unavailable", "RouterOS container status is unavailable.")
		return
	}
	defer stack.REST.CloseIdleConnections()
	rows, err := stack.REST.List(ctx, routerOSContainerInventoryPath)
	if err != nil {
		server.writeErrorResponse(response, request, 502, "routeros_unavailable", "RouterOS container status is unavailable.")
		return
	}
	var current map[string]any
	count := 0
	for _, row := range rows {
		if text(row["comment"]) == "SB-GATEWAY container" {
			current = row
			count++
		}
	}
	if count != 1 {
		server.writeErrorResponse(response, request, 409, "container_memory_live_state_invalid", "The managed container is missing or ambiguous.")
		return
	}
	container := containerSummary(current, nil, true)
	if !server.mutationMu.TryLock() {
		server.writeErrorResponse(response, request, 409, "state_mutation_in_progress", "Another operation is in progress; retry status later.")
		return
	}
	defer server.mutationMu.Unlock()
	operation, err := server.repository.auxiliary(containerMemoryOperation)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	if operation["pending"] == true {
		schedulers, err := stack.REST.List(ctx, "/rest/system/scheduler?.proplist=name")
		if err != nil {
			server.writeErrorResponse(response, request, 502, "routeros_unavailable", "RouterOS memory scheduler status is unavailable.")
			return
		}
		queued := false
		for _, scheduler := range schedulers {
			if text(scheduler["name"]) == routeros.ContainerMemoryScheduler {
				queued = true
			}
		}
		previousState, previousPending := operation["state"], operation["pending"]
		high, highOK := routerOSByteSize(container["memory_high"])
		maximum, maxOK := routerOSByteSize(container["memory_max"])
		wantHigh, _ := numberToInt64(operation["high_bytes"])
		wantMax, _ := numberToInt64(operation["max_bytes"])
		deadline, deadlineErr := time.Parse(time.RFC3339Nano, text(operation["deadline"]))
		if !queued && highOK && maxOK && high == wantHigh && maximum == wantMax && text(container["root_dir"]) == text(operation["root_dir"]) && container["healthy"] == true {
			operation["pending"], operation["state"] = false, "completed"
		} else if deadlineErr == nil && !server.now().Before(deadline) {
			operation["pending"], operation["state"] = queued, "unconfirmed"
		}
		if previousState != operation["state"] || previousPending != operation["pending"] {
			if err := server.repository.saveAuxiliary(containerMemoryOperation, operation); err != nil {
				server.internalStateError(response, request, err)
				return
			}
		}
	}
	server.writeJSON(response, 200, map[string]any{"container": container, "operation": operation})
}

func (server *Server) updateContainerMemory(response http.ResponseWriter, request *http.Request) {
	session, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	highMiB, highOK := numberToInt64(body["memory_high_mib"])
	maxMiB, maxOK := numberToInt64(body["memory_max_mib"])
	if !highOK || !maxOK || highMiB < 16 || highMiB > maxMiB || maxMiB > 8192 || !routeros.ValidContainerMemoryLimits(highMiB<<20, maxMiB<<20) {
		server.writeErrorResponse(response, request, 422, "invalid_container_memory", "Use integer MiB values: 16 <= memory-high <= memory-max <= 8192.")
		return
	}
	if text(body["confirmation"]) != "ПЕРЕЗАПУСТИТЬ" {
		server.writeErrorResponse(response, request, 409, "container_memory_confirmation_required", "Changing memory limits restarts the container; explicit confirmation is required.")
		return
	}
	if !server.mutationMu.TryLock() {
		server.writeErrorResponse(response, request, 409, "state_mutation_in_progress", "Another operation is in progress.")
		return
	}
	defer server.mutationMu.Unlock()
	if server.rejectMutationConflict(response, request, "") {
		return
	}
	config, err := server.repository.loadActive()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		server.writeErrorResponse(response, request, 409, "routeros_live_required", "A live RouterOS connection is required.")
		return
	}
	defer stack.REST.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(request.Context(), 15*time.Second)
	defer cancel()
	rows, err := stack.REST.List(ctx, "/rest/container?.proplist=.id,comment,root-dir,stopped,memory-high,memory-max,memory-current")
	if err != nil {
		server.writeErrorResponse(response, request, 502, "routeros_inventory_failed", "RouterOS container inventory is unavailable.")
		return
	}
	root, containerRoot, err := imageUpdateLiveRoots(rows)
	configuredRoot, rootErr := validateLifecycleStorageRoot(text(objectAt(config, "storage")["root"]))
	if err != nil || rootErr != nil || root != configuredRoot {
		server.writeErrorResponse(response, request, 409, "container_memory_live_state_invalid", "The managed container or storage root is missing, ambiguous or transitioning.")
		return
	}
	var current map[string]any
	for _, row := range rows {
		if text(row["comment"]) == "SB-GATEWAY container" {
			current = row
		}
	}
	if optionalRestBool(current["stopped"]) != false {
		server.writeErrorResponse(response, request, 409, "container_memory_not_running", "The managed container must be running before scheduling a memory restart.")
		return
	}
	oldHigh, highOK := routerOSByteSize(current["memory-high"])
	oldMax, maxOK := routerOSByteSize(current["memory-max"])
	used, usedOK := routerOSByteSize(current["memory-current"])
	if !highOK || !maxOK || !usedOK {
		server.writeErrorResponse(response, request, 409, "container_memory_unavailable", "Live memory limits and usage must be available before changing them.")
		return
	}
	high, maximum := highMiB<<20, maxMiB<<20
	if maximum < oldMax && maximum < used+(16<<20) {
		server.writeErrorResponse(response, request, 409, "container_memory_below_usage", "The reduced hard limit must exceed current usage by at least 16 MiB.")
		return
	}
	if high == oldHigh && maximum == oldMax {
		server.writeJSON(response, 200, map[string]any{"operation": map[string]any{"state": "unchanged", "pending": false}})
		return
	}
	operation := map[string]any{"pending": true, "state": "scheduled", "root_dir": containerRoot, "high_bytes": high, "max_bytes": maximum, "deadline": server.now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)}
	if err := server.repository.saveAuxiliary(containerMemoryOperation, operation); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	scheduleContext, scheduleCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer scheduleCancel()
	_, err = stack.REST.ScheduleContainerMemoryUpdate(scheduleContext, strings.Trim(containerRoot, "/"), oldHigh, oldMax, high, maximum)
	if err != nil {
		// A lost scheduler response may still mean it was armed. Never retry the
		// mutation automatically; readback or the deadline resolves this record.
		server.audit(request, fmt.Sprint(session["sub"]), "container.memory", "schedule_unconfirmed", nil)
		server.writeErrorResponse(response, request, 502, "container_memory_schedule_unconfirmed", "Scheduling was not confirmed; inspect memory status before retrying.")
		return
	}
	server.audit(request, fmt.Sprint(session["sub"]), "container.memory", "scheduled", map[string]any{"memory_high_mib": highMiB, "memory_max_mib": maxMiB})
	server.writeJSON(response, 202, map[string]any{"operation": operation})
}
