package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

const lifecycleImageUpdateResponseTimeout = 5 * time.Minute

const (
	lifecycleContainerMemoryHigh = int64(224 << 20)
	lifecycleContainerMemoryMax  = int64(256 << 20)
	legacyContainerMemoryHigh    = int64(320 << 20)
	legacyContainerMemoryMax     = int64(384 << 20)
)

func (server *Server) scheduleLifecycleImageUpdate(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	if text(body["confirmation"]) != "ОБНОВИТЬ" {
		server.writeErrorResponse(response, request, http.StatusConflict, "image_update_confirmation_required", "Confirm the autonomous image update explicitly.")
		return
	}
	server.lifecycleMu.Lock()
	defer server.lifecycleMu.Unlock()
	if writable, blocked := server.checkPersistentMounts(); !writable {
		server.audit(request, fmt.Sprint(payload["sub"]), "container.image_update", "persistent_storage_read_only", map[string]any{"blocked_mounts": blocked})
		server.writeErrorResponse(response, request, http.StatusServiceUnavailable, "persistent_storage_read_only", "Persistent storage is not writable; image update was not started.")
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	operation, err := server.repository.auxiliary("lifecycle-operation")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	operation = server.reconcileLifecycleOperation(request.Context(), config, operation)
	if lifecycleOperationActive(operation) {
		server.writeErrorResponse(response, request, http.StatusConflict, "image_update_already_running", "Wait for the current image update to finish.")
		return
	}
	configuredRoot, err := validateLifecycleStorageRoot(text(objectAt(config, "storage")["root"]))
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "storage_root_required", err.Error())
		return
	}
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "routeros_live_required", "A live RouterOS HTTPS connection is required for image update.")
		return
	}
	defer stack.REST.CloseIdleConnections()
	inventoryContext, inventoryCancel := context.WithTimeout(request.Context(), 30*time.Second)
	containers, err := stack.REST.List(inventoryContext, "/rest/container?.proplist=.id,comment,root-dir")
	inventoryCancel()
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusBadGateway, "routeros_inventory_failed", "RouterOS container ownership could not be inventoried.")
		return
	}
	liveRoot, liveContainerRoot, err := imageUpdateLiveRoots(containers)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "image_update_live_state_invalid", err.Error())
		return
	}
	if liveRoot != configuredRoot {
		server.writeErrorResponse(response, request, http.StatusConflict, "storage_root_mismatch", "The configured storage root does not match the live managed container.")
		return
	}
	containerAddress, err := lifecycleContainerIPv4(config)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "container_address_required", err.Error())
		return
	}
	source := text(body["candidate_source"])
	reference := strings.TrimSpace(text(body["candidate_reference"]))
	version := strings.TrimSpace(text(body["candidate_version"]))
	switch source {
	case "local-file":
		version, err = server.validateVerifiedLocalImage(configuredRoot, reference)
	case "registry":
		if !lifecycleVersionPattern.MatchString(version) {
			err = errors.New("a valid candidate version is required for a registry image")
		}
	default:
		err = errors.New("image update source must be local-file or registry")
	}
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_image_candidate", err.Error())
		return
	}
	candidateRoot := configuredRoot + "/root-" + version
	if strings.Trim(liveContainerRoot, "/") == candidateRoot {
		server.writeErrorResponse(response, request, http.StatusConflict, "image_version_already_active", "The selected image version is already active.")
		return
	}
	recovery, err := server.createRecoveryArchive()
	if err != nil {
		classifier, action, _ := recoveryArchiveFailurePresentation(err)
		log.Printf("image update recovery archive blocked: class=%s action=%s", classifier, action)
		server.audit(request, fmt.Sprint(payload["sub"]), "container.image_update", "recovery_archive_required", map[string]any{"classifier": classifier, "action": action})
		server.writeRecoveryArchiveFailure(response, request, http.StatusInternalServerError, "recovery_archive_required", err)
		return
	}
	now := server.now().UTC().Format(time.RFC3339Nano)
	operation = map[string]any{
		"kind": "image-update", "state": "preparing", "version": version,
		"candidate_source": source, "candidate_reference": reference,
		"storage_root": configuredRoot, "previous_root": strings.Trim(liveContainerRoot, "/"), "candidate_root": candidateRoot,
		"recovery_archive": recovery.Name, "preparing_at": now,
		"retain_previous_image": keepPreviousImage(config),
	}
	if err := server.repository.saveAuxiliary("lifecycle-operation", operation); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	// Scheduling is the one autonomous action that follows a completed archive.
	// A browser disconnect must not convert it into a second, unsafe user retry.
	scheduleContext, scheduleCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer scheduleCancel()
	result, err := stack.REST.ScheduleImageUpdate(scheduleContext, routeros.ImageUpdateSpec{
		Version: version, StorageRoot: configuredRoot, CandidateRoot: candidateRoot,
		CandidateSource: source, CandidateReference: reference, ContainerAddress: containerAddress,
		KeepPrevious: keepPreviousImage(config),
	})
	if err != nil {
		operation["state"] = "failed"
		operation["failed_at"] = server.now().UTC().Format(time.RFC3339Nano)
		operation["failure"] = "routeros_schedule_rejected"
		_ = server.repository.saveAuxiliary("lifecycle-operation", operation)
		server.writeErrorResponse(response, request, http.StatusBadGateway, "image_update_schedule_failed", "RouterOS rejected the autonomous image update schedule.")
		return
	}
	operation["state"] = "scheduled"
	operation["scheduled_at"] = server.now().UTC().Format(time.RFC3339Nano)
	if err := server.repository.saveAuxiliary("lifecycle-operation", operation); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "container.image_update_scheduled", "ok", map[string]any{
		"version": version, "candidate_source": source, "recovery_archive": recovery.Name,
	})
	log.Printf("lifecycle image update scheduled version=%s source=%s", version, source)
	server.writeJSON(response, http.StatusAccepted, map[string]any{
		"ok": true, "operation": "image-update", "state": "scheduled", "version": version,
		"starts_in_seconds": result["delay_seconds"], "recovery_archive": recovery.Name,
	})
}

func (server *Server) writeRecoveryArchiveFailure(response http.ResponseWriter, request *http.Request, status int, code string, err error) {
	classifier, action, message := recoveryArchiveFailurePresentation(err)
	requestID, _ := request.Context().Value(requestIDKey{}).(string)
	server.writeJSON(response, status, map[string]any{"error": map[string]any{
		"code": code, "message": message,
		"details":    []any{map[string]any{"classifier": classifier, "action": action}},
		"request_id": requestID,
	}})
}

func lifecycleOperationActive(operation map[string]any) bool {
	switch text(operation["state"]) {
	case "preparing", "scheduled", "probation":
		return true
	default:
		return false
	}
}

func (server *Server) reconcileLifecycleOperation(parent context.Context, config, operation map[string]any) map[string]any {
	if text(operation["kind"]) != "image-update" || !lifecycleOperationActive(operation) {
		return operation
	}
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		return operation
	}
	defer stack.REST.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	containers, err := stack.REST.List(ctx, "/rest/container?.proplist=.id,comment,root-dir,memory-high,memory-max")
	if err != nil {
		return operation
	}
	schedulers, err := stack.REST.List(ctx, "/rest/system/scheduler?.proplist=.id,name,comment")
	if err != nil {
		return operation
	}
	schedulerPresent := false
	for _, scheduler := range schedulers {
		if text(scheduler["name"]) == "SB-GATEWAY-image-update" && text(scheduler["comment"]) == "SB-GATEWAY autonomous image update" {
			schedulerPresent = true
		}
	}
	currentRoot := ""
	currentID := ""
	currentMemoryHigh := int64(0)
	currentMemoryMax := int64(0)
	currentCount := 0
	transitionCount := 0
	for _, container := range containers {
		switch text(container["comment"]) {
		case "SB-GATEWAY container":
			currentCount++
			currentRoot = strings.Trim(text(container["root-dir"]), "/")
			currentID = text(container[".id"])
			currentMemoryHigh, _ = routerOSByteSize(container["memory-high"])
			currentMemoryMax, _ = routerOSByteSize(container["memory-max"])
		case "SB-GATEWAY container candidate", "SB-GATEWAY container rollback", "SB-GATEWAY container failed":
			transitionCount++
		}
	}
	if currentCount != 1 {
		return operation
	}
	nextState := text(operation["state"])
	if schedulerPresent && currentRoot == text(operation["candidate_root"]) && transitionCount == 1 {
		nextState = "probation"
	} else if !schedulerPresent && transitionCount == 0 {
		switch currentRoot {
		case text(operation["candidate_root"]):
			targetHigh := max(currentMemoryHigh, lifecycleContainerMemoryHigh)
			targetMax := max(currentMemoryMax, lifecycleContainerMemoryMax, targetHigh)
			// Migrate only the exact historical default pair. Any other higher
			// limits are treated as an explicit administrator override.
			if currentMemoryHigh == legacyContainerMemoryHigh && currentMemoryMax == legacyContainerMemoryMax {
				targetHigh = lifecycleContainerMemoryHigh
				targetMax = lifecycleContainerMemoryMax
			}
			if currentMemoryHigh != targetHigh || currentMemoryMax != targetMax {
				if err := stack.REST.SetContainerMemoryLimits(ctx, currentID, targetHigh, targetMax); err != nil {
					log.Printf("lifecycle image update memory reconciliation pending: %v", err)
					return operation
				}
			}
			nextState = "completed"
		case text(operation["previous_root"]):
			nextState = "rolled_back"
		}
	}
	if nextState == text(operation["state"]) {
		return operation
	}
	operation = cloneJSONObject(operation)
	operation["state"] = nextState
	operation[nextState+"_at"] = server.now().UTC().Format(time.RFC3339Nano)
	_ = server.repository.saveAuxiliary("lifecycle-operation", operation)
	log.Printf("lifecycle image update state=%s version=%s", nextState, text(operation["version"]))
	return operation
}

func routerOSByteSize(value any) (int64, bool) {
	if number, ok := numberToInt64(value); ok && number >= 0 {
		return number, true
	}
	raw := strings.TrimSpace(text(value))
	if number, err := strconv.ParseInt(raw, 10, 64); err == nil && number >= 0 {
		return number, true
	}
	for _, unit := range []struct {
		suffix string
		factor float64
	}{{"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"B", 1}} {
		if !strings.HasSuffix(raw, unit.suffix) {
			continue
		}
		number, err := strconv.ParseFloat(strings.TrimSpace(strings.TrimSuffix(raw, unit.suffix)), 64)
		if err != nil || number < 0 {
			return 0, false
		}
		return int64(number * unit.factor), true
	}
	return 0, false
}

func imageUpdateLiveRoots(containers []map[string]any) (storageRoot, containerRoot string, err error) {
	managed := 0
	for _, container := range containers {
		switch text(container["comment"]) {
		case "SB-GATEWAY container candidate", "SB-GATEWAY container rollback", "SB-GATEWAY container failed":
			return "", "", errors.New("a previous image transition is still present on RouterOS")
		case "SB-GATEWAY container":
			managed++
			containerRoot = strings.Trim(text(container["root-dir"]), "/")
		}
	}
	if managed != 1 {
		return "", "", errors.New("the managed RouterOS container is missing or ambiguous")
	}
	storageRoot, err = managedContainerStorageRoot(containers)
	return storageRoot, containerRoot, err
}

func lifecycleContainerIPv4(config map[string]any) (string, error) {
	value := strings.TrimSpace(text(objectAt(objectAt(config, "system"), "networking")["container_address"]))
	if address, _, err := net.ParseCIDR(value); err == nil && address.To4() != nil {
		return address.String(), nil
	}
	if address := net.ParseIP(value); address != nil && address.To4() != nil {
		return address.String(), nil
	}
	return "", errors.New("the managed container IPv4 address is not configured")
}

// validateVerifiedLocalImage intentionally does not hash the archive again.
// Upload already streamed SHA-256 and architecture validation in one pass; the
// content-addressed private file and exact persisted size are the trust anchor.
func (server *Server) validateVerifiedLocalImage(storageRoot, reference string) (string, error) {
	prefix := storageRoot + "/data/lifecycle-uploads/"
	if !strings.HasPrefix(reference, prefix) {
		return "", errors.New("the uploaded image is outside the managed storage root")
	}
	name := strings.TrimPrefix(reference, prefix)
	if !lifecycleStoredNamePattern.MatchString(name) || filepath.Base(name) != name {
		return "", errors.New("the uploaded image name is invalid")
	}
	verification, err := server.repository.auxiliary("lifecycle-image-verifications")
	if err != nil {
		return "", err
	}
	record := objectAt(objectAt(verification, "images"), reference)
	version := text(record["version"])
	size, ok := numberToInt64(record["size_bytes"])
	if !ok || size < 1024 || !lifecycleVersionPattern.MatchString(version) || len(text(record["sha256"])) != 64 {
		return "", errors.New("the uploaded image has no valid verification record")
	}
	path := filepath.Join(server.opts.DataDir, "lifecycle-uploads", name)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() != size {
		return "", errors.New("the verified uploaded image is missing or changed")
	}
	return version, nil
}

func numberToInt64(value any) (int64, bool) {
	switch number := value.(type) {
	case float64:
		result := int64(number)
		return result, float64(result) == number
	case int64:
		return number, true
	case int:
		return int64(number), true
	case json.Number:
		result, err := number.Int64()
		return result, err == nil
	default:
		return 0, false
	}
}
