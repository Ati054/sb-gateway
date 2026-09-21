package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

func (server *Server) uninstallPreview(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	root := text(objectAt(config, "storage")["root"])
	server.writeJSON(response, http.StatusOK, map[string]any{
		"storage_root": root,
		"removes": []any{
			"точный RouterOS-контейнер SB-GATEWAY",
			"firewall, маршруты, списки и scheduler с владением SB-GATEWAY",
			"envs, mounts, veth и bridge с владением SB-GATEWAY",
			"выделенный каталог проекта на внешнем накопителе",
			"REST user/group и управляемые backup-файлы SB-GATEWAY",
		},
		"preserves": []any{
			"чужие правила firewall и маршруты RouterOS",
			"существующие VPN-интерфейсы и peers",
			"остальные файлы и каталоги внешнего накопителя",
			"пакеты RouterOS, channel и device-mode",
		},
		"confirmation": "УДАЛИТЬ SB-GATEWAY",
	})
}

func (server *Server) scheduleFullUninstall(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	if text(body["confirmation"]) != "УДАЛИТЬ SB-GATEWAY" {
		server.writeErrorResponse(response, request, http.StatusConflict, "uninstall_confirmation_required", "Type УДАЛИТЬ SB-GATEWAY exactly to confirm full uninstall.")
		return
	}
	root, err := validateLifecycleStorageRoot(text(body["storage_root"]))
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_storage_root", err.Error())
		return
	}
	server.mutationMu.Lock()
	defer server.mutationMu.Unlock()
	if server.rejectMutationConflict(response, request, mutationLifecycle) {
		return
	}
	server.lifecycleMu.Lock()
	defer server.lifecycleMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	stack, err := server.newRouterOSStack(config)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "routeros_live_required", "A live RouterOS HTTPS connection is required for full uninstall.")
		return
	}
	defer stack.REST.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(request.Context(), 25*time.Second)
	defer cancel()
	containers, err := stack.REST.List(ctx, "/rest/container?.proplist=.id,comment,root-dir")
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusBadGateway, "routeros_inventory_failed", "RouterOS ownership could not be inventoried before full uninstall.")
		return
	}
	liveRoot, err := managedContainerStorageRoot(containers)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "live_storage_root_unavailable", err.Error())
		return
	}
	if root != liveRoot {
		server.writeErrorResponse(response, request, http.StatusConflict, "storage_root_mismatch", "Refresh the page and use the storage root reported by the live RouterOS container.")
		return
	}
	result, err := stack.REST.ScheduleFullUninstall(ctx, root)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusBadGateway, "uninstall_schedule_failed", "RouterOS rejected the scoped uninstall schedule.")
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "container.full_uninstall_scheduled", "ok", map[string]any{"storage_root": root})
	server.writeJSON(response, http.StatusAccepted, map[string]any{
		"ok": true, "operation": "full-uninstall", "state": "scheduled",
		"starts_in_seconds": result["delay_seconds"], "message": "RouterOS scheduled exact-scope removal. This panel will disconnect.",
	})
}

func managedContainerStorageRoot(containers []map[string]any) (string, error) {
	rootDirectory := ""
	matches := 0
	for _, container := range containers {
		if text(container["comment"]) != "SB-GATEWAY container" {
			continue
		}
		matches++
		if matches > 1 {
			return "", errors.New("managed RouterOS container is ambiguous")
		}
		rootDirectory = strings.Trim(text(container["root-dir"]), "/")
	}
	if matches != 1 || rootDirectory == "" {
		return "", errors.New("managed RouterOS container is unavailable")
	}
	separator := strings.LastIndexByte(rootDirectory, '/')
	if separator < 1 {
		return "", errors.New("managed container root-dir is invalid")
	}
	leaf := rootDirectory[separator+1:]
	if leaf != "root" && !(strings.HasPrefix(leaf, "root-") && len(leaf) > len("root-")) {
		return "", errors.New("managed container root-dir is invalid")
	}
	return validateLifecycleStorageRoot(rootDirectory[:separator])
}
