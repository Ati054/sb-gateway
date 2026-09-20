package controlplane

import (
	"fmt"
	"net/http"
)

func (server *Server) rollbackDraft(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	if body["confirmation"] != "ОТКАТИТЬ" {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "rollback_confirmation_required", "Type ОТКАТИТЬ exactly to confirm rollback.")
		return
	}
	password, _ := body["password"].(string)
	encoded, err := server.secrets.read("admin-password-hash", false)
	if err != nil || encoded == "" || !verifyPassword(password, encoded) {
		server.writeErrorResponse(response, request, http.StatusForbidden, "reauthentication_failed", "Administrator password confirmation failed.")
		return
	}
	if server.runtime == nil {
		server.writeErrorResponse(response, request, http.StatusServiceUnavailable, "native_runtime_unavailable", "Native runtime process control is unavailable.")
		return
	}

	server.configMu.Lock()
	defer server.configMu.Unlock()
	metadata, err := server.repository.metadata()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	previousRevision, _ := metadata["previous_revision"].(string)
	if !safeRevision(previousRevision) {
		server.writeErrorResponse(response, request, http.StatusConflict, "rollback_unavailable", "No verified previous generation is available.")
		return
	}
	config, err := server.repository.loadGeneration(previousRevision)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	actor := fmt.Sprint(payload["sub"])
	operationContext, cancelOperation := applyOperationContext(request.Context())
	defer cancelOperation()
	result, status, err := server.applyConfiguration(operationContext, config, actor)
	if err != nil {
		server.audit(request, actor, "rollback", "failed", map[string]any{"target_revision": previousRevision})
		server.writeErrorResponse(response, request, status, "rollback_failed", "The previous generation could not be restored safely; the active pointer was preserved.")
		return
	}
	result["operation"] = "rolled_back"
	result["rolled_back"] = true
	result["requested_revision"] = previousRevision
	result["restored_revision"] = result["revision"]
	server.audit(request, actor, "rollback", "ok", map[string]any{
		"requested_revision": previousRevision,
		"restored_revision":  result["revision"],
	})
	server.writeJSON(response, http.StatusOK, result)
}
