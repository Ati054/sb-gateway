package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func (server *Server) recoveryBackups(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	items, err := server.listRecoveryArchives()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"items":           items,
		"retention_limit": recoveryRetentionLimit,
		"encryption":      recoveryArchiveCipher,
		"password_source": "panel-administrator",
		"routeros_error":  "mirror-not-configured",
	})
}

func (server *Server) createRecoveryBackup(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	metadata, err := server.createRecoveryArchive()
	if err != nil {
		classifier, action, _ := recoveryArchiveFailurePresentation(err)
		log.Printf("manual recovery archive blocked: class=%s action=%s", classifier, action)
		server.audit(request, fmt.Sprint(payload["sub"]), "recovery.create", "recovery_create_failed", map[string]any{"classifier": classifier, "action": action})
		server.writeRecoveryArchiveFailure(response, request, http.StatusUnprocessableEntity, "recovery_create_failed", err)
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "recovery.create", "ok", map[string]any{"name": metadata.Name, "sha256": metadata.SHA256})
	server.writeJSON(response, http.StatusOK, map[string]any{"ok": true, "archive": metadata.document()})
}

func (server *Server) downloadRecoveryBackup(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	source := request.URL.Query().Get("source")
	if source != "" && source != "auto" && source != "ssd" {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_recovery_source", "Recovery source is invalid.")
		return
	}
	_, root, _ := server.recoveryRoots()
	path, err := recoveryArchivePath(root, request.PathValue("name"))
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusNotFound, "recovery_archive_missing", "The selected recovery archive is unavailable.")
		return
	}
	entry, err := os.Lstat(path)
	if err != nil || !entry.Mode().IsRegular() || entry.Mode()&os.ModeSymlink != 0 || entry.Size() > recoveryMaxArchiveBytes {
		server.writeErrorResponse(response, request, http.StatusNotFound, "recovery_archive_missing", "The selected recovery archive is unavailable.")
		return
	}
	file, err := os.Open(path)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusNotFound, "recovery_archive_missing", "The selected recovery archive is unavailable.")
		return
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > recoveryMaxArchiveBytes {
		server.writeErrorResponse(response, request, http.StatusNotFound, "recovery_archive_missing", "The selected recovery archive is unavailable.")
		return
	}
	response.Header().Set("Content-Type", "application/octet-stream")
	response.Header().Set("Content-Disposition", `attachment; filename="`+info.Name()+`"`)
	http.ServeContent(response, request, info.Name(), info.ModTime(), file)
}

func (server *Server) uploadRecoveryBackup(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	name := request.Header.Get("X-SB-Recovery-Filename")
	if !recoveryArchiveName.MatchString(name) || filepath.Base(name) != name {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_recovery_filename", "Choose an SB Gateway .sbgw recovery archive.")
		return
	}
	server.recoveryMu.Lock()
	defer server.recoveryMu.Unlock()
	_, root, _ := server.recoveryRoots()
	if err := os.MkdirAll(root, 0o700); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	target, _ := recoveryArchivePath(root, name)
	if _, err := os.Lstat(target); err == nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "recovery_archive_exists", "This recovery archive is already stored.")
		return
	}
	temporary, err := os.CreateTemp(root, ".upload-*.tmp")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		server.internalStateError(response, request, err)
		return
	}
	digest := sha256.New()
	limited := http.MaxBytesReader(response, request.Body, recoveryMaxArchiveBytes)
	written, copyErr := io.CopyBuffer(io.MultiWriter(temporary, digest), limited, make([]byte, recoveryChunkBytes))
	if copyErr != nil {
		temporary.Close()
		var maxBytesError *http.MaxBytesError
		if errors.As(copyErr, &maxBytesError) {
			server.writeErrorResponse(response, request, http.StatusRequestEntityTooLarge, "recovery_upload_too_large", "Recovery archive exceeds the safety limit.")
		} else {
			server.writeErrorResponse(response, request, http.StatusBadRequest, "recovery_upload_failed", "Recovery archive upload was interrupted.")
		}
		return
	}
	if written < int64(len(recoveryMagic)+2*recoveryWrapperSlotBytes+32) {
		temporary.Close()
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_recovery_archive", "Recovery archive is empty or truncated.")
		return
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		server.internalStateError(response, request, err)
		return
	}
	if err := temporary.Close(); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	metadata, err := server.recoveryArchiveMetadata(temporaryPath, false)
	if err != nil || metadata.Name == "" {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_recovery_archive", "The uploaded file is not a valid SB Gateway recovery archive.")
		return
	}
	created, parseErr := time.Parse(time.RFC3339, metadata.CreatedAt)
	revision := text(metadata.ActiveRevision)
	if parseErr != nil || recoveryArchiveFilename(created, revision) != name {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_recovery_archive", "Recovery archive name does not match its authenticated metadata.")
		return
	}
	metadata.Name = name
	metadata.Size = written
	metadata.SHA256 = hex.EncodeToString(digest.Sum(nil))
	if err := os.Rename(temporaryPath, target); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	if err := server.pruneRecoveryArchives(root); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	if err := server.updateRecoveryIndex(metadata); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "recovery.upload", "ok", map[string]any{"name": name, "sha256": metadata.SHA256})
	server.writeJSON(response, http.StatusOK, map[string]any{"ok": true, "archive": metadata.document()})
}

func (server *Server) restoreRecoveryBackup(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	password, _ := body["password"].(string)
	encoded, err := server.secrets.read("admin-password-hash", false)
	if err != nil || encoded == "" || !verifyPassword(password, encoded) {
		server.writeErrorResponse(response, request, http.StatusForbidden, "reauthentication_failed", "Administrator password confirmation failed.")
		return
	}
	source, _ := body["source"].(string)
	if source != "" && source != "auto" && source != "ssd" {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_recovery_source", "Recovery source is invalid.")
		return
	}
	name, _ := body["name"].(string)
	_, root, _ := server.recoveryRoots()
	path, err := recoveryArchivePath(root, name)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusNotFound, "recovery_archive_missing", "The selected recovery archive is unavailable.")
		return
	}
	operationID, files, err := server.stageRecoveryArchive(path, name, password)
	if err != nil {
		if errors.Is(err, errRecoveryPending) {
			server.writeErrorResponse(response, request, http.StatusConflict, "recovery_already_pending", "A recovery operation is already pending restart.")
			return
		}
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "recovery_restore_rejected", err.Error())
		return
	}
	restart := map[string]any{"scheduled": false, "manual_restart_required": true}
	config, configErr := server.repository.loadActive()
	if configErr != nil {
		config, configErr = server.getDraft()
	}
	if configErr == nil {
		stack, stackErr := server.newRouterOSStack(config)
		if stackErr == nil {
			ctx, cancel := context.WithTimeout(request.Context(), 20*time.Second)
			scheduled, scheduleErr := stack.REST.ScheduleRecoveryRestart(ctx)
			cancel()
			stack.REST.CloseIdleConnections()
			if scheduleErr == nil {
				restart = scheduled
				restart["manual_restart_required"] = false
			}
		}
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "recovery.restore", "staged", map[string]any{"name": name, "operation_id": operationID})
	server.writeJSON(response, http.StatusAccepted, map[string]any{
		"ok": true, "operation_id": operationID, "archive_name": name, "staged_files": files,
		"restart": restart,
	})
}
