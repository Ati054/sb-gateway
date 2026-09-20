package controlplane

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

func TestRollbackEndpointReauthenticatesAndRestoresPreviousGeneration(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	previous := routerOSReadyConfig(t)
	previous["watchdog"].(map[string]any)["interval_seconds"] = float64(5)
	previousRevision, err := server.repository.stageGeneration(previous)
	if err != nil {
		t.Fatal(err)
	}
	active := cloneJSONObject(previous)
	active["watchdog"].(map[string]any)["interval_seconds"] = float64(6)
	activeRevision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{
		Revision: activeRevision, PreviousRevision: previousRevision,
		RuntimeRevision: strings.Repeat("4", 64), PreviousRuntimeRevision: strings.Repeat("3", 64),
		Actor: "test", CommittedAt: server.now(),
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("5", 64)}
	server.runtime = runtime
	server.applyRouterOS = func(
		ctx context.Context, _ map[string]any, _, _ string,
		health func(context.Context) error,
		finalize func(context.Context, routeros.BackupRef) error,
	) (routerOSApplyOutput, error) {
		if err := health(ctx); err != nil {
			return routerOSApplyOutput{}, err
		}
		backup := routeros.BackupRef{Export: "rollback.rsc", Binary: "rollback.backup"}
		if err := finalize(ctx, backup); err != nil {
			return routerOSApplyOutput{}, err
		}
		return routerOSApplyOutput{Backup: backup, Kind: "delta", Sections: []string{"watchdog"}}, nil
	}

	badPassword := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/rollback", map[string]any{
		"password": "wrong-password", "confirmation": "ОТКАТИТЬ",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if badPassword.Code != http.StatusForbidden {
		t.Fatalf("bad password returned %d", badPassword.Code)
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/rollback", map[string]any{
		"password": "panel-password-123", "confirmation": "ОТКАТИТЬ",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("rollback failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	normalizeXHTTPModeCompatibility(previous)
	normalizedPreviousRevision, err := revisionFor(previous)
	if err != nil {
		t.Fatal(err)
	}
	if body["operation"] != "rolled_back" || body["rolled_back"] != true || body["requested_revision"] != previousRevision || body["restored_revision"] != normalizedPreviousRevision {
		t.Fatalf("rollback response = %#v", body)
	}
	committed, err := server.repository.activeRevision()
	if err != nil || committed != normalizedPreviousRevision {
		t.Fatalf("active revision = %q, err=%v", committed, err)
	}
}

func TestRollbackRequiresExactConfirmationBeforePasswordCheck(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/rollback", map[string]any{
		"password": "panel-password-123", "confirmation": "rollback",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("inexact confirmation returned %d", response.Code)
	}
}
