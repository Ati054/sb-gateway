package controlplane

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestApplyRejectsPersistedConflictingMutation(t *testing.T) {
	server := newTestServer(t)
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("d", 64)}
	server.runtime = runtime
	if err := server.repository.saveAuxiliary("lifecycle-operation", map[string]any{
		"kind": "image-update", "state": "scheduled",
	}); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/apply", map[string]any{
		"config": routerOSReadyConfig(t),
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusConflict {
		t.Fatalf("conflicting Apply status=%d body=%s", response.Code, response.Body.String())
	}
	failure := objectAt(decodeResponse(t, response), "error")
	if failure["code"] != "state_mutation_in_progress" || runtime.prepareCalls != 0 {
		t.Fatalf("conflict=%#v runtime=%#v", failure, runtime)
	}
}

func TestSubscriptionActivationWaitsForPersistedApplyRecovery(t *testing.T) {
	server := newTestServer(t)
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("e", 64)}
	server.runtime = runtime
	if err := server.repository.saveAuxiliary("apply-operation", map[string]any{
		"kind": "apply", "pending": true, "state": "recovery_pending",
	}); err != nil {
		t.Fatal(err)
	}
	worked, err := server.activatePendingSubscription(context.Background())
	if err != nil || worked || runtime.prepareCalls != 0 {
		t.Fatalf("worked=%t err=%v runtime=%#v", worked, err, runtime)
	}
}
