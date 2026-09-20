package controlplane

import (
	"net/http"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestPlanEndpointReturnsUnchangedForActiveRevision(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config := cloneJSONObject(routerOSReadyConfig(t))
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	source, err := runtimeconfig.RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, RouterOSSource: source, Actor: "test"}); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/plan", map[string]any{"config": config}, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("plan failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	if body["valid"] != true || body["idempotent"] != true || body["apply_mode"] != "unchanged" || body["routeros_changed"] != false {
		t.Fatalf("unexpected unchanged plan: %#v", body)
	}
	steps := body["steps"].([]any)
	if len(steps) != 1 || steps[0].(map[string]any)["kind"] != "verify" {
		t.Fatalf("unexpected unchanged steps: %#v", steps)
	}
}

func TestPlanEndpointRequiresSessionAndDoesNotPersistProvidedConfig(t *testing.T) {
	server := newTestServer(t)
	unauthorized := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/plan", map[string]any{}, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated plan returned %d", unauthorized.Code)
	}
	cookie, _ := bootstrapSession(t, server)
	stored, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	provided := cloneJSONObject(stored)
	provided["schema_version"] = 99
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/plan", map[string]any{"config": provided}, nil, cookie)
	if response.Code != http.StatusOK || decodeResponse(t, response)["valid"] != false {
		t.Fatalf("invalid candidate plan failed: %d %s", response.Code, response.Body.String())
	}
	after, err := server.getDraft()
	if err != nil || !equalJSON(stored, after) {
		t.Fatalf("plan mutated stored draft: err=%v", err)
	}
	nonObject := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/plan", map[string]any{"config": "bad"}, nil, cookie)
	if nonObject.Code != http.StatusUnprocessableEntity {
		t.Fatalf("non-object plan config returned %d", nonObject.Code)
	}
}

func TestPlanUsesCommittedNodeSnapshotLikeApply(t *testing.T) {
	server := newTestServer(t)
	active := routerOSReadyConfig(t)
	activeRevision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(activeRevision); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("subscription-nodes-"+activeRevision, map[string]any{
		"revision": activeRevision,
		"nodes": []any{map[string]any{
			"id": "old-node", "server": "203.0.113.7",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	desired := cloneJSONObject(active)
	profile := desired["tls_profiles"].([]any)[0].(map[string]any)
	profile["display_name"] = "Runtime-only label"
	plan, err := server.buildPlan(desired)
	if err != nil {
		t.Fatal(err)
	}
	if plan["routeros_changed"] != true || plan["apply_mode"] != "routeros_safe_mode" {
		t.Fatalf("plan disagrees with Apply node snapshot semantics: %#v", plan)
	}
}

func TestPlanChangesRedactSensitiveValues(t *testing.T) {
	changes := redactPlanChanges([]planChange{{
		Operation: "add", Path: "$.subscriptions[id=private]",
		After: map[string]any{"url": "https://user:secret@example.test/token", "name": "Private"},
	}})
	after := changes[0].After.(map[string]any)
	if after["url"] == "https://user:secret@example.test/token" || after["name"] != "Private" {
		t.Fatalf("plan redaction failed: %#v", after)
	}
}

func TestFlattenPlanChangesUsesStableEntityPaths(t *testing.T) {
	before := map[string]any{"nodes": []any{
		map[string]any{"id": "b", "name": "old"},
		map[string]any{"id": "a", "enabled": true},
	}}
	after := map[string]any{"nodes": []any{
		map[string]any{"id": "a", "enabled": false},
		map[string]any{"id": "c", "name": "new"},
	}}
	changes := flattenPlanChanges(before, after, "$")
	want := []string{"$.nodes[id=a].enabled", "$.nodes[id=b]", "$.nodes[id=c]"}
	if len(changes) != len(want) {
		t.Fatalf("changes = %#v", changes)
	}
	for index, path := range want {
		if changes[index].Path != path {
			t.Fatalf("change %d path = %q, want %q", index, changes[index].Path, path)
		}
	}
}
