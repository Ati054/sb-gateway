package controlplane

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSubscriptionArtifactRetentionKeepsOnlyLiveAndRollbackGenerations(t *testing.T) {
	server := newTestServer(t)
	active := strings.Repeat("a", 64)
	previous := strings.Repeat("b", 64)
	currentState := subscriptionStateWithSecret("quattro", "1111111111111111")
	activeState := subscriptionStateWithSecret("quattro", "2222222222222222")
	previousState := subscriptionStateWithSecret("quattro", "3333333333333333")
	if err := server.repository.writeJSON(filepath.Join(server.repository.root, "active.json"), map[string]any{"revision": active}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.writeJSON(filepath.Join(server.repository.root, "last-known-good.json"), map[string]any{"revision": active}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("apply-metadata", map[string]any{"previous_revision": previous}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("subscription-nodes-"+active, activeState); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("subscription-nodes-"+previous, previousState); err != nil {
		t.Fatal(err)
	}
	staleRevision := strings.Repeat("c", 64)
	if err := server.repository.saveAuxiliary("subscription-nodes-"+staleRevision, subscriptionStateWithSecret("quattro", "4444444444444444")); err != nil {
		t.Fatal(err)
	}
	for _, generation := range []string{"1111111111111111", "2222222222222222", "3333333333333333", "4444444444444444"} {
		path := filepath.Join(server.secrets.root, "subscriptions", "quattro", "generations", generation)
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(path, "node.uuid"), []byte("secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := server.pruneSubscriptionArtifacts(currentState); err != nil {
		t.Fatal(err)
	}
	for _, generation := range []string{"1111111111111111", "2222222222222222", "3333333333333333"} {
		if _, err := os.Stat(filepath.Join(server.secrets.root, "subscriptions", "quattro", "generations", generation)); err != nil {
			t.Fatalf("retained generation %s is missing: %v", generation, err)
		}
	}
	if _, err := os.Stat(filepath.Join(server.secrets.root, "subscriptions", "quattro", "generations", "4444444444444444")); !os.IsNotExist(err) {
		t.Fatalf("stale generation remains: %v", err)
	}
	if _, err := os.Stat(filepath.Join(server.repository.root, "subscription-nodes-"+staleRevision+".json")); !os.IsNotExist(err) {
		t.Fatalf("stale snapshot remains: %v", err)
	}
}

func subscriptionStateWithSecret(subscriptionID, generation string) map[string]any {
	return map[string]any{subscriptionID: map[string]any{
		"nodes": []any{map[string]any{
			"uuid_secret_ref": "subscriptions/" + subscriptionID + "/generations/" + generation + "/node.uuid",
		}},
	}}
}
