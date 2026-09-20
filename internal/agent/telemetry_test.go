package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestTelemetryParsers(t *testing.T) {
	stats, err := parseXrayStats([]byte(`{"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":"120"},{"name":"user>>>alice>>>traffic>>>downlink","value":800}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if stats["alice"] != (counterPair{Uplink: 120, Downlink: 800}) {
		t.Fatalf("unexpected stats: %#v", stats)
	}
	online, err := parseXrayOnlineUsers([]byte(`{"users":["alice","bob"]}`))
	if err != nil || len(online) != 2 {
		t.Fatalf("unexpected online users: %#v, %v", online, err)
	}
	nft, err := parseNFTCounters([]byte(`{"nftables":[{"counter":{"name":"c_a_u","bytes":10}}]}`))
	if err != nil || nft["c_a_u"] != 10 {
		t.Fatalf("unexpected nft counters: %#v, %v", nft, err)
	}
}

func TestCounterResetAndNames(t *testing.T) {
	if counterDelta(20, 150) != 20 || counterDelta(150, 100) != 50 {
		t.Fatal("counter reset semantics changed")
	}
	uplink, downlink := telemetryCounterNames("phone")
	if uplink != "c_45569da57f4b7bf4_u" || downlink != "c_45569da57f4b7bf4_d" {
		t.Fatalf("unstable nft names: %s %s", uplink, downlink)
	}
}

func TestLoadsActiveGenerationAndFallsBackToDraft(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "generations"), 0o700); err != nil {
		t.Fatal(err)
	}
	revision := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	writeFixture(t, filepath.Join(root, "active.json"), map[string]any{"revision": revision})
	writeFixture(t, filepath.Join(root, "generations", revision+".json"), map[string]any{"local_clients": []map[string]any{{"id": "active"}}})
	writeFixture(t, filepath.Join(root, "draft.json"), map[string]any{"local_clients": []map[string]any{{"id": "draft"}}})
	config, err := loadActiveConfig(root)
	if err != nil || len(config.LocalClients) != 1 || config.LocalClients[0].ID != "active" {
		t.Fatalf("unexpected active config: %#v, %v", config, err)
	}
	if err := os.Remove(filepath.Join(root, "active.json")); err != nil {
		t.Fatal(err)
	}
	config, err = loadActiveConfig(root)
	if err != nil || config.LocalClients[0].ID != "draft" {
		t.Fatalf("unexpected draft config: %#v, %v", config, err)
	}
}

func TestInterestMarkerUsesBoundedAge(t *testing.T) {
	path := filepath.Join(t.TempDir(), "interest")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !recentlyInterested(path, info.ModTime().Add(30*time.Second), 45*time.Second) {
		t.Fatal("fresh interest was ignored")
	}
	if recentlyInterested(path, info.ModTime().Add(time.Minute), 45*time.Second) {
		t.Fatal("stale interest remained active")
	}
}

func TestEnabledClientsDefaultsToEnabled(t *testing.T) {
	disabled := false
	values := []clientConfig{{ID: "one"}, {ID: "two", Enabled: &disabled}, {ID: ""}}
	if actual := enabledClients(values); !reflect.DeepEqual(actual, []clientConfig{{ID: "one"}}) {
		t.Fatalf("unexpected clients: %#v", actual)
	}
}

func writeFixture(t *testing.T, path string, value any) {
	t.Helper()
	body, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
}
