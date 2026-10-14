package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync/atomic"
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

func TestReverseConnectionsUseExistingOnlineSnapshot(t *testing.T) {
	disabled := false
	exits := []clientConfig{{ID: "home"}, {ID: "away"}, {ID: "disabled", Enabled: &disabled}, {ID: ""}}
	online, err := parseXrayOnlineUsers([]byte(`{"users":["user>>>reverse-vless-home>>>online","user>>>remote-user>>>online","user>>>bad>>>traffic>>>uplink","user>>>>>>online"]}`))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(online, map[string]struct{}{"reverse-vless-home": {}, "remote-user": {}}) {
		t.Fatalf("online statistic names were not normalized: %#v", online)
	}
	want := map[string]bool{"home": true, "away": false, "disabled": false}
	if got := reverseConnectionSnapshot(exits, online, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected reverse snapshot: %#v", got)
	}
	if got := reverseConnectionSnapshot(exits, online, errors.New("API unavailable")); len(got) != 0 {
		t.Fatalf("failed API snapshot must not claim connected or disconnected: %#v", got)
	}
}

func TestReverseConnectionsIncludeUnusedLiveSessions(t *testing.T) {
	disabled := false
	exits := []clientConfig{{ID: "used"}, {ID: "unused"}, {ID: "disabled", Enabled: &disabled}}
	online := map[string]struct{}{
		"reverse-vless-used": {}, "reverse-vless-unused": {},
		"reverse-vless-disabled": {}, "reverse-vless-new": {},
		"reverse-vless-": {}, "ordinary": {},
	}
	want := map[string]bool{"used": true, "unused": true, "disabled": true, "new": true}
	if got := reverseConnectionSnapshot(exits, online, nil); !reflect.DeepEqual(got, want) {
		t.Fatalf("live connection was hidden by configuration or route usage: %v", got)
	}
	delete(online, "reverse-vless-unused")
	if got := reverseConnectionSnapshot(exits, online, nil); got["unused"] {
		t.Fatal("disconnected profile retained its old connection state")
	}
}

func TestOnlineTelemetryIndependentOfTrafficCounters(t *testing.T) {
	online := commandResult{body: []byte(`{"users":["reverse-vless-unused"]}`)}
	for _, stats := range []commandResult{
		{err: errors.New("counter timeout")}, {body: []byte(`invalid`)},
	} {
		got := decodeRemoteMeasurements(stats, online)
		if got.statsErr == nil || got.onlineErr != nil || !reverseConnectionSnapshot(nil, got.online, got.onlineErr)["unused"] {
			t.Fatalf("counter failure hid live connection: %+v", got)
		}
	}
	stats := commandResult{body: []byte(`{"stat":[{"name":"user>>>ordinary>>>traffic>>>uplink","value":12}]}`)}
	for _, failed := range []commandResult{{err: errors.New("online timeout")}, {body: []byte(`invalid`)}} {
		got := decodeRemoteMeasurements(stats, failed)
		if got.statsErr != nil || got.onlineErr == nil || len(reverseConnectionSnapshot(nil, got.online, got.onlineErr)) != 0 {
			t.Fatalf("failed online request claimed a connection status: %+v", got)
		}
	}
}

func TestTelemetryTickKeepsUnusedReverseWithoutHTTP(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell API fixtures run on Linux")
	}
	root := t.TempDir()
	writeFixture(t, filepath.Join(root, "draft.json"), map[string]any{
		"reverse_vless_exits": []any{map[string]any{"id": "used"}, map[string]any{"id": "unused"}},
		"policies":            []any{map[string]any{"id": "route", "selection_order": []string{"reverse:used"}}},
	})
	binary := filepath.Join(root, "telemetry-fixture")
	script := `#!/bin/sh
case "$2" in
statsquery) exit 1 ;;
statsgetallonlineusers) printf '%s\n' '{"users":["reverse-vless-used","reverse-vless-unused","reverse-vless-new"]}' ;;
list) printf '%s\n' '{"nftables":[]}' ;;
*) exit 99 ;;
esac
`
	if err := os.WriteFile(binary, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	collector := newTelemetryCollector(Options{StateRoot: root, XrayBinary: binary, NFTBinary: binary, ProbeURL: server.URL})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := collector.Tick(ctx, time.Now()); err != nil {
		t.Fatal(err)
	}
	var state telemetryState
	if err := readJSON(statePath(root, "client-telemetry"), &state); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"used": true, "unused": true, "new": true}
	if !reflect.DeepEqual(state.Snapshot.ReverseConnections, want) || state.Snapshot.Sources["xray_online"] != "available" || state.Snapshot.Sources["xray"] != "unavailable" {
		t.Fatalf("independent connection snapshot lost: %+v", state.Snapshot)
	}
	if requests.Load() != 0 {
		t.Fatal("connection telemetry made an HTTP probe")
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
	writeFixture(t, filepath.Join(root, "generations", revision+".json"), map[string]any{"local_clients": []map[string]any{{"id": "active"}}, "reverse_vless_exits": []map[string]any{{"id": "active-reverse"}}})
	writeFixture(t, filepath.Join(root, "draft.json"), map[string]any{"local_clients": []map[string]any{{"id": "draft"}}})
	config, err := loadActiveConfig(root)
	if err != nil || len(config.LocalClients) != 1 || config.LocalClients[0].ID != "active" {
		t.Fatalf("unexpected active config: %#v, %v", config, err)
	}
	if len(config.ReverseExits) != 1 || config.ReverseExits[0].ID != "active-reverse" {
		t.Fatal("reverse telemetry must follow the active generation")
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
