package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestSubscriptionUpdateSelectorHotSwapsDynamicOutbound(t *testing.T) {
	root := t.TempDir()
	poolPath := filepath.Join(root, "urltest-pool.json")
	raw := json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4"}`)
	body, err := json.Marshal(map[string]any{"version": 3, "outbounds": map[string]json.RawMessage{"provider": raw}})
	if err != nil || os.WriteFile(poolPath, body, 0o600) != nil {
		t.Fatal(err)
	}
	options := RuntimeOptions{XrayHealthPool: poolPath, XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"}
	wantTag := runtimeconfig.DynamicOutboundTag(subscriptionUpdateDynamicPrefix, "provider", raw)
	selected := subscriptionUpdateDynamicPrefix + "retired"
	commands := make([]string, 0)
	command := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		switch args[1] {
		case "bi":
			return []byte("  - Selecting Override:\n    1   " + selected + "\n  - Selects:\n"), nil
		case "ado":
			candidateBody, readErr := os.ReadFile(args[len(args)-1])
			if readErr != nil {
				t.Fatal(readErr)
			}
			if !strings.Contains(string(candidateBody), wantTag) {
				t.Fatalf("dynamic candidate has no generated tag: %s", candidateBody)
			}
			return nil, nil
		case "bo":
			selected = args[len(args)-1]
			return nil, nil
		case "rmo":
			return nil, nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "provider", command, nil); err != nil {
		t.Fatal(err)
	}
	wantCommands := []string{"bi", "ado", "bo", "bi", "rmo"}
	if !reflect.DeepEqual(commands, wantCommands) {
		t.Fatalf("commands=%v want=%v", commands, wantCommands)
	}
	if selected != wantTag {
		t.Fatalf("selected=%q want=%q", selected, wantTag)
	}
}

func TestSubscriptionUpdateSelectorUsesStaticOutboundWithoutHandlerMutation(t *testing.T) {
	root := t.TempDir()
	poolPath := filepath.Join(root, "urltest-pool.json")
	if err := os.WriteFile(poolPath, []byte(`{"version":3,"outbounds":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	options := RuntimeOptions{XrayHealthPool: poolPath, XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"}
	selected := "direct-wan"
	commands := make([]string, 0)
	command := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		if args[1] == "bo" {
			selected = args[len(args)-1]
			return nil, nil
		}
		return []byte("  - Selecting Override:\n    1   " + selected + "\n  - Selects:\n"), nil
	}
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "provider-static", command, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"bi", "bo", "bi"}) || selected != "provider-static" {
		t.Fatalf("commands=%v selected=%q", commands, selected)
	}
}

func TestSubscriptionUpdateSelectorReusesSelectedDynamicOutbound(t *testing.T) {
	root := t.TempDir()
	poolPath := filepath.Join(root, "urltest-pool.json")
	raw := json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4"}`)
	body, err := json.Marshal(map[string]any{"version": 3, "outbounds": map[string]json.RawMessage{"provider": raw}})
	if err != nil || os.WriteFile(poolPath, body, 0o600) != nil {
		t.Fatal(err)
	}
	wantTag := runtimeconfig.DynamicOutboundTag(subscriptionUpdateDynamicPrefix, "provider", raw)
	commands := make([]string, 0)
	command := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		if args[1] != "bi" {
			t.Fatalf("selected dynamic outbound must not be mutated: %v", args)
		}
		return []byte("  - Selecting Override:\n    1   " + wantTag + "\n  - Selects:\n"), nil
	}
	options := RuntimeOptions{XrayHealthPool: poolPath, XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"}
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "provider", command, nil); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"bi"}) {
		t.Fatalf("commands=%v want=[bi]", commands)
	}
}

func TestSubscriptionUpdateSelectorRetriesRetiredHandlerCleanupAcrossCalls(t *testing.T) {
	root := t.TempDir()
	repository, err := newStateRepository(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	poolPath := filepath.Join(root, "pool.json")
	readyPath := filepath.Join(root, "xray-ready")
	if err := os.WriteFile(readyPath, []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outbounds := map[string]json.RawMessage{}
	tags := map[string]string{}
	for _, node := range []string{"a", "b", "c"} {
		raw := json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4","node":"` + node + `"}`)
		outbounds[node] = raw
		tags[node] = runtimeconfig.DynamicOutboundTag(subscriptionUpdateDynamicPrefix, node, raw)
	}
	body, err := json.Marshal(map[string]any{"version": 3, "outbounds": outbounds})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(poolPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	options := RuntimeOptions{XrayHealthPool: poolPath, XrayReadyFile: readyPath, XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"}
	selected := tags["a"]
	loaded := map[string]bool{selected: true}
	removed := []string{}
	failRemoval := true
	command := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "bi":
			return []byte("  - Selecting Override:\n    1   " + selected + "\n  - Selects:\n"), nil
		case "ado":
			candidate, readErr := os.ReadFile(args[len(args)-1])
			if readErr != nil {
				t.Fatal(readErr)
			}
			var payload struct {
				Outbounds []struct {
					Tag string `json:"tag"`
				} `json:"outbounds"`
			}
			if err := json.Unmarshal(candidate, &payload); err != nil || len(payload.Outbounds) != 1 {
				t.Fatalf("invalid added outbound: %v", err)
			}
			loaded[payload.Outbounds[0].Tag] = true
			return nil, nil
		case "bo":
			selected = args[len(args)-1]
			return nil, nil
		case "rmo":
			tag := args[len(args)-1]
			if tag == selected {
				t.Fatal("attempted to remove active outbound")
			}
			removed = append(removed, tag)
			if failRemoval {
				return nil, errors.New("temporary API failure")
			}
			delete(loaded, tag)
			return nil, nil
		default:
			t.Fatalf("unexpected command: %v", args)
			return nil, nil
		}
	}
	for _, node := range []string{"b", "c"} {
		if err := selectSubscriptionXrayOutbound(context.Background(), options, node, command, repository); err != nil {
			t.Fatal(err)
		}
	}
	if !reflect.DeepEqual(removed, []string{tags["a"]}) || !loaded[tags["a"]] {
		t.Fatalf("unconfirmed removal lost handler: removed=%v loaded=%v", removed, loaded)
	}
	state, err := repository.auxiliary(subscriptionUpdateRetirementState)
	if err != nil || !reflect.DeepEqual(collectionArray(state["tags"]), []any{tags["a"], tags["b"]}) {
		t.Fatalf("retirement journal was not retained: state=%v err=%v", state, err)
	}
	failRemoval = false
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "c", command, repository); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{tags["a"], tags["a"]}) || loaded[tags["a"]] || !loaded[tags["b"]] || selected != tags["c"] {
		t.Fatalf("cleanup retry failed: removed=%v loaded=%v selected=%s", removed, loaded, selected)
	}
	state, err = repository.auxiliary(subscriptionUpdateRetirementState)
	if err != nil || !reflect.DeepEqual(collectionArray(state["tags"]), []any{tags["b"]}) {
		t.Fatalf("only the newest previous handler should remain: state=%v err=%v", state, err)
	}
	if err := os.WriteFile(readyPath, []byte("124\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "c", command, repository); err != nil {
		t.Fatal(err)
	}
	state, err = repository.auxiliary(subscriptionUpdateRetirementState)
	if err != nil || len(collectionArray(state["tags"])) != 0 || state["xray_pid"] != "124" {
		t.Fatalf("old-process handlers retained after Xray restart: state=%v err=%v", state, err)
	}
}

func TestSubscriptionUpdateSelectorReclaimsUnselectedHandlerAfterLostAddResponse(t *testing.T) {
	root := t.TempDir()
	repository, err := newStateRepository(filepath.Join(root, "state"))
	if err != nil {
		t.Fatal(err)
	}
	poolPath := filepath.Join(root, "pool.json")
	a := json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4"}`)
	b := json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.5"}`)
	body, err := json.Marshal(map[string]any{"version": 3, "outbounds": map[string]json.RawMessage{"a": a, "b": b}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(poolPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	options := RuntimeOptions{XrayHealthPool: poolPath, XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"}
	selected := runtimeconfig.DynamicOutboundTag(subscriptionUpdateDynamicPrefix, "a", a)
	candidate := runtimeconfig.DynamicOutboundTag(subscriptionUpdateDynamicPrefix, "b", b)
	loaded := map[string]bool{selected: true}
	command := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "bi":
			return []byte("  - Selecting Override:\n    1   " + selected + "\n  - Selects:\n"), nil
		case "ado":
			loaded[candidate] = true
			return nil, errors.New("response lost after add")
		case "rmo":
			if args[len(args)-1] != candidate || selected == candidate {
				t.Fatalf("unsafe cleanup: %v", args)
			}
			delete(loaded, candidate)
			return nil, nil
		default:
			t.Fatalf("unexpected command: %v", args)
			return nil, nil
		}
	}
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "b", command, repository); err == nil {
		t.Fatal("lost add response was incorrectly reported as success")
	}
	if !loaded[candidate] {
		t.Fatal("test did not create unselected handler")
	}
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "a", command, repository); err != nil {
		t.Fatal(err)
	}
	if loaded[candidate] || !loaded[selected] {
		t.Fatalf("unselected handler was not reclaimed: %v", loaded)
	}
}
