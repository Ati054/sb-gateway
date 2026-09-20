package controlplane

import (
	"context"
	"encoding/json"
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
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "provider", command); err != nil {
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
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "provider-static", command); err != nil {
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
	if err := selectSubscriptionXrayOutbound(context.Background(), options, "provider", command); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"bi"}) {
		t.Fatalf("commands=%v want=[bi]", commands)
	}
}
