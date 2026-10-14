package agent

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func startupReverseFixture(t *testing.T, mode string, candidates []string, selected string) (string, Options) {
	t.Helper()
	root := t.TempDir()
	config, poolPath := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	writeFixture(t, config, map[string]any{"routing": map[string]any{"balancers": []any{
		map[string]any{"tag": "europe", "selector": append([]string{"block"}, candidates...)},
	}}})
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Mode, contract.Candidates = mode, candidates
	contract.Nodes["reverse-vless-home"] = healthNode{Protocol: "xray-reverse"}
	contract.Nodes["reverse-vless-away"] = healthNode{Protocol: "xray-reverse"}
	pool.HealthPolicies["europe"] = contract
	writeFixture(t, poolPath, pool)
	if selected != "" {
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed, item.Mode = selected, selected, true, mode
		item.CandidateSignature = strings.Join(candidates, "\n")
		item.AvailabilityOK = map[string]bool{selected: true}
		writeFixture(t, statePath(root, "selector-health"), healthState{"europe": item})
	}
	return config, Options{StateRoot: root, HealthPoolFile: poolPath, StartupReverseWait: 30 * time.Second}
}

func TestStartupReverseWaitEligibility(t *testing.T) {
	for _, tc := range []struct {
		name, mode, selected, want string
		candidates                 []string
	}{
		{"saved reverse", "priority", "reverse-vless-home", "reverse-vless-home", []string{"reverse-vless-home", "de"}},
		{"saved second reverse", "priority", "reverse-vless-away", "reverse-vless-away", []string{"reverse-vless-home", "reverse-vless-away", "de"}},
		{"saved ordinary", "priority", "de", "", []string{"reverse-vless-home", "de"}},
		{"new first reverse", "priority", "", "reverse-vless-home", []string{"reverse-vless-home", "de"}},
		{"reverse reserve", "priority", "", "", []string{"de", "reverse-vless-home"}},
		{"mixed URLTest", "best", "reverse-vless-home", "", []string{"reverse-vless-home", "de"}},
		{"reverse only", "best", "", "reverse-vless-home", []string{"reverse-vless-home"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, opts := startupReverseFixture(t, tc.mode, tc.candidates, tc.selected)
			plan, err := xrayStartupPlan(config, opts)
			if err != nil || plan.Reverse["europe"].Outbound != tc.want {
				t.Fatalf("reverse plan=%v want=%q err=%v", plan.Reverse, tc.want, err)
			}
			needed, err := XrayStartupNeedsReverseWait(config, opts)
			if err != nil || needed != (tc.want != "") {
				t.Fatalf("wait eligibility=%v err=%v", needed, err)
			}
			if len(plan.Balancers) != 1 || plan.Balancers[0].Outbound == "reverse-vless-home" || plan.Balancers[0].Outbound == "reverse-vless-away" {
				t.Fatal("unconnected reverse was selected before proof")
			}
		})
	}
}

func TestStartupReverseWaitWithConvertedPrunedSelectors(t *testing.T) {
	for _, selected := range []string{"reverse-vless-home", "de"} {
		t.Run(selected, func(t *testing.T) {
			config, opts := startupReverseFixture(t, "priority", []string{"reverse-vless-home", "de"}, selected)
			values := []map[string]any{
				{"type": "selector", "tag": "europe", "outbounds": []string{"block", "reverse-vless-home", "de", "sb-urltest-fixture-"}},
				{"type": "block", "tag": "block"},
				{"type": "direct", "tag": "reverse-vless-home"},
				{"type": "direct", "tag": "de"},
			}
			converted, err := runtimeconfig.ConvertXrayOutbounds(values, "", nil, map[string]struct{}{"reverse-vless-home": {}})
			if err != nil {
				t.Fatal(err)
			}
			var pool healthPool
			if err := readJSON(opts.HealthPoolFile, &pool); err != nil {
				t.Fatal(err)
			}
			pool.PolicyPrefixes = map[string]string{"europe": "sb-urltest-fixture-"}
			pool.Policies = map[string][]string{"europe": {"reverse-vless-home", "de"}}
			pool.BaseOutboundTags = []string{"block", "reverse-vless-home"}
			pool.Outbounds = map[string]json.RawMessage{"de": json.RawMessage(`{"tag":"de","protocol":"freedom"}`)}
			body, err := json.Marshal(pool)
			if err != nil {
				t.Fatal(err)
			}
			graph := map[string]any{"outbounds": converted.Outbounds, "routing": map[string]any{"balancers": converted.Balancers}}
			if err := runtimeconfig.PruneDynamicXrayOutbounds(graph, body); err != nil {
				t.Fatal(err)
			}
			writeFixture(t, config, graph)
			writeFixture(t, opts.HealthPoolFile, pool)
			plan, err := xrayStartupPlan(config, opts)
			if err != nil || len(plan.Balancers) != 1 || plan.Balancers[0].Outbound != "de" {
				t.Fatalf("pruned plan=%+v err=%v", plan, err)
			}
			if got := plan.Reverse["europe"].Outbound; (got != "") != (selected == "reverse-vless-home") {
				t.Fatalf("reverse wait=%q selected=%q", got, selected)
			}
		})
	}
}

func TestStartupReverseWaitRespectsEditsAndConfirmedFailure(t *testing.T) {
	for _, scenario := range []string{"reordered", "removed", "failed"} {
		t.Run(scenario, func(t *testing.T) {
			config, opts := startupReverseFixture(t, "priority", []string{"reverse-vless-home", "de"}, "reverse-vless-home")
			var pool healthPool
			if err := readJSON(opts.HealthPoolFile, &pool); err != nil {
				t.Fatal(err)
			}
			contract := pool.HealthPolicies["europe"]
			switch scenario {
			case "reordered":
				contract.Candidates = []string{"de", "reverse-vless-home"}
			case "removed":
				contract.Candidates = []string{"de"}
			case "failed":
				var state healthState
				if err := readJSON(statePath(opts.StateRoot, "selector-health"), &state); err != nil {
					t.Fatal(err)
				}
				state["europe"].AvailabilityFailures["reverse-vless-home"] = healthFailureConfirmations
				writeFixture(t, statePath(opts.StateRoot, "selector-health"), state)
			}
			pool.HealthPolicies["europe"] = contract
			writeFixture(t, opts.HealthPoolFile, pool)
			plan, err := xrayStartupPlan(config, opts)
			if err != nil || len(plan.Reverse) != 0 {
				t.Fatalf("obsolete reverse intent survived %s: %v %v", scenario, plan.Reverse, err)
			}
		})
	}
}

func TestStartupReverseWaitOneProofAndSharedWindow(t *testing.T) {
	choices := map[string]startupReverseChoice{
		"one": {Outbound: "reverse", Services: map[string]string{"allowed": "reverse", "denied": "block"}},
		"two": {Outbound: "reverse"},
	}
	called := 0
	started := time.Now()
	got := awaitStartupReverse(context.Background(), time.Second, choices, func(context.Context, string) probeEvidence {
		called++
		return successfulEvidence(20)
	})
	want := map[string]string{"one": "reverse", "two": "reverse", "allowed": "reverse", "denied": "block"}
	if called != 1 || !reflect.DeepEqual(got, want) || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("first proof was delayed or duplicated: %v calls=%d", got, called)
	}
	choices["two"] = startupReverseChoice{Outbound: "other"}
	started = time.Now()
	got = awaitStartupReverse(context.Background(), 25*time.Millisecond, choices, func(context.Context, string) probeEvidence { return failedEvidence() })
	if len(got) != 0 || time.Since(started) > 500*time.Millisecond {
		t.Fatal("multiple offline profiles exceeded one common window")
	}
}

func TestStartupReverseWaitRejectsUnprovenAndCanceledPaths(t *testing.T) {
	for _, evidence := range []probeEvidence{{}, {OK: true, LocalFailure: true}, {OK: true, Deferred: true}} {
		got := awaitStartupReverse(context.Background(), time.Millisecond, map[string]startupReverseChoice{"one": {Outbound: "reverse"}}, func(context.Context, string) probeEvidence { return evidence })
		if len(got) > 0 {
			t.Fatal("unproven route was restored")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := awaitStartupReverse(ctx, time.Second, map[string]startupReverseChoice{"one": {Outbound: "reverse"}}, func(context.Context, string) probeEvidence {
		t.Fatal("canceled startup invoked probe")
		return successfulEvidence(1)
	}); len(got) > 0 {
		t.Fatal("canceled startup restored reverse")
	}
	parent, stop := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer stop()
	awaitStartupReverse(parent, time.Second, map[string]startupReverseChoice{"one": {Outbound: "reverse"}}, func(context.Context, string) probeEvidence {
		t.Fatal("wait consumed reserved selector budget")
		return probeEvidence{}
	})
}

func TestStartupReverseWaitCancelsInFlightProbe(t *testing.T) {
	started := time.Now()
	got := awaitStartupReverse(context.Background(), 20*time.Millisecond, map[string]startupReverseChoice{"one": {Outbound: "reverse"}}, func(ctx context.Context, _ string) probeEvidence {
		<-ctx.Done()
		return successfulEvidence(1)
	})
	if len(got) > 0 || time.Since(started) > 500*time.Millisecond {
		t.Fatal("late proof crossed wait deadline")
	}
}

func TestStartupReverseWaitScriptBudgetIsConditional(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "run-xray.sh"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`reverse_wait_seconds=$((selector_timeout_seconds - 30))`, `reverse_wait_seconds=30`, `selector_timeout_seconds=30`, `--reverse-wait "${reverse_wait_seconds}s"`} {
		if !strings.Contains(string(body), required) {
			t.Fatalf("missing conditional budget %s", required)
		}
	}
}

func TestStartupReverseWaitRestoresOnlyAfterLiveProof(t *testing.T) {
	config, opts := startupReverseFixture(t, "priority", []string{"reverse-vless-home", "de"}, "reverse-vless-home")
	requests := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusNoContent)
	}))
	defer proxy.Close()
	opts.ProbeURL = proxy.URL
	selections := map[string]string{}
	runtime := newXraySelectorRuntime(opts)
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "lso":
			return []byte(`{"outbounds":[{"tag":"reverse-vless-home"}]}`), nil
		case "statsonline":
			return []byte(`{"stat":{"name":"user>>>reverse-vless-home>>>online","value":1}}`), nil
		case "bo":
			selector, target := args[4], args[5]
			if selector == "europe" && requests == 0 {
				t.Fatal("policy selected Reverse before a successful probe")
			}
			selections[selector] = target
			return nil, nil
		case "bi":
			return selectorInfo(selections[args[3]]), nil
		}
		t.Fatalf("unexpected command: %v", args)
		return nil, nil
	}
	// Use a local HTTP target to isolate ordering from public TLS availability.
	targets := slices.Clone(healthTargets)
	healthTargets[0].url = "http://startup-test.invalid/"
	defer func() { healthTargets = targets }()
	if err := restoreXraySelectors(config, opts, runtime); err != nil {
		t.Fatal(err)
	}
	if selections["europe"] != "reverse-vless-home" || requests != 1 {
		t.Fatalf("selection=%v requests=%d", selections, requests)
	}
}

func TestStartupReverseWaitPinnedCoreOfflineFallback(t *testing.T) {
	binary := os.Getenv("SB_TEST_XRAY")
	if binary == "" {
		t.Skip("set SB_TEST_XRAY for the loopback pinned-core startup test")
	}
	config, opts := startupReverseFixture(t, "priority", []string{"reverse-vless-home", "de"}, "reverse-vless-home")
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	writeFixture(t, config, map[string]any{
		"log":       map[string]any{"loglevel": "warning"},
		"api":       map[string]any{"tag": "api", "services": []string{"RoutingService", "StatsService"}},
		"stats":     map[string]any{},
		"inbounds":  []any{map[string]any{"tag": "api-in", "listen": "127.0.0.1", "port": port, "protocol": "dokodemo-door", "settings": map[string]any{"address": "127.0.0.1"}}},
		"outbounds": []any{map[string]any{"tag": "de", "protocol": "freedom"}, map[string]any{"tag": "block", "protocol": "blackhole"}},
		"routing": map[string]any{
			"balancers": []any{map[string]any{"tag": "europe", "selector": []string{"block", "reverse-vless-home", "de"}, "strategy": map[string]any{"type": "random"}}},
			"rules":     []any{map[string]any{"type": "field", "inboundTag": []string{"api-in"}, "outboundTag": "api"}},
		},
	})
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	args := []string{"run", "-config", config}
	if runner := os.Getenv("SB_TEST_XRAY_RUNNER"); runner != "" {
		args, binary = append([]string{binary}, args...), runner
	}
	process := exec.CommandContext(ctx, binary, args...)
	logFile, err := os.Create(filepath.Join(opts.StateRoot, "core.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()
	process.Stdout, process.Stderr = logFile, logFile
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { process.Process.Kill(); process.Wait() }()
	ready := false
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		conn, dialErr := net.DialTimeout("tcp", address, 50*time.Millisecond)
		if dialErr == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated core API did not start")
	}
	opts.XrayAPIServer, opts.StartupReverseWait = address, 100*time.Millisecond
	started := time.Now()
	if err := RestoreXraySelectors(ctx, config, opts); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 80*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("offline wait elapsed=%s", elapsed)
	}
	control, err := newXrayControlClient(address)
	if err != nil {
		t.Fatal(err)
	}
	defer control.close()
	selected, err := control.selected(ctx, "europe")
	if err != nil || selected != "de" {
		t.Fatalf("fallback=%q err=%v", selected, err)
	}
}
