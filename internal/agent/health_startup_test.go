package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestXrayStartupMarkerRejectsPreviousProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ready")
	if xrayStartupReady(path, 20) {
		t.Fatal("missing marker accepted")
	}
	if err := os.WriteFile(path, []byte("20\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if !xrayStartupReady(path, 20) || xrayStartupReady(path, 21) || xrayStartupReady(path, 0) {
		t.Fatal("startup marker must match exactly the running core PID")
	}
}

func TestXrayStartupOrderPinsBeforeRoutingAndHealth(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "run-xray.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	clear := strings.Index(script, `rm -f "$selectors_ready"`)
	start := strings.Index(script, `xray run -config "$config" >>"$process_log" 2>&1 &`)
	restore := strings.Index(script, `if ! sb-gateway xray-balancers --apply`)
	routing := strings.Index(script, `if ! /bin/sh /opt/sb-gateway/scripts/configure-transparent-routing.sh apply; then`)
	ready := strings.Index(script, `printf '%s\n' "$xray_pid" >"$selectors_ready"`)
	if clear < 0 || start <= clear || restore <= start || routing <= restore || ready <= routing {
		t.Fatal("startup must clear marker, start core, restore selectors, admit routing, then release health")
	}
}

func TestXrayStartupUsesOneBoundedReadinessAndRestoreBudget(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "run-xray.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	for _, required := range []string{
		`configured_startup_timeout_seconds="${SB_XRAY_STARTUP_TIMEOUT_SECONDS:-}"`,
		`elif [ "$skip_validation" -eq 1 ]; then`,
		`startup_timeout_seconds=15`,
		`startup_timeout_seconds=30`,
		`startup_deadline=$((startup_started + startup_timeout_seconds))`,
		`while [ "$xray_api_ready" -ne 1 ]; do`,
		`selector_timeout_seconds=$((startup_deadline - startup_now))`,
		`--timeout "${selector_timeout_seconds}s"`,
		`process_log_limit_bytes="${SB_XRAY_PROCESS_LOG_LIMIT_BYTES:-4194304}"`,
		`mv "$process_log" "$process_log.1"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("startup script is missing shared deadline contract %q", required)
		}
	}
	if strings.Contains(script, `tun_attempt`) || strings.Contains(script, `xray_api_attempt`) {
		t.Fatal("startup still contains sequential readiness retry budgets")
	}
	if strings.Index(script, `rm -f "$prevalidated_marker"`) > strings.Index(script, `elif [ "$skip_validation" -eq 1 ]; then`) {
		t.Fatal("one-shot prevalidation marker must be consumed before choosing the fast Apply budget")
	}
}

func TestXrayStartupLoadsTransparentExclusionsInOneNFTTransaction(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "..", "scripts", "configure-transparent-routing.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(body)
	if !strings.Contains(script, `ip daddr { $exclude_elements } return`) || !strings.Contains(script, `nft -f "$nft_candidate"`) {
		t.Fatal("transparent exclusions must be installed with the validated nft table")
	}
}

func TestRestoreXraySelectorsHonorsOverallContext(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "xray.json")
	if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["de"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	runtime := newXraySelectorRuntime(Options{})
	runtime.probeContext = ctx
	runtime.command = func(commandContext context.Context, _ time.Duration, _ string, _ ...string) ([]byte, error) {
		<-commandContext.Done()
		return nil, commandContext.Err()
	}
	started := time.Now()
	err := restoreXraySelectors(config, Options{}, runtime)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("restore error = %v, context = %v", err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed > 500*time.Millisecond {
		t.Fatalf("restore ignored shared context for %s", elapsed)
	}
}

func TestXrayStartupRestoresOnlyCurrentConfirmedURLTestLeaf(t *testing.T) {
	for _, test := range []struct {
		name, mode, savedMode, selected, actual, members string
		confirmed                                        bool
		want                                             string
	}{
		{"confirmed last leaf", "best", "best", "nl", "nl", "nl", true, "nl"},
		{"unconfirmed", "best", "best", "nl", "nl", "nl", false, "de"},
		{"runtime mismatch", "best", "best", "nl", "de", "nl", true, "de"},
		{"removed candidate", "best", "best", "removed", "removed", "removed", true, "de"},
		{"not in rendered balancer", "best", "best", "nl", "nl", "nl-prefix", true, "de"},
		{"priority order wins", "priority", "priority", "nl", "nl", "nl", true, "de"},
		{"mode changed", "best", "priority", "nl", "nl", "nl", true, "de"},
		{"block is not working server", "best", "best", "block", "block", "block", true, "de"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			config := filepath.Join(root, "xray.json")
			pool := filepath.Join(root, "pool.json")
			if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["de","`+test.members+`"]},{"tag":"outbound-health-probe","selector":["de","nl"]}]}}`), 0600); err != nil {
				t.Fatal(err)
			}
			contract := healthFixture(false)
			policy := contract.HealthPolicies["europe"]
			policy.Mode = test.mode
			contract.HealthPolicies["europe"] = policy
			if err := writeJSONAtomic(pool, contract); err != nil {
				t.Fatal(err)
			}
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed, item.Mode = test.selected, test.actual, test.confirmed, test.savedMode
			if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
				t.Fatal(err)
			}
			got, err := XrayStartupSelections(config, Options{HealthPoolFile: pool, StateRoot: root})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Outbound != test.want {
				t.Fatalf("unexpected startup selections: %+v", got)
			}
		})
	}
}

func TestXrayStartupPrefersCurrentConfirmedSelectionOverStaleWorkingHistory(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			config, poolPath := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
			if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["de","nl"]}]}}`), 0600); err != nil {
				t.Fatal(err)
			}
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = mode
			pool.HealthPolicies["europe"] = contract
			if err := writeJSONAtomic(poolPath, pool); err != nil {
				t.Fatal(err)
			}
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
			item.Mode, item.CandidateSignature = mode, "de\nnl"
			item.AvailabilityOK = map[string]bool{"de": true, "nl": true}
			item.LastWorkingSelection = &workingSelection{Selected: "nl", Mode: mode, CandidateSignature: "de\nnl"}
			if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
				t.Fatal(err)
			}

			got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: poolPath})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 1 || got[0].Outbound != "de" {
				t.Fatalf("startup restored stale working history instead of current selector: %+v", got)
			}
		})
	}
}

func TestXrayStartupOmitsOperationalProbeSelectors(t *testing.T) {
	root := t.TempDir()
	config, pool := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["block","de"]},{"tag":"outbound-health-probe","selector":["de"]},{"tag":"subscription-update-egress","selector":["direct-wan"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(pool, healthFixture(false)); err != nil {
		t.Fatal(err)
	}
	got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: pool})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Tag != "europe" {
		t.Fatalf("startup must restore only client policy selectors: %+v", got)
	}
}

func TestXrayStartupUsesKnownReserveWhenSavedActiveWasRemoved(t *testing.T) {
	root := t.TempDir()
	config, pool := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["block","fr","nl"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	contract := healthFixture(false)
	policy := contract.HealthPolicies["europe"]
	policy.Mode = "best"
	policy.Candidates = []string{"nl", "fr"}
	contract.HealthPolicies["europe"] = policy
	if err := writeJSONAtomic(pool, contract); err != nil {
		t.Fatal(err)
	}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed, item.Mode = "de", "de", true, "best"
	item.CandidateSignature = "de\nfr\nnl"
	item.LastWorkingSelection = &workingSelection{Selected: "de", Mode: "best", CandidateSignature: item.CandidateSignature}
	item.Shortlist = []string{"de", "fr", "nl"}
	item.AvailabilityOK = map[string]bool{"fr": true, "nl": true}
	item.Recoveries = map[string]int{"fr": 3, "nl": 3}
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: pool})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Outbound != "fr" {
		t.Fatalf("startup did not promote maintained reserve: %+v", got)
	}
}

func TestXrayStartupReplacesStableFailClosedDefaultWithoutHistory(t *testing.T) {
	root := t.TempDir()
	config, pool := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["block","de","nl"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(pool, healthFixture(false)); err != nil {
		t.Fatal(err)
	}
	got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: pool})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Outbound != "de" {
		t.Fatalf("cold startup kept fail-closed default: %+v", got)
	}
}

func TestXrayStartupWithoutUsableHistoryStillStarts(t *testing.T) {
	root := t.TempDir()
	config, pool := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["de","nl"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeJSONAtomic(pool, healthFixture(false)); err != nil {
		t.Fatal(err)
	}
	for _, history := range []string{"missing", "{", "null"} {
		if history != "missing" {
			if err := os.WriteFile(statePath(root, "selector-health"), []byte(history), 0600); err != nil {
				t.Fatal(err)
			}
		}
		got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: pool})
		if err != nil || len(got) != 1 || got[0].Outbound != "de" {
			t.Fatalf("history %s: %+v, %v", history, got, err)
		}
	}
}

func TestXrayStartupDoesNotRestoreReverseBeforeClientReconnects(t *testing.T) {
	root := t.TempDir()
	config, pool := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["block","reverse-vless-home","de"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	contract := healthFixture(false)
	policy := contract.HealthPolicies["europe"]
	policy.Candidates = []string{"reverse-vless-home", "de"}
	policy.Nodes["reverse-vless-home"] = healthNode{Protocol: "xray-reverse"}
	contract.HealthPolicies["europe"] = policy
	if err := writeJSONAtomic(pool, contract); err != nil {
		t.Fatal(err)
	}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed, item.Mode = "reverse-vless-home", "reverse-vless-home", true, "priority"
	item.CandidateSignature = "reverse-vless-home\nde"
	item.LastWorkingSelection = &workingSelection{Selected: "reverse-vless-home", Mode: "priority", CandidateSignature: item.CandidateSignature}
	item.AvailabilityOK = map[string]bool{}
	item.AvailabilityOK["reverse-vless-home"] = true
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: pool})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Outbound != "de" {
		t.Fatalf("startup restored a session-owned reverse bridge: %+v", got)
	}
}

func TestXrayStartupUsesBlockWhenPolicyHasOnlyReverseClients(t *testing.T) {
	root := t.TempDir()
	config, pool := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"remote","selector":["block","reverse-vless-home"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	contract := healthFixture(false)
	policy := contract.HealthPolicies["europe"]
	policy.Candidates = []string{"reverse-vless-home"}
	policy.Nodes = map[string]healthNode{"reverse-vless-home": {Protocol: "xray-reverse"}}
	contract.HealthPolicies = map[string]healthPolicyContract{"remote": policy}
	if err := writeJSONAtomic(pool, contract); err != nil {
		t.Fatal(err)
	}
	got, err := XrayStartupSelections(config, Options{StateRoot: root, HealthPoolFile: pool})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Outbound != "block" {
		t.Fatalf("reverse-only startup did not remain fail-closed: %+v", got)
	}
}

func TestHealthRestartKeepsRestoredLeafAndCooldown(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			root := t.TempDir()
			now := time.Unix(1000, 0)
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.Mode, item.RuntimeConfirmed = "nl", "nl", mode, true
			item.CooldownUntil = 1500
			item.CandidateSignature = "de\nnl"
			if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
				t.Fatal(err)
			}
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = mode
			contract.Policy.SwitchImprovementMS = 50
			pool.HealthPolicies["europe"] = contract
			runtime := &fakeSelectorRuntime{pool: pool, reset: true, current: map[string]string{"europe": "nl"}, probes: map[string]probeEvidence{"de": successfulEvidence(20), "nl": successfulEvidence(120)}}
			controller := &healthController{opts: Options{StateRoot: root}, runtime: runtime, warmStarted: map[string]bool{}}
			for tick := 0; tick < 4; tick++ {
				if err := controller.Tick(now.Add(time.Duration(tick) * time.Second)); err != nil {
					t.Fatal(err)
				}
			}
			if hasSelection(runtime.selections, "europe", "de") || controller.state["europe"].CooldownUntil != 1500 {
				t.Fatalf("warm restart lost selection/cooldown: %+v", runtime.selections)
			}
		})
	}
}

func TestHealthRestartConfirmsTransientFatalNetworkBeforeFailover(t *testing.T) {
	root := t.TempDir()
	now := time.Unix(1000, 0)
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Mode = "best"
	contract.Policy.ActiveCheckSeconds = 60
	contract.Policy.BackupCheckSeconds = 300
	pool.HealthPolicies["europe"] = contract

	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.Mode = contract.Mode
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.LastWorkingSelection = &workingSelection{Selected: "de", Mode: contract.Mode, CandidateSignature: item.CandidateSignature}
	item.AvailabilityOK = map[string]bool{"de": true, "nl": true}
	item.QualityOK = map[string]bool{"de": true, "nl": true}
	item.Recoveries = map[string]int{"de": 3, "nl": 3}
	activeDelay, reserveDelay := 100, 90
	item.MedianDelayMS = map[string]*int{"de": &activeDelay, "nl": &reserveDelay}
	item.LastProbeAt = map[string]float64{"de": 940, "nl": 1000}
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}

	runtime := &fakeSelectorRuntime{
		pool: pool, reset: true, current: map[string]string{"europe": "de"},
		probes: map[string]probeEvidence{
			"de": {Failure: probeFailureFatal},
			"nl": successfulEvidence(reserveDelay),
		},
	}
	controller := &healthController{opts: Options{StateRoot: root, HealthInterval: time.Minute}, runtime: runtime, warmStarted: make(map[string]bool)}
	if err := controller.Tick(now); err != nil {
		t.Fatal(err)
	}
	got := controller.state["europe"]
	if got.Selected != "de" || got.AvailabilityFailures["de"] != 1 || hasSelection(runtime.selections, "europe", "nl") {
		t.Fatalf("startup race changed the restored route: item=%+v selections=%v", got, runtime.selections)
	}

	runtime.probes["de"] = successfulEvidence(activeDelay)
	if err := controller.Tick(now.Add(failureRetryInterval)); err != nil {
		t.Fatal(err)
	}
	if got.Selected != "de" || got.AvailabilityFailures["de"] != 0 || hasSelection(runtime.selections, "europe", "nl") {
		t.Fatalf("successful confirmation did not preserve the restored route: item=%+v selections=%v", got, runtime.selections)
	}
}

func TestHealthRestartStillFailsOverImmediatelyOnTLSFailure(t *testing.T) {
	root := t.TempDir()
	pool := healthFixture(false)
	contract := pool.HealthPolicies["europe"]
	contract.Mode = "best"
	pool.HealthPolicies["europe"] = contract
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "de", "de", true
	item.Mode = contract.Mode
	item.CandidateSignature = strings.Join(contract.Candidates, "\n")
	item.LastWorkingSelection = &workingSelection{Selected: "de", Mode: contract.Mode, CandidateSignature: item.CandidateSignature}
	reserveDelay := 90
	item.AvailabilityOK = map[string]bool{"de": true, "nl": true}
	item.QualityOK = map[string]bool{"de": true, "nl": true}
	item.Recoveries = map[string]int{"de": 3, "nl": 3}
	item.MedianDelayMS = map[string]*int{"nl": &reserveDelay}
	item.LastProbeAt = map[string]float64{"de": 940, "nl": 1000}
	if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeSelectorRuntime{
		pool: pool, reset: true, current: map[string]string{"europe": "de"},
		probes: map[string]probeEvidence{"de": {Failure: probeFailureTLS}, "nl": successfulEvidence(reserveDelay)},
	}
	controller := &healthController{opts: Options{StateRoot: root, HealthInterval: time.Minute}, runtime: runtime, warmStarted: make(map[string]bool)}
	if err := controller.Tick(time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	if controller.state["europe"].Selected != "nl" || !hasSelection(runtime.selections, "europe", "nl") {
		t.Fatalf("startup delayed deterministic TLS failover: item=%+v selections=%v", controller.state["europe"], runtime.selections)
	}
}
