package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPriorityMembershipEditsRetainActiveUntilFreshRecovery(t *testing.T) {
	for _, candidates := range [][]string{
		{"active", "reserve", "added"}, {"added", "active", "reserve"}, {"active", "added", "reserve"},
	} {
		t.Run(strings.Join(candidates, "-"), func(t *testing.T) {
			controller, item, runtime := stagedOptimizationController(t)
			contract := runtime.pool.HealthPolicies["europe"]
			contract.Mode, contract.Candidates = "priority", candidates
			contract.Policy.ProbeBatchSize = 3
			contract.Nodes["added"] = healthNode{Label: "Added"}
			runtime.pool.HealthPolicies["europe"] = contract
			item.Mode, item.Selected, item.RuntimeSelected = "priority", "reserve", "reserve"
			runtime.current["europe"] = "reserve"
			runtime.probes["active"], runtime.probes["added"] = failedEvidence(), successfulEvidence(100)
			if err := controller.Tick(time.Unix(1060, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "reserve" || hasSelection(runtime.selections, "europe", "active") {
				t.Fatalf("membership-only edit acted as a reorder: selected=%q selections=%v",
					item.Selected, runtime.selections)
			}
		})
	}
}

func TestPriorityStartupMemorySurvivesMembershipOnlyEdit(t *testing.T) {
	for _, tc := range []struct {
		name, old  string
		candidates []string
		want       string
	}{
		{"append", "active\nreserve", []string{"active", "reserve", "added"}, "reserve"},
		{"prepend", "active\nreserve", []string{"added", "active", "reserve"}, "reserve"},
		{"remove-other", "active\nremoved\nreserve", []string{"active", "reserve"}, "reserve"},
		{"reorder", "reserve\nactive", []string{"active", "reserve", "added"}, "active"},
		{"unknown-order", "", []string{"active", "reserve"}, "active"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			config, poolPath := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
			if err := os.WriteFile(config, []byte(`{"routing":{"balancers":[{"tag":"europe","selector":["active","reserve","added"]}]}}`), 0600); err != nil {
				t.Fatal(err)
			}
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode, contract.Candidates = "priority", tc.candidates
			pool.HealthPolicies["europe"] = contract
			if err := writeJSONAtomic(poolPath, pool); err != nil {
				t.Fatal(err)
			}
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "reserve", "reserve", true
			item.Mode, item.CandidateSignature = "priority", tc.old
			item.AvailabilityOK = map[string]bool{"reserve": true, "active": true}
			item.Recoveries["active"] = 3
			if err := writeJSONAtomic(statePath(root, "selector-health"), healthState{"europe": item}); err != nil {
				t.Fatal(err)
			}
			got, err := XrayStartupSelections(config, Options{HealthPoolFile: poolPath, StateRoot: root})
			if err != nil || len(got) != 1 || got[0].Outbound != tc.want {
				t.Fatalf("startup after membership edit: selections=%v err=%v want=%q", got, err, tc.want)
			}
		})
	}
}
