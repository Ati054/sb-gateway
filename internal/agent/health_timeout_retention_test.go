package agent

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type timeoutReverseRuntime struct {
	*fakeSelectorRuntime
	online  bool
	err     error
	checks  int
	onCheck func()
}

func (runtime *timeoutReverseRuntime) reverseOnlineStatus(string) (bool, error) {
	runtime.checks++
	if runtime.onCheck != nil {
		runtime.onCheck()
	}
	return runtime.online, runtime.err
}

func TestTimeoutRetentionThroughResponsiveRuntimeRejectsOldGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "generation")
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := &timeoutReverseRuntime{online: true}
	runtime := &responsiveSelectorRuntime{selectorRuntime: base, generationPaths: []string{path}}
	runtime.generation = generationStamp(runtime.generationPaths)
	item := newPolicyHealthState()
	item.RuntimeConfirmed = true
	item.FailureClass["active"] = string(probeFailureTimeout)
	contract := healthPolicyContract{Nodes: map[string]healthNode{"active": {Protocol: "xray-reverse"}}}
	controller := &healthController{runtime: runtime}
	if retain, err := controller.retainTimedOutSelection("active", []string{"active"}, contract, item); !retain || err != nil || base.checks != 1 {
		t.Fatalf("live Reverse observation was not forwarded: retain=%t err=%v checks=%d", retain, err, base.checks)
	}
	base.onCheck = func() {
		if err := os.WriteFile(path, []byte("changed-generation"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if retain, err := controller.retainTimedOutSelection("active", []string{"active"}, contract, item); retain || !errors.Is(err, errHealthYield) {
		t.Fatalf("old generation retained after API call: retain=%t err=%v", retain, err)
	}
}

func TestTimeoutRetentionEligibility(t *testing.T) {
	for _, test := range []struct {
		name, protocol string
		failure        probeFailureClass
		removed        bool
		unconfirmed    bool
		online         bool
		apiError       bool
		want           bool
	}{
		{name: "VLESS timeout", protocol: "vless", failure: probeFailureTimeout, want: true},
		{name: "REALITY timeout", protocol: "reality", failure: probeFailureTimeout, want: true},
		{name: "online Reverse timeout", protocol: "xray-reverse", failure: probeFailureTimeout, online: true, want: true},
		{name: "offline Reverse", protocol: "xray-reverse", failure: probeFailureTimeout},
		{name: "Reverse API uncertain", protocol: "xray-reverse", failure: probeFailureTimeout, apiError: true},
		{name: "removed or disabled", protocol: "vless", failure: probeFailureTimeout, removed: true},
		{name: "unconfirmed selection", protocol: "vless", failure: probeFailureTimeout, unconfirmed: true},
		{name: "unknown protocol", failure: probeFailureTimeout},
		{name: "WAN", protocol: "direct", failure: probeFailureTimeout},
		{name: "WireGuard", protocol: "wireguard", failure: probeFailureTimeout},
		{name: "TLS failure", protocol: "vless", failure: probeFailureTLS},
		{name: "network failure", protocol: "vless", failure: probeFailureFatal},
		{name: "transient failure", protocol: "vless", failure: probeFailureTransient},
		{name: "unknown failure", protocol: "vless"},
	} {
		t.Run(test.name, func(t *testing.T) {
			item := newPolicyHealthState()
			item.RuntimeConfirmed = !test.unconfirmed
			item.FailureClass["active"] = string(test.failure)
			contract := healthPolicyContract{Nodes: map[string]healthNode{"active": {Protocol: test.protocol}}}
			candidates := []string{"active"}
			if test.removed {
				candidates = nil
			}
			runtime := &timeoutReverseRuntime{online: test.online}
			if test.apiError {
				runtime.err = errors.New("local API unavailable")
			}
			controller := &healthController{runtime: runtime}
			got, err := controller.retainTimedOutSelection("active", candidates, contract, item)
			if got != test.want || errors.Is(err, errProbeSelectorUnavailable) != test.apiError {
				t.Fatalf("retention=%t err=%v, want %t API error=%t", got, err, test.want, test.apiError)
			}
		})
	}
}

func TestTimeoutKeepsPermittedVLESSUntilFreshReserve(t *testing.T) {
	for _, mode := range []string{"priority", "best"} {
		for _, protocol := range []string{"vless", "reality", "xray-reverse"} {
			t.Run(mode+"/"+protocol, func(t *testing.T) {
				controller, base, item := livenessFixture(t, mode)
				contract := base.pool.HealthPolicies["europe"]
				node := contract.Nodes["de"]
				node.Protocol = protocol
				contract.Nodes["de"] = node
				contract.Policy.CandidateServiceIDs = []string{"allowed", "denied"}
				contract.Policy.CandidateServiceAccess = map[string][]string{"country:DE": {"allowed"}}
				base.pool.HealthPolicies["europe"] = contract
				runtime := &timeoutReverseRuntime{fakeSelectorRuntime: base, online: true}
				controller.runtime = runtime
				base.probes["de"] = probeEvidence{Failure: probeFailureTimeout}
				base.probes["nl"] = probeEvidence{Failure: probeFailureTimeout}
				switches := len(base.selections)
				lastSwitch := item.LastSwitchAt
				for _, second := range []int64{1010, 1012, 1014} {
					if err := controller.Tick(time.Unix(second, 0)); err != nil {
						t.Fatal(err)
					}
				}
				if item.Selected != "de" || item.RuntimeSelected != "de" || !item.RuntimeConfirmed || item.LastSwitchAt != lastSwitch {
					t.Fatalf("timed-out path replaced: selected=%s runtime=%s switches=%v", item.Selected, item.RuntimeSelected, base.selections[switches:])
				}
				if item.AvailabilityOK["de"] || item.Recoveries["de"] != 0 || item.FailureClass["de"] != string(probeFailureTimeout) {
					t.Fatal("retention incorrectly qualified the timed-out path as healthy")
				}
				for _, selection := range base.selections[switches:] {
					if selection[0] == "europe" {
						t.Fatalf("retention mutated policy selector: %v", selection)
					}
				}
				if mode == "priority" && (!item.CandidateServiceStatus["allowed"].Allowed || item.CandidateServiceStatus["denied"].Allowed) {
					t.Fatal("retention changed service permissions")
				}
				if protocol == "xray-reverse" && runtime.checks < 2 {
					t.Fatal("Reverse online status was not rechecked during retention")
				}
				base.probes["nl"] = successfulEvidence(90)
				for second := int64(1016); second <= 1032 && item.Selected != "nl"; second += 2 {
					if err := controller.Tick(time.Unix(second, 0)); err != nil {
						t.Fatal(err)
					}
				}
				if item.Selected != "nl" || item.LastSwitchReason != "active-unavailable" {
					t.Fatalf("fresh reserve did not replace retained path: %s / %s", item.Selected, item.LastSwitchReason)
				}
			})
		}
	}
}

func TestRetainedReverseIsWithdrawnWhenSessionGoesOffline(t *testing.T) {
	controller, base, item := livenessFixture(t, "priority")
	contract := base.pool.HealthPolicies["europe"]
	node := contract.Nodes["de"]
	node.Protocol = "xray-reverse"
	contract.Nodes["de"] = node
	base.pool.HealthPolicies["europe"] = contract
	runtime := &timeoutReverseRuntime{fakeSelectorRuntime: base, online: true}
	controller.runtime = runtime
	base.probes["de"] = probeEvidence{Failure: probeFailureTimeout}
	base.probes["nl"] = probeEvidence{Failure: probeFailureTimeout}
	for _, second := range []int64{1010, 1012} {
		if err := controller.Tick(time.Unix(second, 0)); err != nil {
			t.Fatal(err)
		}
	}
	if item.Selected != "de" {
		t.Fatal("online Reverse not retained")
	}
	runtime.online = false
	if err := controller.Tick(time.Unix(1014, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "block" || item.LastSwitchReason != "all-candidates-unavailable" {
		t.Fatalf("offline Reverse retained: %s / %s", item.Selected, item.LastSwitchReason)
	}
}

func TestRetainedVLESSIsWithdrawnWhenRemovedOrExplicitlyFailed(t *testing.T) {
	for _, terminal := range []string{"removed", "network", "TLS"} {
		t.Run(terminal, func(t *testing.T) {
			controller, runtime, item := livenessFixture(t, "priority")
			contract := runtime.pool.HealthPolicies["europe"]
			node := contract.Nodes["de"]
			node.Protocol = "vless"
			contract.Nodes["de"] = node
			runtime.pool.HealthPolicies["europe"] = contract
			runtime.probes["de"] = probeEvidence{Failure: probeFailureTimeout}
			runtime.probes["nl"] = probeEvidence{Failure: probeFailureTimeout}
			for _, second := range []int64{1010, 1012} {
				if err := controller.Tick(time.Unix(second, 0)); err != nil {
					t.Fatal(err)
				}
			}
			if item.Selected != "de" {
				t.Fatal("VLESS not retained after timeout")
			}
			switch terminal {
			case "removed":
				contract.Candidates = []string{"nl"}
				delete(contract.Nodes, "de")
				contract.Groups = contract.Groups[1:]
				runtime.pool.HealthPolicies["europe"] = contract
			case "network":
				runtime.probes["de"] = probeEvidence{Failure: probeFailureFatal}
			case "TLS":
				runtime.probes["de"] = probeEvidence{Failure: probeFailureTLS}
			}
			if err := controller.Tick(time.Unix(1014, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "block" || hasSelection(runtime.selections, "europe", "direct-wan") {
				t.Fatalf("ineligible path retained or WAN selected: %s / %v", item.Selected, runtime.selections)
			}
		})
	}
}
