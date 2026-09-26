package agent

import (
	"reflect"
	"testing"
	"time"
)

func TestChangedOutboundLosesOldHealthWithoutLosingStableID(t *testing.T) {
	item := newPolicyHealthState()
	item.Selected = "node"
	item.CandidateNodes = map[string]healthNode{"node": {Label: "Old name", Fingerprint: "old"}}
	item.LastProbeAt["node"] = 1000
	item.LastGoodAt["node"] = 1000
	item.AvailabilityOK = map[string]bool{"node": true}
	item.QualityOK = map[string]bool{"node": true}
	item.Recoveries["node"] = 3
	item.Samples["node"] = []healthSample{{OK: true}}
	item.LastWorkingSelection = &workingSelection{Selected: "node"}
	current := map[string]healthNode{"node": {Label: "New name", Fingerprint: "old"}}
	if got := invalidateChangedOutboundHealth(item, []string{"node"}, current); len(got) != 0 {
		t.Fatalf("label rename invalidated endpoint: %v", got)
	}
	current["node"] = healthNode{Label: "New name", Fingerprint: "new"}
	if got := invalidateChangedOutboundHealth(item, []string{"node"}, current); !reflect.DeepEqual(got, []string{"node"}) {
		t.Fatalf("changed endpoint not detected: %v", got)
	}
	if item.Selected != "node" || item.LastProbeAt["node"] != 0 || item.LastGoodAt["node"] != 0 || item.AvailabilityOK["node"] || item.QualityOK["node"] || item.Recoveries["node"] != 0 || len(item.Samples["node"]) != 0 || item.LastWorkingSelection != nil {
		t.Fatalf("stale health survived endpoint change: %+v", item)
	}
	if reserve := knownFreshReserve(time.Unix(1001, 0), "block", []string{"node"}, "priority", nil, item, effectivePolicySettings{backup: 300, recoveryThreshold: 3, failureThreshold: 3}); reserve != "" {
		t.Fatalf("stale reserve reused: %q", reserve)
	}
}
