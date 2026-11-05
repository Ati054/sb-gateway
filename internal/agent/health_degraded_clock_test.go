package agent

import (
	"fmt"
	"testing"
	"time"
)

type degradedClockRuntime struct{ *timedPairTestRuntime }

func degradedClockDelay(value int) *int { return &value }

func (r *degradedClockRuntime) ProbeAvailability(node string) probeEvidence {
	*r.clock = r.clock.Add(175 * time.Millisecond)
	return probeEvidence{OK: true, ObservedAt: *r.clock, Targets: map[string]*int{"cloudflare-trace": degradedClockDelay(1)}}
}

func TestSixDegradedListsWithWarmRecentHistoryAndFractionalProbes(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			base := healthFixture(false).HealthPolicies["europe"]
			pool := healthPool{Version: 4, ProbeBudget: 1, HealthPolicies: map[string]healthPolicyContract{}}
			fake := &fakeSelectorRuntime{current: map[string]string{}, probes: map[string]probeEvidence{}}
			now := time.Unix(1000, 173000000)
			runtime := &degradedClockRuntime{&timedPairTestRuntime{fake, &now, 375 * time.Millisecond}}
			c := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime, stateLoaded: true, state: healthState{}, warmStarted: map[string]bool{}}
			for n := 0; n < 6; n++ {
				id := fmt.Sprintf("list-%d", n)
				a, b := id+"-active", id+"-reserve"
				contract := base
				contract.Mode, contract.Groups = mode, nil
				contract.Candidates = []string{a, b}
				contract.Nodes = budgetContract(a, b).Nodes
				contract.Policy.ActiveCheckSeconds, contract.Policy.ActiveLivenessSeconds, contract.Policy.ProbeBatchSize = 60, 3, 1
				contract.Policy.LatencyMeasurement = latencyMeasurement
				pool.HealthPolicies[id] = contract
				s := newPolicyHealthState()
				s.Mode, s.LatencyMeasurement = mode, latencyMeasurement
				s.Selected, s.RuntimeSelected, s.RuntimeConfirmed = a, a, true
				s.CandidateSignature, s.CandidateNodes = a+"\n"+b, contract.Nodes
				s.AvailabilityOK = map[string]bool{a: true, b: true}
				s.QualityOK = map[string]bool{a: true, b: true}
				for _, node := range []string{a, b} {
					s.LastProbeAt[node] = float64(now.Add(-time.Minute).Unix())
					s.Recoveries[node] = 3
					at := now.Add(-time.Duration(6-n) * time.Second)
					s.Samples[node] = []healthSample{{At: float64(at.Unix()), ObservedAt: qualityObservationAt(at, probeEvidence{}), OK: true, DelayMS: degradedClockDelay(125)}}
				}
				fake.probes[a] = probeEvidence{OK: true, QualityUnmeasured: true, PrimaryQualityFailed: true}
				fake.probes[b] = successfulEvidence(125)
				fake.current[id], c.state[id], c.warmStarted[id] = a, s, true
			}
			fake.pool = pool
			until := now.Add(4 * time.Minute)
			for cycles := 0; cycles < 500 && now.Before(until); cycles++ {
				before := len(fake.probeCalls)
				if err := c.Tick(now); err != nil {
					t.Fatal(err)
				}
				if len(fake.probeCalls)-before > 1 {
					t.Fatal("quality budget exceeded")
				}
				all := true
				for id, s := range c.state {
					all = all && s.Selected == id+"-reserve"
				}
				if all {
					return
				}
				now = now.Add(max(time.Millisecond, c.nextIntervalAt(now)))
			}
			for id, s := range c.state {
				if s.Selected != id+"-reserve" {
					t.Errorf("%s starved failures=%d next=%v pending=%+v", id, s.Failures[s.Selected], c.regularNext[id], s.degradedPair)
				}
			}
		})
	}
}
