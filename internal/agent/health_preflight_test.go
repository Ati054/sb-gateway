package agent

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestEmergencyTCPPreflightSharesEndpointButKeepsNodeOrder(t *testing.T) {
	ids := make([]string, 100)
	targets := make(map[string]healthDialTarget, 100)
	for index := range ids {
		ids[index] = fmt.Sprintf("n%d", index)
		targets[ids[index]] = healthDialTarget{Address: "127.0.0.1", Port: 443}
	}
	for _, outcome := range []string{"open", "closed", "timeout"} {
		t.Run(outcome, func(t *testing.T) {
			var calls atomic.Int64
			opened, closed := emergencyTCPPreflight(context.Background(), ids, targets, 10, func(context.Context, string) error {
				calls.Add(1)
				switch outcome {
				case "closed":
					return syscall.ECONNREFUSED
				case "timeout":
					return context.DeadlineExceeded
				default:
					return nil
				}
			})
			if calls.Load() != 1 {
				t.Fatalf("shared endpoint dialed %d times", calls.Load())
			}
			switch outcome {
			case "open":
				if !reflect.DeepEqual(opened, ids) || len(closed) != 0 {
					t.Fatal("shared success lost order or invented closed nodes")
				}
			case "closed":
				if len(opened) != 0 || len(closed) != len(ids) {
					t.Fatal("deterministic failure was not shared")
				}
			case "timeout":
				if len(opened) != 0 || len(closed) != 0 {
					t.Fatal("ambiguous endpoint removed HTTPS candidates")
				}
			}
		})
	}
}

func TestEmergencyTCPPreflightCanonicalizesIPButSeparatesPorts(t *testing.T) {
	ids := []string{"ipv6-short", "ipv6-long", "other-port", "mapped-v4", "v4"}
	targets := map[string]healthDialTarget{
		"ipv6-short": {Address: "::1", Port: 443},
		"ipv6-long":  {Address: "0:0:0:0:0:0:0:1", Port: 443},
		"other-port": {Address: "::1", Port: 444},
		"mapped-v4":  {Address: "::ffff:127.0.0.1", Port: 443},
		"v4":         {Address: "127.0.0.1", Port: 443},
	}
	var calls atomic.Int64
	opened, closed := emergencyTCPPreflight(context.Background(), ids, targets, 10, func(context.Context, string) error {
		calls.Add(1)
		return nil
	})
	if calls.Load() != 3 || !reflect.DeepEqual(opened, ids) || len(closed) != 0 {
		t.Fatalf("canonical endpoint grouping changed: calls=%d open=%v closed=%v", calls.Load(), opened, closed)
	}
}

func TestEmergencyTCPPreflightHonorsSmallWorkerBudget(t *testing.T) {
	for _, limit := range []int{1, 3, 10} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			ids := make([]string, 20)
			targets := make(map[string]healthDialTarget, 20)
			for index := range ids {
				ids[index] = strconv.Itoa(index)
				targets[ids[index]] = healthDialTarget{Address: "127.0.0.1", Port: 10000 + index}
			}
			var active, peak, calls atomic.Int64
			opened, _ := emergencyTCPPreflight(context.Background(), ids, targets, limit, func(context.Context, string) error {
				value := active.Add(1)
				defer active.Add(-1)
				for old := peak.Load(); value > old; old = peak.Load() {
					if peak.CompareAndSwap(old, value) {
						break
					}
				}
				calls.Add(1)
				time.Sleep(5 * time.Millisecond)
				return nil
			})
			if peak.Load() > int64(limit) || calls.Load() != 20 || len(opened) != 20 || active.Load() != 0 {
				t.Fatalf("worker budget or join changed: limit=%d peak=%d calls=%d", limit, peak.Load(), calls.Load())
			}
		})
	}
}

func TestEmergencyTCPPreflightCancellationDoesNotCloseUntestedNodes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ids := []string{"first", "second", "third"}
	targets := map[string]healthDialTarget{
		"first": {Address: "127.0.0.1", Port: 443}, "second": {Address: "127.0.0.1", Port: 444},
		"third": {Address: "127.0.0.1", Port: 445},
	}
	var calls atomic.Int64
	opened, closed := emergencyTCPPreflight(ctx, ids, targets, 1, func(ctx context.Context, _ string) error {
		calls.Add(1)
		cancel()
		return ctx.Err()
	})
	if calls.Load() != 1 || len(opened) != 0 || len(closed) != 0 {
		t.Fatal("cancellation tried later endpoints or created negative evidence")
	}
}

func TestEmergencySharedEndpointRecoversOnNextPreflight(t *testing.T) {
	ids := []string{"primary", "reserve"}
	runtime := &preflightFixture{fakeSelectorRuntime: &fakeSelectorRuntime{}, closed: map[string]bool{"primary": true, "reserve": true}}
	controller := &healthController{runtime: runtime}
	item := newPolicyHealthState()
	item.Selected = "block"
	p := effectivePolicySettings{batch: 10, blockRecovery: 15}
	if got := controller.emergencyTargets(time.Unix(1000, 0), ids, item, p); len(got) != 0 {
		t.Fatal("closed endpoint was not excluded")
	}
	runtime.closed, runtime.opened = nil, ids
	if got := controller.emergencyTargets(time.Unix(1014, 0), ids, item, p); len(got) != 0 {
		t.Fatal("cached preflight did not respect its bounded cadence")
	}
	if got := controller.emergencyTargets(time.Unix(1015, 0), ids, item, p); !reflect.DeepEqual(got, ids) || len(item.PreflightClosed) != 0 {
		t.Fatal("shared endpoint failure became a persistent penalty")
	}
}

func TestEmergencySweepServicesBothBlockedPolicies(t *testing.T) {
	pool := healthPool{Version: 4, ProbeBudget: 2, Policies: map[string][]string{}, HealthPolicies: map[string]healthPolicyContract{}}
	state := healthState{}
	warm := map[string]bool{}
	current := map[string]string{}
	probes := map[string]probeEvidence{}
	for _, mode := range []string{"best", "priority"} {
		ids := []string{mode + "-1", mode + "-2", mode + "-3", mode + "-4"}
		pool.Policies[mode] = ids
		pool.HealthPolicies[mode] = healthPolicyContract{Mode: mode, Candidates: ids, Policy: healthPolicy{ProbeBatchSize: 2}}
		item := newPolicyHealthState()
		item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "block", "block", true
		item.Mode, item.CandidateSignature = mode, strings.Join(ids, "\n")
		state[mode], warm[mode], current[mode] = item, true, "block"
		for _, id := range ids {
			probes[id] = failedEvidence()
		}
	}
	runtime := &fakeSelectorRuntime{pool: pool, current: current, probes: probes}
	controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute},
		runtime: runtime, state: state, stateLoaded: true, warmStarted: warm}
	for cycle := 0; cycle < 2; cycle++ {
		before := len(runtime.availabilityCalls)
		if err := controller.Tick(time.Unix(int64(1000+2*cycle), 0)); err != nil {
			t.Fatal(err)
		}
		calls := runtime.availabilityCalls[before:]
		if len(calls) != 4 {
			t.Fatalf("one failed policy monopolized the pass: %v", calls)
		}
		for _, mode := range []string{"best", "priority"} {
			want := pool.Policies[mode][2*cycle : 2*cycle+2]
			if !reflect.DeepEqual(state[mode].ProbedCandidates, want) || state[mode].Selected != "block" {
				t.Fatalf("failed policy lost bounded sweep progress: mode=%s probes=%v", mode, state[mode].ProbedCandidates)
			}
		}
	}
}

func TestEmergencyTCPPreflightFindsLastOpenNodeAtEveryListSize(t *testing.T) {
	for _, count := range []int{3, 7, 30, 100, 128, 325} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			ids := make([]string, count)
			targets := make(map[string]healthDialTarget, count)
			for i := range ids {
				ids[i] = fmt.Sprintf("n%d", i)
				targets[ids[i]] = healthDialTarget{Address: "127.0.0.1", Port: 10000 + i}
			}
			last := strconv.Itoa(10000 + count - 1)
			opened, closed := emergencyTCPPreflight(context.Background(), ids, targets, 10, func(_ context.Context, address string) error {
				_, port, err := net.SplitHostPort(address)
				if err != nil {
					return err
				}
				if port == last {
					return nil
				}
				return syscall.ECONNREFUSED
			})
			if !reflect.DeepEqual(opened, []string{ids[count-1]}) || len(closed) != count-1 {
				t.Fatalf("open=%v closed=%d", opened, len(closed))
			}
		})
	}
}

func TestEmergencyTCPPreflightKeepsAmbiguousTargetsForXray(t *testing.T) {
	ids := []string{"domain", "udp", "timeout", "closed", "open"}
	targets := map[string]healthDialTarget{
		"timeout": {Address: "127.0.0.1", Port: 10001},
		"closed":  {Address: "127.0.0.1", Port: 10002},
		"open":    {Address: "127.0.0.1", Port: 10003},
	}
	opened, closed := emergencyTCPPreflight(context.Background(), ids, targets, 10, func(_ context.Context, address string) error {
		switch {
		case strings.HasSuffix(address, ":10001"):
			return context.DeadlineExceeded
		case strings.HasSuffix(address, ":10002"):
			return syscall.ECONNREFUSED
		default:
			return nil
		}
	})
	if !reflect.DeepEqual(opened, []string{"open"}) || len(closed) != 1 || !closed["closed"] || closed["timeout"] || closed["domain"] || closed["udp"] {
		t.Fatalf("open=%v closed=%v", opened, closed)
	}
}

type preflightFixture struct {
	*fakeSelectorRuntime
	open   string
	opened []string
	closed map[string]bool
}

func (runtime *preflightFixture) PrioritizeEmergency(_ []string) ([]string, map[string]bool, error) {
	if len(runtime.opened) > 0 {
		return runtime.opened, runtime.closed, nil
	}
	if runtime.open == "" {
		return nil, runtime.closed, nil
	}
	return []string{runtime.open}, runtime.closed, nil
}

func TestEmergencyOpenEndpointsDoNotRestartLargeSweep(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			ids := make([]string, 100)
			for index := range ids {
				ids[index] = fmt.Sprintf("n%d", index+1)
			}
			runtime := &preflightFixture{fakeSelectorRuntime: &fakeSelectorRuntime{}, opened: ids}
			controller := &healthController{runtime: runtime}
			item := newPolicyHealthState()
			item.Selected, item.Mode = "block", mode
			p := policySettings(healthPolicy{ProbeBatchSize: 10}, mode)
			seen := map[string]bool{}
			for cycle := 0; cycle < 10; cycle++ {
				now := time.Unix(1000+int64(cycle)*7, 0)
				batch := controller.emergencyTargets(now, ids, item, p)
				if len(batch) != 10 {
					t.Fatalf("cycle=%d batch=%d, want ten", cycle, len(batch))
				}
				for _, candidate := range batch {
					if seen[candidate] {
						t.Fatalf("cycle=%d repeats %s while later candidates remain untested", cycle, candidate)
					}
					seen[candidate] = true
					item.LastProbeAt[candidate] = float64(now.Unix())
				}
			}
			if !seen[ids[99]] || len(seen) != 100 {
				t.Fatal("last candidate was starved")
			}
		})
	}
}

func TestClosedPrefilterBatchDoesNotStarveLaterDomainCandidates(t *testing.T) {
	ids := []string{"n1", "n2", "n3", "n4", "n5", "domain"}
	closed := map[string]bool{"n1": true, "n2": true, "n3": true, "n4": true, "n5": true}
	runtime := &preflightFixture{fakeSelectorRuntime: &fakeSelectorRuntime{}, closed: closed}
	controller := &healthController{runtime: runtime}
	item := newPolicyHealthState()
	item.Selected = "block"
	p := effectivePolicySettings{batch: 2, blockRecovery: 15}
	if got := controller.emergencyTargets(time.Unix(1000, 0), ids, item, p); !reflect.DeepEqual(got, []string{"domain"}) {
		t.Fatalf("later domain starved by closed first batch: %v", got)
	}
	if got := controller.emergencyTargets(time.Unix(1002, 0), ids, item, p); !reflect.DeepEqual(got, []string{"domain"}) {
		t.Fatalf("closed ports re-entered before retry interval: %v", got)
	}
}

func TestAllClosedPrefilterUsesBlockRecoveryCadence(t *testing.T) {
	item := newPolicyHealthState()
	item.Selected, item.Mode, item.CandidateSignature = "block", "priority", "n1\nn2"
	item.PreflightClosed = map[string]bool{"n1": true, "n2": true}
	item.LastWorkingSelection = &workingSelection{Selected: "n1", Mode: "priority", CandidateSignature: item.CandidateSignature}
	item.ProbeLimits = probeLimits{FailureRetrySeconds: 2, BlockRecoverySeconds: 15}
	controller := &healthController{opts: Options{HealthInterval: time.Minute}, state: healthState{"route": item}}
	if got := controller.nextInterval(); got != 15*time.Second {
		t.Fatalf("all closed endpoints caused a busy recovery loop: %s", got)
	}
}

func TestBlockedControllerProbesOpenLastReserveFirst(t *testing.T) {
	for _, count := range []int{3, 7, 30, 100, 128, 325} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			pool := healthFixture(false)
			contract := pool.HealthPolicies["europe"]
			contract.Mode = "priority"
			contract.Candidates = make([]string, count)
			contract.Policy.ProbeBatchSize = 3
			for i := range contract.Candidates {
				contract.Candidates[i] = fmt.Sprintf("n%d", i)
			}
			pool.HealthPolicies["europe"] = contract
			last := contract.Candidates[count-1]
			item := newPolicyHealthState()
			item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "block", "block", true
			item.CandidateSignature = strings.Join(contract.Candidates, "\n")
			probes := make(map[string]probeEvidence, count)
			for _, id := range contract.Candidates {
				probes[id] = failedEvidence()
			}
			probes[last] = successfulEvidence(50)
			fake := &fakeSelectorRuntime{pool: pool, current: map[string]string{"europe": "block"}, probes: probes}
			runtime := &preflightFixture{fakeSelectorRuntime: fake, open: last}
			controller := &healthController{opts: Options{StateRoot: t.TempDir(), HealthInterval: time.Minute}, runtime: runtime, warmStarted: map[string]bool{"europe": true}, stateLoaded: true, state: healthState{"europe": item}}
			if err := controller.Tick(time.Unix(1000, 0)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != last || len(fake.availabilityCalls) == 0 || fake.availabilityCalls[0] != last {
				t.Fatalf("selected=%s probes=%v", item.Selected, fake.availabilityCalls)
			}
		})
	}
}
