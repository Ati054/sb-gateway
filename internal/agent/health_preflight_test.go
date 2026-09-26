package agent

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestEmergencyTCPPreflightFindsLastOpenNodeAtEveryListSize(t *testing.T) {
	for _, count := range []int{3, 7, 30, 128, 325} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			ids := make([]string, count)
			targets := make(map[string]healthDialTarget, count)
			for i := range ids {
				ids[i] = fmt.Sprintf("n%d", i)
				targets[ids[i]] = healthDialTarget{Address: "127.0.0.1", Port: 10000 + i}
			}
			last := strconv.Itoa(10000 + count - 1)
			opened, closed := emergencyTCPPreflight(context.Background(), ids, targets, func(_ context.Context, address string) error {
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
	opened, closed := emergencyTCPPreflight(context.Background(), ids, targets, func(_ context.Context, address string) error {
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
	closed map[string]bool
}

func (runtime *preflightFixture) PrioritizeEmergency(_ []string) ([]string, map[string]bool, error) {
	if runtime.open == "" {
		return nil, runtime.closed, nil
	}
	return []string{runtime.open}, runtime.closed, nil
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
	for _, count := range []int{3, 7, 30, 128, 325} {
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
