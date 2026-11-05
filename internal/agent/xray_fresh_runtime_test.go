package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestFreshRuntimeMethodsFallbackAndPhysicalRequests(t *testing.T) {
	original := healthTargets
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	t.Cleanup(func() { healthTargets = original })
	for _, scenario := range []string{"ordinary", "reverse", "head-unsupported", "alternate-only", "offline-reverse"} {
		t.Run(scenario, func(t *testing.T) {
			var mu sync.Mutex
			methods, connections := []string{}, []string{}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				methods, connections = append(methods, r.Method), append(connections, r.RemoteAddr)
				mu.Unlock()
				if scenario == "head-unsupported" && r.Method == http.MethodHead {
					w.WriteHeader(http.StatusMethodNotAllowed)
					return
				}
				if scenario == "alternate-only" && r.URL.Path == "/gstatic-204" {
					w.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				if r.URL.Path == "/gstatic-204" {
					w.WriteHeader(http.StatusNoContent)
				} else {
					w.WriteHeader(http.StatusOK)
				}
			}))
			defer server.Close()
			runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
			node := "direct-wan"
			if scenario != "ordinary" && scenario != "alternate-only" {
				node = "reverse-vless-test"
				runtime.pool = healthPool{BaseOutboundTags: []string{node}, HealthPolicies: map[string]healthPolicyContract{
					"route": {Nodes: map[string]healthNode{node: {Protocol: "xray-reverse"}}},
				}}
			}
			runtime.selectorMembers["outbound-health-probe"] = node
			onlineChecks, selections := 0, 0
			runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
				switch args[1] {
				case "statsonline":
					onlineChecks++
					if scenario == "offline-reverse" {
						return []byte(`{"stat":{"name":"user>>>reverse-vless-test>>>online","value":0}}`), nil
					}
					return []byte(`{"stat":{"name":"user>>>reverse-vless-test>>>online","value":1}}`), nil
				case "lso":
					return []byte(`{"outbounds":[]}`), nil
				default:
					selections++
					t.Errorf("unexpected selector/API command: %v", args)
					return nil, nil
				}
			}
			barrier := &qualityStartBarrier{id: 123, ready: make(chan struct{})}
			barrier.left.Store(1)
			evidence := runtime.ProbeWithQualityRequest(node, qualityProbeRequest{Measurement: qualityMeasurementFreshPaired, Start: &qualityStartTicket{barrier: barrier}})
			if selections != 0 {
				t.Fatal("fresh request repeated selector preparation")
			}
			if scenario == "offline-reverse" {
				if evidence.OK || len(methods) != 0 || onlineChecks != 1 || evidence.Planning == nil || !evidence.Planning.Failed {
					t.Fatalf("offline Reverse issued HTTPS: %+v", evidence)
				}
				return
			}
			if !evidence.OK || evidence.LocalFailure || evidence.Warm != nil || evidence.Planning == nil || evidence.Planning.Wave != 123 {
				t.Fatalf("fresh request lost availability or physical identity: %+v", evidence)
			}
			if node != "direct-wan" && onlineChecks != 1 {
				t.Fatal("fresh Reverse bypassed online observation")
			}
			if scenario == "head-unsupported" || scenario == "alternate-only" {
				if validPlanningQuality(evidence.Planning, qualityMeasurementFreshPaired) || !evidence.Planning.Failed || !evidence.QualityUnmeasured || evidence.DelayMS != nil {
					t.Fatalf("GET/alternate success invented planning quality: %+v", evidence)
				}
				if scenario == "head-unsupported" && evidence.PrimaryQualityFailed {
					t.Fatal("working primary GET became a primary-origin outage")
				}
				if scenario == "alternate-only" && !evidence.PrimaryQualityFailed {
					t.Fatal("alternate success hid primary-origin failure")
				}
				mu.Lock()
				defer mu.Unlock()
				if len(methods) < 2 || methods[0] != http.MethodHead || methods[1] != http.MethodGet {
					t.Fatalf("availability did not retain GET: %v", methods)
				}
				return
			}
			if !validPlanningQuality(evidence.Planning, qualityMeasurementFreshPaired) || !evidence.QualityStartedAt.Equal(evidence.Planning.StartedAt) || !evidence.ObservedAt.Equal(evidence.Planning.ObservedAt) {
				t.Fatalf("fresh observation has invented phase timestamps: %+v", evidence)
			}
			second := runtime.ProbeWithQualityRequest(node, qualityProbeRequest{Measurement: qualityMeasurementFreshPaired})
			if !validPlanningQuality(second.Planning, qualityMeasurementFreshPaired) {
				t.Fatal("second fresh job failed")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(methods) != 2 || methods[0] != http.MethodHead || methods[1] != http.MethodHead || connections[0] == connections[1] {
				t.Fatalf("fresh job reused a connection or made extra requests: methods=%v connections=%v", methods, connections)
			}
		})
	}
}

func TestFreshPairAllocatesOnlyPreparationBarrier(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	queues := probeLaneJobsWithMeasurement([]string{"a", "b"}, 2, true, cancel, qualityMeasurementFreshPaired)
	left, right := <-queues[0], <-queues[1]
	if left.start == nil || right.start == nil || left.start.barrier != right.start.barrier || left.warmStart != nil || right.warmStart != nil {
		t.Fatal("fresh pair allocated a second-request barrier or lost physical cohort")
	}
	left.start.arrive()
	right.start.arrive()
	if err := left.start.wait(ctx); err != nil {
		t.Fatal(err)
	}
}
