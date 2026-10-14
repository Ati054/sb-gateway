package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// The optional external TLS origin exposes /mode/{slow,silent,normal,stop} and /data.
// Delays affect probe responses only; data requests still traverse real Reverse.
func testLiveReverseHTTPSFaults(t *testing.T, ctx context.Context, runtime *xraySelectorRuntime, selected, target string, corePID int) {
	t.Helper()
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" {
		t.Fatal("fault fixture requires a trusted HTTPS origin")
	}
	request := func(path string, timeout time.Duration) error {
		endpoint := *u
		endpoint.Path = path
		_, err := downloadThroughProxyContext(ctx, runtime.opts.ProbeURL, endpoint.String(), timeout, 1024, http.StatusNoContent)
		return err
	}
	mode := func(value string) {
		t.Helper()
		if err := request("/mode/"+value, 5*time.Second); err != nil {
			t.Fatalf("origin mode %s: %v", value, err)
		}
	}
	for range 6 {
		if evidence := runtime.ProbeAvailability(selected); !evidence.OK {
			t.Fatalf("HTTPS baseline: %+v", evidence)
		}
	}
	mode("slow")
	var passed, failed atomic.Int64
	dataCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for dataCtx.Err() == nil {
			if err := request("/data", 5*time.Second); err != nil {
				failed.Add(1)
			} else {
				passed.Add(1)
			}
			if !wait(dataCtx, 250*time.Millisecond) {
				return
			}
		}
	}()
	defer func() { cancel(); <-done }()
	if availabilityProbeTimeout != 5*time.Second || availabilityFallbackTimeout != 5*time.Second {
		t.Fatal("fixture requires the production five-second request budgets")
	}
	for sample := 0; sample < 2; sample++ {
		online, err := runtime.reverseOnlineStatus(selected)
		if err != nil || !online {
			t.Fatalf("delayed origin lost Reverse session: online=%t err=%v", online, err)
		}
		started := time.Now()
		evidence := formerAvailabilityProbe(runtime)
		if evidence.OK || evidence.LocalFailure || evidence.Failure != probeFailureTimeout {
			t.Fatalf("expected old deadline rejection: %+v", evidence)
		}
		if len(evidence.TargetStages) != len(healthTargets) {
			t.Fatalf("missing failed request stages: %+v", evidence)
		}
		for _, stage := range evidence.TargetStages {
			if stage != "response-headers" {
				t.Fatalf("delay attributed to unexpected stage: %+v", evidence)
			}
		}
		t.Logf("connected Reverse: old-budget probe %d rejected after %s, stages=%v", sample+1, time.Since(started), evidence.TargetStages)
	}
	if threshold := failureConfirmationThreshold(probeEvidence{Failure: probeFailureTimeout}, 3); threshold != 2 {
		t.Fatalf("update fixture for changed timeout threshold: %d", threshold)
	}
	started := time.Now()
	if evidence := runtime.ProbeAvailability(selected); !evidence.OK || evidence.LocalFailure {
		t.Fatalf("production availability budget rejected delayed response: %+v", evidence)
	}
	comparisonElapsed := time.Since(started)
	if evidence := runtime.Probe(selected); !evidence.OK || evidence.QualityUnmeasured || evidence.DelayMS == nil {
		t.Fatalf("recovery did not qualify the same delayed response: %+v", evidence)
	}
	cancel()
	<-done
	if passed.Load() < 10 || failed.Load() != 0 {
		t.Fatalf("data-path comparison: passed=%d failed=%d", passed.Load(), failed.Load())
	}
	t.Logf("production availability succeeded after %s and recovery agreed; concurrent HTTPS data: %d passed, %d failed", comparisonElapsed, passed.Load(), failed.Load())
	mode("normal")
	if evidence := runtime.ProbeAvailability(selected); !evidence.OK {
		t.Fatalf("normal response recovery: %+v", evidence)
	}
	cpuTicks := func() uint64 {
		return testReverseProcessCPUTicks(t, os.Getpid(), corePID)
	}
	for _, former := range []bool{true, false} {
		at, cpu := time.Now(), cpuTicks()
		for range 20 {
			var evidence probeEvidence
			if former {
				evidence = formerAvailabilityProbe(runtime)
			} else {
				evidence = runtime.probeAvailabilityTargets(probeEvidence{Targets: map[string]*int{}, TargetFailures: map[string]probeFailureClass{}}, false)
			}
			if !evidence.OK {
				t.Fatalf("healthy CPU comparison: %+v", evidence)
			}
		}
		t.Logf("healthy HTTP schedule comparison former=%t probes=20 elapsed=%s test_and_core_cpu_ticks=%d", former, time.Since(at), cpuTicks()-cpu)
	}
	mode("silent")
	for _, former := range []bool{true, false} {
		at := time.Now()
		for range 2 {
			var evidence probeEvidence
			if former {
				evidence = formerAvailabilityProbe(runtime)
			} else {
				evidence = runtime.ProbeAvailability(selected)
			}
			if evidence.OK || evidence.LocalFailure || evidence.Failure != probeFailureTimeout || len(evidence.TargetFailures) != 3 {
				t.Fatalf("silent comparison lost complete failure evidence: %+v", evidence)
			}
		}
		elapsed := time.Since(at)
		if elapsed < 9*time.Second || elapsed > 12*time.Second {
			t.Fatalf("two silent rounds exceeded budget: former=%t elapsed=%s", former, elapsed)
		}
		t.Logf("silent comparison former=%t confirmations=2 elapsed=%s scope=HTTP_evidence_only", former, elapsed)
	}
	mode("normal")
	mode("stop")
	if !wait(ctx, time.Second) {
		t.Fatal(ctx.Err())
	}
	started = time.Now()
	if evidence := runtime.ProbeAvailability(selected); evidence.OK || evidence.LocalFailure {
		t.Fatalf("stopped client accepted or local API failed: %+v", evidence)
	} else {
		t.Logf("stopped client rejected after %s: failure=%s stages=%v", time.Since(started), evidence.Failure, evidence.TargetStages)
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		if evidence := runtime.ProbeAvailability(selected); evidence.OK {
			t.Logf("real client restart recovered after %s", time.Since(started))
			return
		}
		if !wait(ctx, time.Second) {
			t.Fatal(ctx.Err())
		}
	}
	t.Fatal("real client did not recover within the fixture deadline")
}

func testReverseProcessCPUTicks(t *testing.T, pids ...int) uint64 {
	t.Helper()
	var total uint64
	for _, pid := range pids {
		body, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		end := strings.LastIndexByte(text, ')')
		if end < 0 {
			t.Fatal("missing process name boundary")
		}
		fields := strings.Fields(text[end+1:])
		if len(fields) < 13 {
			t.Fatal("missing process CPU counters")
		}
		for _, field := range fields[11:13] {
			ticks, err := strconv.ParseUint(field, 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			total += ticks
		}
	}
	return total
}
