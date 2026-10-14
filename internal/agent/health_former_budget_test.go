package agent

import (
	"context"
	"time"
)

// Preserve the former HTTP schedule only for controlled old/new comparisons:
// primary for two seconds, followed by concurrent three-second alternatives.
// The caller must first select and qualify the real proxy/Reverse handler.
func formerAvailabilityProbe(runtime *xraySelectorRuntime) probeEvidence {
	type result struct {
		index int
		delay int
		err   error
	}
	ctx, cancel := context.WithCancel(runtime.requestContext())
	defer cancel()
	request := func(index int, timeout time.Duration) result {
		target := healthTargets[index]
		trace := beginHealthStage("https", runtime.stageLane(), "", "")
		trace.target(target.label)
		started := time.Now()
		_, err := downloadThroughProxyContext(ctx, runtime.opts.ProbeURL, target.url, timeout, 1024, target.status)
		trace.finish(err == nil)
		return result{index, maxInt(1, int(time.Since(started).Milliseconds())), err}
	}
	evidence := probeEvidence{QualityUnmeasured: true, Targets: map[string]*int{}, TargetFailures: map[string]probeFailureClass{}, TargetStages: map[string]string{}}
	failures := []probeFailureClass{}
	record := func(r result) {
		label := healthTargets[r.index].label
		if r.err == nil {
			evidence.OK, evidence.DelayMS = true, &r.delay
			evidence.Targets[label] = &r.delay
			return
		}
		evidence.Targets[label] = nil
		failure := classifyProbeError(r.err)
		evidence.TargetFailures[label] = failure
		if stage := probeErrorStage(r.err); stage != "" {
			evidence.TargetStages[label] = stage
		}
		failures = append(failures, failure)
	}
	record(request(0, 2*time.Second))
	if evidence.OK {
		return evidence
	}
	count := minInt(3, len(healthTargets)) - 1
	results := make(chan result, count)
	for index := 1; index <= count; index++ {
		go func(index int) { results <- request(index, 3*time.Second) }(index)
	}
	for range count {
		r := <-results
		if !evidence.OK {
			record(r)
			if evidence.OK {
				cancel()
			}
		}
	}
	if !evidence.OK {
		evidence.Failure = classifyTargetFailures(failures)
	}
	return evidence
}
