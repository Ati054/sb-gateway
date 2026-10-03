package agent

import (
	"encoding/json"
	"log"
	"time"
)

// healthEvent is deliberately limited to route/node IDs, fixed probe-target
// labels and failure classes. Server addresses, URLs, credentials and raw
// network errors must not enter the management log.
type healthEvent struct {
	At         string                  `json:"at"`
	Event      string                  `json:"event"`
	Policy     string                  `json:"policy"`
	Node       string                  `json:"node,omitempty"`
	From       string                  `json:"from,omitempty"`
	To         string                  `json:"to,omitempty"`
	Reason     string                  `json:"reason,omitempty"`
	Failure    probeFailureClass       `json:"failure,omitempty"`
	Count      int                     `json:"count,omitempty"`
	Threshold  int                     `json:"threshold,omitempty"`
	Underlay   string                  `json:"underlay,omitempty"`
	Targets    map[string]string       `json:"targets,omitempty"`
	Quality    *switchQuality          `json:"quality,omitempty"`
	Comparison *optimizationComparison `json:"comparison,omitempty"`
}

// Numeric decision evidence is emitted only on a switch. It contains no
// endpoint addresses or probe URLs and does not trigger another probe.
type switchQuality struct {
	FromMedianMS      *int    `json:"from_median_ms,omitempty"`
	FromLossPercent   float64 `json:"from_loss_percent"`
	FromBadProbes     int     `json:"from_bad_probes"`
	ToMedianMS        *int    `json:"to_median_ms,omitempty"`
	ToLossPercent     float64 `json:"to_loss_percent"`
	ToProbeAgeSeconds int     `json:"to_probe_age_seconds"`
}

func switchQualityEvidence(now time.Time, item *policyHealthState, from, to, reason string) *switchQuality {
	if reason != "active-degraded" {
		return nil
	}
	age := int(now.Unix() - int64(item.LastProbeAt[to]))
	if age < 0 {
		age = 0
	}
	return &switchQuality{
		FromMedianMS: item.MedianDelayMS[from], FromLossPercent: item.PacketLossPercent[from],
		FromBadProbes: item.Failures[from], ToMedianMS: item.MedianDelayMS[to],
		ToLossPercent: item.PacketLossPercent[to], ToProbeAgeSeconds: age,
	}
}

func switchOptimizationEvidence(item *policyHealthState, to, reason string) *optimizationComparison {
	comparison := item.OptimizationLastResult
	if !isPlannedOptimization(reason) || comparison == nil || comparison.Result != optimizationWin ||
		comparison.Candidate != to || comparison.At != item.LastSwitchAt {
		return nil
	}
	return comparison
}

func (controller *healthController) emitHealthEvent(event healthEvent) {
	if event.At == "" {
		event.At = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if controller.eventSink != nil {
		controller.eventSink(event)
		return
	}
	if body, err := json.Marshal(event); err == nil {
		log.Printf("agent: route-health %s", body)
	}
}

func probeTargetResults(evidence probeEvidence) map[string]string {
	if len(evidence.Targets) == 0 {
		return nil
	}
	results := make(map[string]string, len(evidence.Targets))
	for target, delay := range evidence.Targets {
		if delay != nil {
			results[target] = "ok"
		} else if failure := evidence.TargetFailures[target]; failure != "" {
			results[target] = string(failure)
		} else {
			results[target] = "failed"
		}
	}
	return results
}
