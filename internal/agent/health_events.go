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
	At               string                  `json:"at"`
	Event            string                  `json:"event"`
	Policy           string                  `json:"policy"`
	Node             string                  `json:"node,omitempty"`
	From             string                  `json:"from,omitempty"`
	To               string                  `json:"to,omitempty"`
	Reason           string                  `json:"reason,omitempty"`
	Failure          probeFailureClass       `json:"failure,omitempty"`
	Count            int                     `json:"count,omitempty"`
	Threshold        int                     `json:"threshold,omitempty"`
	Underlay         string                  `json:"underlay,omitempty"`
	Targets          map[string]string       `json:"targets,omitempty"`
	TargetStages     map[string]string       `json:"target_stages,omitempty"`
	Quality          *switchQuality          `json:"quality,omitempty"`
	Comparison       *optimizationComparison `json:"comparison,omitempty"`
	ReserveSelection *emergencySelection     `json:"reserve_selection,omitempty"`
}

// Captured only for the switching tick, never persisted in health history.
// A missing result means canceled/unfinished work, not a failed reserve.
type emergencySelection struct {
	Reason    string                  `json:"reason"`
	Preferred []string                `json:"preferred,omitempty"`
	Probes    []emergencyReserveProbe `json:"probes"`
}

type emergencyReserveProbe struct {
	Node            string  `json:"node"`
	Result          string  `json:"result"`
	PrimaryDelayMS  *int    `json:"primary_delay_ms,omitempty"`
	PrimarySampleAt float64 `json:"primary_sample_at,omitempty"`
}

func emergencySelectionEvidence(item *policyHealthState, candidates, preferred []string, measured map[string]probeEvidence, chosen string) *emergencySelection {
	result := &emergencySelection{Reason: "no-fresh-ranking", Preferred: append([]string(nil), preferred...)}
	if contains(preferred, chosen) {
		result.Reason = "fresh-ranked-reserve"
	} else if len(preferred) > 0 {
		result.Reason = "ranked-reserves-pending-or-unavailable"
	}
	for _, candidate := range candidates {
		probe := emergencyReserveProbe{Node: candidate, Result: "not-completed"}
		if evidence, checked := measured[candidate]; checked {
			probe.Result = "failed"
			if evidence.OK {
				probe.Result = "ok"
			} else if evidence.Failure != "" {
				probe.Result = string(evidence.Failure)
			}
		}
		if sample, observedAt := latestQualityObservation(item, candidate); sample.OK && sample.DelayMS != nil && *sample.DelayMS > 0 && observedAt > 0 {
			delay := *sample.DelayMS
			probe.PrimaryDelayMS, probe.PrimarySampleAt = &delay, observedAt
		}
		result.Probes = append(result.Probes, probe)
	}
	return result
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
