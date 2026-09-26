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
	At        string            `json:"at"`
	Event     string            `json:"event"`
	Policy    string            `json:"policy"`
	Node      string            `json:"node,omitempty"`
	From      string            `json:"from,omitempty"`
	To        string            `json:"to,omitempty"`
	Reason    string            `json:"reason,omitempty"`
	Failure   probeFailureClass `json:"failure,omitempty"`
	Count     int               `json:"count,omitempty"`
	Threshold int               `json:"threshold,omitempty"`
	Underlay  string            `json:"underlay,omitempty"`
	Targets   map[string]string `json:"targets,omitempty"`
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
