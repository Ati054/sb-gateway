package agent

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

type healthStageRecord struct {
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
	Stage      string `json:"stage"`
	Lane       string `json:"lane"`
	Policy     string `json:"policy,omitempty"`
	Node       string `json:"node,omitempty"`
	Target     string `json:"target,omitempty"`
	Operation  string `json:"operation,omitempty"`
	ElapsedMS  int64  `json:"elapsed_ms"`
	QueueMS    int64  `json:"queue_ms,omitempty"`
	ExecMS     int64  `json:"exec_ms,omitempty"`
	OK         bool   `json:"ok"`
}

type healthStageTrace struct {
	record   healthStageRecord
	started  time.Time
	acquired time.Time
}

// Opt-in laboratory timings never include command arguments or raw errors.
func beginHealthStage(stage, lane, policy, node string) *healthStageTrace {
	if os.Getenv("SB_HEALTH_STAGE_TRACE") != "1" {
		return nil
	}
	return &healthStageTrace{record: healthStageRecord{Stage: stage, Lane: lane, Policy: policy, Node: node}, started: time.Now()}
}

func (trace *healthStageTrace) command(operation string) {
	if trace == nil {
		return
	}
	switch operation {
	case "bi", "lso", "bo", "ado", "rmo", "statsquery":
		trace.record.Operation = operation
	default:
		trace.record.Operation = "other"
	}
}

func (trace *healthStageTrace) acquiredSlot() {
	if trace != nil {
		trace.acquired = time.Now()
	}
}

func (trace *healthStageTrace) target(label string) {
	if trace == nil {
		return
	}
	switch label {
	case "cloudflare-trace", "example-web", "gstatic-204":
		trace.record.Target = label
	default:
		trace.record.Target = "other"
	}
}

func (trace *healthStageTrace) result(finished time.Time, ok bool) healthStageRecord {
	result := trace.record
	result.StartedAt, result.FinishedAt = trace.started.UTC().Format(time.RFC3339Nano), finished.UTC().Format(time.RFC3339Nano)
	result.ElapsedMS, result.OK = nonnegativeStageMS(trace.started, finished), ok
	if result.Stage == "api" {
		if trace.acquired.IsZero() {
			result.QueueMS = result.ElapsedMS
		} else {
			result.QueueMS = nonnegativeStageMS(trace.started, trace.acquired)
			result.ExecMS = nonnegativeStageMS(trace.acquired, finished)
		}
	}
	return result
}

func nonnegativeStageMS(started, finished time.Time) int64 {
	if finished.Before(started) {
		return 0
	}
	return finished.Sub(started).Milliseconds()
}

func (trace *healthStageTrace) finish(ok bool) {
	if trace == nil {
		return
	}
	if body, err := json.Marshal(trace.result(time.Now(), ok)); err == nil {
		log.Printf("agent: health-stage %s", body)
	}
}

func (runtime *xraySelectorRuntime) stageLane() string {
	if runtime.probeSelector != "" {
		return runtime.probeSelector
	}
	return "active"
}
