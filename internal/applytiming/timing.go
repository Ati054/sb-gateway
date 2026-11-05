// Package applytiming records bounded diagnostic spans without controlling Apply.
package applytiming

import (
	"context"
	"encoding/json"
	"sync"
	"time"
)

type Stage uint8

const (
	Prepare Stage = iota
	BackupExport
	BackupBinary
	RouterOSPrepare
	RouterOSExecute
	RuntimeActivate
	RouterOSHealth
	GuardDisarm
	ActiveCommit
	RuntimeLKG
	Prune
	TrafficWait
	RouterOSCleanup
	stageCount
)

var stageNames = [...]string{
	"prepare", "backup_export", "backup_binary", "routeros_prepare_arm",
	"routeros_execute", "runtime_activate", "routeros_health", "guard_disarm",
	"active_commit", "runtime_lkg_commit", "optional_prune", "traffic_wait", "routeros_import_cleanup",
}

type Outcome uint8

const (
	Error Outcome = iota
	Success
	Unchanged
)

const maxSpans = 64
const maxDuration = 24 * time.Hour

type contextKey struct{}
type stageTotal struct {
	count   int
	elapsed time.Duration
}
type recorder struct {
	mu           sync.Mutex
	now          func() time.Time
	emit         func([]byte)
	started      time.Time
	requestID    string
	finished     bool
	startedSpans int
	pending      int
	discarded    int
	totals       [stageCount]stageTotal
}

type spanReport struct {
	Stage     string `json:"stage"`
	Count     int    `json:"count"`
	ElapsedMS int64  `json:"elapsed_ms"`
}
type report struct {
	Version     int          `json:"version"`
	RequestID   string       `json:"request_id,omitempty"`
	Outcome     string       `json:"outcome"`
	ElapsedMS   int64        `json:"elapsed_ms"`
	Nonadditive bool         `json:"spans_nonadditive"`
	Incomplete  int          `json:"incomplete_spans"`
	Discarded   int          `json:"discarded_spans"`
	Stages      []spanReport `json:"stages"`
}

// Begin starts one Apply record. Nested callers share the existing recorder;
// only the first finish call emits. Arbitrary request header text is not retained.
func Begin(ctx context.Context, requestID string, emit func([]byte)) (context.Context, func(Outcome)) {
	return begin(ctx, requestID, emit, time.Now)
}

func begin(ctx context.Context, requestID string, emit func([]byte), now func() time.Time) (context.Context, func(Outcome)) {
	if existing, ok := ctx.Value(contextKey{}).(*recorder); ok {
		return ctx, existing.finish
	}
	if !safeRequestID(requestID) {
		requestID = ""
	}
	r := &recorder{now: now, emit: emit, started: now(), requestID: requestID}
	return context.WithValue(ctx, contextKey{}, r), r.finish
}

func safeRequestID(value string) bool {
	if len(value) < 16 || len(value) > 64 {
		return false
	}
	for _, b := range []byte(value) {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

func boundedDuration(value time.Duration) time.Duration {
	if value < 0 {
		return 0
	}
	if value > maxDuration {
		return maxDuration
	}
	return value
}

func noop() {}

// Start is a no-op outside Apply. Names and errors are never accepted as input.
// Spans can overlap or nest and are explicitly nonadditive. Finish does not wait
// for callbacks; late callbacks cannot alter the emitted record.
func Start(ctx context.Context, stage Stage) func() {
	r, ok := ctx.Value(contextKey{}).(*recorder)
	if !ok || stage >= stageCount {
		return noop
	}
	r.mu.Lock()
	if r.finished {
		r.mu.Unlock()
		return noop
	}
	if r.startedSpans >= maxSpans {
		if r.discarded < maxSpans {
			r.discarded++
		}
		r.mu.Unlock()
		return noop
	}
	r.startedSpans++
	r.pending++
	started := r.now()
	r.mu.Unlock()
	var once sync.Once
	return func() {
		once.Do(func() {
			r.mu.Lock()
			defer r.mu.Unlock()
			if r.finished {
				return
			}
			r.pending--
			total := &r.totals[stage]
			total.count++
			total.elapsed = boundedDuration(total.elapsed + boundedDuration(r.now().Sub(started)))
		})
	}
}

// Run measures the original call without interpreting its result or cancellation.
func Run(ctx context.Context, stage Stage, call func() error) error {
	done := Start(ctx, stage)
	defer done()
	return call()
}

func (r *recorder) finish(outcome Outcome) {
	r.mu.Lock()
	if r.finished {
		r.mu.Unlock()
		return
	}
	r.finished = true
	name := "error"
	if outcome == Success {
		name = "success"
	} else if outcome == Unchanged {
		name = "unchanged"
	}
	value := report{Version: 1, RequestID: r.requestID, Outcome: name,
		ElapsedMS: boundedDuration(r.now().Sub(r.started)).Milliseconds(), Nonadditive: true,
		Incomplete: r.pending, Discarded: r.discarded, Stages: make([]spanReport, 0, stageCount)}
	for stage, total := range r.totals {
		if total.count > 0 {
			value.Stages = append(value.Stages, spanReport{stageNames[stage], total.count, total.elapsed.Milliseconds()})
		}
	}
	r.mu.Unlock()
	// The fixed typed report has neither unsupported values nor unbounded fields.
	body, _ := json.Marshal(value)
	if r.emit != nil {
		r.emit(body)
	}
}
