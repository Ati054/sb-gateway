package agent

import (
	"bytes"
	"context"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

func TestHealthCheckpointCoalescesHistoryButRefreshesReadiness(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "a", "a", true
	item.RuntimeObservedAt = "2026-01-01T00:00:00Z"
	item.LastProbeAt["a"] = 1
	state := healthState{"route": item}
	controller := &healthController{}
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	item.LastProbeAt["a"] = 2
	item.RuntimeObservedAt = "2026-01-01T00:00:01Z"
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) {
		t.Fatal("routine history rewritten before its deadline", err)
	}
	var proof map[string]runtimeproof.SelectorObservation
	if err := readJSON(filepath.Join(root, runtimeproof.SelectorSnapshotName), &proof); err != nil || proof["route"].Observed != item.RuntimeObservedAt {
		t.Fatal("live proof was delayed", err)
	}
	controller.checkpointAt = controller.checkpointAt.Add(-healthCheckpointInterval)
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	var saved healthState
	if err := readJSON(path, &saved); err != nil || saved["route"].LastProbeAt["a"] != 2 {
		t.Fatal("checkpoint did not catch up", err)
	}
}

func TestHealthCheckpointMaintenancePreservesHealthDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		root := t.TempDir()
		item := newPolicyHealthState()
		item.Selected = "a"
		state := healthState{"route": item}
		controller := &healthController{opts: Options{StateRoot: root}, state: state}
		path := statePath(root, "selector-health")
		if err := controller.publishRoutineHealthState(path, state); err != nil {
			t.Fatal(err)
		}
		item.CheckedAt = "changed"
		if err := controller.publishRoutineHealthState(path, state); err != nil {
			t.Fatal(err)
		}
		controller.checkpointAt = time.Now().Add(-healthCheckpointInterval + 20*time.Millisecond)
		start := time.Now()
		if !controller.waitWithHealthCheckpoint(context.Background(), 120*time.Millisecond, nil, time.Millisecond, nil, nil) {
			t.Fatal("health wait was cancelled")
		}
		if elapsed := time.Since(start); elapsed != 120*time.Millisecond {
			t.Fatalf("maintenance displaced original health deadline: %s", elapsed)
		}
		var saved healthState
		if err := readJSON(path, &saved); err != nil || saved["route"].CheckedAt != "changed" || controller.checkpointPending {
			t.Fatal("maintenance did not flush latest state", err)
		}
	})
}

func TestHealthCheckpointImmediatelyPersistsFailureAndSelection(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	controller := &healthController{}
	item := newPolicyHealthState()
	ensureHealthMaps(item)
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "a", "a", true
	item.AvailabilityOK = map[string]bool{"a": true}
	state := healthState{"route": item}
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	item.AvailabilityOK["a"] = false
	item.AvailabilityFailures["a"] = 1
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	var saved healthState
	if err := readJSON(path, &saved); err != nil || saved["route"].AvailabilityFailures["a"] != 1 {
		t.Fatal("failure was delayed", err)
	}
	item.Selected, item.RuntimeSelected = "b", "b"
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(path, &saved); err != nil || saved["route"].Selected != "b" {
		t.Fatal("switch was delayed", err)
	}
	item.LastWorkingSelection = &workingSelection{Selected: "b", Mode: "best", CandidateSignature: "a\nb"}
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(path, &saved); err != nil || saved["route"].LastWorkingSelection == nil {
		t.Fatal("first durable working selection was delayed", err)
	}
}

func TestHealthCheckpointZeroFailureInsertionIsRoutine(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	controller := &healthController{}
	item := newPolicyHealthState()
	state := healthState{"route": item}
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	item.AvailabilityFailures["a"] = 0
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) || !controller.checkpointPending {
		t.Fatal("zero failure insertion forced history")
	}
	item.AvailabilityFailures["a"] = 1
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	var saved healthState
	if err := readJSON(path, &saved); err != nil || saved["route"].AvailabilityFailures["a"] != 1 {
		t.Fatal("real failure not immediate", err)
	}
	item.AvailabilityFailures["a"] = 0
	item.CheckedAt = "recovered"
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(path, &saved); err != nil || saved["route"].AvailabilityFailures["a"] != 0 || saved["route"].CheckedAt != "recovered" {
		t.Fatal("recovery from a positive failure count was delayed", err)
	}
}

func TestHealthCheckpointForcedPublicationResetsRoutineDeadline(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	controller := &healthController{}
	item := newPolicyHealthState()
	state := healthState{"route": item}
	item.CheckedAt = "forced"
	if err := controller.publishImmediateHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	item.CheckedAt = "routine"
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	var saved healthState
	if err := readJSON(path, &saved); err != nil || saved["route"].CheckedAt != "forced" || !controller.checkpointPending {
		t.Fatal("forced checkpoint was immediately duplicated", err)
	}
}

type checkpointMaintenanceFailureCounter struct {
	attempts atomic.Int64
	onFirst  func()
}

func (counter *checkpointMaintenanceFailureCounter) Write(message []byte) (int, error) {
	if bytes.Contains(message, []byte("agent: routine health checkpoint flush failed:")) {
		if counter.attempts.Add(1) == 1 && counter.onFirst != nil {
			counter.onFirst()
		}
	}
	return len(message), nil
}

func captureCheckpointMaintenanceFailures(t *testing.T, onFirst func()) *checkpointMaintenanceFailureCounter {
	t.Helper()
	counter := &checkpointMaintenanceFailureCounter{onFirst: onFirst}
	previous := log.Writer()
	log.SetOutput(counter)
	t.Cleanup(func() { log.SetOutput(previous) })
	return counter
}

func unwritablePendingCheckpoint(t *testing.T) *healthController {
	t.Helper()
	root := t.TempDir()
	path := statePath(root, "selector-health")
	controller := &healthController{opts: Options{StateRoot: root}}
	item := newPolicyHealthState()
	controller.state = healthState{"route": item}
	if err := controller.publishRoutineHealthState(path, controller.state); err != nil {
		t.Fatal(err)
	}
	item.CheckedAt = "pending"
	if err := controller.publishRoutineHealthState(path, controller.state); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	return controller
}

func TestHealthCheckpointWriteFailureDoesNotBusyWake(t *testing.T) {
	controller := unwritablePendingCheckpoint(t)
	failures := captureCheckpointMaintenanceFailures(t, nil)
	controller.checkpointAt = time.Now().Add(-healthCheckpointInterval + 20*time.Millisecond)
	checkpointAt := controller.checkpointAt
	start := time.Now()
	if !controller.waitWithHealthCheckpoint(context.Background(), 120*time.Millisecond, nil, time.Millisecond, nil, nil) {
		t.Fatal("unexpected cancellation")
	}
	if elapsed := time.Since(start); elapsed < 110*time.Millisecond {
		t.Fatalf("failed history write woke before the original health deadline: %s", elapsed)
	}
	if attempts := failures.attempts.Load(); attempts != 1 {
		t.Fatalf("failed history write retried within the same health wait: attempts=%d", attempts)
	}
	if !controller.checkpointPending || !controller.checkpointAt.Equal(checkpointAt) {
		t.Fatal("failed history write acknowledged or discarded the pending checkpoint")
	}
}

func TestHealthCheckpointWriteFailureWaitRemainsCancellable(t *testing.T) {
	controller := unwritablePendingCheckpoint(t)
	// The long deadline catches a lost cancellation without imposing a disk
	// performance requirement; the first actual failure cancels immediately.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	failures := captureCheckpointMaintenanceFailures(t, cancel)
	controller.checkpointAt = time.Now().Add(-healthCheckpointInterval + 20*time.Millisecond)
	if controller.waitWithHealthCheckpoint(ctx, time.Hour, nil, time.Millisecond, nil, nil) {
		t.Fatal("failed maintenance wait ignored context cancellation")
	}
	if ctx.Err() != context.Canceled || failures.attempts.Load() != 1 || !controller.checkpointPending {
		t.Fatalf("cancellation did not interrupt the single failed flush: error=%v attempts=%d pending=%v", ctx.Err(), failures.attempts.Load(), controller.checkpointPending)
	}
}

func TestHealthCheckpointImmediatelyPersistsWithdrawalAndMembership(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	controller := &healthController{}
	item := newPolicyHealthState()
	item.Selected, item.RuntimeSelected, item.RuntimeConfirmed = "a", "a", true
	item.CandidateNodes = map[string]healthNode{"a": {Fingerprint: "first"}}
	state := healthState{"route": item}
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	item.RuntimeConfirmed, item.RuntimeError = false, "offline"
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	var saved healthState
	if err := readJSON(path, &saved); err != nil || saved["route"].RuntimeConfirmed || saved["route"].RuntimeError != "offline" {
		t.Fatal("runtime withdrawal was delayed", err)
	}
	var proof map[string]runtimeproof.SelectorObservation
	if err := readJSON(filepath.Join(root, runtimeproof.SelectorSnapshotName), &proof); err != nil || proof["route"].Confirmed {
		t.Fatal("unready traffic proof remained confirmed", err)
	}
	item.CandidateNodes["a"] = healthNode{Fingerprint: "replacement"}
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	if err := readJSON(path, &saved); err != nil || saved["route"].CandidateNodes["a"].Fingerprint != "replacement" {
		t.Fatal("endpoint replacement was delayed", err)
	}
	if err := controller.publishRoutineHealthState(path, healthState{}); err != nil {
		t.Fatal(err)
	}
	var removed healthState
	if err := readJSON(path, &removed); err != nil || len(removed) != 0 {
		t.Fatal("removed policy remained in checkpoint", err)
	}
}

func TestHealthCheckpointGenerationChangePreemptsMaintenance(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	item := newPolicyHealthState()
	controller := &healthController{opts: Options{StateRoot: root}, state: healthState{"route": item}}
	if err := controller.publishRoutineHealthState(path, controller.state); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	item.CheckedAt = "pending-old-generation"
	if err := controller.publishRoutineHealthState(path, controller.state); err != nil {
		t.Fatal(err)
	}
	generation := filepath.Join(root, "generation")
	if err := os.WriteFile(generation, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	writeDone := make(chan error, 1)
	go func() {
		time.Sleep(20 * time.Millisecond)
		writeDone <- os.WriteFile(generation, []byte("replacement-generation"), 0600)
	}()
	start := time.Now()
	if !controller.waitWithHealthCheckpoint(context.Background(), 2*time.Second, []string{generation}, time.Millisecond, nil, nil) {
		t.Fatal("unexpected cancellation")
	}
	if err := <-writeDone; err != nil {
		t.Fatal(err)
	}
	if time.Since(start) >= time.Second {
		t.Fatal("generation reload waited for routine history")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(before) || !controller.checkpointPending {
		t.Fatal("old pending generation was flushed before reconciliation", err)
	}
}

func TestHealthCheckpointFailedCriticalWriteRemainsPending(t *testing.T) {
	root := t.TempDir()
	path := statePath(root, "selector-health")
	controller := &healthController{}
	item := newPolicyHealthState()
	state := healthState{"route": item}
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	item.RuntimeError = "unavailable"
	if err := controller.publishRoutineHealthState(path, state); err == nil || !controller.checkpointPending {
		t.Fatal("failed critical checkpoint was not retained", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := controller.publishRoutineHealthState(path, state); err != nil {
		t.Fatal(err)
	}
	var saved healthState
	if err := readJSON(path, &saved); err != nil || saved["route"].RuntimeError != "unavailable" || controller.checkpointPending {
		t.Fatal("repaired checkpoint did not publish the latest critical state", err)
	}
}
