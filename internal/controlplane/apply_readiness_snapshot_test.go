package controlplane

import (
	"errors"
	"testing"
	"time"
)

func TestApplyReadinessSnapshotCannotLoseItsLiveAllowance(t *testing.T) {
	server := newTestServer(t)
	operation := map[string]any{"pending": true, "state": "active_committed",
		"previous_routeros_source": "same", "target_routeros_source": "same"}
	if err := server.repository.saveAuxiliary("apply-operation", operation); err != nil {
		t.Fatal(err)
	}
	server.storeApplyReadiness(&server.plannedNginxReload, true)
	read, resume := make(chan struct{}), make(chan struct{})
	result := make(chan bool, 1)
	go func() {
		pending, _ := server.applyReadinessSnapshot(func() (map[string]any, error) {
			old, err := server.repository.auxiliary("apply-operation")
			close(read)
			<-resume
			return old, err
		})
		result <- pending
	}()
	<-read
	journalCleared, finished := make(chan error, 1), make(chan struct{})
	go func() {
		journalCleared <- server.clearApplyRecovery()
		server.storeApplyReadiness(&server.plannedNginxReload, false)
		close(finished)
	}()
	if err := <-journalCleared; err != nil {
		close(resume)
		<-result
		<-finished
		t.Fatal(err)
	}
	select {
	case <-finished:
		t.Error("live allowance changed while its journal snapshot was still being read")
	case <-time.After(50 * time.Millisecond):
	}
	close(resume)
	if <-result {
		t.Error("a completed healthy Apply produced false recovery-pending readiness")
	}
	<-finished
	if pending, _ := server.applyReadinessSnapshot(nil); pending {
		t.Fatal("completed Apply still reports recovery pending")
	}
}

func TestApplyReadinessSnapshotKeepsRecoveryAndReadFailuresClosed(t *testing.T) {
	server := newTestServer(t)
	operation := map[string]any{"pending": true, "state": "active_committed",
		"previous_routeros_source": "same", "target_routeros_source": "same"}
	if pending, _ := server.applyReadinessSnapshot(func() (map[string]any, error) { return operation, nil }); !pending {
		t.Fatal("a recovered journal inherited a process-local live allowance")
	}
	server.storeApplyReadiness(&server.plannedRuntimeApply, true)
	if pending, planned := server.applyReadinessSnapshot(func() (map[string]any, error) { return nil, errors.New("unreadable journal") }); !pending || planned {
		t.Fatal("an unreadable recovery journal admitted traffic")
	}
}
