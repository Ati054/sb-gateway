package controlplane

import "testing"

func TestStatusNeverHidesAnApplyAwaitingCompletion(t *testing.T) {
	server := newTestServer(t)
	server.plannedRuntimeApply.Store(true)
	for _, state := range []string{"prepared", "runtime_activated", "active_committed", "recovery_pending"} {
		if err := server.repository.saveAuxiliary("apply-operation", map[string]any{
			"pending": true, "state": state, "target_routeros_source": "same", "previous_routeros_source": "same",
		}); err != nil {
			t.Fatal(err)
		}
		status, err := server.statusPayloadWithSelectors(nil)
		if err != nil || status["apply_pending"] != true {
			t.Fatalf("state=%s status=%v err=%v", state, status["apply_pending"], err)
		}
	}
	if err := server.clearApplyRecovery(); err != nil {
		t.Fatal(err)
	}
	status, err := server.statusPayloadWithSelectors(nil)
	if err != nil || status["apply_pending"] != false {
		t.Fatalf("completed status=%v err=%v", status["apply_pending"], err)
	}
}
