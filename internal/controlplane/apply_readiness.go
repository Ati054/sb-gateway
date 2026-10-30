package controlplane

import "sync/atomic"

func (server *Server) storeApplyReadiness(flag *atomic.Bool, value bool) {
	server.applyReadinessMu.Lock()
	defer server.applyReadinessMu.Unlock()
	flag.Store(value)
}

func (server *Server) applyReadinessSnapshot(load func() (map[string]any, error)) (pending, plannedRuntime bool) {
	// A journal reader may be descheduled after loading the previous pending
	// record. Keep its live allowances stable until the snapshot is evaluated;
	// successful completion cannot combine that old record with cleared flags.
	server.applyReadinessMu.RLock()
	defer server.applyReadinessMu.RUnlock()
	if load == nil {
		load = func() (map[string]any, error) { return server.repository.auxiliary("apply-operation") }
	}
	operation, err := load()
	if err != nil {
		return true, false
	}
	return operation["pending"] == true && !server.liveApplyReadinessAllowed(operation),
		plannedRuntimeActivationReady(operation, server.plannedRuntimeApply.Load())
}

func (server *Server) prepareHotPolicyReadiness() error {
	// Arm the next allowance before publishing its durable state. Preparation
	// remains valid until this handoff, while the existing runtime is untouched.
	server.storeApplyReadiness(&server.plannedHotPolicyApply, true)
	if err := server.markApplyRecoveryState("runtime_hot_activating"); err != nil {
		return err
	}
	server.storeApplyReadiness(&server.plannedUnchangedApply, false)
	return nil
}
