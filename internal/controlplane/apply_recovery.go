package controlplane

import (
	"context"
	"errors"
	"log"
	"path/filepath"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const applyRecoveryRetryInterval = 15 * time.Second

func (server *Server) beginApplyRecovery(previousRevision, targetRevision, previousRouterOS, targetRouterOS, runtimeRevision string) error {
	return server.repository.saveAuxiliary("apply-operation", map[string]any{
		"kind":                     "apply",
		"pending":                  true,
		"state":                    "prepared",
		"previous_revision":        nullableString(previousRevision),
		"target_revision":          targetRevision,
		"previous_routeros_source": previousRouterOS,
		"target_routeros_source":   targetRouterOS,
		"runtime_revision":         runtimeRevision,
		"started_at":               server.now().UTC().Format(time.RFC3339Nano),
	})
}

func (server *Server) markApplyRecoveryState(state string) error {
	operation, err := server.repository.auxiliary("apply-operation")
	if err != nil || operation["pending"] != true {
		return err
	}
	operation["state"] = state
	operation[state+"_at"] = server.now().UTC().Format(time.RFC3339Nano)
	return server.repository.saveAuxiliary("apply-operation", operation)
}

func (server *Server) clearApplyRecovery() error {
	return server.repository.saveAuxiliary("apply-operation", map[string]any{})
}

func (server *Server) finishFailedApplyRecovery(err error) {
	var failure *applyFailureError
	if errors.As(err, &failure) && failure.state == applyRolledBack {
		if clearErr := server.clearApplyRecovery(); clearErr != nil {
			log.Printf("control-plane: rolled-back Apply journal cleanup pending: %v", clearErr)
		}
		return
	}
	if markErr := server.markApplyRecoveryState("recovery_pending"); markErr != nil {
		log.Printf("control-plane: Apply recovery journal update failed: %v", markErr)
	}
}

func (server *Server) pendingApplyRecovery() (map[string]any, error) {
	operation, err := server.repository.auxiliary("apply-operation")
	if err != nil || operation["pending"] != true {
		return nil, err
	}
	return operation, nil
}

// reconcilePendingApply treats active.json as the only commit decision after a
// crash. It rebuilds runtime and RouterOS from that generation; it never guesses
// whether the interrupted candidate should have committed.
func (server *Server) reconcilePendingApply(ctx context.Context) (bool, error) {
	operation, err := server.pendingApplyRecovery()
	if err != nil || operation == nil {
		return false, err
	}
	if server.runtime == nil || server.applyRouterOS == nil {
		return true, errors.New("Apply recovery requires native runtime and RouterOS control")
	}
	activePointer, err := server.repository.readJSON(filepath.Join(server.repository.root, "active.json"))
	if err != nil {
		return true, err
	}
	activeRevision := text(activePointer["revision"])
	if !safeRevision(activeRevision) {
		return true, errors.New("Apply recovery active revision is invalid")
	}
	active, err := server.repository.loadGeneration(activeRevision)
	if err != nil {
		return true, err
	}
	nodes := server.routerOSNodesForRevision(activeRevision, nil)
	candidate, err := server.runtime.prepare(active, nodes)
	if err != nil {
		return true, err
	}
	desiredRouterOS := text(activePointer["routeros_source"])
	if desiredRouterOS == "" {
		desiredRouterOS, err = runtimeconfig.RenderRouterOSTrafficCandidate(active, nodes, server.opts.Runtime.RuleSetDir)
		if err != nil {
			return true, err
		}
	}
	fallbackRouterOS := text(operation["target_routeros_source"])
	if fallbackRouterOS == "" || fallbackRouterOS == desiredRouterOS {
		fallbackRouterOS = text(operation["previous_routeros_source"])
	}
	if fallbackRouterOS == "" {
		fallbackRouterOS = desiredRouterOS
	}
	activated := false
	activate := func(recoveryContext context.Context) error {
		if activated {
			return nil
		}
		if _, activateErr := server.runtime.activate(recoveryContext, candidate); activateErr != nil {
			return activateErr
		}
		activated = true
		return nil
	}
	_, err = server.applyRouterOS(ctx, active, desiredRouterOS, fallbackRouterOS, activate, func(context.Context, routeros.BackupRef) error {
		if !activated {
			return errors.New("Apply recovery runtime was not activated")
		}
		return server.runtime.commit(candidate)
	})
	if err != nil {
		_ = server.markApplyRecoveryState("recovery_pending")
		return true, err
	}
	if err := server.clearApplyRecovery(); err != nil {
		return true, err
	}
	log.Printf("control-plane: interrupted Apply reconciled to active revision %s", activeRevision)
	return true, nil
}

func (server *Server) runApplyRecoveryScheduler(ctx context.Context) {
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		server.mutationMu.Lock()
		worked, err := server.reconcilePendingApply(ctx)
		server.mutationMu.Unlock()
		if err != nil {
			log.Printf("control-plane: interrupted Apply recovery pending: %v", err)
		}
		delay := 30 * time.Second
		if worked {
			delay = applyRecoveryRetryInterval
		}
		timer.Reset(delay)
	}
}
