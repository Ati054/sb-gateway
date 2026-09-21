package controlplane

import (
	"context"
	"errors"
	"fmt"
	"log"
	"path/filepath"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const applyRecoveryRetryInterval = 15 * time.Second

func (server *Server) beginApplyRecovery(previousRevision, recoveryRevision, targetRevision, previousRouterOS, targetRouterOS, runtimeRevision string) error {
	return server.repository.saveAuxiliary("apply-operation", map[string]any{
		"kind":                     "apply",
		"pending":                  true,
		"state":                    "prepared",
		"previous_revision":        nullableString(previousRevision),
		"recovery_revision":        recoveryRevision,
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
// whether the interrupted candidate should have committed. A first Apply has no
// active commit point, so its journal names a separately persisted safe
// installation generation that is restored without publishing active.json.
func (server *Server) reconcilePendingApply(ctx context.Context) (bool, error) {
	operation, err := server.pendingApplyRecovery()
	if err != nil || operation == nil {
		return false, err
	}
	if server.runtime == nil || server.applyRouterOS == nil {
		return true, errors.New("Apply recovery requires native runtime and RouterOS control")
	}
	activeRevision, err := server.repository.activeRevision()
	if err != nil {
		return true, err
	}
	var desiredConfig map[string]any
	var desiredRevision, desiredRouterOS string
	var nodes []map[string]any
	firstApplyRecovery := activeRevision == ""
	if firstApplyRecovery {
		if text(operation["previous_revision"]) != "" {
			return true, errors.New("Apply recovery active commit point is missing")
		}
		desiredRevision = text(operation["recovery_revision"])
		if desiredRevision == "" {
			// Compatibility with a pending first-Apply journal written before the
			// dedicated recovery_revision field existed. Reconstruct only the
			// deterministic safe baseline and accept it only if its rendered
			// RouterOS source exactly matches the source already in the journal.
			targetRevision := text(operation["target_revision"])
			if !safeRevision(targetRevision) {
				return true, errors.New("first Apply recovery target revision is invalid")
			}
			target, loadErr := server.repository.loadGeneration(targetRevision)
			if loadErr != nil {
				return true, loadErr
			}
			desiredConfig = firstApplyRollbackConfig(target)
			rendered, renderErr := runtimeconfig.RenderRouterOSTrafficCandidate(desiredConfig, nil, server.opts.Runtime.RuleSetDir)
			if renderErr != nil {
				return true, renderErr
			}
			if recorded := text(operation["previous_routeros_source"]); recorded == "" || recorded != rendered {
				return true, errors.New("first Apply recovery baseline cannot be verified")
			}
			desiredRevision, err = server.repository.stageGeneration(desiredConfig)
			if err != nil {
				return true, err
			}
		} else {
			if !safeRevision(desiredRevision) {
				return true, errors.New("first Apply recovery revision is invalid")
			}
			desiredConfig, err = server.repository.loadGeneration(desiredRevision)
			if err != nil {
				return true, err
			}
		}
		desiredRouterOS = text(operation["previous_routeros_source"])
		if desiredRouterOS == "" {
			return true, errors.New("first Apply recovery RouterOS source is missing")
		}
	} else {
		desiredRevision = activeRevision
		desiredConfig, err = server.repository.loadGeneration(activeRevision)
		if err != nil {
			return true, err
		}
		nodes = server.routerOSNodesForRevision(activeRevision, nil)
		activePointer, pointerErr := server.repository.readJSON(filepath.Join(server.repository.root, "active.json"))
		if pointerErr != nil {
			return true, pointerErr
		}
		desiredRouterOS = text(activePointer["routeros_source"])
		if desiredRouterOS == "" {
			desiredRouterOS, err = runtimeconfig.RenderRouterOSTrafficCandidate(desiredConfig, nodes, server.opts.Runtime.RuleSetDir)
			if err != nil {
				return true, err
			}
		}
	}
	candidate, err := server.runtime.prepare(desiredConfig, nodes)
	if err != nil {
		return true, err
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
	_, err = server.applyRouterOS(ctx, desiredConfig, desiredRouterOS, fallbackRouterOS, activate, func(context.Context, routeros.BackupRef) error {
		if !activated {
			return errors.New("Apply recovery runtime was not activated")
		}
		return server.runtime.commit(candidate)
	})
	if err != nil {
		_ = server.markApplyRecoveryState("recovery_pending")
		return true, err
	}
	if firstApplyRecovery {
		confirmedRevision, confirmErr := server.repository.activeRevision()
		if confirmErr != nil {
			return true, confirmErr
		}
		if confirmedRevision != "" {
			return true, fmt.Errorf("first Apply recovery observed a new active revision %s", confirmedRevision)
		}
	}
	if err := server.clearApplyRecovery(); err != nil {
		return true, err
	}
	if firstApplyRecovery {
		log.Printf("control-plane: interrupted first Apply reconciled to safe installation revision %s", desiredRevision)
	} else {
		log.Printf("control-plane: interrupted Apply reconciled to active revision %s", activeRevision)
	}
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
