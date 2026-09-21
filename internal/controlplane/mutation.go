package controlplane

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
)

const (
	mutationApply        = "apply"
	mutationLifecycle    = "lifecycle"
	mutationRecovery     = "recovery"
	mutationSubscription = "subscription"
)

// stateMutationConflict checks the durable operation journals. mutationMu is
// the in-process owner; these records extend the same exclusion across an API
// restart while RouterOS or runtime work may still be in flight.
func (server *Server) stateMutationConflict(allowed string) (string, error) {
	if allowed != mutationApply {
		operation, err := server.repository.auxiliary("apply-operation")
		if err != nil {
			return "", err
		}
		if operation["pending"] == true {
			return mutationApply, nil
		}
	}
	if allowed != mutationLifecycle {
		operation, err := server.repository.auxiliary("lifecycle-operation")
		if err != nil {
			return "", err
		}
		if lifecycleOperationActive(operation) {
			return mutationLifecycle, nil
		}
	}
	if allowed != mutationSubscription {
		operation, err := server.repository.auxiliary("subscription-runtime-operation")
		if err != nil {
			return "", err
		}
		if operation["pending"] == true {
			return mutationSubscription, nil
		}
	}
	if allowed != mutationRecovery {
		configRoot, _, _ := server.recoveryRoots()
		_, err := os.Lstat(filepath.Join(configRoot, ".sb-gateway-recovery-pending.json"))
		if err == nil {
			return mutationRecovery, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
	}
	return "", nil
}

func (server *Server) rejectMutationConflict(response http.ResponseWriter, request *http.Request, allowed string) bool {
	conflict, err := server.stateMutationConflict(allowed)
	if err != nil {
		server.internalStateError(response, request, err)
		return true
	}
	if conflict == "" {
		return false
	}
	server.writeErrorResponse(response, request, 409, "state_mutation_in_progress", "Another configuration-changing operation is still in progress. Status and diagnostics remain available.")
	return true
}
