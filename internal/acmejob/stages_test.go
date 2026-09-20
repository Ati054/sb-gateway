package acmejob

import (
	"errors"
	"strings"
	"testing"
)

func TestWorkerFailureUsesOnlyAllowlistedStages(t *testing.T) {
	for code, want := range map[int]error{
		WorkerExitInput:        ErrWorkerInput,
		WorkerExitRegistration: ErrRegistration,
		WorkerExitProvider:     ErrDNSProvider,
		WorkerExitValidation:   ErrCAValidation,
		WorkerExitOutput:       ErrWorkerOutput,
		WorkerExitDelegation:   ErrDelegation,
		WorkerExitPropagation:  ErrPropagation,
		99:                     ErrWorker,
	} {
		got := WorkerFailure(code)
		if !errors.Is(got, want) || strings.Contains(got.Error(), "secret") {
			t.Fatalf("exit %d: %v", code, got)
		}
	}
}
