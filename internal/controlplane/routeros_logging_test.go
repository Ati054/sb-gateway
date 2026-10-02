package controlplane

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRouterOSLogReconciliationDefersWithoutWaitingForApply(t *testing.T) {
	server := newTestServer(t)
	server.mutationMu.Lock()
	defer server.mutationMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := server.suppressRouterOSFetchInfo(ctx)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, errRouterOSLogSyncDeferred) {
			t.Fatalf("busy reconciliation: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("log reconciliation blocked behind Apply")
	}
}

func TestRouterOSLogReconciliationRejectsCancelledContext(t *testing.T) {
	server := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := server.suppressRouterOSFetchInfo(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled reconciliation: %v", err)
	}
}

func TestRouterOSLogReconciliationDefersForPersistedMutation(t *testing.T) {
	for _, test := range []struct {
		journal   string
		operation map[string]any
	}{
		{"apply-operation", map[string]any{"pending": true}},
		{"lifecycle-operation", map[string]any{"state": "scheduled"}},
		{"subscription-runtime-operation", map[string]any{"pending": true}},
	} {
		t.Run(test.journal, func(t *testing.T) {
			server := newTestServer(t)
			if err := server.repository.saveAuxiliary(test.journal, test.operation); err != nil {
				t.Fatal(err)
			}
			if _, err := server.suppressRouterOSFetchInfo(context.Background()); !errors.Is(err, errRouterOSLogSyncDeferred) {
				t.Fatalf("persisted mutation was not deferred before network access: %v", err)
			}
		})
	}
}
