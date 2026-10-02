package controlplane

import (
	"context"
	"errors"
	"log"
	"os"
	"time"
)

var errRouterOSLogSyncDeferred = errors.New("RouterOS log reconciliation deferred during configuration mutation")

// This runs in the new image, not in the old image's update scheduler. A
// production upgrade therefore applies the logging change without a new Apply.
// Periodic reconciliation also covers a later RouterOS backup rollback.
func (server *Server) runRouterOSFetchLogScheduler(ctx context.Context) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		operation, cancel := context.WithTimeout(ctx, 20*time.Second)
		changed, err := server.suppressRouterOSFetchInfo(operation)
		cancel()
		interval := time.Hour
		if err != nil {
			interval = 30 * time.Second
			if !errors.Is(err, os.ErrNotExist) && !errors.Is(err, errRouterOSLogSyncDeferred) && ctx.Err() == nil {
				log.Printf("control-plane: RouterOS service log reconciliation pending: %v", err)
			}
		} else if changed {
			log.Print("control-plane: RouterOS service log rules synchronized")
		}
		timer.Reset(interval)
	}
}

func (server *Server) suppressRouterOSFetchInfo(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !server.mutationMu.TryLock() {
		return false, errRouterOSLogSyncDeferred
	}
	defer server.mutationMu.Unlock()
	if conflict, err := server.stateMutationConflict(""); err != nil {
		return false, err
	} else if conflict != "" {
		return false, errRouterOSLogSyncDeferred
	}
	active, err := server.repository.loadActive()
	if err != nil {
		return false, err
	}
	client, _, err := server.newRouterOSRESTClient(active)
	if err != nil {
		return false, err
	}
	defer client.CloseIdleConnections()
	return client.SuppressServiceInfoLogs(ctx)
}
