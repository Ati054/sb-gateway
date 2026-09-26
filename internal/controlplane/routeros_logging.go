package controlplane

import (
	"context"
	"errors"
	"log"
	"os"
	"time"
)

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
		interval := 5 * time.Minute
		if err != nil {
			interval = 30 * time.Second
			if !errors.Is(err, os.ErrNotExist) && ctx.Err() == nil {
				log.Printf("control-plane: RouterOS fetch log filter pending: %v", err)
			}
		} else if changed {
			log.Print("control-plane: RouterOS fetch,info log entries suppressed")
		}
		timer.Reset(interval)
	}
}

func (server *Server) suppressRouterOSFetchInfo(ctx context.Context) (bool, error) {
	server.mutationMu.Lock()
	defer server.mutationMu.Unlock()
	active, err := server.repository.loadActive()
	if err != nil {
		return false, err
	}
	client, _, err := server.newRouterOSRESTClient(active)
	if err != nil {
		return false, err
	}
	defer client.CloseIdleConnections()
	return client.SuppressFetchInfoLogs(ctx)
}
