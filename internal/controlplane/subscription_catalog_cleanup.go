package controlplane

import (
	"context"
	"log"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

// Keep bulk retention off the Apply/refresh response path. Admission never
// waits behind a user mutation or an in-flight subscription download.
func (server *Server) runSubscriptionCatalogRetention(ctx context.Context) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		server.trySubscriptionCatalogRetention(ctx)
		timer.Reset(time.Hour)
	}
}

func (server *Server) trySubscriptionCatalogRetention(ctx context.Context) bool {
	if !server.mutationMu.TryLock() {
		return false
	}
	defer server.mutationMu.Unlock()
	if !server.subscriptionMu.TryLock() {
		return false
	}
	defer server.subscriptionMu.Unlock()
	server.configMu.Lock()
	defer server.configMu.Unlock()
	bounded, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := server.pruneSubscriptionCatalogs(bounded); err != nil {
		log.Printf("subscription-catalog: retention deferred safely")
	}
	return true
}

// The failed import already owns subscriptionMu. TryLock makes the reverse
// admission order nonblocking. Reachability is reread before any removal, so a
// complete pointer whose final durability report was uncertain is protected.
func (server *Server) cleanupUnpublishedSubscriptionCatalog(ctx context.Context, ref subscriptioncatalog.Ref) {
	if !server.mutationMu.TryLock() {
		return
	}
	defer server.mutationMu.Unlock()
	server.configMu.Lock()
	defer server.configMu.Unlock()
	bounded, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	_, _ = server.pruneSubscriptionCatalogCandidate(bounded, ref)
}
