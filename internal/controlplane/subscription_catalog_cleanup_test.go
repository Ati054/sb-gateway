package controlplane

import (
	"context"
	"testing"
)

func TestCatalogRetentionDoesNotWaitForUserMutationOrDownload(t *testing.T) {
	server := newTestServer(t)
	server.mutationMu.Lock()
	if server.trySubscriptionCatalogRetention(context.Background()) {
		t.Fatal("retention entered during user mutation")
	}
	server.mutationMu.Unlock()
	server.subscriptionMu.Lock()
	if server.trySubscriptionCatalogRetention(context.Background()) {
		t.Fatal("retention entered during subscription download")
	}
	server.subscriptionMu.Unlock()
	if !server.mutationMu.TryLock() {
		t.Fatal("failed admission leaked mutation lock")
	}
	server.mutationMu.Unlock()
}
