package controlplane

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestRefreshOneDueSubscriptionRunsOneAndSleepsUntilDeadline(t *testing.T) {
	server := newTestServer(t)
	now := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	config := currentConfigFixture(t)
	config["subscriptions"] = []any{map[string]any{
		"id": "provider", "display_name": "Provider", "enabled": true,
		"url_secret_ref": "subscriptions/provider.url", "refresh_minutes": 60,
	}}
	if err := server.secrets.write("subscriptions/provider.url", "https://provider.example.test/sub", false); err != nil {
		t.Fatal(err)
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	calls := 0
	server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		calls++
		return []byte("vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@de.example.test:443?security=tls#DE"), nil, nil
	}
	delay, err := server.refreshOneDueSubscription(context.Background())
	if err != nil || delay != subscriptionSchedulerBatch || calls != 1 {
		t.Fatalf("first cycle delay=%s calls=%d err=%v", delay, calls, err)
	}
	status, err := server.repository.auxiliary("subscription-refresh-status")
	if err != nil || nestedValue(status, "provider", "state") != "ok" {
		t.Fatalf("status=%#v err=%v", status, err)
	}
	delay, err = server.refreshOneDueSubscription(context.Background())
	if err != nil || delay != time.Hour || calls != 1 {
		t.Fatalf("second cycle delay=%s calls=%d err=%v", delay, calls, err)
	}
}

func TestSubscriptionRefreshIntervalIsBounded(t *testing.T) {
	if got := subscriptionRefreshInterval(map[string]any{"refresh_minutes": 0}); got != time.Minute {
		t.Fatalf("minimum interval = %s", got)
	}
	if got := subscriptionRefreshInterval(map[string]any{"refresh_minutes": 999999}); got != 7*24*time.Hour {
		t.Fatalf("maximum interval = %s", got)
	}
}
