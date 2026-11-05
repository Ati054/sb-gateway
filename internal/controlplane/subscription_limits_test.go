package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

func syntheticSubscriptionCatalog(count int) []byte {
	var body strings.Builder
	for index := range count {
		fmt.Fprintf(&body, "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@node-%04d.example.test:443?security=tls#Node-%04d\n", index, index)
	}
	return []byte(body.String())
}

func subscriptionLimitFixture(t *testing.T) (*Server, map[string]any) {
	t.Helper()
	s := newTestServer(t)
	const reference = "subscriptions/provider.url"
	if err := s.secrets.write(reference, "https://provider.example.test/sub", false); err != nil {
		t.Fatal(err)
	}
	return s, map[string]any{"id": "provider", "enabled": true, "url_secret_ref": reference}
}

// These regressions cross config persistence and the HTTP refresh handler.
// Stop at busy-commit admission, avoiding 600 unnecessary secret-file writes.
func TestSubscriptionRefreshNodeLimitAboveLegacy500(t *testing.T) {
	for _, item := range []struct {
		name  string
		limit any
	}{{"omitted-default", nil}, {"explicit-1000", 1000}} {
		t.Run(item.name, func(t *testing.T) {
			s := newTestServer(t)
			cookie, csrf := bootstrapSession(t, s)
			config := map[string]any{
				"id": "provider", "display_name": "Provider", "enabled": true, "url": "https://provider.example.test/sub",
			}
			if item.limit != nil {
				config["max_nodes"] = item.limit
			}
			created := performRequest(t, s, http.MethodPost, apiPrefix+"/subscriptions", config, map[string]string{csrfHeader: csrf}, cookie)
			if created.Code != http.StatusOK {
				t.Fatalf("create: %d %s", created.Code, created.Body.String())
			}
			body := syntheticSubscriptionCatalog(600)
			s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
				return body, nil, nil
			}
			s.mutationMu.Lock()
			response := performRequest(t, s, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
			s.mutationMu.Unlock()
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"state_mutation_in_progress"`) {
				t.Fatalf("catalog rejected before atomic commit admission: status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestSubscriptionRefreshExplicitLowNodeLimitPreservesLastMetadata(t *testing.T) {
	s, subscription := subscriptionLimitFixture(t)
	subscription["max_nodes"] = 10
	body := syntheticSubscriptionCatalog(10)
	s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		return body, http.Header{"Subscription-Userinfo": []string{"expire=2000000000"}}, nil
	}
	if _, err := s.refreshSubscriptionNow(context.Background(), subscription); err != nil {
		t.Fatal(err)
	}
	before, err := s.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}
	beforeMetadata, err := s.repository.subscriptionMetadata()
	if err != nil {
		t.Fatal(err)
	}
	body = syntheticSubscriptionCatalog(11)
	_, err = s.refreshSubscriptionNow(context.Background(), subscription)
	var failure *subscriptionParseError
	if !errors.As(err, &failure) || failure.code != "too_many_nodes" {
		t.Fatalf("explicit low limit was ignored: %v", err)
	}
	after, err := s.repository.auxiliary("subscription-nodes")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("failed refresh changed last inventory: %v", err)
	}
	afterMetadata, err := s.repository.subscriptionMetadata()
	if err != nil || !reflect.DeepEqual(beforeMetadata, afterMetadata) {
		t.Fatalf("failed refresh changed last confirmed metadata: %v", err)
	}
}

func TestSubscriptionRefreshUnchangedBodyPublishesNewProviderMetadata(t *testing.T) {
	s, subscription := subscriptionLimitFixture(t)
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	s.now = func() time.Time { return now }
	body := syntheticSubscriptionCatalog(1)
	expiry := int64(2000000000)
	s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		return body, http.Header{"Subscription-Userinfo": []string{fmt.Sprintf("expire=%d", expiry)}}, nil
	}
	first, err := s.refreshSubscriptionNow(context.Background(), subscription)
	if err != nil {
		t.Fatal(err)
	}
	// Warm the compact public cache before replacing the same inventory body.
	beforeMetadata, err := s.repository.subscriptionMetadata()
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	expiry = 2100000000
	second, err := s.refreshSubscriptionNow(context.Background(), subscription)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := s.repository.subscriptionMetadata()
	if err != nil {
		t.Fatal(err)
	}
	wantExpiry := time.Unix(expiry, 0).UTC().Format(time.RFC3339)
	if first["fingerprint"] != second["fingerprint"] || first["refreshed_at"] == second["refreshed_at"] {
		t.Fatal("fixture must keep the same body and advance its successful refresh")
	}
	if nestedValue(metadata, "provider", "provider", "expires_at") != wantExpiry || nestedValue(metadata, "provider", "refreshed_at") != now.Format(time.RFC3339Nano) {
		t.Fatalf("unchanged body retained stale public metadata: %#v", metadata)
	}
	if reflect.DeepEqual(beforeMetadata, metadata) {
		t.Fatal("compact metadata cache did not invalidate")
	}
}
