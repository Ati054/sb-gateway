package controlplane

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestSubscriptionRefreshBusyCommitPreservesNodesAndCanRetry(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	created := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions", map[string]any{
		"id": "provider", "display_name": "Provider", "enabled": true,
		"url": "https://provider.example.test/private", "max_nodes": 10,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("create status %d", created.Code)
	}
	body := []byte("vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@old.example.test:443?security=tls&type=ws#Old")
	server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		return body, http.Header{}, nil
	}
	first := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if first.Code != http.StatusOK {
		t.Fatalf("initial refresh status %d: %s", first.Code, first.Body.String())
	}
	before, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.ReplaceAll(string(body), "old.example.test", "new.example.test"))
	server.mutationMu.Lock()
	busy := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	server.mutationMu.Unlock()
	if busy.Code != http.StatusConflict || !strings.Contains(busy.Body.String(), `"state_mutation_in_progress"`) {
		t.Fatalf("busy commit must report a retryable conflict, got %d: %s", busy.Code, busy.Body.String())
	}
	after, err := server.repository.auxiliary("subscription-nodes")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("busy refresh changed persisted nodes: err=%v", err)
	}
	if err := server.repository.saveAuxiliary("apply-operation", map[string]any{"pending": true}); err != nil {
		t.Fatal(err)
	}
	durableBusy := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if err := server.repository.saveAuxiliary("apply-operation", map[string]any{"pending": false}); err != nil {
		t.Fatal(err)
	}
	if durableBusy.Code != http.StatusConflict || !strings.Contains(durableBusy.Body.String(), `"state_mutation_in_progress"`) {
		t.Fatalf("durable operation must report a retryable conflict, got %d: %s", durableBusy.Code, durableBusy.Body.String())
	}
	after, err = server.repository.auxiliary("subscription-nodes")
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatalf("durable conflict changed persisted nodes: err=%v", err)
	}
	retry := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if retry.Code != http.StatusOK {
		t.Fatalf("explicit retry did not finish: %d %s", retry.Code, retry.Body.String())
	}
	updated, err := server.repository.auxiliary("subscription-nodes")
	if err != nil || reflect.DeepEqual(before, updated) {
		t.Fatalf("retry did not publish new nodes: err=%v", err)
	}
}
