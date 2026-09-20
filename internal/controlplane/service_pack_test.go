package controlplane

import (
	"errors"
	"net/http"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

func TestResolveServicePackReturnsBuiltinWithoutNetwork(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	server.refreshServicePack = func(rulesets.ServicePack, string) (map[string]any, error) {
		t.Fatal("builtin pack attempted a network refresh")
		return nil, nil
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/service-packs/resolve", map[string]any{
		"upstream_name": "youtube.com",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("builtin resolution failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	if body["builtin"] != true || body["rules"].(float64) < 1 {
		t.Fatalf("unexpected builtin response: %#v", body)
	}
}

func TestResolveServicePackRefreshesOneValidatedCustomPack(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	server.refreshServicePack = func(pack rulesets.ServicePack, root string) (map[string]any, error) {
		if pack.ID != "avito" || pack.Name != "Авито" || root != server.opts.Runtime.RuleSetDir {
			t.Fatalf("unexpected refresh: %#v %q", pack, root)
		}
		return map[string]any{"rules": 7, "sha256": "digest", "updated_at": "2026-09-03T00:00:00Z"}, nil
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/service-packs/resolve", map[string]any{
		"upstream_name": "avito", "display_name": "Авито",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("custom resolution failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	if body["builtin"] != false || body["rules"].(float64) != 7 {
		t.Fatalf("unexpected custom response: %#v", body)
	}
}

func TestResolveServicePackRejectsFailedCustomRefresh(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	server.refreshServicePack = func(rulesets.ServicePack, string) (map[string]any, error) { return nil, errors.New("rejected") }
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/service-packs/resolve", map[string]any{
		"upstream_name": "unknown-pack",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("failed pack accepted: %d %s", response.Code, response.Body.String())
	}
}
