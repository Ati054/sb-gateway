package controlplane

import (
	"errors"
	"net/http"
	"reflect"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

func TestApplyRefreshesNewBuiltInCatalogCardsBeforeRendering(t *testing.T) {
	server := newTestServer(t)
	called := []string{}
	server.refreshServicePack = func(pack rulesets.ServicePack, root string) (map[string]any, error) {
		if root != server.opts.Runtime.RuleSetDir {
			t.Fatalf("unexpected rule-set root %q", root)
		}
		called = append(called, pack.ID)
		return map[string]any{"rules": 3}, nil
	}
	active := map[string]any{"policies": []any{map[string]any{
		"id": "lab", "direct_services": []any{"youtube"},
	}}}
	desired := map[string]any{"policies": []any{map[string]any{
		"id": "lab", "direct_services": []any{"youtube", "cn-baidu", "ir-aparat", "geoip-ir", "manual-pack"},
	}}}
	if err := server.refreshNewSelectedCatalogPacks(active, desired); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(called, []string{"cn-baidu", "ir-aparat"}) {
		t.Fatalf("unexpected catalog refreshes: %v", called)
	}
	if err := server.refreshNewSelectedCatalogPacks(nil, desired); err != nil {
		t.Fatal(err)
	}
	if len(called) != 2 {
		t.Fatalf("first installation fetched catalog unexpectedly: %v", called)
	}
}

func TestApplyRejectsUnavailableNewCatalogCard(t *testing.T) {
	server := newTestServer(t)
	server.refreshServicePack = func(rulesets.ServicePack, string) (map[string]any, error) {
		return nil, errors.New("unavailable")
	}
	active := map[string]any{"policies": []any{map[string]any{"id": "lab", "direct_services": []any{}}}}
	desired := map[string]any{"policies": []any{map[string]any{"id": "lab", "direct_services": []any{"cn-baidu"}}}}
	if err := server.refreshNewSelectedCatalogPacks(active, desired); err == nil {
		t.Fatal("new catalog card was accepted without full rules")
	}
}

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

func TestResolveGeoSitePrefixUsesTrustedCatalog(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	server.refreshServicePack = func(pack rulesets.ServicePack, _ string) (map[string]any, error) {
		if pack.ID != "baidu" || pack.UpstreamName == nil || *pack.UpstreamName != "baidu" {
			t.Fatalf("unexpected GeoSite catalog lookup: %#v", pack)
		}
		return map[string]any{"rules": 3}, nil
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/service-packs/resolve", map[string]any{
		"upstream_name": "geosite:baidu",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("GeoSite resolution failed: %d %s", response.Code, response.Body.String())
	}
}

func TestResolveGeoIPCountryRequiresValidatedRefresh(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	server.refreshServicePack = func(pack rulesets.ServicePack, _ string) (map[string]any, error) {
		if pack.ID != "geoip-ir" || pack.UpdateMode != "geoip" {
			t.Fatalf("unexpected GeoIP pack: %#v", pack)
		}
		return map[string]any{"rules": 2}, nil
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/service-packs/resolve", map[string]any{
		"upstream_name": "geoip:ir",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("GeoIP resolution failed: %d %s", response.Code, response.Body.String())
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
