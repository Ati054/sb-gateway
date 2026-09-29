package controlplane

import (
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

func TestClientGeoIPExportFailsExplicitly(t *testing.T) {
	_, err := buildClientRouteMatch([]string{"geoip-ru"}, map[string]rulesets.ServicePack{
		"geoip-ru": {ID: "geoip-ru", UpdateMode: "geoip"},
	})
	if err == nil || !strings.Contains(err.Error(), "gateway-only") {
		t.Fatalf("GeoIP client export silently lost CIDRs: %v", err)
	}
}

func TestClientCustomRoutesKeepExplicitTargetsAcrossExportFormats(t *testing.T) {
	config := map[string]any{
		"policies": []any{map[string]any{
			"id": "route", "enabled": true, "traffic_mode": "vless_with_wan_exceptions",
			"custom_routes": []any{
				map[string]any{"kind": "domain", "value": "example.com", "target": "vless"},
				map[string]any{"kind": "ip", "value": "203.0.113.42", "protocols": "http", "target": "wan"},
				map[string]any{"kind": "port", "value": "5000-5010", "network": "udp", "target": "vless"},
			},
		}},
	}
	user := map[string]any{"role": "internet-only", "client_individual_routing": true, "policy_id": "route"}
	plan, err := buildClientProfileRoutePlan(config, user, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.CustomRoutes) != 3 || plan.CustomRoutes[0].Target != clientRouteProxy || plan.CustomRoutes[1].Target != clientRouteDirect || plan.CustomRoutes[2].Target != clientRouteProxy {
		t.Fatalf("custom route plan lost targets: %#v", plan.CustomRoutes)
	}
	xray := appendXrayClientMatchRules(nil, plan.CustomRoutes[0].Match, plan.CustomRoutes[0].Target, "client-proxy", false)
	if len(xray) != 1 || !strings.Contains(strings.Join(xrayClientDomainMatchers(plan.CustomRoutes[0].Match), ","), "example.com") {
		t.Fatalf("Xray domain route missing: %#v", xray)
	}
	singBox := buildSingBoxClientRules(plan)
	if len(singBox) < 6 {
		t.Fatalf("sing-box custom rules missing: %#v", singBox)
	}
	if len(appendXrayClientMatchRules(nil, plan.CustomRoutes[1].Match, plan.CustomRoutes[1].Target, "client-proxy", false)) != 1 ||
		len(appendSingBoxClientMatchRules(nil, plan.CustomRoutes[1].Match, plan.CustomRoutes[1].Target)) != 1 {
		t.Fatal("IP and protocol filter must stay in one client route")
	}
	if _, err := buildMihomoProfile(config, user, nil); err == nil || !strings.Contains(err.Error(), "cannot export custom sniffed-protocol") {
		t.Fatalf("Mihomo must reject combined IP/protocol route explicitly: %v", err)
	}
}

func TestClientDomainProtocolRouteIsConjunctiveAndExplicitlyRejectedForMihomo(t *testing.T) {
	config := map[string]any{"policies": []any{map[string]any{
		"id": "route", "enabled": true, "traffic_mode": "vless_with_wan_exceptions",
		"custom_routes": []any{map[string]any{"kind": "domain", "value": "secure.example.com", "protocols": "tls,quic", "target": "wan"}},
	}}}
	user := map[string]any{"role": "internet-only", "client_individual_routing": true, "policy_id": "route"}
	plan, err := buildClientProfileRoutePlan(config, user, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.CustomRoutes) != 1 || len(plan.CustomRoutes[0].Match.Protocols) != 2 {
		t.Fatalf("protocol route omitted from compatible client plan: %#v", plan.CustomRoutes)
	}
	xray := appendXrayClientMatchRules(nil, plan.CustomRoutes[0].Match, plan.CustomRoutes[0].Target, "client-proxy", false)
	if len(xray) != 1 {
		t.Fatalf("Xray split conjunctive route: %#v", xray)
	}
	singBox := appendSingBoxClientMatchRules(nil, plan.CustomRoutes[0].Match, plan.CustomRoutes[0].Target)
	if len(singBox) != 1 {
		t.Fatalf("sing-box split conjunctive route: %#v", singBox)
	}
	if _, err := buildMihomoProfile(config, user, nil); err == nil || !strings.Contains(err.Error(), "cannot export custom sniffed-protocol") {
		t.Fatalf("Mihomo must reject unsupported protocol rule explicitly: %v", err)
	}
}

func anyStrings(values []any) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if item, ok := value.(string); ok {
			result = append(result, item)
		}
	}
	return result
}
