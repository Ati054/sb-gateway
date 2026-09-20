package runtimeconfig

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func sharedIngressFixture() map[string]any {
	return map[string]any{
		"public_exposure": map[string]any{"shared_tcp_443": true},
		"system":          map[string]any{"networking": map[string]any{"routeros_gateway": "192.168.98.1"}},
		"ingress":         map[string]any{"tls_profile_id": "tls", "subscription_endpoint_mode": "reuse-cdn"},
		"tls_profiles":    []any{map[string]any{"id": "tls", "certificate_secret_ref": "cert", "private_key_secret_ref": "key"}},
		"transports": []any{
			map[string]any{"id": "ws", "kind": "ws", "hostname": "cf.example.test", "path_secret_ref": "path", "cdn_deployments": []any{
				map[string]any{"id": "cf", "cdn_provider": "cloudflare", "hostname": "cf.example.test", "origin_server_name": "cf.example.test", "origin_port": 443, "tls_profile_id": "tls", "origin_protection_mode": "auto-cidr"},
				map[string]any{"id": "g", "cdn_provider": "gcore", "hostname": "g.example.test", "origin_server_name": "g.example.test", "origin_port": 443, "tls_profile_id": "tls", "origin_protection_mode": "auto-cidr"},
			}},
			map[string]any{"id": "r", "kind": "reality", "listen_port": 443, "server_name": "reality.example.test", "server_names": []any{"extra.example.test"}, "cover_mode": "api", "tls_profile_id": "tls"},
		},
	}
}

func TestShared443RenderIsolationAndPassthrough(t *testing.T) {
	config := sharedIngressFixture()
	body, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	render := func() string {
		result, err := RenderNginxCandidate(config, func(ref string) (string, error) {
			if ref == "path" {
				return "/private", nil
			}
			return "management-token", nil
		}, inboundSecretPath, NginxRenderOptions{Template: string(body)})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	got := render()
	for _, want := range []string{"ssl_preread on;", "reality.example.test 127.0.0.1:16444;", "extra.example.test 127.0.0.1:16444;", "cf.example.test 127.0.0.1:16443;", "listen 127.0.0.1:16443 ssl proxy_protocol;"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(got, "listen 443 ssl") || strings.Contains(got, "$http_x_forwarded_for $sb_origin") {
		t.Fatal("public backend or spoofable source")
	}
	for _, p := range OriginPolicies(config) {
		if !strings.Contains(got, "if ($"+originGeoName(p)+" = 0) { return 403; }") || !strings.Contains(got, "if ($sb_origin_sni != \""+p.Host+"\") { return 421; }") {
			t.Fatal("missing per-origin guard", p.Host)
		}
	}
	if !strings.Contains(got, "cloudflare/addresses.conf") || !strings.Contains(got, "gcore/addresses.conf") {
		t.Fatal("feed isolation absent")
	}
	config["public_exposure"].(map[string]any)["shared_tcp_443"] = false
	got = render()
	if strings.Contains(got, "ssl_preread") || strings.Contains(got, "16443") || !strings.Contains(got, "listen 443 ssl;") {
		t.Fatal("opt-out did not retain original HTTP listener")
	}
}

func TestSharedSNIConflictsAndDistinctDomains(t *testing.T) {
	config := sharedIngressFixture()
	if err := ValidateSharedIngress(config); err != nil {
		t.Fatal(err)
	}
	transports := config["transports"].([]any)
	r := transports[1].(map[string]any)
	r["server_name"] = "CF.EXAMPLE.TEST"
	if ValidateSharedIngress(config) == nil {
		t.Fatal("SNI collision accepted")
	}
	r["server_name"] = "reality.example.test"
	r["wan_destination_address"] = "192.0.2.1"
	if ValidateSharedIngress(config) == nil {
		t.Fatal("unrepresentable WAN binding accepted")
	}
	delete(r, "wan_destination_address")
	deployments := transports[0].(map[string]any)["cdn_deployments"].([]any)
	deployments[1].(map[string]any)["origin_server_name"] = "cf.example.test"
	if ValidateSharedIngress(config) == nil {
		t.Fatal("same origin with different CIDR accepted")
	}
}

func TestDedicatedSubscriptionOriginUsesOriginBoundaryWithoutBlockingIncompleteDraft(t *testing.T) {
	config := sharedIngressFixture()
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_endpoint_mode"] = "separate"
	ingress["subscription_hostname"] = "edge.cdn.example.test"
	ingress["subscription_origin_server_name"] = "subscription-origin.example.test."
	ingress["subscription_listen_port"] = 443
	ingress["subscription_tls_profile_id"] = "tls"
	ingress["subscription_origin_protection_mode"] = "secret-header"

	policies := OriginPolicies(config)
	found := false
	for _, policy := range policies {
		if policy.Mode == "secret-header" {
			found = true
			if policy.Host != "subscription-origin.example.test" || policy.Host == "edge.cdn.example.test" {
				t.Fatalf("subscription policy routed through edge instead of origin: %#v", policy)
			}
		}
	}
	if !found || !SharedOriginPorts(config)[443] || ValidateSharedIngress(config) != nil {
		t.Fatalf("shared 443 boundaries changed: policies=%#v ports=%#v", policies, SharedOriginPorts(config))
	}

	ingress["subscription_origin_server_name"] = ""
	if ValidateSharedIngress(config) != nil {
		t.Fatal("incomplete draft must retain ordinary shared-ingress validation")
	}
	if _, err := RenderRouterOSTrafficCandidate(config, nil); err == nil || !strings.Contains(err.Error(), "concrete DNS origin") {
		t.Fatalf("RouterOS runtime renderer accepted missing separate origin: %v", err)
	}
}

func TestDisabledSubscriptionPublicationRemovesOnlySubscriptionBoundaries(t *testing.T) {
	config := sharedIngressFixture()
	baseline := OriginPolicies(config)
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_endpoint_enabled"] = false
	ingress["subscription_endpoint_mode"] = "separate"
	ingress["subscription_hostname"] = "edge.cdn.example.test"
	ingress["subscription_origin_server_name"] = ""
	ingress["subscription_listen_port"] = 443
	ingress["subscription_tls_profile_id"] = ""
	ingress["subscription_origin_protection_mode"] = "secret-header"

	if err := ValidateDedicatedSubscriptionOrigin(config); err != nil {
		t.Fatalf("disabled subscription still requires an origin: %v", err)
	}
	if policies := OriginPolicies(config); !reflect.DeepEqual(policies, baseline) {
		t.Fatalf("disabled subscription changed unrelated origin policies: %#v", policies)
	}
	if err := ValidateSharedIngress(config); err != nil {
		t.Fatalf("disabled subscription changed shared ingress validation: %v", err)
	}
}

func TestSharedRealityBackendPreservesProxySource(t *testing.T) {
	for _, kind := range []string{"reality", "reality-grpc", "xhttp-reality"} {
		config := inboundSourceBaseConfig()
		config["public_exposure"] = map[string]any{"shared_tcp_443": true}
		config["transports"] = []any{map[string]any{"id": "r", "kind": kind, "listen_port": 443, "server_name": "r.example.test", "path_secret_ref": "path", "service_name_secret_ref": "service", "secret_refs": map[string]any{"reality_private_key": "key", "reality_short_id": "short"}}}
		source, err := BuildXrayInboundSource(config, inboundSecretReader(map[string]string{"key": "private-key", "short": "0123456789abcdef", "path": "/path", "service": "service"}), inboundSecretPath)
		if err != nil {
			t.Fatal(err)
		}
		v := inboundSourceByTag(source.Inbounds)["vless-"+kind]
		if v["listen"] != "127.0.0.1" || v["listen_port"] != RealityBackendPort(kind) {
			t.Fatal(v)
		}
		stream, err := ConvertXrayStream(v, true, nil, source.Options.RealitySettingsByTag["vless-"+kind])
		if err != nil {
			t.Fatal(err)
		}
		if objectValue(stream["sockopt"])["acceptProxyProtocol"] != true {
			t.Fatal("real source lost")
		}
	}
}

func TestPublicIngressCannotOccupyInternalPorts(t *testing.T) {
	for _, port := range []int{8080, 9080, 9443, 11001, 11002, 11003, 11004, 18081, 19080, 19081, 19082, 19083, 19084, 19085, 16443, 16444, 16445, 16446, 16447, 16448} {
		config := sharedIngressFixture()
		deployment := config["transports"].([]any)[0].(map[string]any)["cdn_deployments"].([]any)[0].(map[string]any)
		deployment["origin_port"] = port
		if ValidateSharedIngress(config) == nil {
			t.Fatal("internal port accepted", port)
		}
	}
}
