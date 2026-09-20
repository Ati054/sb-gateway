package runtimeconfig

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestCompilePolicyDNSEmptySource(t *testing.T) {
	artifacts, err := CompilePolicyDNS(PolicyDNSSource{}, PolicyDNSCompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	body, err := MarshalPolicyDNS(artifacts.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(body), "{\"lanes\":[],\"servers\":{},\"version\":1}\n"; got != want {
		t.Fatalf("unexpected empty runtime:\n%s\nwant:\n%s", got, want)
	}
	if len(artifacts.XrayInbounds) != 0 || len(artifacts.XrayOutbounds) != 0 || len(artifacts.XrayRules) != 0 {
		t.Fatal("empty policy DNS source produced Xray wiring")
	}
}

func TestCompilePolicyDNSMatchesCurrentArtifactContract(t *testing.T) {
	rulesetRoot := t.TempDir()
	ruleset := `{"rules":[{"domain_suffix":["YouTube.COM."]},{"port":[443]}]}`
	if err := os.WriteFile(filepath.Join(rulesetRoot, "video.json"), []byte(ruleset), 0o600); err != nil {
		t.Fatal(err)
	}
	source := PolicyDNSSource{
		Servers: []PolicyDNSSourceServer{
			{Tag: "vpn", Type: "https", Server: "1.1.1.1", Detour: "europe", TLS: PolicyDNSSourceTLS{ServerName: "cloudflare-dns.com"}, DoTFallback: true},
			{Tag: "direct", Type: "udp", Server: "192.168.88.1", ServerPort: 53},
		},
		Final: "direct",
		Rules: []PolicyDNSSourceRule{
			{SourceCIDR: []string{"10.0.0.2/32", "10.0.0.1/32", "10.0.0.2/32"}, Domain: []string{".Example.COM."}, Action: "route", Server: "vpn"},
			{SourceCIDR: []string{"10.0.0.1/32", "10.0.0.2/32"}, RuleSet: []string{"service-video"}, Action: "route", Server: "vpn"},
			{AuthUser: []string{"alice"}, Action: "reject"},
		},
	}
	artifacts, err := CompilePolicyDNS(source, PolicyDNSCompileOptions{
		ExistingInboundPorts: []int{30000, 32001},
		Selectable:           map[string]struct{}{"europe": {}},
		RuleSets:             map[string]PolicyDNSRuleSetDescriptor{"service-video": {Path: "/config/rulesets/video.srs"}},
		RuleSetRoot:          rulesetRoot,
	})
	if err != nil {
		t.Fatal(err)
	}
	body, err := MarshalPolicyDNS(artifacts.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"lanes\":[" +
		"{\"final\":\"direct\",\"host\":\"127.0.0.1\",\"id\":\"dns-policy-lane-0\",\"port\":30001,\"rules\":[" +
		"{\"action\":\"route\",\"domain\":[\"example.com\"],\"domain_suffix\":[],\"server\":\"vpn\"}," +
		"{\"action\":\"route\",\"domain\":[],\"domain_suffix\":[\"youtube.com\"],\"server\":\"vpn\"}]}," +
		"{\"final\":\"reject\",\"host\":\"127.0.0.1\",\"id\":\"dns-policy-lane-1\",\"port\":30002,\"rules\":[]}," +
		"{\"final\":\"direct\",\"host\":\"127.0.0.1\",\"id\":\"dns-policy-lane-2\",\"port\":30003,\"rules\":[]}" +
		"],\"servers\":{" +
		"\"direct\":{\"detour\":\"direct-wan\",\"path\":\"/dns-query\",\"server\":\"192.168.88.1\",\"server_name\":\"\",\"server_port\":53,\"type\":\"udp\"}," +
		"\"vpn\":{\"detour\":\"europe\",\"dot_fallback\":true,\"path\":\"/dns-query\",\"server\":\"1.1.1.1\",\"server_name\":\"cloudflare-dns.com\",\"server_port\":443,\"tunnel_host\":\"127.0.0.1\",\"tunnel_port\":32002,\"type\":\"https\"}" +
		"},\"timeout_seconds\":5,\"version\":1}\n"
	if got := string(body); got != want {
		t.Fatalf("runtime contract changed:\n%s\nwant:\n%s", got, want)
	}

	if len(artifacts.XrayInbounds) != 1 || artifacts.XrayInbounds[0]["tag"] != "dns-upstream-1" {
		t.Fatalf("unexpected tunnel inbounds: %#v", artifacts.XrayInbounds)
	}
	if got := artifacts.XrayRules[0]["balancerTag"]; got != "europe" {
		t.Fatalf("encrypted resolver did not retain selectable detour: %#v", artifacts.XrayRules[0])
	}
	if got := artifacts.XrayRules[1]["source"]; !reflect.DeepEqual(got, []string{"10.0.0.1/32", "10.0.0.2/32"}) {
		t.Fatalf("specific lane identity was not normalized: %#v", got)
	}
	if _, ok := artifacts.XrayRules[len(artifacts.XrayRules)-1]["source"]; ok {
		t.Fatal("catch-all DNS lane unexpectedly has a source match")
	}
}

func TestCompilePolicyDNSRejectsMissingFinalAndUnsupportedServer(t *testing.T) {
	_, err := CompilePolicyDNS(PolicyDNSSource{
		Servers: []PolicyDNSSourceServer{{Tag: "direct", Type: "udp", Server: "127.0.0.1"}},
		Final:   "missing",
	}, PolicyDNSCompileOptions{})
	if err == nil || !strings.Contains(err.Error(), "final server is missing") {
		t.Fatalf("unexpected missing-final result: %v", err)
	}

	_, err = CompilePolicyDNS(PolicyDNSSource{
		Servers: []PolicyDNSSourceServer{{Tag: "bad", Type: "quic", Server: "127.0.0.1"}},
		Final:   "bad",
	}, PolicyDNSCompileOptions{})
	if err == nil || !strings.Contains(err.Error(), "unsupported type") {
		t.Fatalf("unexpected unsupported-server result: %v", err)
	}
}

func TestCompilePolicyDNSRejectsEmptyRuleSet(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "empty.json"), []byte(`{"rules":[{}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := CompilePolicyDNS(PolicyDNSSource{
		Servers: []PolicyDNSSourceServer{{Tag: "direct", Type: "udp", Server: "127.0.0.1"}},
		Final:   "direct",
		Rules:   []PolicyDNSSourceRule{{RuleSet: []string{"service-empty"}, Action: "route", Server: "direct"}},
	}, PolicyDNSCompileOptions{RuleSetRoot: root})
	if err == nil || !strings.Contains(err.Error(), "no usable match conditions") {
		t.Fatalf("unexpected empty-ruleset result: %v", err)
	}
}

func TestMarshalPolicyDNSProducesValidJSON(t *testing.T) {
	body, err := MarshalPolicyDNS(PolicyDNSRuntime{Lanes: []PolicyDNSLane{}, Servers: map[string]PolicyDNSServer{}, Version: 1})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatal(err)
	}
}
