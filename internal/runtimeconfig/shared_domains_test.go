package runtimeconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
)

func TestLargeDomainPacksUseOneImmutableGeoSiteReference(t *testing.T) {
	root := t.TempDir()
	values := make([]string, 1000)
	for i := range values {
		values[i] = fmt.Sprintf("host-%d.example", i)
	}
	write := func() {
		body, _ := json.Marshal(map[string]any{"rules": []any{map[string]any{"domain_suffix": values}}})
		if err := os.WriteFile(filepath.Join(root, "sample.json"), body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	write()
	source := []any{map[string]any{"action": "route", "outbound": "a", "rule_set": []string{"service-sample"}}, map[string]any{"action": "reject", "rule_set": []string{"service-sample"}}}
	rules, err := ConvertXrayRules(source, nil, nil, root)
	if err != nil {
		t.Fatal(err)
	}
	reference := rules[0]["domain"].([]string)
	if len(reference) != 1 || !reflect.DeepEqual(reference, rules[1]["domain"]) || rules[0]["outboundTag"] != "a" || rules[1]["outboundTag"] != "block" {
		t.Fatal("shared membership mixed decisions")
	}
	if err := geoipasset.Verify(root, reference[0]); err != nil {
		t.Fatal(err)
	}
	values[0] = "changed.example"
	write()
	updated, err := ConvertXrayRules(source, nil, nil, root)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(reference, updated[0]["domain"]) {
		t.Fatal("asset update reused a stale matcher cache key")
	}
	if err := geoipasset.Verify(root, reference[0]); err != nil {
		t.Fatal("old runtime asset was overwritten", err)
	}
}

func TestPolicyDNSLargeSetsAreInternedAndWireCompatible(t *testing.T) {
	domains := make([]string, 1000)
	for i := range domains {
		domains[i] = fmt.Sprintf("host-%d.example", i)
	}
	source := PolicyDNSSource{Final: "wan", Servers: []PolicyDNSSourceServer{{Tag: "wan", Type: "udp", Server: "192.0.2.1"}}, Rules: []PolicyDNSSourceRule{{SourceCIDR: []string{"192.0.2.2/32"}, DomainSuffix: domains, Action: "route", Server: "wan"}, {SourceCIDR: []string{"192.0.2.3/32"}, DomainSuffix: domains, Action: "reject"}}}
	artifacts, err := CompilePolicyDNS(source, PolicyDNSCompileOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(artifacts.Runtime.DomainSets) != 1 {
		t.Fatalf("set duplicated %d times", len(artifacts.Runtime.DomainSets))
	}
	for _, lane := range artifacts.Runtime.Lanes {
		for _, rule := range lane.Rules {
			if len(rule.DomainSuffix) != 0 || len(rule.Domain) != 0 || rule.DomainSet == "" {
				t.Fatal("large rules retained inline")
			}
		}
	}
	before, err := json.Marshal(artifacts.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	body, err := MarshalPolicyDNS(artifacts.Runtime)
	if err != nil {
		t.Fatal(err)
	}
	// These fields are exactly what predecessor workers understand.
	var legacy struct {
		Version int `json:"version"`
		Lanes   []struct {
			Rules []struct {
				DomainSuffix []string `json:"domain_suffix"`
				Action       string   `json:"action"`
				Server       string   `json:"server"`
			} `json:"rules"`
		} `json:"lanes"`
	}
	if err := json.Unmarshal(body, &legacy); err != nil {
		t.Fatal(err)
	}
	if legacy.Version != 1 || len(legacy.Lanes) != len(artifacts.Runtime.Lanes) {
		t.Fatal("incompatible persisted DNS format")
	}
	for n, lane := range legacy.Lanes {
		for m, rule := range lane.Rules {
			original := artifacts.Runtime.Lanes[n].Rules[m]
			set := artifacts.Runtime.DomainSets[original.DomainSet]
			if !reflect.DeepEqual(rule.DomainSuffix, set.DomainSuffix) || rule.Action != original.Action || rule.Server != original.Server {
				t.Fatal("predecessor would lose a DNS rule")
			}
		}
	}
	after, err := json.Marshal(artifacts.Runtime)
	if err != nil || string(after) != string(before) {
		t.Fatal("marshal mutated the compiled candidate")
	}
}
