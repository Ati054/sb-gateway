package runtimeconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
)

func TestPolicyDNSIPPresenceMatchesStringSliceValidation(t *testing.T) {
	for _, body := range []string{`null`, `[]`, `[null]`, `[""]`, `["203.0.113.0/24","2001:db8::/32"]`, `["escaped\"string"]`, `42`, `"scalar"`, `{}`, `[true]`, `[1]`, `[[]]`, `["ok",1]`, `["unterminated]`} {
		var legacy []string
		var compact policyDNSIPPresence
		oldErr, err := json.Unmarshal([]byte(body), &legacy), json.Unmarshal([]byte(body), &compact)
		if (oldErr == nil) != (err == nil) {
			t.Fatalf("validation changed for %s: %v / %v", body, oldErr, err)
		}
		if err == nil && compact.present != (len(legacy) > 0) {
			t.Fatalf("presence changed for %s", body)
		}
	}
}

func TestXrayRulesetNormalizedListsPreserveValuesAndOwnership(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "sample.json"), []byte(`{"rules":[{"domain":"example.com","port":[443,"8443"],"ip_cidr":["203.0.113.0/24"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	compiler := xrayRuleCompiler{root: root, cache: make(map[string][]map[string]any)}
	for iteration := 0; iteration < 2; iteration++ {
		expanded, err := compiler.expand(map[string]any{"rule_set": []string{"service-sample"}})
		if err != nil {
			t.Fatal(err)
		}
		rule, err := convertXrayRuleConditions(expanded[0], "direct-wan", nil)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(rule["domain"], []string{"full:example.com"}) || rule["port"] != "443,8443" || !reflect.DeepEqual(rule["ip"], []string{"203.0.113.0/24"}) {
			t.Fatalf("rule changed: %v", rule)
		}
		rule["ip"].([]string)[0] = "mutated"
	}
}

func TestLargeGeoIPRulesRetainEveryPrefixForTraffic(t *testing.T) {
	root := t.TempDir()
	prefixes := make([]string, 20001)
	for index := range prefixes[:20000] {
		prefixes[index] = fmt.Sprintf("10.%d.%d.0/24", index/256, index%256)
	}
	prefixes[20000] = "2001:db8::/32"
	body, err := json.Marshal(map[string]any{"rules": []any{map[string]any{"ip_cidr": prefixes}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "geoip-cn.json"), body, 0600); err != nil {
		t.Fatal(err)
	}
	rules, err := ConvertXrayRules([]any{map[string]any{
		"action": "route", "outbound": "direct-wan", "rule_set": []any{"service-geoip-cn"},
	}}, nil, nil, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 2 || rules[0]["outboundTag"] != "direct-wan" || rules[0]["ruleTag"] != "sb-geoip-geoip-cn-0-0" {
		t.Fatal("GeoIP traffic rule changed")
	}
	reference := rules[0]["ip"].([]string)
	if len(reference) != 1 {
		t.Fatal("GeoIP was expanded inline")
	}
	name, valid := geoipasset.ReferenceName(reference[0])
	if !valid {
		t.Fatal("invalid binary reference")
	}
	want, err := geoipasset.Encode("geoip-cn", body)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, name))
	if err != nil || string(got) != string(want) {
		t.Fatal("GeoIP traffic prefixes/order were changed or removed")
	}
	var dnsDocument policyDNSRuleSetDocument
	if err := json.Unmarshal(body, &dnsDocument); err != nil {
		t.Fatal(err)
	}
	if len(dnsDocument.Rules) != 1 || !dnsDocument.Rules[0].nonDNSCondition() || len(dnsDocument.Rules[0].Domain)+len(dnsDocument.Rules[0].DomainSuffix) != 0 {
		t.Fatal("GeoIP pack became a DNS name rule")
	}
}

func BenchmarkPolicyDNSIPConditionDecode(b *testing.B) {
	body := []byte(`{"ip_cidr":[` + strings.Repeat(`"203.0.113.0/24",`, 99999) + `"203.0.113.0/24"]}`)
	b.Run("legacy-prefixes", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var rule struct {
				IP []string `json:"ip_cidr"`
			}
			if err := json.Unmarshal(body, &rule); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("presence-only", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			var rule policyDNSRuleSetRule
			if err := json.Unmarshal(body, &rule); err != nil {
				b.Fatal(err)
			}
			if !rule.nonDNSCondition() {
				b.Fatal("IP condition was lost")
			}
		}
	})
}
