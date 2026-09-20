package runtimeconfig

import (
	"net/url"
	"reflect"
	"testing"
)

func TestBuildXrayOutboundSourceIncludesReverseWireGuardAndCurrentPolicy(t *testing.T) {
	secrets := map[string]string{"node/de": "uuid-de", "node/hy": "hy-pass", "node/obfs": "obfs-pass"}
	read := func(reference string) (string, error) { return secrets[reference], nil }
	nodes := []map[string]any{
		{"id": "de-1", "protocol": "vless", "server": "de.example", "server_port": 443, "uuid_secret_ref": "node/de", "country": "DE", "city": "Berlin"},
		{"id": "de-2", "protocol": "hysteria2", "server": "hy.example", "server_port": 8443, "password_secret_ref": "node/hy", "obfs": map[string]any{"type": "salamander"}, "obfs_password_secret_ref": "node/obfs", "country": "DE", "city": "Hamburg"},
		{"id": "wg-home", "protocol": "routeros-wireguard", "source_address": "198.18.0.2", "source_type": "routeros-wireguard", "wireguard_egress_id": "home"},
		{"id": "reverse-vless-home", "protocol": "xray-reverse", "source_type": "xray-reverse", "reverse_vless_id": "home"},
		{"id": "reserve-only", "protocol": "vless", "server": "reserve.example", "server_port": 443, "uuid_secret_ref": "node/de", "country": "FI", "subscription_reserve_id": "reserve"},
	}
	config := map[string]any{"policies": []any{map[string]any{
		"id": "europe", "enabled": true, "mode": "best", "max_active_candidates": 1,
		"selection_order": []any{"reverse:home", "wireguard:home", "country:DE"},
	}}}
	result, err := BuildXrayOutboundSource(config, nodes, read)
	if err != nil {
		t.Fatal(err)
	}
	byTag := make(map[string]map[string]any)
	for _, outbound := range result {
		byTag[textValue(outbound["tag"])] = outbound
	}
	policy := byTag["europe"]
	for _, tag := range []string{"outbound-health-background", "outbound-health-background-2", "outbound-health-background-3"} {
		if !reflect.DeepEqual(byTag["outbound-health-probe"]["outbounds"], byTag[tag]["outbounds"]) {
			t.Fatalf("fast and background probe lane %s must address the same candidates", tag)
		}
	}
	want := []string{"block", "de-1", "de-2", "reverse-vless-home", "wg-home"}
	if !reflect.DeepEqual(stringSlice(policy["outbounds"]), want) {
		t.Fatalf("policy outbounds = %#v, want %#v", policy["outbounds"], want)
	}
	if byTag["wg-home"]["inet4_bind_address"] != "198.18.0.2" || byTag["reverse-vless-home"]["type"] != "direct" {
		t.Fatalf("special exits changed: %#v %#v", byTag["wg-home"], byTag["reverse-vless-home"])
	}
	if _, exists := byTag["reserve-only"]; !exists {
		t.Fatal("reserve node must remain available for subscription refresh")
	}
	updates := byTag["subscription-update-egress"]
	if !containsText(stringSlice(updates["outbounds"]), "reserve-only") {
		t.Fatalf("reserve node missing from updater: %#v", updates)
	}
}

func TestPolicyCandidateGroupsKeepsAllSelectedNodesBeyondWorkingPoolLimit(t *testing.T) {
	policy := map[string]any{
		"id": "route", "selection_order": []any{"country:DE", "country:FI"}, "max_active_candidates": 3,
	}
	nodes := []map[string]any{
		{"id": "de-1", "country": "DE"}, {"id": "de-2", "country": "DE"}, {"id": "de-3", "country": "DE"},
		{"id": "fi-1", "country": "FI"}, {"id": "fi-2", "country": "FI"},
	}
	groups := policyCandidateGroups(policy, nodes)
	want := []policyCandidateGroup{
		{Selector: "country:DE", Members: []string{"de-1", "de-2", "de-3"}},
		{Selector: "country:FI", Members: []string{"fi-1", "fi-2"}},
	}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("limited groups = %#v, want %#v", groups, want)
	}
}

func TestPolicyCandidateGroupsKeepsCityWhenProviderChangesLeadingBadges(t *testing.T) {
	oldCity := "🇨🇦 ⭐️ Канада"
	currentCity := "🇨🇦 ⚡️ ⭐️ Канада"
	policy := map[string]any{
		"id": "route", "selection_order": []any{"city:CA:" + url.PathEscape(oldCity)},
	}
	nodes := []map[string]any{
		{"id": "canada", "country": "CA", "city": currentCity},
		{"id": "toronto", "country": "CA", "city": "🇨🇦 Toronto"},
	}
	groups := policyCandidateGroups(policy, nodes)
	want := []policyCandidateGroup{{Selector: "city:CA:" + url.PathEscape("Канада"), Members: []string{"canada"}}}
	if !reflect.DeepEqual(groups, want) {
		t.Fatalf("badge-renamed city groups = %#v, want %#v", groups, want)
	}
}

func TestBuildXrayOutboundSourceBuildsPriorityServiceSelectors(t *testing.T) {
	config := map[string]any{"policies": []any{map[string]any{
		"id": "europe", "enabled": true, "mode": "priority", "selection_order": []any{"country:DE", "country:FI"},
		"candidate_service_ids":    []any{"claude"},
		"candidate_service_access": map[string]any{"country:DE": []any{"claude"}},
	}}}
	nodes := []map[string]any{
		{"id": "de", "protocol": "xray-reverse", "source_type": "xray-reverse", "reverse_vless_id": "de", "country": "DE"},
		{"id": "provider-de", "protocol": "vless", "server": "de.example", "server_port": 443, "uuid_secret_ref": "de", "country": "DE"},
		{"id": "provider-fi", "protocol": "vless", "server": "fi.example", "server_port": 443, "uuid_secret_ref": "fi", "country": "FI"},
	}
	result, err := BuildXrayOutboundSource(config, nodes, func(reference string) (string, error) { return reference + "-uuid", nil })
	if err != nil {
		t.Fatal(err)
	}
	byTag := make(map[string]map[string]any)
	for _, outbound := range result {
		byTag[textValue(outbound["tag"])] = outbound
	}
	service := byTag[policyServiceSelectorTag("europe", "claude")]
	want := []string{policyServiceBlockTag("europe"), "de", "provider-de", "provider-fi"}
	if !reflect.DeepEqual(stringSlice(service["outbounds"]), want) {
		t.Fatalf("service selector = %#v, want %#v", service, want)
	}
}

func TestBuildXrayOutboundSourceKeepsLegacyPolicyFailClosed(t *testing.T) {
	config := map[string]any{"policies": []any{map[string]any{
		"id": "closed", "enabled": true, "mode": "best", "outbounds": []any{"provider-de"},
	}}}
	nodes := []map[string]any{{
		"id": "provider-de", "protocol": "vless", "server": "de.example", "server_port": 443, "uuid_secret_ref": "de",
	}}
	result, err := BuildXrayOutboundSource(config, nodes, func(reference string) (string, error) { return "uuid", nil })
	if err != nil {
		t.Fatal(err)
	}
	for _, outbound := range result {
		if outbound["tag"] == "closed" {
			members := stringSlice(outbound["outbounds"])
			if !reflect.DeepEqual(members, []string{"block", "provider-de"}) {
				t.Fatalf("stable selector membership = %#v", outbound)
			}
			if members[0] != "block" {
				t.Fatalf("legacy policy must remain fail-closed: %#v", outbound)
			}
		}
	}
}

func TestPolicyEligibilityEditDoesNotRewriteXraySelectors(t *testing.T) {
	nodes := []map[string]any{
		{"id": "de", "protocol": "vless", "server": "de.example", "server_port": 443, "uuid_secret_ref": "de", "country": "DE"},
		{"id": "fi", "protocol": "vless", "server": "fi.example", "server_port": 443, "uuid_secret_ref": "fi", "country": "FI"},
	}
	config := func(order ...any) map[string]any {
		return map[string]any{"policies": []any{map[string]any{
			"id": "route", "enabled": true, "mode": "best", "selection_order": order,
		}}}
	}
	read := func(reference string) (string, error) { return reference + "-uuid", nil }
	before, err := BuildXrayOutboundSource(config("country:DE", "country:FI"), nodes, read)
	if err != nil {
		t.Fatal(err)
	}
	after, err := BuildXrayOutboundSource(config("country:FI"), nodes, read)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("eligibility-only edit rewrote Xray outbounds:\nbefore=%#v\nafter=%#v", before, after)
	}
}
