package runtimeconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

func TestEveryCatalogOutageFallbackDomainIsSafeAndUnique(t *testing.T) {
	packs, err := rulesets.Catalog()
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, pack := range packs {
		seen := map[string]bool{}
		for _, raw := range pack.FallbackDomains {
			domain, normalizeErr := normalizeOutageDomain(raw)
			if normalizeErr != nil || domain == "" || !outageDomainPattern.MatchString(domain) {
				t.Errorf("service pack %s has unsafe fallback domain %q", pack.ID, raw)
				continue
			}
			if seen[domain] {
				t.Errorf("service pack %s repeats fallback domain %q", pack.ID, domain)
			}
			seen[domain] = true
			checked++
		}
	}
	if checked == 0 {
		t.Fatal("service catalog domain audit checked no domains")
	}
}

func TestOutageCardsReconcileAddRemoveAndDoNotDependOnExitHealth(t *testing.T) {
	config := routerOSModelConfig()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "binance.json"), []byte(`{"rules":[{"domain_suffix":["binance.com"]}]}`), 0600); err != nil {
		t.Fatal(err)
	}
	policy := objectSlice(config["policies"])[0]
	policy["traffic_mode"] = "vless_with_wan_exceptions"
	policy["torrent_direct"] = false
	policy["direct_services"] = []any{"bybit", "binance", "openai", "ru-banks"}
	first, err := RenderRouterOSTrafficCandidate(config, nil, root)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(first, `[0-9A-F_]+\$"`) {
		t.Fatal("RouterOS regex end anchor must escape dollar interpolation")
	}
	for _, domain := range []string{"bybit.com", "binance.com", "openai.com"} {
		if !strings.Contains(first, `"`+domain+`|`) {
			t.Fatalf("missing card domain %s", domain)
		}
	}
	policy["direct_services"] = []any{"bybit"}
	second, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	delta := BuildRouterOSDelta(first, second, 1)
	if delta == nil || !reflect.DeepEqual(delta.Sections, []string{"outage-exceptions"}) {
		t.Fatalf("card changes not applied independently: %#v", delta)
	}
	if strings.Contains(second, `"binance.com|`) || !strings.Contains(second, "SB-GATEWAY outage direct ") {
		t.Fatal("stale permissions retained")
	}
	if strings.Contains(delta.ApplyScript, "startup-fail-open") || strings.Contains(delta.ApplyScript, "connection/remove") {
		t.Fatal("card update interrupts unrelated connections")
	}
	policy["direct_services"] = []any{}
	empty, err := routerOSOutageGroups(config)
	if err != nil || len(empty) != 0 {
		t.Fatalf("removed cards retained: %#v %v", empty, err)
	}
	policy["direct_services"] = []any{"bybit"}
	policy["traffic_mode"] = "wan_with_vless_exceptions"
	empty, err = routerOSOutageGroups(config)
	if err != nil || len(empty) != 0 {
		t.Fatal("proxy exceptions leaked through WAN during container failure")
	}
}

func TestCandidateRepairsMissingFailClosedRuleButRejectsAmbiguity(t *testing.T) {
	config := routerOSModelConfig()
	source, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`:if ([:len $failClosedDrop] > 1) do={ :error "SB-GATEWAY fail-closed rule ambiguous" }`,
		`place-before=$forwardReturn comment="SB-GATEWAY fail-closed public drop"`,
		`/ip/firewall/filter/set $failClosedDrop chain="sb-gateway-forward" action=drop src-address-list="SB_FAIL_CLOSED_CLIENTS" dst-address-list="!SB_INTERNAL_NETWORKS" disabled=no`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("candidate lacks self-healing fail-closed invariant %q", required)
		}
	}
	if strings.Contains(source, `:if ([:len $failClosedDrop] != 1)`) {
		t.Fatal("candidate still rejects a missing repairable fail-closed rule")
	}
}

func TestOutage127DomainsUseBoundedDelta(t *testing.T) {
	config := routerOSModelConfig()
	policy := objectSlice(config["policies"])[0]
	domains := []any{}
	for i := 0; i < 127; i++ {
		domains = append(domains, fmt.Sprintf("site%d.example.test", i))
	}
	policy["direct_domains"] = domains
	previous, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy["direct_domains"] = domains[:126]
	desired, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	delta := BuildRouterOSDelta(previous, desired, 0.8)
	if delta == nil || len(delta.ApplyScript) > 16*1024 || len(delta.RollbackScript) > 16*1024 {
		t.Fatal("ordinary card set must fit direct delta")
	}
	if count := strings.Count(delta.ApplyScript, "/ip/dns/static/add "); count != 1 {
		t.Fatalf("DNS reconciliation program duplicated %d times", count)
	}
	t.Logf("127-domain delta: apply=%d rollback=%d", len(delta.ApplyScript), len(delta.RollbackScript))
}

func TestOutageOverlappingPoliciesShareDNSWithoutSharingUnrelatedPermissions(t *testing.T) {
	config := map[string]any{"local_clients": []any{
		map[string]any{"id": "a", "container_outage": "lan_only", "source_cidrs": []any{"10.0.0.1/32"}, "direct_domains": []any{"example.com"}},
		map[string]any{"id": "b", "container_outage": "lan_only", "source_cidrs": []any{"10.0.0.2/32"}, "direct_domains": []any{"api.example.com", "private.test"}},
	}}
	groups, err := routerOSOutageGroups(config)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string][]string{"example.com": {"10.0.0.1/32"}, "api.example.com": {"10.0.0.1/32", "10.0.0.2/32"}, "private.test": {"10.0.0.2/32"}}
	for _, group := range groups {
		for _, domain := range group.Domains {
			if !reflect.DeepEqual(group.Sources, want[domain]) {
				t.Fatalf("permissions %s: %v", domain, group.Sources)
			}
			delete(want, domain)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing domains: %v", want)
	}
	again, _ := routerOSOutageGroups(config)
	if !reflect.DeepEqual(groups, again) {
		t.Fatal("nondeterministic outage groups")
	}
}

func TestOutageCustomRuleSetAcceptsReviewedTLDAndIgnoresEmptyForSingleLANDevice(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "single-device.json"),
		[]byte(`{"rules":[{"domain_suffix":["", "ru", "example.com"]}]}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{
		"local_clients": []any{
			map[string]any{
				"id": "all-lan", "enabled": true, "source_kind": "lan", "source_scope": "lan-all",
				"container_outage": "direct", "source_cidrs": []any{"192.168.50.0/24"},
			},
			map[string]any{
				"id": "single-device", "enabled": true, "source_kind": "lan", "container_outage": "lan_only",
				"source_cidrs": []any{"192.168.50.20/32"}, "direct_services": []any{"single-device"},
			},
		},
	}
	groups, err := routerOSOutageGroups(config, root)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 1 || !reflect.DeepEqual(groups[0].Sources, []string{"192.168.50.20/32"}) || !reflect.DeepEqual(groups[0].Domains, []string{"example.com", "ru"}) {
		t.Fatalf("single-device outage group = %#v", groups)
	}
}

func TestOutageCustomRuleSetReportsOriginalUnsafeDomain(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(
		filepath.Join(root, "unsafe-device.json"),
		[]byte(`{"rules":[{"domain_suffix":["not-a-domain"]}]}`),
		0600,
	); err != nil {
		t.Fatal(err)
	}
	config := map[string]any{"local_clients": []any{map[string]any{
		"id": "single-device", "enabled": true, "container_outage": "lan_only",
		"source_cidrs": []any{"192.168.50.20/32"}, "direct_services": []any{"unsafe-device"},
	}}}
	_, err := routerOSOutageGroups(config, root)
	if err == nil || !strings.Contains(err.Error(), `unsafe outage domain "not-a-domain"`) {
		t.Fatalf("unsafe source domain was not preserved: %v", err)
	}
}

func TestOutage5000DomainsChooseFullImportWithoutTruncation(t *testing.T) {
	config := routerOSModelConfig()
	policy := objectSlice(config["policies"])[0]
	domains := make([]any, 5000)
	for i := range domains {
		domains[i] = fmt.Sprintf("site%04d.example.test", i)
	}
	policy["direct_domains"] = domains
	previous, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	policy["direct_domains"] = domains[:4999]
	desired, err := RenderRouterOSTrafficCandidate(config, nil)
	if err != nil {
		t.Fatal(err)
	}
	if BuildRouterOSDelta(previous, desired, 0.8) != nil {
		t.Fatal("oversized apply/rollback must use full file import")
	}
	for _, domain := range domains {
		if !strings.Contains(previous, `"`+domain.(string)+`|`) {
			t.Fatalf("domain %s was lost", domain)
		}
	}
	if len(previous) >= 2<<20 || strings.Count(previous, "/ip/dns/static/add ") != 1 {
		t.Fatal("large set duplicates reconciliation code or exceeds managed import size")
	}
	t.Logf("5000 domains: candidate=%d bytes; full import selected", len(previous))
}
