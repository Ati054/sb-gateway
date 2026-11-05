package runtimeconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

type syntheticRuntimeCatalog struct {
	count   int
	gets    int
	country string
}

func (source *syntheticRuntimeCatalog) References() []subscriptioncatalog.Ref {
	return []subscriptioncatalog.Ref{{Generation: strings.Repeat("a", 64)}}
}
func (source *syntheticRuntimeCatalog) InventoryCount() int { return source.count }
func (source *syntheticRuntimeCatalog) LookupDefinition(context.Context, string) (subscriptioncatalog.Record, error) {
	source.gets++
	return subscriptioncatalog.Record{}, errors.New("unexpected private definition lookup")
}
func (source *syntheticRuntimeCatalog) WalkMetadata(ctx context.Context, visit func(RuntimeCatalogNode) error) error {
	for i := 0; i < source.count; i++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := fmt.Sprintf("feed-node-%05d", i)
		country := "DE"
		if i == 0 {
			country = "FI"
		}
		if source.country != "" {
			country = source.country
		}
		if err := visit(RuntimeCatalogNode{ID: id, Generation: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), Metadata: map[string]any{"protocol": "vless", "display_protocol": "reality", "transport_type": "tcp", "country": country, "label": id, "subscription_id": "feed", "selection_key": fmt.Sprintf("%016x", i), "server": "203.0.113.8", "server_port": 443}}); err != nil {
			return err
		}
	}
	return nil
}

func TestCatalogRuntimeScopeKeepsFullEligibleSetWithoutDefinitions(t *testing.T) {
	for _, all := range []bool{false, true} {
		t.Run(fmt.Sprint(all), func(t *testing.T) {
			source := &syntheticRuntimeCatalog{count: 10000}
			selection := "country:FI"
			if all {
				selection = "group:all"
			}
			config := map[string]any{"policies": []any{map[string]any{"id": "best", "mode": "best", "selection_order": []string{selection}, "node_groups": []any{map[string]any{"id": "all", "subscription_ids": []string{"*"}}}}, map[string]any{"id": "unassigned", "mode": "priority", "selection_order": []string{"country:FI"}}}}
			plan, err := buildCatalogRuntimePlan(config, nil, source)
			if err != nil {
				t.Fatal(err)
			}
			want := 1
			if all {
				want = 10000
			}
			if len(plan.nodes) != want || plan.inventory != 10000 || source.gets != 0 {
				t.Fatalf("nodes=%d inventory=%d private_gets=%d", len(plan.nodes), plan.inventory, source.gets)
			}
			if len(plan.groups["unassigned"]) != 1 {
				t.Fatal("unassigned enabled policy lost its candidates")
			}
			body, err := buildCatalogHealthPool(config, plan, map[string]any{"outbounds": []any{map[string]any{"tag": "block", "protocol": "blackhole"}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			var pool struct {
				Version            int
				Outbounds          map[string]json.RawMessage
				CatalogDefinitions map[string]CatalogDefinition `json:"catalog_definitions"`
				Nodes              map[string]catalogHealthNode
				HealthPolicies     map[string]map[string]json.RawMessage `json:"health_policies"`
			}
			if err := json.Unmarshal(body, &pool); err != nil {
				t.Fatal(err)
			}
			if pool.Version != 5 || len(pool.Outbounds) != 0 || len(pool.CatalogDefinitions) != want || len(pool.Nodes) != want {
				t.Fatal("pool eagerly materialized or lost eligible definitions")
			}
			for _, contract := range pool.HealthPolicies {
				if _, duplicated := contract["nodes"]; duplicated {
					t.Fatal("metadata repeated per policy")
				}
			}
		})
	}
}

func TestCatalogRuntimeMatchingUsesCanonicalFirstClaimAndStableGeometry(t *testing.T) {
	source := &syntheticRuntimeCatalog{count: 7}
	config := map[string]any{"policies": []any{map[string]any{"id": "priority", "mode": "priority", "selection_order": []string{"country:FI", "group:all"}, "node_groups": []any{map[string]any{"id": "all", "subscription_ids": []string{"feed"}}}}}}
	plan, err := buildCatalogRuntimePlan(config, nil, source)
	if err != nil {
		t.Fatal(err)
	}
	groups := plan.groups["priority"]
	if len(groups) != 2 || !reflect.DeepEqual(groups[0].Members, []string{"feed-node-00000"}) || len(groups[1].Members) != 6 {
		t.Fatalf("bad claim groups: %#v", groups)
	}
	config["policies"].([]any)[0].(map[string]any)["selection_order"] = []string{"country:FI"}
	other, err := buildCatalogRuntimePlan(config, nil, source)
	if err != nil {
		t.Fatal(err)
	}
	if len(other.nodes) != 1 || other.inventory != plan.inventory || len(xrayHealthProbeLanesForConfig(config, other.inventory)) != len(xrayHealthProbeLanesForConfig(config, plan.inventory)) {
		t.Fatal("eligibility edit changed stable probe geometry")
	}
}

func TestRenderCatalogOutboundReadsOnlyRecordSecretsAndKeepsScopedID(t *testing.T) {
	node := map[string]any{"id": "provider-base", "subscription_id": "feed", "protocol": "vless", "server": "example.test", "server_port": 443, "uuid_secret_ref": "@catalog:uuid", "tls": map[string]any{"enabled": true, "server_name": "example.test"}}
	body, _ := json.Marshal(node)
	secrets, _ := json.Marshal(map[string]string{"@catalog:uuid": "123e4567-e89b-42d3-a456-426614174000"})
	record := subscriptioncatalog.Record{ID: "feed-provider-base", Node: body, Secrets: secrets, Metadata: json.RawMessage(`{"id":"feed-provider-base","provider_node_id":"provider-base","subscription_id":"feed"}`)}
	raw, err := RenderCatalogOutbound(record)
	if err != nil {
		t.Fatal(err)
	}
	var outbound map[string]any
	if err := json.Unmarshal(raw, &outbound); err != nil {
		t.Fatal(err)
	}
	if outbound["tag"] != record.ID || outbound["protocol"] != "vless" {
		t.Fatal("scoped definition changed")
	}
	if err := ValidateCatalogRecordSource(record, "another-feed"); err == nil {
		t.Fatal("record escaped its source scope")
	}
	bad := record
	bad.ID = "other-provider-base"
	if _, err := RenderCatalogOutbound(bad); err == nil {
		t.Fatal("overlay hid a mismatched scoped record ID")
	}
	record.Secrets = json.RawMessage(`{}`)
	if _, err := RenderCatalogOutbound(record); err == nil || strings.Contains(err.Error(), "@catalog") {
		t.Fatal("missing secret did not fail privately")
	}
}

func TestNativeCatalogArtifactsNeverExpandAllCandidateDefinitions(t *testing.T) {
	template, err := os.ReadFile("../../templates/nginx.conf.j2")
	if err != nil {
		t.Fatal(err)
	}
	config := inboundSourceBaseConfig()
	objectValue(objectValue(config["system"])["networking"])["routeros_gateway"] = "192.168.3.1"
	config["dns"] = map[string]any{"internal_server": "192.168.3.1", "direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"}, "vpn_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"}}
	config["ingress"] = map[string]any{"tls_profile_id": "public"}
	config["tls_profiles"] = []any{map[string]any{"id": "public", "enabled": true, "certificate_secret_ref": "tls/cert", "private_key_secret_ref": "tls/key"}}
	config["watchdog"] = map[string]any{"interval_seconds": 5, "failure_threshold": 3, "recovery_threshold": 3, "max_restarts_per_hour": 6}
	config["policies"] = []any{map[string]any{"id": "best", "mode": "best", "selection_order": []string{"group:all"}, "node_groups": []any{map[string]any{"id": "all", "subscription_ids": []string{"*"}}}}}
	source := &syntheticRuntimeCatalog{count: 1000}
	artifacts, err := BuildNativeRuntimeArtifacts(config, nil, func(reference string) (string, error) {
		if reference == "management-api-token" {
			return "management-token", nil
		}
		return "", fmt.Errorf("unexpected external secret read")
	}, inboundSecretPath, NativeArtifactOptions{Catalog: source, RuleSetRoot: t.TempDir(), Nginx: NginxRenderOptions{Template: string(template)}})
	if err != nil {
		t.Fatal(err)
	}
	if source.gets != 0 {
		t.Fatal("full graph eagerly read private definitions")
	}
	var graph map[string]any
	if err := json.Unmarshal(artifacts["xray.json"], &graph); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range objectSlice(graph["outbounds"]) {
		if strings.HasPrefix(textValue(outbound["tag"]), "feed-node-") {
			t.Fatal("catalog candidate became a static handler")
		}
	}
	route := objectValue(graph["routing"])
	best := findXraySourceRule(objectSlice(route["balancers"]), func(b map[string]any) bool { return b["tag"] == "best" })
	if best == nil || !containsText(stringSlice(best["selector"]), urlTestPolicyPrefix("best")) {
		t.Fatal("lazy policy selector has no dynamic prefix")
	}
	if len(artifacts["urltest-pool.json"]) == 0 {
		t.Fatal("missing lazy pool")
	}
}
