package runtimeconfig

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestHealthProbeLanesBoundedByCoreInventory(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, requested := range []int{0, 5, 10, 64} {
			for _, inventory := range []int{0, 1, 5, 100} {
				t.Run(fmt.Sprintf("%s/request%d/inventory%d", mode, requested, inventory), func(t *testing.T) {
					config := inboundSourceBaseConfig()
					config["system"].(map[string]any)["routing_monitor"] = map[string]any{"probe_batch_size": requested}
					config["policies"] = []any{map[string]any{"id": "route", "mode": mode, "selection_order": []any{"country:DE"}}}
					nodes := make([]map[string]any, inventory)
					for index := range nodes {
						nodes[index] = map[string]any{
							"id": fmt.Sprintf("node-%d", index), "country": "DE", "protocol": "vless",
							"server": "edge.example", "server_port": 443, "uuid_secret_ref": "node/uuid",
						}
					}
					source, err := BuildXraySourceModel(config, nodes,
						inboundSecretReader(map[string]string{"node/uuid": "123e4567-e89b-42d3-a456-426614174000"}), inboundSecretPath, "/config/rulesets")
					if err != nil {
						t.Fatal(err)
					}
					budget := requested
					if budget == 0 {
						budget = 10
					}
					want := min(budget, max(1, inventory))
					inbounds := inboundSourceByTag(objectSlice(source.Model["inbounds"]))
					outbounds := inboundSourceByTag(objectSlice(source.Model["outbounds"]))
					rules := objectSlice(objectValue(source.Model["route"])["rules"])
					backgrounds := 0
					for tag, inbound := range inbounds {
						if !strings.HasPrefix(tag, "outbound-health-background") {
							continue
						}
						backgrounds++
						if inbound["listen"] != "127.0.0.1" || !containsText(stringSlice(rules[2]["inbound"]), tag) {
							t.Fatalf("unprotected health listener %s: %#v", tag, inbound)
						}
						if inventory > 0 && (outbounds[tag] == nil || findXraySourceRule(rules, func(rule map[string]any) bool {
							return textValue(rule["outbound"]) == tag && containsText(stringSlice(rule["inbound"]), tag)
						}) == nil) {
							t.Fatalf("health listener %s lost matching selector/route", tag)
						}
					}
					if backgrounds != want {
						t.Fatalf("backgrounds=%d want=%d", backgrounds, want)
					}
					if inbounds["outbound-health-probe"] == nil {
						t.Fatal("active liveness lane missing")
					}
					body, err := BuildXrayHealthPool(config, nodes, map[string]any{})
					if err != nil {
						t.Fatal(err)
					}
					var pool map[string]any
					if err := json.Unmarshal(body, &pool); err != nil {
						t.Fatal(err)
					}
					candidates := stringSlice(objectValue(objectValue(pool["health_policies"])["route"])["candidates"])
					if len(candidates) != inventory || int(pool["probe_budget"].(float64)) != budget || int(pool["probe_lanes"].(float64)) != want {
						t.Fatalf("pool and source bounds diverged: %#v", pool)
					}
				})
			}
		}
	}
}

func TestHealthProbeInventoryExcludesDisabledReservedAndDuplicateNodes(t *testing.T) {
	config := map[string]any{}
	nodes := []map[string]any{
		{"id": "shared", "country": "DE"}, {"id": "shared", "country": "DE"},
		{"id": "disabled", "country": "DE", "enabled": false},
		{"id": "refresh-only", "country": "DE", "subscription_reserve_id": "feed"},
		{"id": "outside", "country": "FR"},
	}
	if got := healthProbeInventoryCount(nodes); got != 2 {
		t.Fatalf("concrete unique count=%d want2", got)
	}
	if got := len(xrayHealthProbeLanesForConfig(config, 1)); got != 2 {
		t.Fatalf("one candidate needs one active and one background lane, got%d", got)
	}
}

func TestRequestedHealthProbeBatchPreservesExplicitFive(t *testing.T) {
	for _, tc := range []struct {
		value any
		want  int
	}{{nil, 10}, {0, 10}, {5, 5}, {64, 64}, {100, 64}} {
		config := map[string]any{"system": map[string]any{"routing_monitor": map[string]any{"probe_batch_size": tc.value}}}
		if got := requestedHealthProbeBatch(config); got != tc.want {
			t.Fatalf("value=%v got=%d want=%d", tc.value, got, tc.want)
		}
	}
}

func TestProbeLaneContractStableAcrossEligibilityEditsAndReverseInventory(t *testing.T) {
	config := inboundSourceBaseConfig()
	policy := map[string]any{"id": "route", "mode": "best", "selection_order": []any{"country:DE", "country:FI", "reverse:home"}}
	config["policies"] = []any{policy}
	config["reverse_vless_exits"] = []any{map[string]any{"id": "home", "enabled": true, "uuid_secret_ref": "node/uuid"}}
	nodes := []map[string]any{
		{"id": "dynamic", "subscription_id": "feed", "country": "DE", "protocol": "vless", "server": "de.example", "server_port": 443, "uuid_secret_ref": "node/uuid"},
		{"id": "static", "country": "FI", "protocol": "vless", "server": "fi.example", "server_port": 443, "uuid_secret_ref": "node/uuid"},
	}
	read := inboundSecretReader(map[string]string{"node/uuid": "123e4567-e89b-42d3-a456-426614174000"})
	before, err := BuildXraySourceModel(config, nodes, read, inboundSecretPath, "/config/rulesets")
	if err != nil {
		t.Fatal(err)
	}
	for _, order := range [][]any{{"country:DE", "country:FI", "reverse:home"}, {"country:FI"}, {}} {
		policy["selection_order"] = order
		after, err := BuildXraySourceModel(config, nodes, read, inboundSecretPath, "/config/rulesets")
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(before, after) {
			t.Fatal("hot eligibility edit changed core source")
		}
		body, err := BuildXrayHealthPool(config, nodes, map[string]any{})
		if err != nil {
			t.Fatal(err)
		}
		var pool map[string]any
		if err := json.Unmarshal(body, &pool); err != nil {
			t.Fatal(err)
		}
		if pool["probe_lanes"] != float64(3) {
			t.Fatalf("mixed dynamic/static/reverse lanes changed with eligibility: %s", body)
		}
	}
}
