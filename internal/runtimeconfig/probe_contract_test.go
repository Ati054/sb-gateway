package runtimeconfig

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

type probeContractCatalog struct {
	count, disabled, gets int
}

func (source *probeContractCatalog) References() []subscriptioncatalog.Ref {
	return []subscriptioncatalog.Ref{{Generation: strings.Repeat("a", 64)}}
}
func (source *probeContractCatalog) InventoryCount() int { return 99999 }
func (source *probeContractCatalog) LookupDefinition(context.Context, string) (subscriptioncatalog.Record, error) {
	source.gets++
	return subscriptioncatalog.Record{}, errors.New("private lookup is forbidden for probe geometry")
}
func (source *probeContractCatalog) WalkMetadata(ctx context.Context, emit func(RuntimeCatalogNode) error) error {
	for index := 0; index < source.count; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		id := fmt.Sprintf("feed-node-%d", index)
		if err := emit(RuntimeCatalogNode{ID: id, Generation: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), Metadata: map[string]any{
			"id": id, "enabled": index >= source.disabled, "protocol": "vless", "country": "DE", "subscription_id": "feed",
		}}); err != nil {
			return err
		}
	}
	return nil
}

func TestCatalogProbeContractMatchesRenderedMetadataInventory(t *testing.T) {
	for _, tc := range []struct {
		name                    string
		count, disabled, budget int
		legacy                  bool
		reverse                 bool
		want                    int
	}{
		{"empty", 0, 0, 10, false, false, 1},
		{"small", 3, 0, 10, false, false, 3},
		{"bounded", 12, 0, 10, false, false, 10},
		{"explicit budget", 12, 0, 3, false, false, 3},
		{"disabled metadata", 4, 3, 10, false, false, 1},
		{"mixed legacy", 3, 1, 10, true, false, 3},
		{"configuration-owned reverse", 1, 0, 10, false, true, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			catalog := &probeContractCatalog{count: tc.count, disabled: tc.disabled}
			config := map[string]any{"system": map[string]any{"routing_monitor": map[string]any{"probe_batch_size": tc.budget}}, "policies": []any{
				map[string]any{"id": "best", "mode": "best", "selection_order": []string{"country:DE"}},
			}}
			if tc.reverse {
				config["reverse_vless_exits"] = []any{map[string]any{"id": "synthetic", "enabled": true}}
			}
			var legacy []map[string]any
			if tc.legacy {
				legacy = []map[string]any{
					{"id": "legacy", "protocol": "vless", "country": "DE"},
					{"id": "disabled", "enabled": false},
					{"id": "refresh", "subscription_reserve_id": "reserve"},
				}
			}
			contract, err := BuildXrayProbeContract(config, legacy, catalog)
			if err != nil || contract.ProbeBudget != tc.budget || contract.ProbeLanes != tc.want {
				t.Fatalf("contract=%+v error=%v", contract, err)
			}
			plan, err := buildCatalogRuntimePlan(config, legacy, catalog)
			if err != nil {
				t.Fatal(err)
			}
			body, err := buildCatalogHealthPool(config, plan, map[string]any{}, legacy)
			if err != nil {
				t.Fatal(err)
			}
			var rendered XrayProbeContract
			if err := json.Unmarshal(body, &rendered); err != nil || rendered != contract || catalog.gets != 0 {
				t.Fatal("probe contract differs from renderer or read a private provider definition")
			}
		})
	}
}

func TestLegacyProbeContractKeepsExistingHealthPoolGeometry(t *testing.T) {
	nodes := []map[string]any{{"id": "one"}, {"id": "two"}, {"id": "disabled", "enabled": false}}
	contract, err := BuildXrayProbeContract(map[string]any{}, nodes, nil)
	if err != nil || contract.ProbeBudget != 10 || contract.ProbeLanes != 2 {
		t.Fatalf("legacy contract=%+v error=%v", contract, err)
	}
}
