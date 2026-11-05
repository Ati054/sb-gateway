package runtimeconfig

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestCatalogPlanningRejectsBeforeUnboundedRetainedState(t *testing.T) {
	source := &syntheticRuntimeCatalog{count: 100000}
	plan, err := buildCatalogRuntimePlanWithBudget(map[string]any{}, nil, source, 800)
	if !errors.Is(err, ErrCatalogPlanningBudget) {
		t.Fatalf("unexpected admission error: %v", err)
	}
	if plan.inventory > 4 || len(plan.nodes) != 0 || source.gets != 0 {
		t.Fatalf("planning continued past its budget: inventory=%d selected=%d gets=%d", plan.inventory, len(plan.nodes), source.gets)
	}
}

func TestCatalogPlanningBudgetAccountsSelectionAndKeepsFullAdmittedSet(t *testing.T) {
	config := map[string]any{"policies": []any{map[string]any{"id": "best", "mode": "best", "selection_order": []string{"country:FI"}}}}
	source := &syntheticRuntimeCatalog{count: 5001, country: "FI"}
	if _, err := buildCatalogRuntimePlanWithBudget(config, nil, source, 4096); !errors.Is(err, ErrCatalogPlanningBudget) {
		t.Fatalf("selected-set admission error: %v", err)
	}
	plan, err := buildCatalogRuntimePlanWithBudget(config, nil, source, 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan.nodes) != 5001 || plan.inventory != 5001 || len(plan.groups["best"]) != 1 || len(plan.groups["best"][0].Members) != 5001 || source.gets != 0 {
		t.Fatalf("admitted inventory was truncated: selected=%d inventory=%d groups=%d gets=%d", len(plan.nodes), plan.inventory, len(plan.groups["best"]), source.gets)
	}
}

type catalogLongDisplayFixture struct{ *syntheticRuntimeCatalog }

func (source *catalogLongDisplayFixture) WalkMetadata(ctx context.Context, visit func(RuntimeCatalogNode) error) error {
	return source.syntheticRuntimeCatalog.WalkMetadata(ctx, func(item RuntimeCatalogNode) error {
		item.ID = strings.Repeat("x", 48) + item.ID
		item.Metadata["label"] = strings.Repeat("<&", 128)
		return visit(item)
	})
}

func TestCatalogPlanningBudgetChargesLongIDsAndPriorityServiceFanout(t *testing.T) {
	source := &catalogLongDisplayFixture{&syntheticRuntimeCatalog{count: 100, country: "FI"}}
	policy := func(id, mode string) map[string]any {
		return map[string]any{"id": id, "mode": mode, "selection_order": []string{"country:FI"}}
	}
	config := map[string]any{"policies": []any{policy("best", "best")}}
	plan, err := buildCatalogRuntimePlanWithBudget(config, nil, source, 1<<20)
	if err != nil || len(plan.nodes) != 100 {
		t.Fatalf("small admitted plan: selected=%d error=%v", len(plan.nodes), err)
	}
	services := make([]string, 20)
	for i := range services {
		services[i] = fmt.Sprintf("service-%d", i)
	}
	policies := make([]any, 6)
	for i := range policies {
		p := policy(fmt.Sprintf("priority-%d", i), "priority")
		p["candidate_service_ids"] = services
		policies[i] = p
	}
	config["policies"] = policies
	if _, err := buildCatalogRuntimePlanWithBudget(config, nil, source, 1<<20); !errors.Is(err, ErrCatalogPlanningBudget) {
		t.Fatalf("priority fanout escaped admission: %v", err)
	}
	if source.gets != 0 {
		t.Fatal("budget admission read private definitions")
	}
}
