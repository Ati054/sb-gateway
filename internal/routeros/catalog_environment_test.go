package routeros

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestCatalogImageEnvironmentFieldContract(t *testing.T) {
	for _, scenario := range []struct {
		name string
		row  map[string]any
		want []string
	}{
		{"plural-string", map[string]any{"envlists": "env-main,env-extra"}, []string{"env-extra", "env-main"}},
		{"plural-json-array", map[string]any{"envlists": []any{"env-main", "env-extra"}}, []string{"env-extra", "env-main"}},
		{"plural-typed-array", map[string]any{"envlists": []string{"env-main"}}, []string{"env-main"}},
		{"legacy-string", map[string]any{"envlist": "env-main"}, []string{"env-main"}},
		{"legacy-array", map[string]any{"envlist": []any{"env-main"}}, []string{"env-main"}},
		{"both-equivalent", map[string]any{"envlists": "env-main,env-extra", "envlist": []any{"env-extra", "env-main"}}, []string{"env-extra", "env-main"}},
		{"both-conflicting", map[string]any{"envlists": "env-main", "envlist": "env-other"}, nil},
		{"both-conflicting-length", map[string]any{"envlists": "env-main,env-extra", "envlist": "env-main"}, nil},
		{"invalid-preferred-no-fallback", map[string]any{"envlists": false, "envlist": "env-main"}, nil},
		{"invalid-legacy-not-ignored", map[string]any{"envlists": "env-main", "envlist": map[string]any{}}, nil},
		{"empty-preferred-no-fallback", map[string]any{"envlists": "", "envlist": "env-main"}, nil},
		{"null-preferred-no-fallback", map[string]any{"envlists": nil, "envlist": "env-main"}, nil},
		{"invalid-array-member", map[string]any{"envlists": []any{"env-main", 1}}, nil},
		{"duplicate-array-member", map[string]any{"envlists": []any{"env-main", "env-main"}}, nil},
		{"empty-array-member", map[string]any{"envlists": []any{""}}, nil},
		{"empty-array", map[string]any{"envlists": []any{}}, nil},
		{"missing", map[string]any{}, nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			got, err := compatEnvironment(scenario.row)
			if scenario.want == nil {
				if !errors.Is(err, ErrCatalogImageCompatibility) {
					t.Fatal("ambiguous environment accepted")
				}
				return
			}
			if err != nil || !reflect.DeepEqual(got, scenario.want) {
				t.Fatalf("environment contract: %v, %v", got, err)
			}
		})
	}
}

func TestCatalogImagePluralRESTInventoryAndRuntimeProof(t *testing.T) {
	f := compatFixture()
	// Sanitized modern REST shape: comma-separated mountlists, plural envlists,
	// absent status flags for the running image and string stopped for standby.
	for _, row := range f.containers {
		delete(row, "envlist")
		row["envlists"] = "env-main"
	}
	f.containers[0]["mountlists"] = "live"
	delete(f.containers[0], "stopped")
	f.containers[1]["mountlists"] = ""
	f.containers[1]["stopped"] = "true"
	// Unmanaged containers need not have any environment list.
	f.containers = append(f.containers, map[string]any{".id": "*99", "comment": "unrelated"})
	client := compatFixtureClient(t, f)
	inventory, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil || inventory.Previous == nil || !inventory.Previous.Stopped || !reflect.DeepEqual(inventory.Current.Environment, []string{"env-main"}) {
		t.Fatalf("modern REST inventory rejected: %v", err)
	}
	contract := CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: inventory.Current.Root, CatalogSchema: 1}
	if err := client.PublishCatalogImageContract(context.Background(), contract); err != nil {
		t.Fatal(err)
	}
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), inventory.Current, inventory.Fingerprint); err != nil {
		t.Fatal("modern REST runtime proof rejected")
	}
	// Spelling changes must not alter a normalized environment fingerprint.
	for _, row := range f.containers[:2] {
		delete(row, "envlists")
		row["envlist"] = []any{"env-main"}
	}
	legacy, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil || legacy.Fingerprint != inventory.Fingerprint {
		t.Fatal("equivalent legacy alias changed managed fingerprint")
	}
	for _, target := range []int{0, 1} {
		f.containers[target]["envlists"] = "conflicting"
		if _, err := client.InspectCatalogImageCompatibility(context.Background()); !errors.Is(err, ErrCatalogImageCompatibility) {
			t.Fatal("conflicting managed alias accepted by inventory")
		}
		if err := client.ValidateCatalogRuntimeImageProof(context.Background(), inventory.Current, inventory.Fingerprint); !errors.Is(err, ErrCatalogImageCompatibility) {
			t.Fatal("conflicting managed alias accepted by runtime proof")
		}
		delete(f.containers[target], "envlists")
	}
}
