package routeros

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func seedCompletedCatalogArrival(t *testing.T, f *compatRESTFixture, promoted bool) {
	t.Helper()
	contract := CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: "disk/sb-gateway/root-previous", CatalogSchema: 1}
	if promoted {
		contract.ProducerRoot = "disk/sb-gateway/root-current"
		contract.PreviousRoot = "disk/sb-gateway/root-previous"
		contract.PreviousCatalogSchema = 1
	}
	body, _ := json.Marshal(contract)
	f.marker = map[string]any{".id": "*90", "name": CatalogImageContractName, "comment": catalogImageContractComment, "source": string(body)}
	receipt := map[string]any{"catalog-schema": 1, "candidate-id": "*1", "candidate-root": "/disk/sb-gateway/root-current", "previous-id": "*2", "previous-root": "/disk/sb-gateway/root-previous", "phase": "completed", "live-if": "live", "mountlists": []string{"live"}}
	body, _ = json.Marshal(receipt)
	f.arrival = map[string]any{".id": "*91", "name": CatalogImageArrivalName, "comment": "SB-GATEWAY catalog image arrival", "source": string(body)}
}

func TestCatalogCompletedArrivalProvesCapabilityWithoutHistoricalFingerprint(t *testing.T) {
	for _, promoted := range []bool{false, true} {
		f := compatFixture()
		seedCompletedCatalogArrival(t, f, promoted)
		client := compatFixtureClient(t, f)
		inventory, err := client.InspectCatalogImageCompatibility(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		capable, err := client.ValidateCompletedCatalogImageArrival(context.Background(), inventory)
		if err != nil || !capable {
			t.Fatalf("completed capability promoted=%t: %v", promoted, err)
		}
		if len(f.mountlistPatches) != 0 {
			t.Fatal("read-only proof attached a mountlist")
		}
	}
}

func TestCatalogCompletedArrivalRejectsPositiveClaimWithMissingOrChangedProof(t *testing.T) {
	for _, scenario := range []string{"missing", "wrong-owner", "probation", "schema-zero", "candidate-id", "candidate-root", "previous-id", "previous-root", "live-interface", "mountlists", "environment", "attached-previous", "active-transfer", "stale-inventory"} {
		t.Run(scenario, func(t *testing.T) {
			f := compatFixture()
			seedCompletedCatalogArrival(t, f, false)
			client := compatFixtureClient(t, f)
			inventory, err := client.InspectCatalogImageCompatibility(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			var receipt map[string]any
			_ = json.Unmarshal([]byte(text(f.arrival["source"])), &receipt)
			switch scenario {
			case "missing":
				f.arrival = nil
			case "wrong-owner":
				f.arrival["comment"] = "foreign"
			case "probation":
				receipt["phase"] = "probation"
			case "schema-zero":
				receipt["catalog-schema"] = 0
			case "candidate-id":
				receipt["candidate-id"] = "*99"
			case "candidate-root":
				receipt["candidate-root"] = "/disk/sb-gateway/root-foreign"
			case "previous-id":
				receipt["previous-id"] = "*99"
			case "previous-root":
				receipt["previous-root"] = "/disk/sb-gateway/root-foreign"
			case "live-interface":
				receipt["live-if"] = "foreign"
			case "mountlists":
				receipt["mountlists"] = []string{"foreign"}
			case "environment":
				f.containers[1]["envlist"] = []string{"other"}
			case "attached-previous":
				f.containers[1]["mountlists"] = []string{"attached"}
			case "active-transfer":
				f.transfer = map[string]any{"name": imageUpdateTransfer}
			case "stale-inventory":
				f.mounts[0]["src"] = "/disk/sb-gateway/changed"
			}
			if f.arrival != nil {
				body, _ := json.Marshal(receipt)
				f.arrival["source"] = string(body)
			}
			if scenario == "environment" || scenario == "attached-previous" {
				// These are stable but unsafe physical states, not merely a
				// caller snapshot race. Exercise the namespace/attachment guard.
				inventory, err = client.InspectCatalogImageCompatibility(context.Background())
				if err != nil {
					t.Fatal(err)
				}
			}
			capable, err := client.ValidateCompletedCatalogImageArrival(context.Background(), inventory)
			if err == nil || capable {
				t.Fatal("unbound positive capability claim accepted")
			}
			if len(f.mountlistPatches) != 0 {
				t.Fatal("rejected proof mutated mount binding")
			}
		})
	}
}

func TestCatalogCompletedArrivalDoesNotInventLegacyCapability(t *testing.T) {
	f := compatFixture()
	client := compatFixtureClient(t, f)
	inventory, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	capable, err := client.ValidateCompletedCatalogImageArrival(context.Background(), inventory)
	if err != nil || capable {
		t.Fatal("absent legacy capability was guessed")
	}
}

func TestCatalogCompletedArrivalRejectsChangingInventoryContractAndReceipt(t *testing.T) {
	for _, kind := range []string{"inventory", "contract", "arrival"} {
		t.Run(kind, func(t *testing.T) {
			f := compatFixture()
			seedCompletedCatalogArrival(t, f, false)
			client := compatFixtureClient(t, f)
			before, err := client.InspectCatalogImageCompatibility(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			reads := 0
			f.readHook = func(r *http.Request) {
				matches := kind == "inventory" && r.URL.Path == "/rest/container" || kind == "contract" && r.URL.Query().Get("name") == CatalogImageContractName || kind == "arrival" && r.URL.Query().Get("name") == CatalogImageArrivalName
				if !matches {
					return
				}
				reads++
				if reads != 2 {
					return
				}
				switch kind {
				case "inventory":
					f.mounts[0]["src"] = "/disk/sb-gateway/changed"
				case "contract":
					var contract CatalogImageContract
					_ = json.Unmarshal([]byte(text(f.marker["source"])), &contract)
					contract.PreviousRoot = "disk/sb-gateway/other"
					contract.PreviousCatalogSchema = 1
					body, _ := json.Marshal(contract)
					f.marker["source"] = string(body)
				case "arrival":
					f.arrival["source"] = text(f.arrival["source"]) + " "
				}
			}
			if capable, err := client.ValidateCompletedCatalogImageArrival(context.Background(), before); err == nil || capable {
				t.Fatal("changing authority pair accepted")
			}
		})
	}
}
