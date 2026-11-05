package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

type compatRESTFixture struct {
	containers            []map[string]any
	mounts                []map[string]any
	marker                map[string]any
	transfer              map[string]any
	arrival               map[string]any
	jobs                  []map[string]any
	mountlistPatches      []map[string]any
	ignoreArrayMountlists bool
	ignoreMountlistPatch  bool
	readHook              func(*http.Request)
}

func compatFixture() *compatRESTFixture {
	f := &compatRESTFixture{containers: []map[string]any{
		{".id": "*1", "root-dir": "/disk/sb-gateway/root-current", "comment": "SB-GATEWAY container", "interface": "live", "envlist": []any{"env"}, "mountlists": []any{"live"}, "stopped": false},
		{".id": "*2", "root-dir": "/disk/sb-gateway/root-previous", "comment": "SB-GATEWAY container previous", "interface": "hold", "envlist": []any{"env"}, "mountlists": []any{}, "stopped": true},
	}}
	for _, dst := range []string{"/config", "/data", "/logs", "/state"} {
		f.mounts = append(f.mounts, map[string]any{"list": "live", "src": "/disk/sb-gateway" + dst, "dst": dst, "comment": "SB-GATEWAY storage", "disabled": false})
	}
	return f
}

func compatFixtureClient(t *testing.T, f *compatRESTFixture) *Client {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && f.readHook != nil {
			f.readHook(r)
		}
		w.Header().Set("Content-Type", "application/json")
		var value any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container":
			value = f.containers
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/scheduler":
			value = []any{}
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script/job":
			if f.jobs == nil {
				value = []any{}
			} else {
				value = f.jobs
			}
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container/mounts":
			value = f.mounts
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script":
			if r.URL.Query().Get("name") == CatalogImageArrivalName {
				if f.arrival == nil {
					value = []any{}
				} else {
					value = []any{f.arrival}
				}
			} else if r.URL.Query().Get("name") == imageUpdateTransfer {
				if f.transfer == nil {
					value = []any{}
				} else {
					value = []any{f.transfer}
				}
			} else if f.marker == nil {
				value = []any{}
			} else {
				value = []any{f.marker}
			}
		case r.Method == http.MethodPut && r.URL.Path == "/rest/container/mounts":
			var row map[string]any
			json.NewDecoder(r.Body).Decode(&row)
			f.mounts = append(f.mounts, row)
			value = row
		case r.Method == http.MethodPatch && r.URL.Path == "/rest/container/*2":
			var row map[string]any
			if json.NewDecoder(r.Body).Decode(&row) != nil || len(row) != 1 {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			f.mountlistPatches = append(f.mountlistPatches, row)
			switch value := row["mountlists"].(type) {
			case string:
				if value == "" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if !f.ignoreMountlistPatch {
					f.containers[1]["mountlists"] = value
				}
			case []any:
				// Optional regression backend: accepts a list with HTTP 200 but
				// does not change the property. Default fixture is scalar-only.
				if !f.ignoreArrayMountlists {
					w.WriteHeader(http.StatusBadRequest)
					return
				}
			default:
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			value = f.containers[1]
		case r.Method == http.MethodPut && r.URL.Path == "/rest/system/script":
			json.NewDecoder(r.Body).Decode(&f.marker)
			f.marker[".id"] = "*90"
			value = f.marker
		case r.Method == http.MethodPatch && r.URL.Path == "/rest/system/script/*90":
			json.NewDecoder(r.Body).Decode(&f.marker)
			f.marker[".id"] = "*90"
			value = f.marker
		default:
			w.WriteHeader(http.StatusNotFound)
			value = map[string]any{"error": "unexpected synthetic request"}
		}
		json.NewEncoder(w).Encode(value)
	}))
	t.Cleanup(server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, RootCAs: pool, Username: "synthetic", Password: "synthetic"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.CloseIdleConnections)
	return client
}

func TestCatalogRuntimeProbationRequiresBoundIncomingCapability(t *testing.T) {
	f := compatFixture()
	client := compatFixtureClient(t, f)
	before, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	contract := CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: before.Current.Root, CatalogSchema: 1}
	if err := client.PublishCatalogImageContract(context.Background(), contract); err != nil {
		t.Fatal(err)
	}
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err != nil {
		t.Fatal(err)
	}
	old := f.containers[0]
	old["comment"] = "SB-GATEWAY container rollback"
	old["stopped"] = true
	old["mountlists"] = []any{}
	current := map[string]any{".id": "*3", "root-dir": "/disk/sb-gateway/root-next", "comment": "SB-GATEWAY container", "interface": "live", "envlist": []any{"env"}, "mountlists": []any{"live"}, "stopped": false}
	f.containers = []map[string]any{current, old}
	receipt := map[string]any{"catalog-schema": 1, "candidate-root": "/disk/sb-gateway/root-next", "previous-root": "/" + before.Current.Root, "phase": "probation", "mountlists": []string{"live"}}
	body, _ := json.Marshal(receipt)
	f.transfer = map[string]any{"name": imageUpdateTransfer, "comment": "SB-GATEWAY image transfer metadata", "source": string(body)}
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err != nil {
		t.Fatal("read-only catalog-aware probation was blocked")
	}
	receipt["catalog-schema"] = 0
	body, _ = json.Marshal(receipt)
	f.transfer["source"] = string(body)
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err == nil {
		t.Fatal("unverified incoming image accepted")
	}
	receipt["catalog-schema"] = 1
	receipt["phase"] = "completed"
	receipt["previous-id"] = before.Current.ID
	receipt["candidate-id"] = "*3"
	body, _ = json.Marshal(receipt)
	f.transfer = nil
	f.arrival = map[string]any{"name": CatalogImageArrivalName, "comment": "SB-GATEWAY catalog image arrival", "source": string(body)}
	f.containers = []map[string]any{current} // predecessor may be removed after probation.
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err != nil {
		t.Fatal("durable arrival cannot bridge post-probation restart")
	}
	// Simulate marker publication succeeding and auxiliary publication failing:
	// caller still presents the old producer/fingerprint after process restart.
	contract.ProducerRoot = "disk/sb-gateway/root-next"
	if err := client.PublishCatalogImageContract(context.Background(), contract); err != nil {
		t.Fatal(err)
	}
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err != nil {
		t.Fatal("promoted marker and old auxiliary cannot resume")
	}
	old["comment"] = "SB-GATEWAY container previous"
	f.containers = []map[string]any{current, old}
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err == nil {
		t.Fatal("promoted marker ignored retained predecessor binding")
	}
	contract.PreviousRoot = before.Current.Root
	contract.PreviousCatalogSchema = 1
	if err := client.PublishCatalogImageContract(context.Background(), contract); err != nil {
		t.Fatal(err)
	}
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err != nil {
		t.Fatal("retained catalog-aware predecessor cannot resume")
	}
	f.arrival = nil
	old["comment"] = "SB-GATEWAY container rollback"
	receipt["phase"] = "probation"
	body, _ = json.Marshal(receipt)
	f.transfer = map[string]any{"name": imageUpdateTransfer, "comment": "SB-GATEWAY image transfer metadata", "source": string(body)}
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err == nil {
		t.Fatal("probation receipt promoted producer")
	}
	f.transfer = nil
	old["comment"] = "SB-GATEWAY container previous"
	receipt["phase"] = "completed"
	body, _ = json.Marshal(receipt)
	f.arrival = map[string]any{"name": CatalogImageArrivalName, "comment": "SB-GATEWAY catalog image arrival", "source": string(body)}
	receipt["candidate-id"] = "*unknown"
	body, _ = json.Marshal(receipt)
	f.arrival["source"] = string(body)
	if err := client.ValidateCatalogRuntimeImageProof(context.Background(), before.Current, before.Fingerprint); err == nil {
		t.Fatal("unbound arrival accepted")
	}
}

func TestCatalogImageHandoffPreservesCurrentAndChecksReadback(t *testing.T) {
	f := compatFixture()
	client := compatFixtureClient(t, f)
	before, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("a", 64)
	if err := client.AssertCatalogImageHandoffUnused(context.Background(), before, id); err != nil {
		t.Fatal("unreferenced stage vetoed")
	}
	mounts := append([]CatalogImageMount(nil), before.Mounts...)
	for i := range mounts {
		if mounts[i].Destination != "/logs" {
			mounts[i].Source += "/.catalog-compat/" + id + mounts[i].Destination
		}
	}
	list, err := client.AttachCatalogImageHandoff(context.Background(), before, id, mounts)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.mountlistPatches) != 1 || !reflect.DeepEqual(f.mountlistPatches[0], map[string]any{"mountlists": list}) {
		t.Fatal("handoff did not send exactly the scalar mount-list property")
	}
	after, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil || after.Fingerprint != before.Fingerprint || !reflect.DeepEqual(after.Current, before.Current) || !after.Previous.Stopped {
		t.Fatal("live container changed")
	}
	contract := CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: before.Current.Root, CatalogSchema: 1, PreviousRoot: before.Previous.Root, Mountlist: list, Handoff: id}
	for i, mount := range mounts {
		contract.MountSources[i] = mount.Source
	}
	if err := client.PublishCatalogImageContract(context.Background(), contract); err != nil {
		t.Fatal(err)
	}
	if _, err := client.AttachCatalogImageHandoff(context.Background(), before, id, mounts); err != nil {
		t.Fatal("idempotent readback rejected")
	}
	if err := client.AssertCatalogImageHandoffUnused(context.Background(), before, id); err == nil {
		t.Fatal("attached or marked stage can be deleted")
	}
	f.containers[1]["stopped"] = false
	if _, err := client.AttachCatalogImageHandoff(context.Background(), before, id, mounts); err == nil {
		t.Fatal("running predecessor modified")
	}
}

func TestCatalogImageHandoffRequiresEffectiveScalarMountlistReadback(t *testing.T) {
	f := compatFixture()
	f.ignoreArrayMountlists = true
	client := compatFixtureClient(t, f)
	before, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("c", 64)
	list := "sb-catalog-compat-" + id[:16]
	mounts := append([]CatalogImageMount(nil), before.Mounts...)
	for i := range mounts {
		if mounts[i].Destination != "/logs" {
			mounts[i].Source += "/.catalog-compat/" + id + mounts[i].Destination
		}
		f.mounts = append(f.mounts, map[string]any{"list": list, "src": "/" + mounts[i].Source, "dst": mounts[i].Destination, "comment": catalogImageContractComment + " " + id, "disabled": false})
	}
	// A successful legacy-shaped response is not proof of an effective change.
	if _, err := client.request(context.Background(), http.MethodPatch, "/rest/container/*2", map[string]any{"mountlists": []string{list}}); err != nil {
		t.Fatal(err)
	}
	ignored, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil || len(ignored.Previous.Mountlists) != 0 {
		t.Fatal("synthetic array write did not remain ineffective")
	}
	f.ignoreMountlistPatch = true
	if _, err := client.AttachCatalogImageHandoff(context.Background(), before, id, mounts); err == nil {
		t.Fatal("HTTP 200 without persisted predecessor mount list was accepted")
	}
	if len(f.mounts) != 8 || len(f.mountlistPatches) != 2 || f.marker != nil {
		t.Fatal("failed readback changed the existing four handoff rows or published a contract")
	}
	f.ignoreMountlistPatch = false
	if got, err := client.AttachCatalogImageHandoff(context.Background(), before, id, mounts); err != nil || got != list {
		t.Fatal("scalar retry could not attach existing checked rows:", err)
	}
	after, err := client.InspectCatalogImageCompatibility(context.Background())
	if err != nil || !reflect.DeepEqual(after.Previous.Mountlists, []string{list}) || after.Fingerprint != before.Fingerprint || !reflect.DeepEqual(after.Current, before.Current) || !after.Previous.Stopped || len(f.mounts) != 8 {
		t.Fatal("scalar persisted handoff failed identity or readback checks")
	}
	if len(f.mountlistPatches) != 3 || !reflect.DeepEqual(f.mountlistPatches[1], map[string]any{"mountlists": list}) || !reflect.DeepEqual(f.mountlistPatches[2], map[string]any{"mountlists": list}) {
		t.Fatal("product retry sent a non-scalar or unrelated setting")
	}
}

func TestCatalogImageInventoryRejectsAmbiguityAndTransactions(t *testing.T) {
	for _, scenario := range []string{"duplicate-current", "running-previous", "job", "foreign-mount"} {
		t.Run(scenario, func(t *testing.T) {
			f := compatFixture()
			switch scenario {
			case "duplicate-current":
				f.containers = append(f.containers, f.containers[0])
			case "running-previous":
				f.containers[1]["stopped"] = false
			case "job":
				f.jobs = []map[string]any{{"script": "SB-GATEWAY-apply-test"}}
			case "foreign-mount":
				f.mounts = append(f.mounts, map[string]any{"list": "live", "src": "/other/dir", "dst": "/config"})
			}
			client := compatFixtureClient(t, f)
			if _, err := client.InspectCatalogImageCompatibility(context.Background()); err == nil {
				t.Fatal("ambiguous inventory accepted")
			}
		})
	}
}

func TestCatalogImageWorkerUsesTargetSpecificMountsAndCapability(t *testing.T) {
	spec := ImageUpdateSpec{Version: "2.0.0", StorageRoot: "disk/sb-gateway", CandidateRoot: "disk/sb-gateway/root-2.0.0", CandidateSource: "local-file", CandidateReference: "disk/sb-gateway/data/lifecycle-uploads/image.tar", ContainerAddress: "192.0.2.2", CatalogSchema: 1}
	worker := renderImageUpdateWorker(spec)
	if !validFixedManagedScript(imageUpdateWorker, worker) {
		t.Fatal("worker contract invalid")
	}
	for _, part := range []string{`savedMountlists [$catalogTargetMountlists $oldRoot`, `failedMountlists [$catalogTargetMountlists`, `:local preserveCompat false`, `target image catalog capability is unconfirmed`, `rollback image has no matching data handoff`} {
		if !strings.Contains(worker, part) {
			t.Fatalf("missing worker safety branch %q", part)
		}
	}
	guard := strings.Index(worker, `target image catalog capability is unconfirmed`)
	add := strings.Index(worker, `/container/add `)
	if guard < 0 || add < 0 || guard > add {
		t.Fatal("unsupported target guard is too late")
	}
	if _, err := validateImageUpdateSpec(ImageUpdateSpec{CatalogSchema: 2}); err == nil {
		t.Fatal("unknown target schema accepted")
	}
}

func TestCatalogImageUnusedStageChecksCanonicalGlobalMountSources(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, scenario := range []struct {
		name    string
		source  any
		blocked bool
	}{
		{"dot-parent", "disk/sb-gateway/config/.catalog-compat/other/../" + id + "/config", true},
		{"dot-self", "disk/sb-gateway/config/.catalog-compat/./" + id + "/config", true},
		{"relative-parent", "./disk/sb-gateway/config/.catalog-compat/other/../" + id + "/config", true},
		{"bare-relative", ".catalog-compat/" + id + "/config", true},
		{"exact-stage", "disk/sb-gateway/config/.catalog-compat/" + id, true},
		{"raw-reference-retains-veto", "disk/sb-gateway/config/.catalog-compat/" + id + "/../other", true},
		{"empty", "", true},
		{"whitespace", "  ", true},
		{"null", nil, true},
		{"number", 7, true},
		{"object", map[string]any{"path": "unknown"}, true},
		{"backslash-unresolved", "disk\\.catalog-compat\\" + id + "\\config", true},
		{"control-byte", "disk/\x00unknown", true},
		{"unrelated-dot-path", "./disk/sb-gateway/config/../state/cache", false},
		{"stage-id-prefix-lookalike", "disk/sb-gateway/config/.catalog-compat/" + id + "0/config", false},
		{"unrelated-stage", "disk/sb-gateway/config/.catalog-compat/other/config", false},
		{"root", "/", false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			fixture := compatFixture()
			// A custom list is not part of the managed live mount inventory.
			// The global deletion veto must still inspect its source.
			fixture.mounts = append(fixture.mounts, map[string]any{"list": "unmanaged-custom", "src": scenario.source, "dst": "/other"})
			client := compatFixtureClient(t, fixture)
			inventory, err := client.InspectCatalogImageCompatibility(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			err = client.AssertCatalogImageHandoffUnused(context.Background(), inventory, id)
			if scenario.blocked {
				if !errors.Is(err, ErrCatalogImageCompatibility) {
					t.Fatal("ambiguous or referenced global mount proved stage unused")
				}
			} else if err != nil {
				t.Fatal("harmless unrelated path blocked retirement")
			}
		})
	}
}
