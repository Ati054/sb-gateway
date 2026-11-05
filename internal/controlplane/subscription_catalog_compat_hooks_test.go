package controlplane

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type catalogCompatTestREST struct {
	mutations              atomic.Int64
	fail                   atomic.Bool
	url, root, certificate string
}

// A real authenticated TLS REST boundary with an owned current container and
// checked four-mount binding; this is not a production compatibility bypass.
func installCatalogCompatibilityRESTFixture(t *testing.T, server *Server, config map[string]any) *catalogCompatTestREST {
	t.Helper()
	storage, ok := config["storage"].(map[string]any)
	if !ok {
		storage = map[string]any{}
		config["storage"] = storage
	}
	root := strings.Trim(text(storage["root"]), "/")
	if root == "" {
		root = "disk/sb-gateway"
		storage["root"] = root
	}
	fixture := newCatalogCompatibilityRESTFixture(t, root)
	bindCatalogCompatibilityRESTFixture(t, server, config, fixture)
	return fixture
}

func newCatalogCompatibilityRESTFixture(t *testing.T, root string) *catalogCompatTestREST {
	t.Helper()
	fixture := &catalogCompatTestREST{root: root}
	var mu sync.Mutex
	var marker map[string]any
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if fixture.fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			json.NewEncoder(w).Encode(map[string]any{"error": "synthetic unavailable"})
			return
		}
		var result any
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container":
			result = []any{map[string]any{".id": "*1", "root-dir": "/" + root + "/root-current", "comment": "SB-GATEWAY container", "interface": "veth-sb", "envlist": []string{"env"}, "mountlists": []string{"live"}, "stopped": false}}
		case r.Method == http.MethodGet && r.URL.Path == "/rest/container/mounts":
			rows := []any{}
			for _, dst := range []string{"/config", "/data", "/logs", "/state"} {
				rows = append(rows, map[string]any{"list": "live", "src": "/" + root + dst, "dst": dst, "comment": "SB-GATEWAY storage"})
			}
			result = rows
		case r.Method == http.MethodGet && (r.URL.Path == "/rest/system/scheduler" || r.URL.Path == "/rest/system/script/job"):
			result = []any{}
		case r.Method == http.MethodGet && r.URL.Path == "/rest/system/script":
			result = []any{}
			if marker != nil && r.URL.Query().Get("name") == "SB-GATEWAY-catalog-data-contract" {
				result = []any{marker}
			}
		case (r.Method == http.MethodPut && r.URL.Path == "/rest/system/script") || (r.Method == http.MethodPatch && r.URL.Path == "/rest/system/script/*90"):
			fixture.mutations.Add(1)
			if err := json.NewDecoder(r.Body).Decode(&marker); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			marker[".id"] = "*90"
			result = marker
		default:
			w.WriteHeader(http.StatusNotFound)
			result = map[string]any{"error": "unexpected synthetic request"}
		}
		json.NewEncoder(w).Encode(result)
	}))
	t.Cleanup(remote.Close)
	fixture.url = remote.URL
	fixture.certificate = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw}))
	return fixture
}

func bindCatalogCompatibilityRESTFixture(t *testing.T, server *Server, config map[string]any, fixture *catalogCompatTestREST) {
	t.Helper()
	storage, ok := config["storage"].(map[string]any)
	if !ok {
		storage = map[string]any{}
		config["storage"] = storage
	}
	storage["root"] = fixture.root
	const prefix = "test/catalog-compat/"
	for ref, value := range map[string]string{prefix + "username": "synthetic", prefix + "password": "synthetic", prefix + "ca.pem": fixture.certificate} {
		if existing, err := server.secrets.read(ref, true); err == nil {
			if existing != strings.TrimRight(value, "\r\n") {
				t.Fatal("synthetic compatibility reference has unexpected value")
			}
			continue
		} else if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		if err := server.secrets.write(ref, value, false); err != nil {
			t.Fatal(err)
		}
	}
	router, ok := config["routeros"].(map[string]any)
	if !ok {
		router = map[string]any{}
		config["routeros"] = router
	}
	router["base_url"] = fixture.url
	router["username_secret_ref"] = prefix + "username"
	router["password_secret_ref"] = prefix + "password"
	router["ca_certificate_secret_ref"] = prefix + "ca.pem"
	server.opts.Runtime.XrayConfig = filepath.Join(server.opts.DataDir, "compat-live", "xray.json")
	server.opts.Runtime.XrayHealthPool = filepath.Join(server.opts.DataDir, "compat-live", "urltest-pool.json")
}

func TestCatalogCompatibilityRealApplyProofPrecedesPreparationAndJournal(t *testing.T) {
	config := routerOSReadyConfig(t)
	subscriptions := collectionArray(config["subscriptions"])
	id := "catalog-proof-provider"
	server, cookie, csrf := catalogIntegrationServer(t, id)
	catalogIntegrationRefresh(t, server, cookie, csrf, id, catalogIntegrationFeed(1, catalogIntegrationUUID), 1893456000)
	draft, _ := server.getDraft()
	config["subscriptions"] = append(subscriptions, collectionArray(draft["subscriptions"])[0])
	fixture := installCatalogCompatibilityRESTFixture(t, server, config)
	fixture.fail.Store(true)
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("2", 64)}
	server.runtime = runtime
	_, status, err := server.applyConfiguration(context.Background(), config, "synthetic")
	if err == nil || status != http.StatusConflict {
		t.Fatalf("physical proof was not required: status=%d error=%v", status, err)
	}
	if runtime.prepareCalls != 0 || runtime.activateCalls != 0 {
		t.Fatal("runtime touched before physical compatibility proof")
	}
	operation, _ := server.repository.auxiliary("apply-operation")
	if operation["pending"] == true {
		t.Fatal("transaction journal published before compatibility proof")
	}
}

func TestCatalogCompatibilityImportRejectsUnprovenActiveBeforePointerAndSnapshot(t *testing.T) {
	server, cookie, csrf := catalogIntegrationServer(t, "provider")
	config, _ := server.getDraft()
	fixture := installCatalogCompatibilityRESTFixture(t, server, config)
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "synthetic", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	before, _ := server.repository.auxiliary("subscription-nodes")
	beforeBody, _ := json.Marshal(before)
	fixture.fail.Store(true)
	server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		return catalogIntegrationFeed(1, catalogIntegrationUUID), http.Header{}, nil
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code == http.StatusOK {
		t.Fatal("unproven active image accepted a catalog pointer")
	}
	after, _ := server.repository.auxiliary("subscription-nodes")
	afterBody, _ := json.Marshal(after)
	if string(beforeBody) != string(afterBody) {
		t.Fatal("catalog pointer changed before compatibility proof")
	}
	snapshot, _ := server.repository.auxiliary("subscription-nodes-" + revision)
	if len(snapshot) != 0 {
		t.Fatal("applied snapshot changed before compatibility proof")
	}
}

func TestCatalogCompatibilityPlanDoesNotPreparePhysicalProducer(t *testing.T) {
	server, cookie, csrf := catalogIntegrationServer(t, "provider")
	catalogIntegrationRefresh(t, server, cookie, csrf, "provider", catalogIntegrationFeed(1, catalogIntegrationUUID), 1893456000)
	draft, _ := server.getDraft()
	fixture := installCatalogCompatibilityRESTFixture(t, server, draft)
	before, _ := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	beforeBody, _ := json.Marshal(before)
	if _, err := server.buildPlan(draft); err != nil {
		t.Fatal(err)
	}
	after, _ := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	afterBody, _ := json.Marshal(after)
	if fixture.mutations.Load() != 0 || string(beforeBody) != string(afterBody) {
		t.Fatal("read-only plan prepared compatibility")
	}
}

func TestCatalogCompatibilityStartupV5MissingProofIsFatalAndReadOnly(t *testing.T) {
	server := newTestServer(t)
	config := routerOSReadyConfig(t)
	config["policies"] = []any{}
	config["devices"] = []any{}
	fixture := installCatalogCompatibilityRESTFixture(t, server, config)
	if err := os.MkdirAll(filepath.Dir(server.opts.Runtime.XrayHealthPool), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server.opts.Runtime.XrayHealthPool, []byte(`{"version":5}`), 0600); err != nil {
		t.Fatal(err)
	}
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "synthetic", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	_, err = MigrateLegacyDynamicRuntime(context.Background(), server.opts)
	if !errors.Is(err, ErrProbeContractMigration) {
		t.Fatalf("unproven v5 startup is not fatal: %v", err)
	}
	if fixture.mutations.Load() != 0 {
		t.Fatal("startup proof mutated RouterOS")
	}
	proof, _ := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	if len(proof) != 0 {
		t.Fatal("startup invented a compatibility receipt")
	}
}

func TestCatalogCompatibilityStartupValidatorNeverInitializesMissingRepository(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(root, "state")
	secrets := filepath.Join(root, "secrets")
	for _, path := range []string{state, secrets} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateSubscriptionCatalogRuntimeCompatibility(context.Background(), Options{StateDir: state, SecretsDir: secrets}, map[string]any{}); err == nil {
		t.Fatal("missing repository accepted")
	}
	if _, err := os.Stat(filepath.Join(state, "generations")); !os.IsNotExist(err) {
		t.Fatal("read-only validator initialized repository")
	}
}
