package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

const catalogIntegrationUUID = "123e4567-e89b-42d3-a456-426614174000"

func catalogIntegrationFeed(count int, uuid string) []byte {
	var body strings.Builder
	for index := 0; index < count; index++ {
		fmt.Fprintf(&body, "vless://%s@edge-%05d.example.test:443?security=tls&sni=edge-%05d.example.test&type=ws&path=%%2Fpublic#DE%%20Node%%20%05d\n", uuid, index, index, index)
	}
	return []byte(body.String())
}

func catalogIntegrationServer(t *testing.T, id string) (*Server, *http.Cookie, string) {
	t.Helper()
	server := newTestServer(t)
	draft, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	installCatalogCompatibilityRESTFixture(t, server, draft)
	if _, err := server.repository.saveDraft(draft); err != nil {
		t.Fatal(err)
	}
	cookie, csrf := bootstrapSession(t, server)
	created := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions", map[string]any{"id": id, "display_name": "Synthetic provider", "enabled": true, "url": "https://catalog.example.test/subscription"}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("create subscription: status=%d", created.Code)
	}
	return server, cookie, csrf
}

func catalogIntegrationRefresh(t *testing.T, server *Server, cookie *http.Cookie, csrf, id string, body []byte, expiry int64) *httptest.ResponseRecorder {
	t.Helper()
	server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		return body, http.Header{"Subscription-Userinfo": []string{fmt.Sprintf("upload=1; download=2; total=100; expire=%d", expiry)}}, nil
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/subscriptions/"+id+"/refresh", nil, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("refresh subscription: status=%d response=%s", response.Code, response.Body.String())
	}
	return response
}

func catalogIntegrationEntry(t *testing.T, server *Server, id string) (map[string]any, subscriptioncatalog.Ref) {
	t.Helper()
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}
	entry, ok := state[id].(map[string]any)
	if !ok {
		t.Fatal("missing catalog state")
	}
	if _, inline := entry["nodes"]; inline {
		t.Fatal("catalog state retained inline node definitions")
	}
	ref, err := decodeSubscriptionCatalogRef(entry["catalog_ref"])
	if err != nil {
		t.Fatal(err)
	}
	return entry, ref
}

// Tests inspect one checked private record; production/public projections never
// decode the full record file merely to display the inventory.
func catalogIntegrationPrivateRecord(t *testing.T, server *Server, entry map[string]any) (map[string]any, map[string]string) {
	t.Helper()
	if _, inline := entry["nodes"]; inline {
		t.Fatal("new HTTP refresh persisted inline definitions")
	}
	ref, err := decodeSubscriptionCatalogRef(entry["catalog_ref"])
	if err != nil {
		t.Fatal(err)
	}
	reader, err := subscriptioncatalog.Open(server.secrets.subscriptionCatalogRoot(), ref)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	first := ""
	stop := errors.New("first metadata row selected")
	err = reader.WalkMetadata(context.Background(), func(row subscriptioncatalog.MetadataRecord) error { first = row.ID; return stop })
	if !errors.Is(err, stop) || first == "" {
		t.Fatal("private catalog has no first record")
	}
	record, err := reader.Get(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	var node map[string]any
	var secrets map[string]string
	if json.Unmarshal(record.Node, &node) != nil || json.Unmarshal(record.Secrets, &secrets) != nil {
		t.Fatal("invalid private test record")
	}
	stateBytes, err := os.ReadFile(filepath.Join(server.repository.root, "subscription-nodes.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(stateBytes) > 16<<10 {
		t.Fatal("source pointer state unexpectedly contains a complete graph")
	}
	for _, secret := range secrets {
		if secret != "" && strings.Contains(string(stateBytes), secret) {
			t.Fatal("source pointer state exposed a credential")
		}
	}
	return node, secrets
}

func catalogIntegrationAdapter(t *testing.T, server *Server) (map[string]any, []map[string]any, runtimeconfig.RuntimeNodeCatalog) {
	t.Helper()
	draft, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}
	rows := runtimeSubscriptionNodes(draft, state)
	legacy, catalog, err := splitSubscriptionCatalogNodes(server.secrets, rows)
	if err != nil {
		t.Fatal(err)
	}
	if catalog == nil {
		t.Fatal("missing real disk-backed runtime adapter")
	}
	return draft, legacy, catalog
}

func catalogIntegrationNative(t *testing.T, server *Server, subscriptions any, rows []map[string]any, selection string, configure ...func(map[string]any)) (runtimeconfig.RuntimeCandidate, *nativeRuntime) {
	t.Helper()
	root := filepath.Join(server.opts.DataDir, "native-catalog")
	opts := RuntimeOptions{CandidateDir: filepath.Join(root, "candidates"), RuleSetDir: filepath.Join(root, "rulesets"), NginxTemplate: "../../templates/nginx.conf.j2", XrayConfig: filepath.Join(root, "live", "xray.json"), XrayHealthPool: filepath.Join(root, "live", "urltest-pool.json"), PolicyDNSConfig: filepath.Join(root, "live", "policy-dns.json"), NginxConfig: filepath.Join(root, "live", "nginx.conf"), WatchdogEnvironment: filepath.Join(root, "live", "watchdog.env"), ClientTelemetryNFT: filepath.Join(root, "live", "client-telemetry.nft"), TransparentExclusions: filepath.Join(root, "live", "transparent-exclusions.txt")}
	config := map[string]any{"system": map[string]any{"networking": map[string]any{"routeros_gateway": "192.168.3.1", "container_address": "198.18.0.2/29", "tun_address": "198.18.0.1/30", "tun_mtu": 1400, "tun_stack": "system", "remote_ipv6_mode": "proxy_only"}, "management": map[string]any{}}, "dns": map[string]any{"internal_server": "192.168.3.1", "direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"}, "vpn_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"}}, "ingress": map[string]any{"tls_profile_id": "public"}, "tls_profiles": []any{map[string]any{"id": "public", "enabled": true, "certificate_secret_ref": "tls/cert", "private_key_secret_ref": "tls/key"}}, "watchdog": map[string]any{"interval_seconds": 5, "failure_threshold": 3, "recovery_threshold": 3, "max_restarts_per_hour": 6}, "subscriptions": subscriptions, "policies": []any{map[string]any{"id": "selected", "mode": "best", "selection_order": []string{selection}, "node_groups": []any{map[string]any{"id": "all", "subscription_ids": []string{"*"}}}}}}
	for _, edit := range configure {
		edit(config)
	}
	native, err := newNativeRuntimeStore(opts, server.secrets)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := native.prepare(config, rows)
	if err != nil {
		t.Fatal(err)
	}
	return candidate, native
}

func TestSubscriptionCatalogIntegrationHTTPFullInventoryWithoutImplicitQuota(t *testing.T) {
	for _, count := range []int{1005, 5001} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			server, cookie, csrf := catalogIntegrationServer(t, "provider")
			refresh := catalogIntegrationRefresh(t, server, cookie, csrf, "provider", catalogIntegrationFeed(count, catalogIntegrationUUID), 1893456000)
			if decodeResponse(t, refresh)["nodes"] != float64(count) {
				t.Fatal("import truncated the complete feed")
			}
			entry, ref := catalogIntegrationEntry(t, server, "provider")
			if ref.Count != uint64(count) {
				t.Fatal("catalog reference count differs from accepted response")
			}
			stateBytes, err := os.ReadFile(filepath.Join(server.repository.root, "subscription-nodes.json"))
			if err != nil {
				t.Fatal(err)
			}
			if len(stateBytes) > 16<<10 || strings.Contains(string(stateBytes), catalogIntegrationUUID) {
				t.Fatal("durable pointer state is not compact and credential-free")
			}
			public := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions/provider/nodes", nil, nil, cookie)
			if public.Code != http.StatusOK {
				t.Fatalf("inventory status=%d", public.Code)
			}
			var response struct {
				Nodes      []map[string]any `json:"nodes"`
				Count      uint64           `json:"node_count"`
				Generation string           `json:"generation"`
			}
			if err := json.Unmarshal(public.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			if len(response.Nodes) != count || response.Count != uint64(count) || response.Generation != ref.Generation {
				t.Fatal("public inventory omitted nodes or mixed generations")
			}
			for _, forbidden := range []string{catalogIntegrationUUID, "uuid_secret_ref", "@catalog:", "definition_fingerprint", "provider_node_id", `"server"`} {
				if strings.Contains(public.Body.String(), forbidden) {
					t.Fatalf("public projection exposed private field %q", forbidden)
				}
			}
			seen := make(map[string]bool, count)
			for _, node := range response.Nodes {
				id := subscriptionText(node["id"])
				if id == "" || seen[id] {
					t.Fatal("public inventory has missing/duplicate stable IDs")
				}
				seen[id] = true
			}
			reader, err := subscriptioncatalog.Open(server.secrets.subscriptionCatalogRoot(), ref)
			if err != nil {
				t.Fatal(err)
			}
			defer reader.Close()
			record, err := reader.Get(context.Background(), subscriptionText(response.Nodes[0]["id"]))
			if err != nil {
				t.Fatal(err)
			}
			var privateNode map[string]any
			var secrets map[string]string
			_ = json.Unmarshal(record.Node, &privateNode)
			_ = json.Unmarshal(record.Secrets, &secrets)
			if privateNode["uuid_secret_ref"] != "@catalog:uuid" || privateNode["_uuid"] != nil || secrets["@catalog:uuid"] != catalogIntegrationUUID {
				t.Fatal("private record did not isolate its credentials")
			}
			draft, legacy, catalog := catalogIntegrationAdapter(t, server)
			if len(legacy) != 0 || catalog.InventoryCount() != count {
				t.Fatal("adapter expanded or lost source nodes")
			}
			metadataCount := 0
			if err := catalog.WalkMetadata(context.Background(), func(node runtimeconfig.RuntimeCatalogNode) error {
				metadataCount++
				if !seen[node.ID] || node.Generation != ref.Generation || len(node.Fingerprint) != 64 {
					return fmt.Errorf("adapter identity mismatch")
				}
				bytes, _ := json.Marshal(node.Metadata)
				if strings.Contains(string(bytes), catalogIntegrationUUID) || strings.Contains(string(bytes), "uuid_secret_ref") {
					return fmt.Errorf("adapter read private credentials into metadata")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if metadataCount != count {
				t.Fatal("adapter metadata walk truncated source")
			}
			if count == 1005 {
				state, err := server.repository.auxiliary("subscription-nodes")
				if err != nil {
					t.Fatal(err)
				}
				rows := runtimeSubscriptionNodes(draft, state)
				candidate, _ := catalogIntegrationNative(t, server, draft["subscriptions"], rows, "group:all")
				poolBytes, err := os.ReadFile(candidate.Files["urltest-pool.json"])
				if err != nil {
					t.Fatal(err)
				}
				var pool struct {
					Version     int                                        `json:"version"`
					Outbounds   map[string]json.RawMessage                 `json:"outbounds"`
					Definitions map[string]runtimeconfig.CatalogDefinition `json:"catalog_definitions"`
					ProbeLanes  int                                        `json:"probe_lanes"`
				}
				if err := json.Unmarshal(poolBytes, &pool); err != nil {
					t.Fatal(err)
				}
				if pool.Version != 5 || len(pool.Outbounds) != 0 || len(pool.Definitions) != count || pool.ProbeLanes != 10 {
					t.Fatal("real native prepare did not retain lazy full inventory and bounded probe geometry")
				}
				if strings.Contains(string(poolBytes), catalogIntegrationUUID) {
					t.Fatal("native health pool eagerly contains credentials")
				}
			}
			if entry["provider"] == nil {
				t.Fatal("provider header metadata missing")
			}
		})
	}
}

func TestSubscriptionCatalogIntegrationIdenticalBodyUpdatesExpiryWithoutNewGeneration(t *testing.T) {
	server, cookie, csrf := catalogIntegrationServer(t, "provider")
	body := catalogIntegrationFeed(2, catalogIntegrationUUID)
	clock := server.now()
	server.now = func() time.Time { return clock }
	catalogIntegrationRefresh(t, server, cookie, csrf, "provider", body, 1893456000)
	before, oldRef := catalogIntegrationEntry(t, server, "provider")
	clock = clock.Add(time.Second)
	catalogIntegrationRefresh(t, server, cookie, csrf, "provider", body, 1893542400)
	after, newRef := catalogIntegrationEntry(t, server, "provider")
	if oldRef != newRef || before["fingerprint"] != after["fingerprint"] {
		t.Fatal("identical definitions changed immutable generation")
	}
	if before["refreshed_at"] == after["refreshed_at"] {
		t.Fatal("successful refresh did not update freshness")
	}
	if subscriptionText(after["provider"].(map[string]any)["expires_at"]) != time.Unix(1893542400, 0).UTC().Format(time.RFC3339) {
		t.Fatal("new provider expiry was discarded with identical links")
	}
	public := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions/provider/nodes", nil, nil, cookie)
	if public.Code != http.StatusOK || decodeResponse(t, public)["provider"].(map[string]any)["expires_at"] != after["provider"].(map[string]any)["expires_at"] {
		t.Fatal("public provider metadata is stale")
	}
}

func TestSubscriptionCatalogIntegrationRejectsSourceChangesDuringFetch(t *testing.T) {
	for _, kind := range []string{"url", "options", "deletion"} {
		t.Run(kind, func(t *testing.T) {
			server, cookie, csrf := catalogIntegrationServer(t, "provider")
			catalogIntegrationRefresh(t, server, cookie, csrf, "provider", catalogIntegrationFeed(1, catalogIntegrationUUID), 1893456000)
			before, err := server.repository.auxiliary("subscription-nodes")
			if err != nil {
				t.Fatal(err)
			}
			beforeMetadata, err := server.repository.metadata()
			if err != nil {
				t.Fatal(err)
			}
			started, release := make(chan struct{}), make(chan struct{})
			server.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
				close(started)
				<-release
				return catalogIntegrationFeed(2, catalogIntegrationUUID), http.Header{"Subscription-Userinfo": []string{"expire=1999999999"}}, nil
			}
			finished := make(chan *httptest.ResponseRecorder, 1)
			go func() {
				request := httptest.NewRequest(http.MethodPost, apiPrefix+"/subscriptions/provider/refresh", nil)
				request.RemoteAddr = "192.0.2.10:12345"
				request.Header.Set(csrfHeader, csrf)
				request.AddCookie(cookie)
				response := httptest.NewRecorder()
				server.ServeHTTP(response, request)
				finished <- response
			}()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("fetch did not start")
			}
			method, payload := http.MethodPut, map[string]any{"url": "https://catalog.example.test/replaced"}
			if kind == "options" {
				payload = map[string]any{"max_nodes": 2000}
			}
			if kind == "deletion" {
				method, payload = http.MethodDelete, nil
			}
			changed := performRequest(t, server, method, apiPrefix+"/subscriptions/provider", payload, map[string]string{csrfHeader: csrf}, cookie)
			close(release)
			if changed.Code != http.StatusOK {
				t.Fatalf("source mutation status=%d", changed.Code)
			}
			select {
			case response := <-finished:
				if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "subscription_source_changed") {
					t.Fatalf("stale response status=%d", response.Code)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("stale import did not complete")
			}
			after, err := server.repository.auxiliary("subscription-nodes")
			if err != nil {
				t.Fatal(err)
			}
			afterMetadata, err := server.repository.metadata()
			if err != nil {
				t.Fatal(err)
			}
			if !equalJSONObject(before, after) || !equalJSONObject(beforeMetadata, afterMetadata) {
				t.Fatal("rejected stale fetch changed prior entry/provider/active metadata")
			}
		})
	}
}

func TestSubscriptionCatalogIntegrationLegacyLocationAndAppliedLongID(t *testing.T) {
	for _, appliedOnly := range []bool{false, true} {
		t.Run(fmt.Sprint(appliedOnly), func(t *testing.T) {
			id := "provider"
			if appliedOnly {
				id = strings.Repeat("s", 60)
			}
			server, cookie, csrf := catalogIntegrationServer(t, id)
			body := catalogIntegrationFeed(1, catalogIntegrationUUID)
			parsed, err := parseProxySubscription(body, 10)
			if err != nil {
				t.Fatal(err)
			}
			node := cloneJSONObject(parsed[0])
			delete(node, "_uuid")
			delete(node, "selection_identity")
			node["id"] = "legacy-selected-provider"
			node["subscription_id"] = id
			secretRef := "subscriptions/" + id + "/generations/0123456789abcdef/legacy-selected-provider.uuid"
			node["uuid_secret_ref"] = secretRef
			if err := server.secrets.write(secretRef, catalogIntegrationUUID, false); err != nil {
				t.Fatal(err)
			}
			wantID := scopedSubscriptionNodeID(id, "legacy-selected-provider")
			wantLocation := scopedSubscriptionLocation(id, subscriptionText(node["location_key"]), subscriptionNodeProtocol(node))
			draft, err := server.getDraft()
			if err != nil {
				t.Fatal(err)
			}
			sub := draft["subscriptions"].([]any)[0].(map[string]any)
			if appliedOnly {
				node["id"] = wantID
				if strings.HasPrefix(wantID, id+"-") {
					t.Fatal("fixture did not exercise hash-shortened source prefix")
				}
				revision, err := server.repository.stageGeneration(draft)
				if err != nil {
					t.Fatal(err)
				}
				if err := server.saveSubscriptionSnapshot(revision, []map[string]any{node}); err != nil {
					t.Fatal(err)
				}
				if err := server.repository.commitActive(commitMetadata{Revision: revision, RuntimeRevision: strings.Repeat("1", 64), NodeSnapshotRevision: revision, Actor: "test", CommittedAt: server.now()}); err != nil {
					t.Fatal(err)
				}
				bad := cloneJSONObject(node)
				bad["uuid_secret_ref"] = "subscriptions/other/generations/0123456789abcdef/legacy-selected-provider.uuid"
				if _, err := previousSubscriptionBaseID(id, bad); err == nil {
					t.Fatal("guessed an inverse hash from an unrelated secret reference")
				}
			} else {
				if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{id: map[string]any{"source_revision": mustSubscriptionSourceRevision(sub), "nodes": []any{node}}}); err != nil {
					t.Fatal(err)
				}
			}
			catalogIntegrationRefresh(t, server, cookie, csrf, id, body, 1893456000)
			if appliedOnly {
				proof, _ := server.repository.auxiliary(catalogCompatibilityAuxiliary)
				producer, _ := proof["producer"].(map[string]any)
				if proof["state"] != "prepared" || producer["root"] == "" {
					t.Fatal("applied catalog import omitted physical producer proof")
				}
			}
			public := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions/"+id+"/nodes", nil, nil, cookie)
			if public.Code != http.StatusOK {
				t.Fatalf("nodes status=%d", public.Code)
			}
			rows := decodeResponse(t, public)["nodes"].([]any)
			if len(rows) != 1 || rows[0].(map[string]any)["id"] != wantID || rows[0].(map[string]any)["location_key"] != wantLocation {
				t.Fatal("legacy runtime ID or effective explicit location changed")
			}
			draft, _, catalog := catalogIntegrationAdapter(t, server)
			seen := false
			if err := catalog.WalkMetadata(context.Background(), func(n runtimeconfig.RuntimeCatalogNode) error {
				seen = n.ID == wantID && n.Metadata["selection_key"] == wantLocation
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if !seen {
				t.Fatal("runtime adapter lost preserved location")
			}
			state, _ := server.repository.auxiliary("subscription-nodes")
			candidate, _ := catalogIntegrationNative(t, server, draft["subscriptions"], runtimeSubscriptionNodes(draft, state), "location:"+wantLocation)
			poolBytes, err := os.ReadFile(candidate.Files["urltest-pool.json"])
			if err != nil {
				t.Fatal(err)
			}
			var pool struct {
				Policies map[string][]string `json:"policies"`
			}
			if err := json.Unmarshal(poolBytes, &pool); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(pool.Policies["selected"], []string{wantID}) {
				t.Fatal("native compiler did not select preserved legacy member")
			}
		})
	}
}

func TestSubscriptionCatalogIntegrationInvalidMetadataNeverCompletesPublicInventory(t *testing.T) {
	for _, kind := range []string{"scope", "frame"} {
		t.Run(kind, func(t *testing.T) {
			server, cookie, _ := catalogIntegrationServer(t, "provider")
			draft, _ := server.getDraft()
			sub := draft["subscriptions"].([]any)[0].(map[string]any)
			nodes, err := parseProxySubscription(catalogIntegrationFeed(2, catalogIntegrationUUID), 10)
			if err != nil {
				t.Fatal(err)
			}
			builder, err := subscriptioncatalog.NewBuilder(server.secrets.subscriptionCatalogRoot(), subscriptioncatalog.Limits{})
			if err != nil {
				t.Fatal(err)
			}
			defer builder.Abort()
			for index, node := range nodes {
				record, err := subscriptionCatalogRecord(sub, node, nil)
				if err != nil {
					t.Fatal(err)
				}
				if kind == "scope" && index == 1 {
					var metadata map[string]any
					_ = json.Unmarshal(record.Metadata, &metadata)
					metadata["subscription_id"] = "another-provider"
					record.Metadata, _ = json.Marshal(metadata)
				}
				if err := builder.Append(context.Background(), record); err != nil {
					t.Fatal(err)
				}
			}
			ref, err := builder.Seal(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			refBytes, _ := json.Marshal(ref)
			refObject, err := decodeObject(refBytes)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.saveAuxiliary("subscription-nodes", map[string]any{"provider": map[string]any{"catalog_ref": refObject}}); err != nil {
				t.Fatal(err)
			}
			if kind == "frame" {
				path := filepath.Join(server.secrets.subscriptionCatalogRoot(), ref.Generation, "metadata.bin")
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if len(data) == 0 {
					t.Fatal("empty metadata fixture")
				}
				data[len(data)/2] ^= 1
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			response := performRequest(t, server, http.MethodGet, apiPrefix+"/subscriptions/provider/nodes", nil, nil, cookie)
			var completed map[string]any
			err = json.Unmarshal(response.Body.Bytes(), &completed)
			if response.Code == http.StatusOK && err == nil {
				t.Fatal("corrupt catalog produced a complete successful partial inventory")
			}
			if strings.Contains(response.Body.String(), catalogIntegrationUUID) {
				t.Fatal("error/partial metadata response exposed UUID")
			}
		})
	}
}

func TestSubscriptionCatalogIntegrationV5RefreshSelectorRendersAndRetiresWithReadback(t *testing.T) {
	server, cookie, csrf := catalogIntegrationServer(t, "provider")
	body := catalogIntegrationFeed(1, catalogIntegrationUUID)
	catalogIntegrationRefresh(t, server, cookie, csrf, "provider", body, 1893456000)
	poolPath := filepath.Join(server.opts.DataDir, "selector-pool.json")
	if err := os.MkdirAll(filepath.Dir(poolPath), 0o700); err != nil {
		t.Fatal(err)
	}
	options := RuntimeOptions{XrayHealthPool: poolPath, XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"}
	selected := subscriptionUpdateDynamicPrefix + strings.Repeat("1", 12)
	oldest := selected
	ado, bo := 0, 0
	removed := []string{}
	trace := []string{}
	wantTag := ""
	command := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		op := args[1]
		trace = append(trace, op)
		switch op {
		case "bi":
			return []byte("  - Selecting Override:\n    1   " + selected + "\n  - Selects:\n"), nil
		case "ado":
			ado++
			data, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				return nil, err
			}
			if !strings.Contains(string(data), wantTag) {
				return nil, fmt.Errorf("wrong catalog handler tag")
			}
			return nil, nil
		case "bo":
			bo++
			selected = args[len(args)-1]
			return nil, nil
		case "rmo":
			tag := args[len(args)-1]
			if tag == selected {
				return nil, fmt.Errorf("selected handler retired")
			}
			removed = append(removed, tag)
			return nil, nil
		}
		return nil, fmt.Errorf("unexpected command %s", op)
	}
	writePool := func() string {
		t.Helper()
		_, ref := catalogIntegrationEntry(t, server, "provider")
		_, _, catalog := catalogIntegrationAdapter(t, server)
		var id string
		var definition runtimeconfig.CatalogDefinition
		if err := catalog.WalkMetadata(context.Background(), func(n runtimeconfig.RuntimeCatalogNode) error {
			id = n.ID
			definition = runtimeconfig.CatalogDefinition{Generation: n.Generation, Fingerprint: n.Fingerprint, FingerprintKind: runtimeconfig.CatalogFingerprintKind}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		pool := map[string]any{"version": 5, "catalogs": map[string]subscriptioncatalog.Ref{ref.Generation: ref}, "catalog_definitions": map[string]runtimeconfig.CatalogDefinition{id: definition}}
		data, _ := json.Marshal(pool)
		if err := os.WriteFile(poolPath, data, 0o600); err != nil {
			t.Fatal(err)
		}
		wantTag = runtimeconfig.CatalogDynamicOutboundTag(subscriptionUpdateDynamicPrefix, id, definition)
		return id
	}
	id := writePool()
	if err := selectSubscriptionXrayOutbound(context.Background(), options, id, command, server.repository, server.secrets.subscriptionCatalogRoot()); err != nil {
		t.Fatal(err)
	}
	first := selected
	if ado != 1 || bo != 1 || selected != wantTag || len(removed) != 0 {
		t.Fatal("first catalog selection/readback or last-generation retention failed")
	}
	if err := selectSubscriptionXrayOutbound(context.Background(), options, id, command, server.repository, server.secrets.subscriptionCatalogRoot()); err != nil {
		t.Fatal(err)
	}
	if ado != 1 || bo != 1 {
		t.Fatal("same selected catalog handler was added or switched again")
	}
	rotated := strings.ReplaceAll(string(body), catalogIntegrationUUID, "223e4567-e89b-42d3-a456-426614174000")
	catalogIntegrationRefresh(t, server, cookie, csrf, "provider", []byte(rotated), 1893456000)
	if nextID := writePool(); nextID != id {
		t.Fatal("credential rotation changed stable ID")
	}
	if wantTag == first {
		t.Fatal("credential rotation did not change semantic handler identity")
	}
	if err := selectSubscriptionXrayOutbound(context.Background(), options, id, command, server.repository, server.secrets.subscriptionCatalogRoot()); err != nil {
		t.Fatal(err)
	}
	if selected != wantTag || ado != 2 || bo != 2 || !reflect.DeepEqual(removed, []string{oldest}) {
		t.Fatal("catalog handler retirement failed to retain one previous generation")
	}
	if len(trace) < 3 || trace[len(trace)-1] != "rmo" || trace[len(trace)-2] != "bi" {
		t.Fatal("retirement happened before final selector readback")
	}
}
