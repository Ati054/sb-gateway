package controlplane

import (
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func TestConnectionAddressSelectsOnlyActiveMainWAN(t *testing.T) {
	addresses := []map[string]any{
		{"address": "192.168.40.199/24", "interface": "management"},
		{"address": "172.30.77.15/24", "interface": "host-ingress"},
		{"address": "192.168.0.15/24", "interface": "physical-wan"},
	}
	members := []map[string]any{{"list": "WAN", "interface": "host-ingress"}, {"list": "WAN", "interface": "physical-wan"}}
	routes := []map[string]any{
		{"dst-address": "0.0.0.0/0", "active": "true", "routing-table": "vpn", "immediate-gw": "172.30.77.2%host-ingress"},
		{"dst-address": "0.0.0.0/0", "active": "false", "routing-table": "main", "immediate-gw": "172.30.77.2%host-ingress"},
		{"dst-address": "0.0.0.0/0", "active": "true", "routing-table": "main", "immediate-gw": "192.168.0.1%physical-wan"},
		{"dst-address": "0.0.0.0/0", "active": "true", "routing-table": "main", "immediate-gw": "192.168.40.1%management"},
	}
	if got := selectConnectionAddress(addresses, routes, members); got["address"] != "192.168.0.15" || got["interface"] != "physical-wan" {
		t.Fatalf("selection: %v", got)
	}
	addresses[2]["address"] = "192.168.0.16/24"
	if got := selectConnectionAddress(addresses, routes, members); got["address"] != "192.168.0.16" {
		t.Fatalf("DHCP change: %v", got)
	}
	addresses = append(addresses, map[string]any{"address": "198.51.100.2/24", "interface": "physical-wan"})
	if got := selectConnectionAddress(addresses, routes, members); got["state"] != "ambiguous" || got["address"] != "" {
		t.Fatalf("ambiguous: %v", got)
	}
	if got := selectConnectionAddress(addresses, nil, members); got["state"] != "unavailable" {
		t.Fatalf("missing route: %v", got)
	}
}

func TestConnectionAddressIncludesCurrentNonWANAddresses(t *testing.T) {
	addresses := []map[string]any{
		{"address": "192.168.98.1/24", "interface": "bridge-lan"},
		{"address": "192.168.0.15/24", "interface": "wan"},
		{"address": "192.168.50.1/24", "interface": "bridge-lan", "disabled": "true"},
		{"address": "192.168.97.1/24", "interface": "bridge-lan", "invalid": "true"},
		{"address": "127.0.0.1/8", "interface": "lo"},
	}
	members := []map[string]any{{"interface": "wan", "list": "WAN"}}
	for _, address := range []string{"192.168.98.1", "192.168.88.254"} {
		addresses[0]["address"] = address + "/24"
		result := selectConnectionAddress(addresses, nil, members)
		local := collectionArray(result["local_addresses"])
		if len(local) != 1 || text(local[0].(map[string]any)["address"]) != address {
			t.Fatalf("stale or invalid local inventory: %v", local)
		}
	}
}

func TestPanelPortConfigurationValidation(t *testing.T) {
	for _, port := range []any{17443, 1024, 65535, 0, 443, 9443, 65536, 1.5, "17443"} {
		result := configValidation{}
		result.validateSystemSettings(map[string]any{"system": map[string]any{
			"networking": map[string]any{},
			"management": map[string]any{"routeros_panel_port": port, "allowed_source_cidrs": []any{}, "allowed_ingress_interfaces": []any{}},
		}})
		valid := port == 17443 || port == 1024 || port == 65535
		if (len(result.Errors) == 0) != valid {
			t.Fatalf("port %v: %v", port, result.Errors)
		}
	}
}

func TestConnectionAddressModeValidationAcrossTransports(t *testing.T) {
	for _, kind := range []string{"reality", "reality-grpc", "xhttp-reality", "hysteria2", "ws"} {
		for _, mode := range []string{"auto", "manual", "invalid"} {
			result := configValidation{}
			result.validateTransportSettings(map[string]any{}, map[string][]map[string]any{"transports": {
				{"kind": kind, "hostname_mode": mode, "enabled": false},
			}})
			wantError := mode == "invalid" || kind == "ws" && mode == "auto"
			modeError := false
			for _, issue := range result.Errors {
				if strings.HasSuffix(issue.Path, ".hostname_mode") {
					modeError = true
				}
			}
			if modeError != wantError {
				t.Fatalf("%s/%s: %v", kind, mode, result.Errors)
			}
		}
	}
}

func TestConnectionAddressManualWANBindingOnSave(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	key, _ := revisionFor(objectAt(config, "routeros"))
	snapshot := selectConnectionAddress([]map[string]any{
		{"address": "198.51.100.9/24", "interface": "wan1"},
		{"address": "198.51.100.10/24", "interface": "wan1"},
		{"address": "203.0.113.2/24", "interface": "wan2"},
		{"address": "192.168.40.1/24", "interface": "management"},
		{"address": "203.0.113.3/24", "interface": "wan2", "disabled": true},
	}, []map[string]any{{"dst-address": "0.0.0.0/0", "active": true, "immediate-gw": "198.51.100.1%wan1", "routing-table": "main"}},
		[]map[string]any{{"list": "WAN", "interface": "wan1"}, {"list": "WAN", "interface": "wan2"}})
	if snapshot["state"] != "ambiguous" || len(collectionArray(snapshot["wan_addresses"])) != 3 {
		t.Fatalf("inventory: %v", snapshot)
	}
	server.connectionAddressCache = connectionAddressCache{key: key, expires: server.now().Add(time.Hour), value: snapshot}
	renderBase := routerOSReadyConfig(t)
	for _, kind := range []string{"reality", "reality-grpc", "xhttp-reality", "hysteria2"} {
		item := map[string]any{"id": "binding-" + kind, "kind": kind, "enabled": false, "hostname_mode": "manual", "hostname": "198.51.100.9", "listen_port": 2443}
		if kind == "hysteria2" {
			item["xray_hysteria"] = map[string]any{"quic_params": map[string]any{}, "masquerade": map[string]any{}}
		}
		response := performRequest(t, server, http.MethodPost, apiPrefix+"/transports", map[string]any{"item": item}, map[string]string{csrfHeader: csrf}, cookie)
		if response.Code != http.StatusOK {
			t.Fatalf("create %s: %d %s", kind, response.Code, response.Body.String())
		}
		if objectAt(decodeResponse(t, response), "item")["wan_destination_address"] != "198.51.100.9" {
			t.Fatal("create did not bind own WAN")
		}
		for _, scenario := range []struct{ mode, host, binding string }{
			{"manual", "198.51.100.10", "198.51.100.10"},
			{"manual", "203.0.113.2", "203.0.113.2"}, // standby WAN, no active default
			{"manual", "203.0.113.100", ""},          // public IP owned by another router
			{"manual", "192.168.40.1", ""},           // local, but not WAN
			{"manual", "203.0.113.3", ""},            // disabled address
			{"manual", "vpn.example.com", ""},
			{"manual", "198.51.100.9", "198.51.100.9"},
			{"auto", "198.51.100.9", ""},
		} {
			item["hostname_mode"], item["hostname"], item["wan_destination_address"] = scenario.mode, scenario.host, "192.0.2.222"
			response = performRequest(t, server, http.MethodPut, apiPrefix+"/transports/"+text(item["id"]), item, map[string]string{csrfHeader: csrf}, cookie)
			if response.Code != http.StatusOK {
				t.Fatalf("save %s %s: %d %s", kind, scenario.host, response.Code, response.Body.String())
			}
			saved := objectAt(decodeResponse(t, response), "item")
			if saved["hostname"] != scenario.host || saved["wan_destination_address"] != scenario.binding {
				t.Fatalf("binding %s %s: %v", kind, scenario.host, saved["wan_destination_address"])
			}
			renderConfig := cloneJSONObject(renderBase)
			saved["enabled"] = true
			renderConfig["transports"] = []any{saved}
			source, err := runtimeconfig.RenderRouterOSTrafficCandidate(renderConfig, nil)
			if err != nil {
				t.Fatal(err)
			}
			match := `dst-port=2443 dst-address-type=local`
			if scenario.binding != "" {
				match = `dst-port=2443 dst-address="` + scenario.binding + `"`
			}
			if !strings.Contains(source, match) {
				t.Fatalf("rendered NAT does not match saved binding %s", scenario.binding)
			}
		}
	}
	before, _ := server.getDraft()
	beforeRevision, _ := revisionFor(before)
	server.connectionAddressCache.value = map[string]any{"state": "unavailable"}
	response := performRequest(t, server, http.MethodPut, apiPrefix+"/transports/binding-reality", map[string]any{
		"kind": "reality", "enabled": false, "hostname_mode": "manual", "hostname": "198.51.100.9",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown inventory: %d", response.Code)
	}
	after, _ := server.getDraft()
	afterRevision, _ := revisionFor(after)
	if afterRevision != beforeRevision {
		t.Fatal("unavailable inventory changed draft")
	}
}

func TestConnectionAddressCachesRefreshesAndDrivesAllExports(t *testing.T) {
	server := newTestServer(t)
	var calls atomic.Int32
	address := "192.168.0.15/24"
	failed := false
	remote := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if failed {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		rows := []map[string]any{}
		switch r.URL.Path {
		case "/rest/ip/address":
			rows = []map[string]any{{"address": address, "interface": "ether4"}}
		case "/rest/ip/route":
			rows = []map[string]any{{"dst-address": "0.0.0.0/0", "active": "true", "immediate-gw": "192.168.0.1%ether4", "routing-table": "main"}}
		case "/rest/interface/list/member":
			rows = []map[string]any{{"list": "WAN", "interface": "ether4"}}
		default:
			t.Errorf("unexpected endpoint: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(rows)
	}))
	defer remote.Close()
	for reference, value := range map[string]string{
		"routeros/username": "admin", "routeros/password": "secret", "routeros/backup": "backup",
		"routeros/ca": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: remote.Certificate().Raw})),
		"test/uuid":   "2f1c08fc-3f43-4e95-8f57-f8bded750a1a", "test/short": "0123456789abcdef",
		"test/path": "/xhttp", "test/service": "grpc", "test/hy2": "hysteria-password",
	} {
		if err := server.secrets.write(reference, value, false); err != nil {
			t.Fatal(err)
		}
	}
	config := map[string]any{"routeros": map[string]any{
		"base_url": remote.URL, "ssh_port": 22, "username_secret_ref": "routeros/username",
		"password_secret_ref": "routeros/password", "backup_password_secret_ref": "routeros/backup", "ca_certificate_secret_ref": "routeros/ca",
	}}
	var transports []any
	for _, kind := range []string{"reality", "reality-grpc", "xhttp-reality", "hysteria2"} {
		transports = append(transports, map[string]any{
			"id": kind, "kind": kind, "hostname_mode": "auto", "hostname": "192.168.3.187", "listen_port": 2443,
			"server_name": "example.com", "tls_server_name": "example.com", "public_key": "public-key",
			"path_secret_ref": "test/path", "service_name_secret_ref": "test/service",
			"secret_refs": map[string]any{"reality_short_id": "test/short"},
		})
	}
	config["transports"] = transports
	config["reverse_vless_exits"] = []any{map[string]any{"id": "home", "uuid_secret_ref": "test/uuid", "transport_ids": []any{"reality", "reality-grpc", "xhttp-reality"}}}
	user := map[string]any{"id": "phone", "uuid_secret_ref": "test/uuid", "hysteria2_password_secret_ref": "test/hy2"}
	before, _ := revisionFor(config)
	now := time.Now()
	server.now = func() time.Time { return now }
	var wait sync.WaitGroup
	for range 12 {
		wait.Add(1)
		go func() { defer wait.Done(); server.connectionAddress(config) }()
	}
	wait.Wait()
	if calls.Load() != 3 {
		t.Fatalf("duplicate refresh: %d requests", calls.Load())
	}
	for _, expected := range []string{"192.168.0.15", "192.168.0.16"} {
		if expected == "192.168.0.16" {
			address = expected + "/24"
			now = now.Add(31 * time.Second)
		}
		nodes, err := server.buildClientProfileNodes(config, user)
		if err != nil {
			t.Fatal(err)
		}
		if len(nodes) != 4 {
			t.Fatalf("nodes: %d", len(nodes))
		}
		for _, node := range nodes {
			if !strings.Contains(node.link, "@"+expected+":") || node.mihomo["server"] != expected || objectAt(node.xray, "settings")["address"] != expected {
				t.Fatalf("formats disagree for %s", node.name)
			}
		}
		export, err := server.buildReverseVLESSClientConfig(config, "home")
		if err != nil || strings.Count(string(export), `"address": "`+expected+`"`) != 3 {
			t.Fatalf("reverse export: %v %s", err, export)
		}
	}
	if calls.Load() != 6 {
		t.Fatalf("exports bypassed cache: %d", calls.Load())
	}
	if after, _ := revisionFor(config); after != before {
		t.Fatal("resolution mutated saved config")
	}
	manual := map[string]any{"kind": "reality", "hostname_mode": "manual", "hostname": "vpn.example.com"}
	if got, err := server.resolveConnectionTransport(config, manual); err != nil || got["hostname"] != "vpn.example.com" {
		t.Fatal("manual override changed")
	}
	failed = true
	now = now.Add(31 * time.Second)
	if got := server.connectionAddress(config); got["state"] != "unavailable" || got["address"] != "" {
		t.Fatalf("stale address on failure: %v", got)
	}
	if _, err := server.buildClientProfileNodes(config, user); err == nil {
		t.Fatal("export silently reused stale address")
	}
}
