package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSubscriptionEndpointsPrepareVerifyPrune(t *testing.T) {
	for _, mode := range []string{"ok", "silent-add", "foreign"} {
		t.Run(mode, func(t *testing.T) {
			rows := []map[string]any{{".id": "*1", "list": "SB_BYPASS_ENDPOINTS", "address": "8.8.8.8", "comment": "SB-GATEWAY loop bypass"}, {".id": "*9", "list": "personal", "address": "1.1.1.1", "comment": "user"}}
			if mode == "foreign" {
				rows[0]["comment"] = "user"
			}
			adds, deletes := 0, 0
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.Method {
				case "GET":
					_ = json.NewEncoder(w).Encode(rows)
				case "PUT":
					adds++
					var row map[string]any
					_ = json.NewDecoder(r.Body).Decode(&row)
					row[".id"] = "*2"
					if mode != "silent-add" {
						rows = append(rows, row)
					}
					_ = json.NewEncoder(w).Encode(row)
				case "DELETE":
					deletes++
					if r.URL.Path != "/rest/ip/firewall/address-list/*1" {
						t.Errorf("foreign delete %s", r.URL.Path)
					}
					if adds != 1 || len(rows) != 3 {
						t.Error("pruning before verified preparation")
					}
					rows = rows[1:]
					fmt.Fprint(w, `{}`)
				default:
					t.Error("unexpected method")
				}
			}))
			defer srv.Close()
			pool := x509.NewCertPool()
			pool.AddCert(srv.Certificate())
			client, err := NewClient(Options{BaseURL: srv.URL, Username: "test", Password: "test", RootCAs: pool})
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			err = client.SyncSubscriptionEndpoints(context.Background(), []string{"9.9.9.9/32"}, false)
			if mode != "ok" {
				if err == nil || deletes != 0 {
					t.Fatal("unsafe successful preparation")
				}
				if mode == "foreign" && adds != 0 {
					t.Fatal("foreign list modified")
				}
				return
			}
			if err != nil || len(rows) != 3 || deletes != 0 {
				t.Fatalf("add-only stage: %v", err)
			}
			if err = client.SyncSubscriptionEndpoints(context.Background(), []string{"9.9.9.9/32"}, true); err != nil {
				t.Fatal(err)
			}
			if len(rows) != 2 || deletes != 1 {
				t.Fatal("stale endpoint retained")
			}
			if err = client.SyncSubscriptionEndpoints(context.Background(), []string{"9.9.9.9/32"}, true); err != nil || adds != 1 || deletes != 1 {
				t.Fatal("no-op issued writes")
			}
		})
	}
}
