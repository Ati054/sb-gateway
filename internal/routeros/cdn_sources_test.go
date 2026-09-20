package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
)

func TestCDNSyncAddsBeforeRemovingAndVerifiesExecution(t *testing.T) {
	for _, provider := range []string{"cloudflare", "gcore", "edgecenter", "yandex", "beeline", "timeweb"} {
		for _, mode := range []string{"ok", "silent-script-failure", "unowned", "failed-second-batch"} {
			t.Run(provider+"/"+mode, func(t *testing.T) {
				values := []string{}
				for i := 0; i < 405; i++ {
					values = append(values, fmt.Sprintf("8.8.%d.%d/32", i/256, i%256))
				}
				name := cdnfeed.ListName(provider)
				if provider == "cloudflare" {
					name = "SB_CDN_CLOUDFLARE_V4"
				}
				prefix := "SB-GATEWAY CDN " + provider + " "
				rows := []map[string]any{{"list": name, "address": "9.9.9.0/24", "comment": prefix + "old"}, {"list": "user-list", "address": "1.1.1.1", "comment": "personal"}}
				if mode == "unowned" {
					rows[0]["comment"] = "personal"
				}
				var script string
				runs, prunes := 0, 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					switch {
					case r.Method == "GET" && r.URL.Path == "/rest/ip/firewall/address-list":
						_ = json.NewEncoder(w).Encode(rows)
					case r.Method == "GET" && r.URL.Path == "/rest/system/script":
						fmt.Fprint(w, `[]`)
					case r.Method == "PUT" && r.URL.Path == "/rest/system/script":
						var payload map[string]any
						_ = json.NewDecoder(r.Body).Decode(&payload)
						script = text(payload["source"])
						if len(script) > maxDirectScriptBytes || strings.Contains(script, "/connection/") {
							t.Error("unsafe script")
						}
						fmt.Fprint(w, `{".id":"*1"}`)
					case r.Method == "POST" && r.URL.Path == "/rest/system/script/run":
						runs++
						if mode == "silent-script-failure" {
							fmt.Fprint(w, `{}`)
							return
						}
						if mode == "failed-second-batch" && runs == 2 {
							http.Error(w, "failed", 500)
							return
						}
						if strings.Contains(script, `:foreach address`) || strings.Contains(script, `address=$address`) {
							t.Error("RouterOS field name reused as loop variable")
						}
						match := regexp.MustCompile(`:foreach cidr in=\{([^}]+)\}`).FindStringSubmatch(script)
						comments := regexp.MustCompile(regexp.QuoteMeta(prefix)+`[0-9a-f]{12}`).FindAllString(script, -1)
						if len(comments) == 0 {
							t.Error("missing generation")
							return
						}
						generation := comments[0]
						if len(match) > 0 {
							for _, raw := range strings.Split(match[1], ";") {
								address := strings.Trim(raw, `"`)
								found := false
								for _, row := range rows {
									if text(row["list"]) == name && text(row["address"]) == address {
										row["comment"] = generation
										found = true
									}
								}
								if !found {
									rows = append(rows, map[string]any{"list": name, "address": address, "comment": generation})
								}
							}
						} else {
							prunes++
							kept := []map[string]any{}
							for _, row := range rows {
								if text(row["list"]) != name || text(row["comment"]) == generation {
									kept = append(kept, row)
								}
							}
							rows = kept
						}
						fmt.Fprint(w, `{}`)
					case r.Method == "DELETE" && r.URL.Path == "/rest/system/script/*1":
						fmt.Fprint(w, `{}`)
					default:
						t.Errorf("unexpected %s %s", r.Method, r.URL)
						http.Error(w, "bad", 400)
					}
				}))
				defer server.Close()
				pool := x509.NewCertPool()
				pool.AddCert(server.Certificate())
				client, err := NewClient(Options{BaseURL: server.URL, Username: "test", Password: "test", RootCAs: pool})
				if err != nil {
					t.Fatal(err)
				}
				defer client.CloseIdleConnections()
				err = client.SyncCDNSources(context.Background(), provider, values)
				if mode == "ok" {
					if err != nil || runs != 4 || prunes != 1 || len(rows) != 406 {
						t.Fatalf("%v runs=%d prunes=%d rows=%d", err, runs, prunes, len(rows))
					}
					if err := client.SyncCDNSources(context.Background(), provider, values); err != nil || runs != 4 {
						t.Fatalf("unchanged sync was not a no-op: %v", err)
					}
				} else {
					if err == nil || prunes != 0 {
						t.Fatalf("unsafe success/prune: %v %d", err, prunes)
					}
					if text(rows[0]["address"]) != "9.9.9.0/24" {
						t.Fatal("LKG removed")
					}
				}
			})
		}
	}
}
