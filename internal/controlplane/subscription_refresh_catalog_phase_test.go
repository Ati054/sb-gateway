package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func subscriptionCatalogChannelFixture(t *testing.T, quota int, proofHook func(*http.Request)) (*Server, *http.Cookie, string, *catalogCompatTestREST) {
	t.Helper()
	s, cookie, csrf := subscriptionAdmissionFixture(t)
	config, err := s.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	sub := config["subscriptions"].([]any)[0].(map[string]any)
	sub["max_nodes"] = quota
	sub["download_timeout_seconds"] = 2
	sub["refresh_via_direct"] = true
	sub["refresh_via_vpn"] = true
	sub["refresh_via_active_outbounds"] = true
	config["reverse_vless_exits"] = []any{map[string]any{"id": "home", "enabled": true}}
	proof := installCatalogCompatibilityRESTFixture(t, s, config)
	if proofHook != nil {
		target, err := url.Parse(proof.url)
		if err != nil {
			t.Fatal(err)
		}
		roots := x509.NewCertPool()
		roots.AppendCertsFromPEM([]byte(proof.certificate))
		transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}}
		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.Transport = transport
		var once sync.Once
		delayed := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/rest/container" {
				once.Do(func() { proofHook(r) })
			}
			proxy.ServeHTTP(w, r)
		}))
		t.Cleanup(delayed.Close)
		t.Cleanup(transport.CloseIdleConnections)
		certificate := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: delayed.Certificate().Raw}))
		if err := s.secrets.write("test/catalog-phase/proxy-ca.pem", certificate, false); err != nil {
			t.Fatal(err)
		}
		objectAt(config, "routeros")["base_url"] = delayed.URL
		objectAt(config, "routeros")["ca_certificate_secret_ref"] = "test/catalog-phase/proxy-ca.pem"
	}
	if _, err := s.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	revision, err := s.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.repository.setActiveRevision(revision); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.saveAuxiliary("selector-health", map[string]any{"europe": map[string]any{"selected": "reverse-vless-home", "availability_ok": map[string]any{"reverse-vless-home": true}}}); err != nil {
		t.Fatal(err)
	}
	s.selectUpdateExit = func(context.Context, map[string]any, string) error { return nil }
	return s, cookie, csrf, proof
}

func TestSubscriptionCatalogRefreshInvalid200FallsBackWithinOneNetworkBudget(t *testing.T) {
	s, cookie, csrf, _ := subscriptionCatalogChannelFixture(t, 10, nil)
	direct, proxy := 0, 0
	var networkDeadline time.Time
	s.fetchSubscription = func(ctx context.Context, _ string, _ int) ([]byte, http.Header, error) {
		direct++
		networkDeadline, _ = ctx.Deadline()
		return []byte("<html>temporary interstitial</html>"), nil, nil
	}
	s.fetchViaProxy = func(ctx context.Context, _, _ string, _ int) ([]byte, http.Header, error) {
		proxy++
		deadline, _ := ctx.Deadline()
		if !deadline.Equal(networkDeadline) {
			t.Error("fallback renewed the original network budget")
		}
		return []byte(admissionSubscriptionBody), nil, nil
	}
	response := subscriptionAdmissionRequest(s, context.Background(), cookie, csrf)
	if response.Code != http.StatusOK || direct != 1 || proxy != 1 {
		t.Fatalf("HTTP200 invalid-content fallback: status=%d direct=%d proxy=%d", response.Code, direct, proxy)
	}
	state, _ := s.repository.auxiliary("subscription-nodes")
	entry, _ := state["provider"].(map[string]any)
	if entry["catalog_ref"] == nil {
		t.Fatal("fallback did not publish a complete catalog")
	}
}

func TestSubscriptionCatalogRefreshLocalFailureNeverRefetches(t *testing.T) {
	for _, failure := range []string{"staging", "compatibility", "terminal-quota"} {
		t.Run(failure, func(t *testing.T) {
			quota := 10
			if failure == "terminal-quota" {
				quota = 1
			}
			s, cookie, csrf, proof := subscriptionCatalogChannelFixture(t, quota, nil)
			if failure == "staging" {
				if err := os.WriteFile(s.secrets.subscriptionCatalogRoot(), []byte("occupied"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if failure == "compatibility" {
				proof.fail.Store(true)
			}
			direct, proxy := 0, 0
			s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
				direct++
				body := admissionSubscriptionBody
				if failure == "terminal-quota" {
					body += "\n" + strings.ReplaceAll(admissionSubscriptionBody, "provider.example.test", "other.example.test")
				}
				return []byte(body), nil, nil
			}
			s.fetchViaProxy = func(context.Context, string, string, int) ([]byte, http.Header, error) {
				proxy++
				return []byte(admissionSubscriptionBody), nil, nil
			}
			response := subscriptionAdmissionRequest(s, context.Background(), cookie, csrf)
			if response.Code == http.StatusOK || direct != 1 || proxy != 0 {
				t.Fatalf("local/terminal failure refetched: status=%d direct=%d proxy=%d", response.Code, direct, proxy)
			}
			state, _ := s.repository.auxiliary("subscription-nodes")
			if len(state) != 0 {
				t.Fatal("failed import published a pointer")
			}
		})
	}
}

func TestSubscriptionCatalogRefreshLocalImportOutlivesNetworkDeadline(t *testing.T) {
	for _, caller := range []string{"manual-api", "scheduler"} {
		t.Run(caller, func(t *testing.T) {
			// A real compatibility REST boundary delays only local import. The body
			// download has already returned; this is not a simulated WAN benchmark.
			s, cookie, csrf, _ := subscriptionCatalogChannelFixture(t, 10, func(*http.Request) { time.Sleep(2100 * time.Millisecond) })
			var downloaded context.Context
			direct, proxy := 0, 0
			s.fetchSubscription = func(ctx context.Context, _ string, _ int) ([]byte, http.Header, error) {
				downloaded = ctx
				direct++
				return []byte(admissionSubscriptionBody), nil, nil
			}
			s.fetchViaProxy = func(context.Context, string, string, int) ([]byte, http.Header, error) {
				proxy++
				return nil, nil, errors.New("unexpected fallback")
			}
			if caller == "manual-api" {
				response := subscriptionAdmissionRequest(s, context.Background(), cookie, csrf)
				if response.Code != http.StatusOK {
					t.Fatalf("local import inherited network deadline: %d", response.Code)
				}
			} else {
				if _, err := s.refreshOneDueSubscription(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if downloaded == nil || !errors.Is(downloaded.Err(), context.DeadlineExceeded) || direct != 1 || proxy != 0 {
				t.Fatal("test did not expire the original completed-download context")
			}
			state, _ := s.repository.auxiliary("subscription-nodes")
			entry, _ := state["provider"].(map[string]any)
			if entry["catalog_ref"] == nil {
				t.Fatal("bounded local import did not finish")
			}
		})
	}
}

func TestSubscriptionCatalogRefreshOriginalCancellationStillStopsImport(t *testing.T) {
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	var releaseOnce sync.Once
	s, cookie, csrf, _ := subscriptionCatalogChannelFixture(t, 10, func(*http.Request) { entered <- struct{}{}; <-release })
	direct, proxy := 0, 0
	s.fetchSubscription = func(context.Context, string, int) ([]byte, http.Header, error) {
		direct++
		return []byte(admissionSubscriptionBody), nil, nil
	}
	s.fetchViaProxy = func(context.Context, string, string, int) ([]byte, http.Header, error) {
		proxy++
		return []byte(admissionSubscriptionBody), nil, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer releaseOnce.Do(func() { close(release) })
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- subscriptionAdmissionRequest(s, ctx, cookie, csrf) }()
	select {
	case <-entered:
	case <-time.After(10 * time.Second):
		t.Fatal("import never reached compatibility boundary")
	}
	cancel()
	releaseOnce.Do(func() { close(release) })
	select {
	case response := <-done:
		if response.Code == http.StatusOK {
			t.Fatal("canceled original request published catalog")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("original cancellation did not release import")
	}
	if direct != 1 || proxy != 0 {
		t.Fatal("original cancellation refetched a response")
	}
	state, _ := s.repository.auxiliary("subscription-nodes")
	if len(state) != 0 {
		t.Fatal("canceled import replaced inventory")
	}
}

func TestSubscriptionCatalogImportResponseBudgetHasHeadroom(t *testing.T) {
	if subscriptionCatalogImportTimeout != 2*time.Minute || subscriptionRefreshResponseTimeout < subscriptionCatalogImportTimeout+subscriptionDownloadTimeout(nil)+30*time.Second {
		t.Fatal("refresh response has no bounded import/network/publication headroom")
	}
}
