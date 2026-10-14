package controlplane

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

func TestACMEManualIssueSurvivesDisabledProfileAndUnrelatedApply(t *testing.T) {
	for _, timing := range []string{"before-queue", "queued", "running"} {
		t.Run(timing, func(t *testing.T) {
			s := newTestServer(t)
			cookie, csrf := bootstrapSession(t, s)
			config := routerOSReadyConfig(t)
			config["tls_profiles"] = append(config["tls_profiles"].([]any), map[string]any{
				"id": "prepared-tls", "display_name": "Prepared TLS", "enabled": timing != "before-queue",
			})
			if _, err := s.repository.saveDraft(config); err != nil {
				t.Fatal(err)
			}
			url := apiPrefix + "/tls-profiles/prepared-tls/acme"
			queued := performRequest(t, s, http.MethodPost, url, map[string]any{
				"settings": acmeTestSettings(), "credentials": map[string]string{"token": "test-dns-secret"}, "issue": true,
			}, map[string]string{csrfHeader: csrf}, cookie)
			if queued.Code != http.StatusAccepted {
				t.Fatalf("queue: %d %s", queued.Code, queued.Body.String())
			}
			s.runtime = &fakeRuntimeApplier{revision: strings.Repeat("4", 64)}
			s.applyRouterOS = func(ctx context.Context, _ map[string]any, _, _ string, health func(context.Context) error, finalize func(context.Context, routeros.BackupRef) error) (routerOSApplyOutput, error) {
				if err := health(ctx); err != nil {
					return routerOSApplyOutput{}, err
				}
				return routerOSApplyOutput{}, finalize(ctx, routeros.BackupRef{})
			}
			disableAndApply := func() {
				draft, err := s.getDraft()
				if err != nil {
					t.Fatal(err)
				}
				profile := acmeProfile(draft, "prepared-tls")
				profile["enabled"] = false
				response := performRequest(t, s, http.MethodPut, apiPrefix+"/tls-profiles/prepared-tls", map[string]any{"item": profile}, map[string]string{csrfHeader: csrf}, cookie)
				if response.Code != http.StatusOK {
					t.Fatalf("disable profile: %d %s", response.Code, response.Body.String())
				}
				state, _ := s.repository.auxiliary("acme")
				before := mustDecodeACMERecord(t, state["prepared-tls"])
				saved := performRequest(t, s, http.MethodPost, url, map[string]any{"settings": acmeTestSettings()}, map[string]string{csrfHeader: csrf}, cookie)
				if saved.Code != http.StatusAccepted {
					t.Fatalf("unchanged save: %d %s", saved.Code, saved.Body.String())
				}
				state, _ = s.repository.auxiliary("acme")
				after := mustDecodeACMERecord(t, state["prepared-tls"])
				if after.Revision != before.Revision || after.State != before.State || !after.LastAttempt.Equal(before.LastAttempt) || decodeResponse(t, saved)["message"] != before.Message {
					t.Fatal("unchanged save reset pending issuance")
				}
				draft, _ = s.getDraft()
				objectAt(draft, "watchdog")["interval_seconds"] = float64(6)
				applied := performRequest(t, s, http.MethodPost, apiPrefix+"/drafts/apply", map[string]any{"config": draft}, map[string]string{csrfHeader: csrf}, cookie)
				if applied.Code != http.StatusOK {
					t.Fatalf("unrelated Apply: %d %s", applied.Code, applied.Body.String())
				}
			}
			if timing != "running" {
				disableAndApply()
			}
			calls := 0
			s.issueACME = func(_ context.Context, request acmejob.Request) (acmejob.Result, error) {
				calls++
				if timing == "running" {
					disableAndApply()
				}
				result, roots := acmeTestPair(t, s.now(), request.Settings.Domains)
				s.acmeRoots = roots
				return result, nil
			}
			if err := s.processOneACME(context.Background()); err != nil {
				t.Fatal(err)
			}
			draft, _ := s.getDraft()
			profile := acmeProfile(draft, "prepared-tls")
			ref := "tls-profiles/prepared-tls/acme-bundle.pem"
			if calls != 1 || profile["enabled"] != false || profile["certificate_secret_ref"] != ref || profile["private_key_secret_ref"] != ref || profile["certificate_metadata"] == nil {
				t.Fatal("manual issuance did not prepare disabled profile")
			}
			active, _ := s.repository.loadActive()
			interval, validInterval := jsonInt(objectAt(active, "watchdog")["interval_seconds"])
			if subscriptionText(acmeProfile(active, "prepared-tls")["certificate_secret_ref"]) != "" || acmeProfile(active, "prepared-tls")["enabled"] != false || !validInterval || interval != 6 {
				t.Fatalf("issuance activated profile or reverted Apply: profile=%#v watchdog=%#v", acmeProfile(active, "prepared-tls"), objectAt(active, "watchdog"))
			}
			state, _ := s.repository.auxiliary("acme")
			issued := mustDecodeACMERecord(t, state["prepared-tls"])
			if issued.State != "issued" || issued.ManualIssue {
				t.Fatal("manual marker survived completion")
			}
			now := s.now().Add(62 * 24 * time.Hour)
			s.now = func() time.Time { return now }
			if err := s.processOneACME(context.Background()); err != nil || calls != 1 {
				t.Fatal("disabled unused profile renewed", err, calls)
			}
		})
	}
}

func TestACMEManualIssueRejectsProfileRemovalAndPairReplacement(t *testing.T) {
	for _, change := range []string{"remove", "replace"} {
		t.Run(change, func(t *testing.T) {
			s := newTestServer(t)
			queueTestACME(t, s)
			s.issueACME = func(_ context.Context, request acmejob.Request) (acmejob.Result, error) {
				s.configMu.Lock()
				defer s.configMu.Unlock()
				draft, _ := s.getDraft()
				if change == "remove" {
					draft["tls_profiles"] = []any{}
				} else {
					profile := acmeProfile(draft, "cdn-default")
					profile["certificate_secret_ref"] = "replacement/cert.pem"
					profile["private_key_secret_ref"] = "replacement/key.pem"
				}
				if _, err := s.repository.saveDraft(draft); err != nil {
					t.Fatal(err)
				}
				result, roots := acmeTestPair(t, s.now(), request.Settings.Domains)
				s.acmeRoots = roots
				return result, nil
			}
			if err := s.processOneACME(context.Background()); err == nil {
				t.Fatal("obsolete profile accepted pair")
			}
			if s.secrets.exists("tls-profiles/cdn-default/acme-bundle.pem") {
				t.Fatal("obsolete pair persisted")
			}
		})
	}
}
