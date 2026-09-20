package controlplane

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmedns"
	"github.com/sb-gateway/sb-gateway/internal/acmejob"
	"github.com/sb-gateway/sb-gateway/internal/policydns"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type acmeRecord struct {
	Settings                acmejob.Settings    `json:"settings"`
	Revision                string              `json:"revision"`
	CredentialsRef          string              `json:"credentials_ref"`
	Intent                  string              `json:"intent,omitempty"`
	State                   string              `json:"state"`
	LastOutcome             string              `json:"last_outcome,omitempty"`
	Message                 string              `json:"message"`
	LastAttempt             time.Time           `json:"last_attempt,omitempty"`
	NextAttempt             time.Time           `json:"next_attempt,omitempty"`
	Metadata                map[string]any      `json:"metadata,omitempty"`
	Diagnostic              *acmejob.Diagnostic `json:"diagnostic,omitempty"`
	CARetryNotBefore        time.Time           `json:"ca_retry_not_before,omitempty"`
	CARetryAfterUnsupported bool                `json:"ca_retry_after_unsupported,omitempty"`
}
type acmeIssueFunc func(context.Context, acmejob.Request) (acmejob.Result, error)

const (
	automaticACMERetryDelay = 15 * time.Minute
	manualACMERetryCooldown = 5 * time.Second
	successfulACMECooldown  = time.Hour
	acmeIntentInitial       = "initial"
	acmeIntentRenewal       = "renewal"
	manualACMEFailureSuffix = "Выпуск не выполнен. Повторите вручную."
)

func decodeACMERecord(raw any) acmeRecord {
	body, _ := json.Marshal(raw)
	var record acmeRecord
	_ = json.Unmarshal(body, &record)
	return record
}

func (record *acmeRecord) preserveLegacyFailure() {
	if record.LastOutcome == "" && record.State == "failed" {
		record.LastOutcome = "failed"
	}
}

func (record acmeRecord) failedLastAttempt() bool {
	return record.LastOutcome == "failed" || (record.LastOutcome == "" && record.State == "failed")
}

// automaticRenewalIntent preserves successful pre-intent records, but never
// promotes a legacy failed or interrupted first issuance into an automatic
// order. A newly persisted renewal intent is assigned only after the managed
// certificate pair has been verified locally.
func (record acmeRecord) automaticRenewalIntent() bool {
	switch record.Intent {
	case acmeIntentRenewal:
		return true
	case acmeIntentInitial:
		return false
	default:
		return record.LastOutcome == "issued" || record.State == "issued" || (record.Metadata != nil && !record.failedLastAttempt())
	}
}

func (record acmeRecord) legacyRenewalCandidate() bool {
	return record.Intent == "" && record.failedLastAttempt() && record.Metadata != nil
}

func (record acmeRecord) manualRetryOnly() bool {
	return record.failedLastAttempt() && !record.automaticRenewalIntent()
}

// manualFailureStatusMessage prevents a pre-intent record from retaining the
// old automatic-retry promise after it has become a manual-only first issue.
// Current failures already carry a safe, specific prefix followed by this
// suffix; an older message is replaced rather than interpreted or echoed.
func (record acmeRecord) manualFailureStatusMessage() string {
	if record.CARetryAfterUnsupported {
		return "CA передал неподдерживаемый срок ожидания. Выпуск временно заблокирован."
	}
	if record.Diagnostic != nil {
		return acmeFailureMessageWithDiagnostic(nil, record.Diagnostic) + " " + manualACMEFailureSuffix
	}
	message := strings.TrimSpace(record.Message)
	if strings.HasSuffix(message, manualACMEFailureSuffix) {
		return message
	}
	return manualACMEFailureSuffix
}

func (record acmeRecord) caRetryBlocked(now time.Time) bool {
	return record.CARetryAfterUnsupported || (!record.CARetryNotBefore.IsZero() && now.Before(record.CARetryNotBefore))
}

func (record *acmeRecord) clearCARetry() {
	record.CARetryNotBefore = time.Time{}
	record.CARetryAfterUnsupported = false
}

func acmeRetryNotBefore(now time.Time, diagnostic acmejob.Diagnostic) (time.Time, bool, bool) {
	if diagnostic.RetryAfterUnsupported {
		return time.Time{}, false, true
	}
	if diagnostic.RetryAfterSeconds == 0 && diagnostic.RetryAfterNanos == 0 {
		return time.Time{}, false, false
	}
	const maxDurationSeconds = int64((1<<63 - 1) / int64(time.Second))
	if diagnostic.RetryAfterSeconds > maxDurationSeconds {
		return time.Time{}, false, true
	}
	duration := time.Duration(diagnostic.RetryAfterSeconds) * time.Second
	if time.Duration(diagnostic.RetryAfterNanos) > time.Duration(1<<63-1)-duration {
		return time.Time{}, false, true
	}
	duration += time.Duration(diagnostic.RetryAfterNanos)
	deadline := now.Add(duration)
	if duration <= 0 || !deadline.After(now) {
		return time.Time{}, false, true
	}
	return deadline, true, false
}
func acmeProfile(config map[string]any, id string) map[string]any {
	for _, p := range objects(config["tls_profiles"]) {
		if p["id"] == id {
			return p
		}
	}
	return nil
}

func acmeRecursiveResolver(config map[string]any) (acmejob.RecursiveResolver, error) {
	server, err := runtimeconfig.DirectPublicDNSServer(config)
	if err != nil {
		return acmejob.RecursiveResolver{}, err
	}
	resolver := acmejob.RecursiveResolver{
		Type: server.Type, Server: server.Server, ServerName: server.TLS.ServerName,
		ServerPort: server.ServerPort, Path: server.Path, DoTFallback: server.DoTFallback,
	}
	if err := resolver.Validate(); err != nil {
		return acmejob.RecursiveResolver{}, err
	}
	return resolver, nil
}

func freshACMEResolver(ctx context.Context, resolver acmejob.RecursiveResolver) (*policydns.FreshResolver, error) {
	return policydns.StartFreshResolver(ctx, policydns.FreshResolverConfig{
		Type: resolver.Type, Server: resolver.Server, ServerName: resolver.ServerName,
		ServerPort: resolver.ServerPort, Path: resolver.Path, DoTFallback: resolver.DoTFallback,
	}, policydns.FreshResolverOptions{Workers: 4, TCPSessions: 2, Timeout: 5 * time.Second})
}

// acmeResolverFromActive selects the applied direct resolver whenever it
// exists. Pending draft DNS edits must not change the resolver of a live ACME
// job; before first apply, the draft remains the only available source.
func (s *Server) acmeResolverFromActive(draft map[string]any) (acmejob.RecursiveResolver, map[string]any, error) {
	active, err := s.repository.loadActive()
	if err == nil {
		resolver, resolverErr := acmeRecursiveResolver(active)
		return resolver, active, resolverErr
	}
	if !errors.Is(err, os.ErrNotExist) {
		return acmejob.RecursiveResolver{}, nil, err
	}
	resolver, resolverErr := acmeRecursiveResolver(draft)
	return resolver, nil, resolverErr
}
func (s *Server) acmeStatus(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireSession(w, r); !ok {
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		s.internalStateError(w, r, err)
		return
	}
	record := decodeACMERecord(state[r.PathValue("entity")])
	var delegations []acmejob.Delegation
	if record.Settings.Provider == "acmedns" {
		credentials, err := s.acmeCredentials(nil, record, record.Settings)
		if err == nil {
			delegations, _ = acmejob.ACMEDNSDelegations(record.Settings, credentials)
		}
	}
	// Credentials and private/account keys are never returned to the browser.
	manualIssueNeeded := true
	var renewalNotBefore time.Time
	if draft, draftErr := s.getDraft(); draftErr == nil {
		manualIssueNeeded, renewalNotBefore = s.acmeManualIssueStatus(r.PathValue("entity"), acmeProfile(draft, r.PathValue("entity")), record, record.Settings, s.now())
	}
	manualRetryOnly := record.manualRetryOnly()
	if manualRetryOnly && record.legacyRenewalCandidate() {
		if draft, err := s.getDraft(); err == nil {
			active, activeErr := s.repository.loadActive()
			profile := acmeProfile(draft, r.PathValue("entity"))
			if activeErr == nil {
				if live := acmeProfile(active, r.PathValue("entity")); live != nil && live["enabled"] != false && live["certificate_secret_ref"] == "tls-profiles/"+r.PathValue("entity")+"/acme-bundle.pem" {
					profile = live
				}
			}
			manualRetryOnly = !s.verifiedManagedACMEPair(r.PathValue("entity"), profile, record, record.Settings)
		}
	}
	message := record.Message
	if manualRetryOnly {
		message = record.manualFailureStatusMessage()
	}
	response := map[string]any{"settings": record.Settings, "state": record.State, "message": message, "last_attempt": record.LastAttempt, "metadata": record.Metadata, "credentials_configured": record.CredentialsRef != "", "delegations": delegations, "manual_issue_needed": manualIssueNeeded}
	if !renewalNotBefore.IsZero() {
		response["renewal_not_before"] = renewalNotBefore
	}
	if record.State == "running" {
		if timeout := acmejob.ControllerTimeout(record.Settings); timeout > 0 {
			response["operation_timeout_seconds"] = int64(timeout / time.Second)
		}
		if progress, ok := s.currentACMEProgress(r.PathValue("entity"), record); ok {
			response["operation_stage"] = progress.Stage
			response["operation_stage_at"] = progress.At
		}
	}
	// An unsupported Retry-After is fail-closed: a regular automatic deadline
	// would falsely suggest that retry becomes safe at that time.
	if !record.CARetryAfterUnsupported && !manualRetryOnly {
		response["next_attempt"] = record.NextAttempt
	}
	if manualRetryOnly {
		response["manual_retry_only"] = true
	}
	if record.Diagnostic != nil {
		response["diagnostic"] = record.Diagnostic
	}
	if !record.CARetryNotBefore.IsZero() {
		response["ca_retry_not_before"] = record.CARetryNotBefore
	}
	if record.CARetryAfterUnsupported {
		response["ca_retry_after_unsupported"] = true
	}
	s.writeJSON(w, http.StatusOK, response)
}

func (s *Server) acmeCredentials(body map[string]any, record acmeRecord, settings acmejob.Settings) (map[string]string, error) {
	var credentials map[string]string
	if raw, exists := body["credentials"]; exists {
		encoded, err := json.Marshal(raw)
		if err != nil || json.Unmarshal(encoded, &credentials) != nil {
			return nil, errors.New("Некорректные данные DNS API.")
		}
	} else if record.CredentialsRef != "" && record.Settings.Provider == settings.Provider {
		if settings.Provider == "acmedns" && record.Settings.ACMEDNSServer != settings.ACMEDNSServer {
			return nil, errors.New("После смены сервиса загрузите его учётные записи заново.")
		}
		secret, err := s.secrets.read(record.CredentialsRef, true)
		if err != nil || json.Unmarshal([]byte(secret), &credentials) != nil {
			return nil, errors.New("Не удалось прочитать доступ к DNS API.")
		}
	}
	return credentials, nil
}

// Read-only preflight, also available before a new TLS profile is saved.
func (s *Server) checkACMEDNSDelegations(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireCSRF(w, r); !ok {
		return
	}
	body, ok := s.readObject(w, r, 32<<10)
	if !ok {
		return
	}
	var settings acmejob.Settings
	encoded, _ := json.Marshal(body["settings"])
	if json.Unmarshal(encoded, &settings) != nil || acmejob.ValidateACMEDNSSettings(settings) != nil {
		s.writeErrorResponse(w, r, 422, "invalid_acmedns", "Некорректные настройки ACME-DNS.")
		return
	}
	s.configMu.Lock()
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		s.configMu.Unlock()
		s.internalStateError(w, r, err)
		return
	}
	record := decodeACMERecord(state[subscriptionText(body["profile_id"])])
	credentials, credentialsErr := s.acmeCredentials(body, record, settings)
	draft, draftErr := s.getDraft()
	var recursiveResolver acmejob.RecursiveResolver
	var resolverErr error
	if draftErr == nil {
		recursiveResolver, _, resolverErr = s.acmeResolverFromActive(draft)
	}
	s.configMu.Unlock()
	if draftErr != nil {
		s.internalStateError(w, r, draftErr)
		return
	}
	if credentialsErr != nil {
		s.writeErrorResponse(w, r, 422, "invalid_credentials", credentialsErr.Error())
		return
	}
	if resolverErr != nil {
		s.writeErrorResponse(w, r, 422, "acme_resolver", "Не удалось подготовить доверенный DNS-резолвер ACME.")
		return
	}
	records, err := acmejob.ACMEDNSDelegations(settings, credentials)
	if err != nil {
		s.writeErrorResponse(w, r, 422, "invalid_acmedns", err.Error())
		return
	}
	lookup := s.acmeDNSLookup
	var forwarder *policydns.FreshResolver
	if lookup == nil {
		forwarder, err = freshACMEResolver(r.Context(), recursiveResolver)
		if err != nil {
			s.writeErrorResponse(w, r, 503, "acme_resolver", "Не удалось подготовить доверенный DNS-резолвер ACME.")
			return
		}
		defer forwarder.Close()
		lookup = forwarder.LookupCNAME
	}
	if err := acmedns.CheckDelegations(r.Context(), records, lookup); err != nil {
		s.writeErrorResponse(w, r, 422, "acmedns_cname", acmejob.ErrDelegation.Error())
		return
	}
	s.writeJSON(w, 200, map[string]any{"verified": true, "delegations": records})
}

func (s *Server) configureACME(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireCSRF(w, r)
	if !ok {
		return
	}
	body, ok := s.readObject(w, r, 32<<10)
	if !ok {
		return
	}
	id := r.PathValue("entity")
	if !entityIDPattern.MatchString(id) {
		s.writeErrorResponse(w, r, 422, "invalid_id", "Некорректный TLS-профиль.")
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	draft, err := s.getDraft()
	if err != nil {
		s.internalStateError(w, r, err)
		return
	}
	if acmeProfile(draft, id) == nil {
		s.writeErrorResponse(w, r, 404, "not_found", "Сначала сохраните TLS-профиль.")
		return
	}
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		s.internalStateError(w, r, err)
		return
	}
	record := decodeACMERecord(state[id])
	record.preserveLegacyFailure()
	if body["disable"] == true {
		record.Settings.Enabled = false
		record.State = "disabled"
		record.Message = "Автопродление выключено."
		record.Revision, _ = randomURLToken(12)
		state[id] = record
		if err := s.repository.saveAuxiliary("acme", state); err != nil {
			s.internalStateError(w, r, err)
			return
		}
		s.audit(r, subscriptionText(actor["sub"]), "tls.acme.disable", "ok", map[string]any{"id": id})
		s.writeJSON(w, 200, map[string]any{"saved": true})
		return
	}
	var settings acmejob.Settings
	encoded, _ := json.Marshal(body["settings"])
	if err := json.Unmarshal(encoded, &settings); err != nil {
		s.writeErrorResponse(w, r, 422, "invalid_acme", "Некорректные настройки ACME.")
		return
	}
	if err := acmejob.Validate(settings); err != nil {
		s.writeErrorResponse(w, r, 422, "invalid_acme", err.Error())
		return
	}
	issue := body["issue"] == true
	if issue && (record.State == "queued" || record.State == "running") {
		s.writeErrorResponse(w, r, http.StatusConflict, "acme_busy", "Выпуск уже выполняется. Дождитесь его завершения.")
		return
	}
	if issue && !settings.Enabled {
		s.writeErrorResponse(w, r, 422, "acme_disabled", "Включите автоматическое продление перед выпуском.")
		return
	}
	if issue {
		now := s.now()
		if record.caRetryBlocked(now) {
			message := "CA временно ограничил выпуск. Дождитесь указанного времени следующей попытки."
			if record.CARetryAfterUnsupported {
				message = "CA передал неподдерживаемый срок ожидания. Выпуск временно заблокирован."
			}
			s.writeErrorResponse(w, r, http.StatusTooManyRequests, "acme_ca_backoff", message)
			return
		}
		if metadata, verified := s.verifiedManagedACMEPairMetadata(id, acmeProfile(draft, id), record, settings); verified && !acmeManualIssueNeeded(metadata, now) {
			s.writeErrorResponse(w, r, http.StatusConflict, "acme_not_due", "Действующий сертификат ещё не требует продления.")
			return
		}
		if record.failedLastAttempt() {
			if !record.LastAttempt.IsZero() && now.Before(record.LastAttempt.Add(manualACMERetryCooldown)) {
				s.writeErrorResponse(w, r, http.StatusTooManyRequests, "acme_retry_cooldown", "Повторный выпуск доступен через несколько секунд.")
				return
			}
			// A deliberate retry after a failed attempt remains rate-limited by
			// LastAttempt, but need not wait for the automatic retry deadline.
			record.NextAttempt = now
		} else if now.Before(record.NextAttempt) {
			s.writeErrorResponse(w, r, http.StatusTooManyRequests, "acme_backoff", "Повторный выпуск пока недоступен. Дождитесь указанного времени следующей попытки.")
			return
		}
	}
	credentials, err := s.acmeCredentials(body, record, settings)
	if err != nil {
		s.writeErrorResponse(w, r, 422, "invalid_credentials", err.Error())
		return
	}
	if err := acmejob.ValidateConfiguration(settings, credentials); err != nil {
		s.writeErrorResponse(w, r, 422, "invalid_credentials", err.Error())
		return
	}
	secret, _ := json.Marshal(credentials)
	ref := "acme/" + id + "/dns.json"
	undo, err := s.writeEntitySecrets([]pendingEntitySecret{{reference: ref, value: string(secret), overwrite: true}})
	if err != nil {
		s.writeErrorResponse(w, r, 500, "secret_store_failed", "Не удалось сохранить доступ к DNS API.")
		return
	}
	record.Settings = settings
	record.CredentialsRef = ref
	record.Revision, _ = randomURLToken(12)
	if issue {
		if s.verifiedManagedACMEPair(id, acmeProfile(draft, id), record, settings) {
			record.Intent = acmeIntentRenewal
		} else {
			record.Intent = acmeIntentInitial
		}
		record.State = "queued"
		record.Message = "Выпуск поставлен в очередь."
	} else if !settings.Enabled {
		record.State = "disabled"
		record.Message = "Автопродление выключено."
	} else {
		record.State = "configured"
		record.Message = "Настройки сохранены."
	}
	state[id] = record
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		_ = undo()
		s.internalStateError(w, r, err)
		return
	}
	manualIssueNeeded, renewalNotBefore := s.acmeManualIssueStatus(id, acmeProfile(draft, id), record, settings, s.now())
	response := map[string]any{"saved": true, "state": record.State, "manual_issue_needed": manualIssueNeeded}
	if !renewalNotBefore.IsZero() {
		response["renewal_not_before"] = renewalNotBefore
	}
	s.audit(r, subscriptionText(actor["sub"]), "tls.acme.configure", "ok", map[string]any{"id": id, "issue": issue})
	s.writeJSON(w, http.StatusAccepted, response)
}

func (s *Server) runACMEScheduler(ctx context.Context) {
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			_ = s.processOneACME(ctx)
			timer.Reset(15 * time.Second)
		}
	}
}

func acmeDue(record acmeRecord, now time.Time) bool {
	if !record.Settings.Enabled || record.caRetryBlocked(now) || now.Before(record.NextAttempt) {
		return false
	}
	if record.State == "queued" {
		return true
	}
	// A persisted running state has no live worker after a restart. It is
	// recovered explicitly below and never replays an order by itself.
	if record.State == "running" {
		return false
	}
	if record.failedLastAttempt() {
		return record.Intent == acmeIntentRenewal || record.legacyRenewalCandidate()
	}
	if !record.automaticRenewalIntent() {
		return false
	}
	return acmeRenewalDue(record.Metadata, now)
}

// acmeRenewalWindow derives the automatic renewal boundary from the verified
// certificate lifetime. It intentionally makes no assumption about a 90-day
// certificate. Invalid lifetime metadata must not suppress a manual recovery.
func acmeRenewalWindow(metadata map[string]any) (notBefore, notAfter, starts time.Time, ok bool) {
	notBefore, _ = time.Parse(time.RFC3339, subscriptionText(metadata["not_before"]))
	notAfter, _ = time.Parse(time.RFC3339, subscriptionText(metadata["not_after"]))
	if notBefore.IsZero() || notAfter.IsZero() || !notAfter.After(notBefore) {
		return time.Time{}, time.Time{}, time.Time{}, false
	}
	lastThird := notAfter.Sub(notBefore) / 3
	if lastThird > 30*24*time.Hour {
		lastThird = 30 * 24 * time.Hour
	}
	return notBefore, notAfter, notAfter.Add(-lastThird), true
}

func acmeRenewalDue(metadata map[string]any, now time.Time) bool {
	_, _, starts, ok := acmeRenewalWindow(metadata)
	return ok && !now.Before(starts)
}

// acmeManualIssueNeeded permits a recovery when the pair is absent, invalid,
// outside the requested SANs, expired, not yet valid, or in its renewal
// window. It otherwise prevents a redundant production order.
func acmeManualIssueNeeded(metadata map[string]any, now time.Time) bool {
	notBefore, notAfter, starts, ok := acmeRenewalWindow(metadata)
	if !ok || now.Before(notBefore) || !now.Before(notAfter) {
		return true
	}
	return !now.Before(starts)
}

func acmeMetadataNames(value any) []string {
	switch names := value.(type) {
	case []string:
		return append([]string(nil), names...)
	case []any:
		return stringsOf(names)
	default:
		return nil
	}
}

func acmePairCoversDomains(certificatePEM, privateKeyPEM string, domains []string) bool {
	pair, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			matched := false
			for _, name := range leaf.DNSNames {
				if normalizeDomain(name) == normalizeDomain(domain) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
			continue
		}
		if leaf.VerifyHostname(normalizeDomain(domain)) != nil {
			return false
		}
	}
	return true
}

func acmeMetadataMatches(record, actual map[string]any) bool {
	if record == nil || actual == nil {
		return false
	}
	for _, key := range []string{"fingerprint_sha256", "not_before", "not_after"} {
		if subscriptionText(record[key]) == "" || subscriptionText(record[key]) != subscriptionText(actual[key]) {
			return false
		}
	}
	recorded, received := acmeMetadataNames(record["dns_names"]), acmeMetadataNames(actual["dns_names"])
	if len(recorded) == 0 || len(recorded) != len(received) {
		return false
	}
	for index := range recorded {
		if recorded[index] != received[index] {
			return false
		}
	}
	return true
}

// verifiedManagedACMEPair proves that an already installed bundle, its
// persisted metadata and the current requested SANs still agree. It
// deliberately does not reject an expired certificate: expiry is exactly when
// automatic renewal must remain possible after an outage.
func (s *Server) verifiedManagedACMEPairMetadata(id string, profile map[string]any, record acmeRecord, settings acmejob.Settings) (map[string]any, bool) {
	ref := "tls-profiles/" + id + "/acme-bundle.pem"
	if profile == nil || subscriptionText(profile["certificate_secret_ref"]) != ref || subscriptionText(profile["private_key_secret_ref"]) != ref {
		return nil, false
	}
	bundle, err := s.secrets.read(ref, false)
	if err != nil || bundle == "" || !acmePairCoversDomains(bundle, bundle, settings.Domains) {
		return nil, false
	}
	metadata, err := tlsCertificateMetadata(bundle, bundle)
	if err != nil || !acmeMetadataMatches(record.Metadata, metadata) {
		return nil, false
	}
	return metadata, true
}

func (s *Server) verifiedManagedACMEPair(id string, profile map[string]any, record acmeRecord, settings acmejob.Settings) bool {
	_, ok := s.verifiedManagedACMEPairMetadata(id, profile, record, settings)
	return ok
}

func (s *Server) acmeManualIssueStatus(id string, profile map[string]any, record acmeRecord, settings acmejob.Settings, now time.Time) (bool, time.Time) {
	metadata, verified := s.verifiedManagedACMEPairMetadata(id, profile, record, settings)
	if !verified {
		return true, time.Time{}
	}
	_, _, starts, windowOK := acmeRenewalWindow(metadata)
	if !windowOK {
		return true, time.Time{}
	}
	return acmeManualIssueNeeded(metadata, now), starts
}

func (record *acmeRecord) markManualACMEFailure(message string) {
	record.Intent = acmeIntentInitial
	record.State = "failed"
	record.LastOutcome = "failed"
	record.NextAttempt = time.Time{}
	record.Message = strings.TrimSpace(message) + " " + manualACMEFailureSuffix
}

func (s *Server) processOneACME(ctx context.Context) error {
	if !s.acmeMu.TryLock() {
		return nil
	}
	defer s.acmeMu.Unlock()
	s.configMu.Lock()
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		s.configMu.Unlock()
		return err
	}
	draft, err := s.getDraft()
	if err != nil {
		s.configMu.Unlock()
		return err
	}
	active, activeErr := s.repository.loadActive()
	resolverSource := draft
	if activeErr == nil {
		resolverSource = active
	}
	var recursiveResolver acmejob.RecursiveResolver
	var resolverErr error
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		resolverErr = activeErr
	} else {
		recursiveResolver, resolverErr = acmeRecursiveResolver(resolverSource)
	}
	id := ""
	orphaned := false
	var record acmeRecord
	var profile map[string]any
	for candidate, raw := range state {
		rec := decodeACMERecord(raw)
		p := acmeProfile(draft, candidate)
		if live := acmeProfile(active, candidate); live != nil && live["enabled"] != false && live["certificate_secret_ref"] == "tls-profiles/"+candidate+"/acme-bundle.pem" {
			p = live
		}
		if p == nil {
			p = acmeProfile(active, candidate)
		}
		if p == nil || p["enabled"] == false {
			continue
		}
		if rec.State == "running" {
			if id == "" || (!orphaned || rec.LastAttempt.Before(record.LastAttempt)) {
				id, record, profile, orphaned = candidate, rec, p, true
			}
			continue
		}
		if orphaned || !acmeDue(rec, s.now()) {
			continue
		}
		if id == "" || rec.LastAttempt.Before(record.LastAttempt) {
			id, record, profile = candidate, rec, p
		}
	}
	if id == "" {
		s.configMu.Unlock()
		return nil
	}
	if orphaned {
		now := s.now()
		if record.Intent != acmeIntentInitial && s.verifiedManagedACMEPair(id, profile, record, record.Settings) {
			record.Intent = acmeIntentRenewal
			record.State = "failed"
			record.LastOutcome = "failed"
			record.NextAttempt = now.Add(automaticACMERetryDelay)
			if record.CARetryNotBefore.After(record.NextAttempt) {
				record.NextAttempt = record.CARetryNotBefore
			}
			if record.caRetryBlocked(now) {
				if record.CARetryAfterUnsupported {
					record.Message = "Продление не завершилось. CA передал неподдерживаемый срок ожидания."
				} else {
					record.Message = "Продление не завершилось. Повтор после указанного времени."
				}
			} else {
				record.Message = "Продление не завершилось. Повтор через 15 минут."
			}
		} else {
			record.markManualACMEFailure("Выпуск был прерван до завершения.")
		}
		state[id] = record
		saveErr := s.repository.saveAuxiliary("acme", state)
		s.configMu.Unlock()
		return saveErr
	}
	if record.State != "queued" {
		if !s.verifiedManagedACMEPair(id, profile, record, record.Settings) {
			record.markManualACMEFailure("Не удалось подтвердить установленный сертификат для автопродления.")
			state[id] = record
			saveErr := s.repository.saveAuxiliary("acme", state)
			s.configMu.Unlock()
			return saveErr
		}
		record.Intent = acmeIntentRenewal
	}
	if resolverErr != nil {
		now := s.now()
		record.Diagnostic = nil
		record.clearCARetry()
		record.LastAttempt = now
		if record.Intent == acmeIntentRenewal {
			record.State = "failed"
			record.LastOutcome = "failed"
			record.Message = "Не удалось подготовить доверенный DNS-резолвер ACME. Повтор через 15 минут."
			record.NextAttempt = now.Add(automaticACMERetryDelay)
		} else {
			record.markManualACMEFailure("Не удалось подготовить доверенный DNS-резолвер ACME.")
		}
		state[id] = record
		saveErr := s.repository.saveAuxiliary("acme", state)
		s.configMu.Unlock()
		return errors.Join(resolverErr, saveErr)
	}
	if err := acmejob.Validate(record.Settings); err != nil {
		now := s.now()
		record.Diagnostic = nil
		record.clearCARetry()
		record.LastAttempt = now
		if record.Intent == acmeIntentRenewal {
			record.State = "failed"
			record.LastOutcome = "failed"
			record.Message = "Настройки ACME недействительны. Повтор через 15 минут."
			record.NextAttempt = now.Add(automaticACMERetryDelay)
		} else {
			record.markManualACMEFailure("Настройки ACME недействительны.")
		}
		state[id] = record
		saveErr := s.repository.saveAuxiliary("acme", state)
		s.configMu.Unlock()
		return errors.Join(err, saveErr)
	}
	// Persist the cooldown before any network action, including across restarts.
	record.State = "running"
	record.LastOutcome = "running"
	record.Message = "Проверка DNS и выпуск сертификата…"
	record.Diagnostic = nil
	record.clearCARetry()
	record.LastAttempt = s.now()
	record.NextAttempt = s.now().Add(automaticACMERetryDelay)
	state[id] = record
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		s.configMu.Unlock()
		return err
	}
	s.beginACMEProgress(id, record.Revision, record.LastAttempt)
	defer s.clearACMEProgress(id, record.Revision, record.LastAttempt)
	credential, err := s.secrets.read(record.CredentialsRef, true)
	var credentials map[string]string
	if err == nil {
		err = json.Unmarshal([]byte(credential), &credentials)
	}
	accountRef := "acme/" + id + "/account.pem"
	accountKey, readErr := s.secrets.read(accountRef, false)
	if err == nil {
		err = readErr
	}
	if err == nil && accountKey == "" {
		var key *ecdsa.PrivateKey
		key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err == nil {
			der, e := x509.MarshalPKCS8PrivateKey(key)
			err = e
			accountKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
			if err == nil {
				err = s.secrets.write(accountRef, accountKey, false)
			}
		}
	}
	originalCertRef := subscriptionText(profile["certificate_secret_ref"])
	operation, cancel := context.WithTimeout(ctx, acmejob.ControllerTimeout(record.Settings))
	defer cancel()
	s.configMu.Unlock()
	var result acmejob.Result
	if err == nil {
		issuer := s.issueACME
		request := acmejob.Request{Settings: record.Settings, Credentials: credentials, AccountKey: accountKey, RecursiveResolver: recursiveResolver}
		if issuer != nil {
			result, err = issuer(operation, request)
		} else {
			result, err = runACMEWorkerWithProgress(operation, request, func(event acmejob.ProgressEvent) {
				s.noteACMEProgress(id, record.Revision, record.LastAttempt, event)
			})
		}
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	state, stateErr := s.repository.auxiliary("acme")
	if stateErr != nil {
		return stateErr
	}
	current := decodeACMERecord(state[id])
	if current.Revision != record.Revision || !current.Settings.Enabled {
		// Never resurrect an obsolete certificate/settings result. A typed CA
		// Retry-After is the sole safe exception: preserve only its hold so a
		// save or disable/enable cycle cannot evade a CA rate limit.
		if diagnostic, ok := acmejob.DiagnosticFromError(err); ok && persistCARetryHold(&current, s.now(), diagnostic) {
			state[id] = current
			return errors.Join(err, s.repository.saveAuxiliary("acme", state))
		}
		return nil
	} // User changed/disabled the job while DNS was pending.
	if err == nil {
		if operation.Err() != nil {
			err = acmejob.ErrWorker
		}
	}
	if err == nil {
		s.noteACMEProgress(id, record.Revision, record.LastAttempt, acmejob.ProgressEvent{Version: 1, Stage: acmejob.ProgressLocalInstall})
		if installErr := s.installACMECertificate(operation, id, record.Settings.Domains, originalCertRef, result, &record); installErr != nil {
			err = acmejob.ErrLocalInstall
		}
	}
	if err != nil {
		record.State = "failed"
		record.LastOutcome = "failed"
		diagnostic, hasDiagnostic := acmejob.DiagnosticFromError(err)
		if hasDiagnostic {
			record.Diagnostic = &diagnostic
		} else {
			record.Diagnostic = nil
		}
		record.Message = acmeFailureMessageWithDiagnostic(err, record.Diagnostic)
		// The crash-recovery deadline is persisted before DNS work begins. A
		// completed long propagation wait receives a fresh automatic backoff so
		// the scheduler cannot immediately queue another CA order.
		now := s.now()
		if record.Intent == acmeIntentRenewal {
			record.NextAttempt = now.Add(automaticACMERetryDelay)
			record.Message += " Повтор через 15 минут."
		} else {
			record.NextAttempt = time.Time{}
			record.Message += " Выпуск не выполнен. Повторите вручную."
		}
		record.clearCARetry()
		if hasDiagnostic {
			if deadline, hasRetryAfter, unsupported := acmeRetryNotBefore(now, diagnostic); unsupported {
				record.CARetryAfterUnsupported = true
				record.Message = "CA передал неподдерживаемый срок ожидания. Выпуск временно заблокирован."
			} else if hasRetryAfter {
				record.CARetryNotBefore = deadline
				if record.Intent == acmeIntentRenewal && deadline.After(record.NextAttempt) {
					record.NextAttempt = deadline
				}
				if record.Intent == acmeIntentRenewal {
					record.Message = acmeFailureMessageWithDiagnostic(err, record.Diagnostic) + " Повтор после указанного времени."
				} else {
					record.Message = acmeFailureMessageWithDiagnostic(err, record.Diagnostic) + " Выпуск не выполнен. Повторите вручную."
				}
			}
		}
	} else {
		record.State = "issued"
		record.LastOutcome = "issued"
		record.Intent = acmeIntentRenewal
		record.Message = "Сертификат выпущен. Автопродление включено."
		record.NextAttempt = s.now().Add(successfulACMECooldown)
		record.Diagnostic = nil
		record.clearCARetry()
	}
	state[id] = record
	return errors.Join(err, s.repository.saveAuxiliary("acme", state))
}

func acmeFailureMessage(err error) string {
	for _, stage := range []error{
		acmejob.ErrDelegation,
		acmejob.ErrDNSProvider,
		acmejob.ErrPropagation,
		acmejob.ErrRegistration,
		acmejob.ErrCAValidation,
		acmejob.ErrLocalInstall,
		acmejob.ErrWorkerInput,
		acmejob.ErrWorkerStart,
		acmejob.ErrWorkerOutput,
		acmejob.ErrWorkerCancel,
		acmejob.ErrWorkerTimeout,
	} {
		if errors.Is(err, stage) {
			return stage.Error()
		}
	}
	return acmejob.ErrWorker.Error()
}

func acmeFailureMessageWithDiagnostic(err error, diagnostic *acmejob.Diagnostic) string {
	if diagnostic == nil {
		return acmeFailureMessage(err)
	}
	switch diagnostic.Category {
	case "ca_rate_limited":
		return "CA: лимит выпуска сертификатов."
	case "ca_caa":
		return "CA: выпуск запрещён записью CAA."
	case "ca_dns":
		return "CA: DNS-проверка домена не подтверждена."
	case "ca_connection":
		return "CA: не удалось подключиться для проверки домена."
	case "ca_tls":
		return "CA: TLS-проверка домена не подтверждена."
	case "ca_unauthorized":
		return "CA: авторизация домена не подтверждена."
	case "ca_rejected_identifier":
		return "CA: выпуск для доменного имени отклонён."
	case "ca_server_internal":
		return "CA: временная внутренняя ошибка выпуска."
	case "transport_timeout":
		return "ACME: истекло время сетевого запроса."
	case "transport_cancelled":
		return "ACME: сетевой запрос был отменён."
	case "transport_tls":
		return "ACME: TLS-соединение с внешним сервисом не подтверждено."
	case "transport_connection":
		return "ACME: не удалось установить сетевое соединение."
	case "transport_dns":
		return "ACME: DNS-запрос внешнего сервиса не подтверждён."
	case "ca_other":
		return "CA: проверка домена или выпуск сертификата не подтверждены."
	default:
		return acmeFailureMessage(err)
	}
}

func persistCARetryHold(record *acmeRecord, now time.Time, diagnostic acmejob.Diagnostic) bool {
	if diagnostic.Category != "ca_rate_limited" {
		return false
	}
	deadline, hasRetryAfter, unsupported := acmeRetryNotBefore(now, diagnostic)
	if !hasRetryAfter && !unsupported {
		return false
	}
	record.Diagnostic = &diagnostic
	if unsupported {
		record.CARetryAfterUnsupported = true
		return true
	}
	if deadline.After(record.CARetryNotBefore) {
		record.CARetryNotBefore = deadline
	}
	if deadline.After(record.NextAttempt) {
		record.NextAttempt = deadline
	}
	return true
}

func validateACMEPair(result acmejob.Result, domains []string, now time.Time, roots *x509.CertPool) (map[string]any, error) {
	pair, err := tls.X509KeyPair([]byte(result.Certificate), []byte(result.PrivateKey))
	if err != nil {
		return nil, errors.New("invalid ACME pair")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, err
	}
	if !leaf.NotAfter.After(now.Add(24 * time.Hour)) {
		return nil, errors.New("ACME certificate expires too soon")
	}
	intermediates := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		cert, e := x509.ParseCertificate(der)
		if e != nil {
			return nil, e
		}
		intermediates.AddCert(cert)
	}
	for _, domain := range domains {
		if strings.HasPrefix(domain, "*.") {
			domain = "acme-check." + strings.TrimPrefix(domain, "*.")
		}
		if _, err := leaf.Verify(x509.VerifyOptions{DNSName: domain, CurrentTime: now, Roots: roots, Intermediates: intermediates}); err != nil {
			return nil, err
		}
	}
	return tlsCertificateMetadata(result.Certificate, result.PrivateKey)
}

func (s *Server) installACMECertificate(ctx context.Context, id string, domains []string, originalRef string, result acmejob.Result, record *acmeRecord) error {
	draft, err := s.getDraft()
	if err != nil {
		return err
	}
	profile := acmeProfile(draft, id)
	active, activeErr := s.repository.loadActive()
	if activeErr != nil && !errors.Is(activeErr, os.ErrNotExist) {
		return activeErr
	}
	live := acmeProfile(active, id)
	managedLive := live != nil && live["enabled"] != false && live["certificate_secret_ref"] == "tls-profiles/"+id+"/acme-bundle.pem" && originalRef == subscriptionText(live["certificate_secret_ref"])
	if !managedLive && (profile == nil || profile["enabled"] == false || subscriptionText(profile["certificate_secret_ref"]) != originalRef) {
		return errors.New("TLS profile changed during issuance")
	}
	metadata, err := validateACMEPair(result, domains, s.now(), s.acmeRoots)
	if err != nil {
		return err
	}
	ref := "tls-profiles/" + id + "/acme-bundle.pem"
	old, err := s.secrets.read(ref, false)
	if err != nil {
		return err
	}
	if old != "" {
		// Do not withdraw SANs still served by an active profile during renewal.
		active, _ := s.repository.loadActive()
		if p := acmeProfile(active, id); p != nil && p["certificate_secret_ref"] == ref {
			oldMeta, e := tlsCertificateMetadata(old, old)
			if e != nil {
				return e
			}
			names, _ := oldMeta["dns_names"].([]string)
			if _, e := validateACMEPair(result, names, s.now(), s.acmeRoots); e != nil {
				return e
			}
		}
	}
	// One atomic PEM bundle is both certificateFile and keyFile: a power loss
	// cannot persist a new certificate paired with the previous private key.
	undo, err := s.writeEntitySecrets([]pendingEntitySecret{{reference: ref, value: strings.TrimSpace(result.Certificate) + "\n" + strings.TrimSpace(result.PrivateKey), overwrite: true}})
	if err != nil {
		return err
	}
	restore := func(cause error) error {
		undoErr := undo()
		recovery, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return errors.Join(cause, undoErr, s.reloadACMENginx(recovery, ref))
	}
	if err := s.reloadACMENginx(ctx, ref); err != nil {
		return restore(err)
	}
	// First issuance attaches the managed pair to the draft. Renewal is
	// operational state: it must neither resurrect a deleted draft profile nor
	// dirty a user's configuration just because the certificate dates changed.
	if !managedLive {
		profile["certificate_secret_ref"], profile["private_key_secret_ref"] = ref, ref
		profile["certificate_metadata"] = metadata
		profile["certificate_source"] = "acme"
		delete(profile, "local_ca_server_name")
		delete(profile, "local_ca_certificate_secret_ref")
		delete(profile, "local_ca_private_key_secret_ref")
		if _, err := s.repository.saveDraft(draft); err != nil {
			return restore(err)
		}
	}
	record.Metadata = metadata
	return nil
}

func (s *Server) reloadACMENginx(ctx context.Context, ref string) error {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	native, ok := s.runtime.(*nativeRuntime)
	if !ok {
		return nil
	}
	path, err := s.secrets.path(ref)
	if err != nil {
		return err
	}
	config, err := os.ReadFile(native.options.NginxConfig)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !bytes.Contains(config, []byte(path)) {
		return nil
	}
	command := native.nginxCommand
	if command == nil {
		command = func(ctx context.Context, args ...string) error {
			return runValidationCommand(ctx, native.options.NginxBinary, args...)
		}
	}
	if err := command(ctx, "-t", "-c", native.options.NginxConfig, "-p", "/"); err != nil {
		return err
	}
	if err := command(ctx, "-s", "reload", "-c", native.options.NginxConfig, "-p", "/"); err != nil {
		return err
	}
	return native.controller.Probe(ctx, []string{"nginx"})
}

var acmeWorkerCommand = func(ctx context.Context, binary string) *exec.Cmd {
	return exec.CommandContext(ctx, binary)
}

var openACMEProgressPipe = newACMEProgressPipe

func runACMEWorker(ctx context.Context, request acmejob.Request) (acmejob.Result, error) {
	return runACMEWorkerWithProgress(ctx, request, nil)
}

// runACMEWorkerWithProgress keeps the worker's stdout protocol separate from
// optional FD3 telemetry. A missing, closed, or malformed telemetry stream
// never changes the issuance result.
func runACMEWorkerWithProgress(ctx context.Context, request acmejob.Request, progress func(acmejob.ProgressEvent)) (acmejob.Result, error) {
	body, err := json.Marshal(request)
	if err != nil {
		return acmejob.Result{}, acmejob.ErrWorker
	}
	command := acmeWorkerCommand(ctx, envOr("SB_ACME_BIN", "sb-acme"))
	command.Stdin = bytes.NewReader(body)
	command.Env = []string{"GOMAXPROCS=1", "GOMEMLIMIT=48MiB", "GOGC=50", "PATH=/usr/local/bin:/usr/bin:/bin"}
	// Production workers run in Linux. Windows needs SystemRoot solely for the
	// local helper-process regression; no ambient proxy or credential settings
	// are inherited into the worker.
	if runtime.GOOS == "windows" && os.Getenv("SystemRoot") != "" {
		command.Env = append(command.Env, "SystemRoot="+os.Getenv("SystemRoot"))
	}
	var progressReader, progressWriter *os.File
	var progressDone chan struct{}
	if progress != nil {
		if reader, writer, ok := openACMEProgressPipe(); ok {
			progressReader, progressWriter = reader, writer
			command.ExtraFiles = append(command.ExtraFiles, progressWriter)
			command.Env = append(command.Env, "SB_ACME_PROGRESS_FD=3")
			progressDone = make(chan struct{})
			go func() {
				defer close(progressDone)
				defer progressReader.Close()
				acmejob.ConsumeProgress(progressReader, progress)
			}()
		}
	}
	output := &limitedWriter{remaining: 256 << 10}
	command.Stdout = output
	command.Stderr = io.Discard
	startErr := command.Start()
	if progressWriter != nil {
		_ = progressWriter.Close()
	}
	if startErr != nil {
		if progressReader != nil {
			_ = progressReader.Close()
		}
		if progressDone != nil {
			<-progressDone
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return acmejob.Result{}, acmejob.ErrWorkerTimeout
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return acmejob.Result{}, acmejob.ErrWorkerCancel
		}
		return acmejob.Result{}, acmejob.ErrWorkerStart
	}
	runErr := command.Wait()
	waitACMEProgress(progressReader, progressDone)
	if runErr != nil {
		var exit *exec.ExitError
		if errors.As(runErr, &exit) {
			failure := acmejob.WorkerFailure(exit.ExitCode())
			if diagnostic, ok := acmejob.DecodeDiagnostic([]byte(output.String()), exit.ExitCode()); ok {
				return acmejob.Result{}, acmejob.WrapDiagnostic(failure, diagnostic)
			}
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return acmejob.Result{}, acmejob.ErrWorkerTimeout
		}
		if errors.Is(ctx.Err(), context.Canceled) {
			return acmejob.Result{}, acmejob.ErrWorkerCancel
		}
		if exit != nil {
			return acmejob.Result{}, acmejob.WorkerFailure(exit.ExitCode())
		}
		return acmejob.Result{}, acmejob.ErrWorkerStart
	}
	var result acmejob.Result
	if err := json.Unmarshal([]byte(output.String()), &result); err != nil {
		return result, acmejob.ErrWorkerOutput
	}
	return result, nil
}

// waitACMEProgress never lets a telemetry-only inherited descriptor delay an
// ACME result. A descendant that kept FD3 open is detached after the short
// drain grace; closing the local reader releases its bounded drain goroutine.
func waitACMEProgress(reader *os.File, done <-chan struct{}) {
	if reader == nil || done == nil {
		return
	}
	select {
	case <-done:
		return
	case <-time.After(100 * time.Millisecond):
		_ = reader.Close()
		<-done
	}
}
