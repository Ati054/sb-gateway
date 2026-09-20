// sb-acme is launched on demand, never as a resident daemon. Secrets travel
// over inherited pipes, not argv, environment variables or diagnostic logs.
package main

import (
	"context"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	stdlog "log"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/certcrypto"
	"github.com/go-acme/lego/v5/certificate"
	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/challenge/dns01"
	"github.com/go-acme/lego/v5/lego"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/providers/dns/cloudflare"
	"github.com/go-acme/lego/v5/providers/dns/gcore"
	"github.com/go-acme/lego/v5/providers/dns/regru"
	"github.com/go-acme/lego/v5/providers/dns/yandexcloud"
	"github.com/go-acme/lego/v5/registration"
	"github.com/sb-gateway/sb-gateway/internal/acmedns"
	"github.com/sb-gateway/sb-gateway/internal/acmejob"
	"github.com/sb-gateway/sb-gateway/internal/policydns"
)

type account struct {
	email        string
	key          crypto.Signer
	registration *acme.ExtendedAccount
}

var newYandexDNSProvider = func(config *yandexcloud.Config) (challenge.Provider, error) {
	return yandexcloud.NewDNSProviderConfig(config)
}

func (a *account) GetEmail() string                       { return a.email }
func (a *account) GetPrivateKey() crypto.Signer           { return a.key }
func (a *account) GetRegistration() *acme.ExtendedAccount { return a.registration }

// progressReporter writes a handful of allowlisted events to the optional
// non-blocking FD3 pipe. It is never part of the stdout result protocol.
type progressReporter struct {
	mu      sync.Mutex
	emitted map[acmejob.ProgressStage]bool
	highest int
	write   func([]byte)
}

func progressStageOrder(stage acmejob.ProgressStage) int {
	switch stage {
	case acmejob.ProgressPreparing:
		return 1
	case acmejob.ProgressCARegistration:
		return 2
	case acmejob.ProgressCAObtain:
		return 3
	case acmejob.ProgressDNSPresent:
		return 4
	case acmejob.ProgressDNSPrecheck:
		return 5
	case acmejob.ProgressCertificateReceived:
		return 6
	default:
		return 0
	}
}

func (p *progressReporter) report(stage acmejob.ProgressStage) {
	if p == nil || p.write == nil {
		return
	}
	body, err := acmejob.EncodeProgress(acmejob.ProgressEvent{Version: 1, Stage: stage})
	if err != nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.emitted == nil {
		p.emitted = map[acmejob.ProgressStage]bool{}
	}
	order := progressStageOrder(stage)
	if order == 0 || p.emitted[stage] || order < p.highest {
		return
	}
	p.emitted[stage] = true
	p.highest = order
	p.write(append(body, '\n'))
}

type providerSequential interface {
	Sequential() time.Duration
}

type issuanceProgress struct {
	mu                   sync.Mutex
	providerFailed       bool
	propagationAttempted map[string]bool
	propagationConfirmed map[string]bool
	reporter             *progressReporter
}

func (p *issuanceProgress) diagnosticStage() string {
	if p == nil {
		return "before_dns_check"
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.propagationAttempted) == 0 {
		return "before_dns_check"
	}
	for challenge := range p.propagationAttempted {
		if !p.propagationConfirmed[challenge] {
			return "pending_dns"
		}
	}
	return "after_dns_check"
}

func (p *issuanceProgress) noteProvider(err error) {
	if err == nil {
		return
	}
	p.mu.Lock()
	p.providerFailed = true
	p.mu.Unlock()
}

func (p *issuanceProgress) preCheck(ctx context.Context, _ string, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
	p.reporter.report(acmejob.ProgressDNSPrecheck)
	ok, err := check(ctx, fqdn, value)
	challenge := fqdn + "\x00" + value
	p.mu.Lock()
	if p.propagationAttempted == nil {
		p.propagationAttempted = map[string]bool{}
		p.propagationConfirmed = map[string]bool{}
	}
	p.propagationAttempted[challenge] = true
	if err == nil && ok {
		p.propagationConfirmed[challenge] = true
	}
	p.mu.Unlock()
	return ok, err
}

func (p *issuanceProgress) obtainFailureExitCode() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.providerFailed {
		return acmejob.WorkerExitProvider
	}
	for challenge := range p.propagationAttempted {
		if !p.propagationConfirmed[challenge] {
			return acmejob.WorkerExitPropagation
		}
	}
	return acmejob.WorkerExitValidation
}

type trackedProvider struct {
	provider challenge.Provider
	progress *issuanceProgress
}

func (p *trackedProvider) Present(ctx context.Context, domain, token, keyAuth string) error {
	p.progress.reporter.report(acmejob.ProgressDNSPresent)
	err := p.provider.Present(ctx, domain, token, keyAuth)
	p.progress.noteProvider(err)
	return err
}

func (p *trackedProvider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	return p.provider.CleanUp(ctx, domain, token, keyAuth)
}

type trackedProviderTimeout struct {
	*trackedProvider
	timeout challenge.ProviderTimeout
}

func (p *trackedProviderTimeout) Timeout() (time.Duration, time.Duration) {
	return p.timeout.Timeout()
}

type trackedProviderSequential struct {
	*trackedProvider
	sequential providerSequential
}

func (p *trackedProviderSequential) Sequential() time.Duration {
	return p.sequential.Sequential()
}

type trackedProviderTimeoutSequential struct {
	*trackedProvider
	timeout    challenge.ProviderTimeout
	sequential providerSequential
}

func (p *trackedProviderTimeoutSequential) Timeout() (time.Duration, time.Duration) {
	return p.timeout.Timeout()
}

func (p *trackedProviderTimeoutSequential) Sequential() time.Duration {
	return p.sequential.Sequential()
}

func trackProvider(provider challenge.Provider, reporters ...*progressReporter) (challenge.Provider, *issuanceProgress) {
	var reporter *progressReporter
	if len(reporters) > 0 {
		reporter = reporters[0]
	}
	progress := &issuanceProgress{reporter: reporter}
	tracked := &trackedProvider{provider: provider, progress: progress}
	timeout, hasTimeout := provider.(challenge.ProviderTimeout)
	sequential, hasSequential := provider.(providerSequential)
	switch {
	case hasTimeout && hasSequential:
		return &trackedProviderTimeoutSequential{trackedProvider: tracked, timeout: timeout, sequential: sequential}, progress
	case hasTimeout:
		return &trackedProviderTimeout{trackedProvider: tracked, timeout: timeout}, progress
	case hasSequential:
		return &trackedProviderSequential{trackedProvider: tracked, sequential: sequential}, progress
	default:
		return tracked, progress
	}
}

func providerFor(r acmejob.Request) (challenge.Provider, error) {
	// Explicit config avoids provider endpoint/credential overrides from env.
	client := &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSHandshakeTimeout: 15 * time.Second}}
	propagationTimeout := acmejob.PropagationTimeout(r.Settings)
	switch r.Settings.Provider {
	case "acmedns":
		return acmedns.New(r.Settings, r.Credentials)
	case "yandexcloud":
		return newYandexDNSProvider(&yandexcloud.Config{IamToken: base64.StdEncoding.EncodeToString([]byte(r.Credentials["service_account_key"])), FolderID: r.Credentials["folder_id"], TTL: 120, PropagationTimeout: propagationTimeout, PollingInterval: acmejob.PropagationPollingInterval})
	case "gcore":
		return gcore.NewDNSProviderConfig(&gcore.Config{APIToken: r.Credentials["token"], TTL: 120, PropagationTimeout: propagationTimeout, PollingInterval: acmejob.PropagationPollingInterval, HTTPClient: client})
	case "regru":
		return regru.NewDNSProviderConfig(&regru.Config{Username: r.Credentials["username"], Password: r.Credentials["password"], TTL: 300, PropagationTimeout: propagationTimeout, PollingInterval: acmejob.PropagationPollingInterval, HTTPClient: client})
	case "cloudflare":
		return cloudflare.NewDNSProviderConfig(&cloudflare.Config{AuthToken: r.Credentials["token"], TTL: 120, PropagationTimeout: propagationTimeout, PollingInterval: acmejob.PropagationPollingInterval, HTTPClient: client})
	default:
		return nil, errors.New("unsupported DNS provider")
	}
}

func freshResolverConfig(resolver acmejob.RecursiveResolver) policydns.FreshResolverConfig {
	return policydns.FreshResolverConfig{
		Type: resolver.Type, Server: resolver.Server, ServerName: resolver.ServerName,
		ServerPort: resolver.ServerPort, Path: resolver.Path, DoTFallback: resolver.DoTFallback,
	}
}

func diagnosticForFailure(exitCode int, progress *issuanceProgress, err error) acmejob.Diagnostic {
	diagnostic := acmejob.Diagnostic{Version: 1, ExitCode: exitCode, Stage: progress.diagnosticStage(), Category: "unknown"}
	if err == nil {
		return diagnostic
	}
	if rateLimited, found, unsupported := largestRateLimited(err); found {
		setProblemDetails(&diagnostic, rateLimited.ProblemDetails)
		diagnostic.Category = "ca_rate_limited"
		if unsupported {
			diagnostic.RetryAfterUnsupported = true
		} else if rateLimited.RetryAfter > 0 {
			diagnostic.RetryAfterSeconds = int64(rateLimited.RetryAfter / time.Second)
			diagnostic.RetryAfterNanos = int(rateLimited.RetryAfter % time.Second)
		}
		return diagnostic
	}
	var details *acme.ProblemDetails
	if errors.As(err, &details) {
		setProblemDetails(&diagnostic, details)
		return diagnostic
	}
	if errors.Is(err, context.DeadlineExceeded) {
		diagnostic.Category = "transport_timeout"
		return diagnostic
	}
	if errors.Is(err, context.Canceled) {
		diagnostic.Category = "transport_cancelled"
		return diagnostic
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		diagnostic.Category = "transport_dns"
		return diagnostic
	}
	var recordHeaderErr tls.RecordHeaderError
	var recordHeaderPtr *tls.RecordHeaderError
	var unknownAuthorityErr x509.UnknownAuthorityError
	var invalidCertErr x509.CertificateInvalidError
	var hostnameErr x509.HostnameError
	if errors.As(err, &recordHeaderErr) || errors.As(err, &recordHeaderPtr) || errors.As(err, &unknownAuthorityErr) || errors.As(err, &invalidCertErr) || errors.As(err, &hostnameErr) {
		diagnostic.Category = "transport_tls"
		return diagnostic
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		diagnostic.Category = "transport_timeout"
		return diagnostic
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		diagnostic.Category = "transport_connection"
	}
	return diagnostic
}

func largestRateLimited(err error) (*acme.RateLimitedError, bool, bool) {
	var selected *acme.RateLimitedError
	unsupported := false
	walkErrorTree(err, func(current error) {
		rateLimited, ok := current.(*acme.RateLimitedError)
		if !ok {
			return
		}
		if rateLimited.RetryAfter < 0 {
			unsupported = true
		}
		if selected == nil || rateLimited.RetryAfter > selected.RetryAfter {
			selected = rateLimited
		}
	})
	return selected, selected != nil, unsupported
}

func walkErrorTree(err error, visit func(error)) {
	walkErrorTreeDepth(err, visit, 0)
}

// Error trees originate in lego and the standard library. Bound traversal so a
// malformed custom wrapper can never turn diagnostic classification into an
// unbounded walk.
func walkErrorTreeDepth(err error, visit func(error), depth int) {
	if err == nil || depth >= 64 {
		return
	}
	visit(err)
	if multiple, ok := err.(interface{ Unwrap() []error }); ok {
		for _, nested := range multiple.Unwrap() {
			walkErrorTreeDepth(nested, visit, depth+1)
		}
		return
	}
	if single, ok := err.(interface{ Unwrap() error }); ok {
		walkErrorTreeDepth(single.Unwrap(), visit, depth+1)
	}
}

func setProblemDetails(diagnostic *acmejob.Diagnostic, details *acme.ProblemDetails) {
	if details == nil {
		return
	}
	if details.HTTPStatus >= 400 && details.HTTPStatus <= 599 {
		diagnostic.HTTPStatus = details.HTTPStatus
	}
	switch details.Type {
	case acme.RateLimitedErrorType:
		diagnostic.Category = "ca_rate_limited"
		diagnostic.ProblemType = "rate_limited"
	case acme.CaaErrorType:
		diagnostic.Category = "ca_caa"
		diagnostic.ProblemType = "caa"
	case acme.DNSErrorType:
		diagnostic.Category = "ca_dns"
		diagnostic.ProblemType = "dns"
	case acme.ConnectionErrorType:
		diagnostic.Category = "ca_connection"
		diagnostic.ProblemType = "connection"
	case acme.TLSErrorType:
		diagnostic.Category = "ca_tls"
		diagnostic.ProblemType = "tls"
	case acme.UnauthorizedErrorType:
		diagnostic.Category = "ca_unauthorized"
		diagnostic.ProblemType = "unauthorized"
	case acme.RejectedIdentifierErrorType:
		diagnostic.Category = "ca_rejected_identifier"
		diagnostic.ProblemType = "rejected_identifier"
	case acme.ServerInternalErrorType:
		diagnostic.Category = "ca_server_internal"
		diagnostic.ProblemType = "server_internal"
	case acme.AccountDoesNotExistErrorType:
		diagnostic.ProblemType = "account_does_not_exist"
	case acme.BadCSRErrorType:
		diagnostic.ProblemType = "bad_csr"
	case acme.BadNonceErrorType:
		diagnostic.ProblemType = "bad_nonce"
	case acme.BadPublicKeyErrorType:
		diagnostic.ProblemType = "bad_public_key"
	case acme.BadSignatureAlgorithmErrorType:
		diagnostic.ProblemType = "bad_signature_algorithm"
	case acme.ExternalAccountRequiredErrorType:
		diagnostic.ProblemType = "external_account_required"
	case acme.IncorrectResponseErrorType:
		diagnostic.ProblemType = "incorrect_response"
	case acme.InvalidContactErrorType:
		diagnostic.ProblemType = "invalid_contact"
	case acme.MalformedErrorType:
		diagnostic.ProblemType = "malformed"
	case acme.OrderNotReadyErrorType:
		diagnostic.ProblemType = "order_not_ready"
	case acme.UnsupportedContactErrorType:
		diagnostic.ProblemType = "unsupported_contact"
	case acme.UnsupportedIdentifierErrorType:
		diagnostic.ProblemType = "unsupported_identifier"
	case acme.UserActionRequiredErrorType:
		diagnostic.ProblemType = "user_action_required"
	case acme.InvalidProfileErrorType:
		diagnostic.ProblemType = "invalid_profile"
	case acme.AlreadyReplacedErrorType:
		diagnostic.ProblemType = "already_replaced"
	default:
		diagnostic.Category = "ca_other"
	}
}

func fail(output io.Writer, exitCode int, progress *issuanceProgress, err error) int {
	diagnostic := diagnosticForFailure(exitCode, progress, err)
	body, encodeErr := acmejob.EncodeDiagnostic(diagnostic)
	if encodeErr != nil {
		return acmejob.WorkerExitOutput
	}
	if _, writeErr := output.Write(append(body, '\n')); writeErr != nil {
		return acmejob.WorkerExitOutput
	}
	return exitCode
}

func run(ctx context.Context, input io.Reader, output io.Writer) int {
	var req acmejob.Request
	decoder := json.NewDecoder(io.LimitReader(input, 64<<10))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&req) != nil || acmejob.ValidateConfiguration(req.Settings, req.Credentials) != nil || req.RecursiveResolver.Validate() != nil {
		return fail(output, acmejob.WorkerExitInput, nil, nil)
	}
	operation, cancel := context.WithTimeout(ctx, acmejob.WorkerTimeout(req.Settings))
	defer cancel()
	ctx = operation
	reporter := newWorkerProgressReporter()
	reporter.report(acmejob.ProgressPreparing)
	resolver, err := policydns.StartFreshResolver(ctx, freshResolverConfig(req.RecursiveResolver), policydns.FreshResolverOptions{Workers: 4, TCPSessions: 2, Timeout: 5 * time.Second})
	if err != nil {
		return fail(output, acmejob.WorkerExitProvider, nil, err)
	}
	defer resolver.Close()
	dns01.SetDefaultClient(dns01.NewClient(&dns01.Options{RecursiveNameservers: []string{resolver.Address()}}))
	provider, err := providerFor(req)
	if err != nil {
		return fail(output, acmejob.WorkerExitProvider, nil, err)
	}
	if checker, ok := provider.(*acmedns.Provider); ok {
		checker.SetLookup(resolver.LookupCNAME)
		if err := checker.Check(ctx); err != nil {
			return fail(output, acmejob.WorkerExitDelegation, nil, err)
		}
	}
	block, _ := pem.Decode([]byte(req.AccountKey))
	if block == nil {
		return fail(output, acmejob.WorkerExitInput, nil, nil)
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return fail(output, acmejob.WorkerExitInput, nil, err)
	}
	key, ok := raw.(crypto.Signer)
	if !ok {
		return fail(output, acmejob.WorkerExitInput, nil, nil)
	}
	user := &account{email: req.Settings.Email, key: key}
	cfg := lego.NewConfig(user)
	cfg.UserAgent = "SB-Gateway-ACME"
	cfg.HTTPClient = &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSHandshakeTimeout: 15 * time.Second}}
	client, err := lego.NewClient(cfg)
	if err != nil {
		return fail(output, acmejob.WorkerExitRegistration, nil, err)
	}
	provider, progress := trackProvider(provider, reporter)
	if err := client.Challenge.SetDNS01Provider(provider, dns01.WrapPreCheck(progress.preCheck)); err != nil {
		return fail(output, acmejob.WorkerExitProvider, progress, err)
	}
	reporter.report(acmejob.ProgressCARegistration)
	user.registration, err = client.Registration.Register(ctx, registration.RegisterOptions{TermsOfServiceAgreed: true})
	if err != nil {
		return fail(output, acmejob.WorkerExitRegistration, progress, err)
	}
	reporter.report(acmejob.ProgressCAObtain)
	cert, err := client.Certificate.Obtain(ctx, certificate.ObtainRequest{Domains: req.Settings.Domains, KeyType: certcrypto.EC256, Bundle: true})
	if err != nil {
		return fail(output, progress.obtainFailureExitCode(), progress, err)
	}
	reporter.report(acmejob.ProgressCertificateReceived)
	if json.NewEncoder(output).Encode(acmejob.Result{Certificate: string(cert.Certificate), PrivateKey: string(cert.PrivateKey)}) != nil {
		return acmejob.WorkerExitOutput
	}
	return 0
}

func configureWorkerLogging() {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stdlog.SetOutput(io.Discard)
	slog.SetDefault(logger)
	// lego owns a separate default logger which otherwise writes to stdout.
	// stdout is the worker's strict JSON-only protocol, so it must never carry
	// upstream log lines that could corrupt it or expose DNS-provider data.
	legolog.SetDefault(logger)
}

func main() {
	// Never log upstream errors: some DNS APIs echo their request credentials.
	configureWorkerLogging()
	os.Exit(run(context.Background(), os.Stdin, os.Stdout))
}
