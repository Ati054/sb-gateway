package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
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
	"os"
	"os/exec"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/acme"
	"github.com/go-acme/lego/v5/challenge"
	legolog "github.com/go-acme/lego/v5/log"
	"github.com/go-acme/lego/v5/providers/dns/yandexcloud"
	"github.com/sb-gateway/sb-gateway/internal/acmejob"
)

func workerTestResolver() acmejob.RecursiveResolver {
	return acmejob.RecursiveResolver{Type: "https", Server: "127.0.0.1", ServerName: "example.com", ServerPort: 443, Path: "/dns-query", DoTFallback: true}
}

type stageTestProvider struct {
	presentErr error
	cleanupErr error
}

func (p *stageTestProvider) Present(context.Context, string, string, string) error {
	return p.presentErr
}
func (p *stageTestProvider) CleanUp(context.Context, string, string, string) error {
	return p.cleanupErr
}

type stageTestProviderTimeout struct{ *stageTestProvider }

func (*stageTestProviderTimeout) Timeout() (time.Duration, time.Duration) {
	return 6 * time.Minute, 10 * time.Second
}

type stageTestProviderSequential struct{ *stageTestProvider }

func (*stageTestProviderSequential) Sequential() time.Duration { return 11 * time.Second }

type stageTestProviderTimeoutSequential struct{ *stageTestProvider }

func (*stageTestProviderTimeoutSequential) Timeout() (time.Duration, time.Duration) {
	return 6 * time.Minute, 10 * time.Second
}
func (*stageTestProviderTimeoutSequential) Sequential() time.Duration { return 11 * time.Second }

func TestTrackedProviderPreservesOptionalInterfacesAndStages(t *testing.T) {
	for name, test := range map[string]struct {
		provider   challenge.Provider
		timeout    bool
		sequential bool
	}{
		"none":       {provider: &stageTestProvider{}},
		"Timeout":    {provider: &stageTestProviderTimeout{&stageTestProvider{}}, timeout: true},
		"Sequential": {provider: &stageTestProviderSequential{&stageTestProvider{}}, sequential: true},
		"both":       {provider: &stageTestProviderTimeoutSequential{&stageTestProvider{}}, timeout: true, sequential: true},
	} {
		t.Run(name, func(t *testing.T) {
			wrapped, _ := trackProvider(test.provider)
			timeout, hasTimeout := wrapped.(challenge.ProviderTimeout)
			if hasTimeout != test.timeout {
				t.Fatalf("Timeout presence: %t", hasTimeout)
			}
			if hasTimeout {
				if got, interval := timeout.Timeout(); got != 6*time.Minute || interval != 10*time.Second {
					t.Fatalf("Timeout: %v %v", got, interval)
				}
			}
			sequential, hasSequential := wrapped.(providerSequential)
			if hasSequential != test.sequential {
				t.Fatalf("Sequential presence: %t", hasSequential)
			}
			if hasSequential && sequential.Sequential() != 11*time.Second {
				t.Fatal("Sequential value changed")
			}
		})
	}

	secret := errors.New("provider echoed secret")
	wrapped, progress := trackProvider(&stageTestProviderTimeoutSequential{&stageTestProvider{presentErr: secret}})
	if err := wrapped.Present(context.Background(), "api.example.com", "", ""); !errors.Is(err, secret) {
		t.Fatalf("Present: %v", err)
	}
	if code := progress.obtainFailureExitCode(); code != acmejob.WorkerExitProvider {
		t.Fatalf("provider stage: %d", code)
	}

	cleanup, cleanupProgress := trackProvider(&stageTestProvider{cleanupErr: secret})
	if err := cleanup.CleanUp(context.Background(), "api.example.com", "", ""); !errors.Is(err, secret) {
		t.Fatalf("CleanUp: %v", err)
	}
	if code := cleanupProgress.obtainFailureExitCode(); code == acmejob.WorkerExitProvider {
		t.Fatalf("cleanup changed failure stage: %d", code)
	}

	propagation := &issuanceProgress{}
	if ok, err := propagation.preCheck(context.Background(), "", "first.example.", "first", func(context.Context, string, string) (bool, error) {
		return true, nil
	}); !ok || err != nil {
		t.Fatal("successful first challenge changed")
	}
	if ok, err := propagation.preCheck(context.Background(), "", "second.example.", "second", func(context.Context, string, string) (bool, error) {
		return false, errors.New("DNS response contained secret")
	}); ok || err == nil {
		t.Fatal("precheck result changed")
	}
	if code := propagation.obtainFailureExitCode(); code != acmejob.WorkerExitPropagation {
		t.Fatalf("propagation stage: %d", code)
	}
}

func TestWorkerProgressReporterDeduplicatesConcurrentDNSCallbacks(t *testing.T) {
	var mu sync.Mutex
	var events []acmejob.ProgressStage
	reporter := &progressReporter{write: func(body []byte) {
		event, ok := acmejob.DecodeProgress(bytes.TrimSpace(body))
		if !ok {
			t.Errorf("invalid progress line: %q", body)
			return
		}
		mu.Lock()
		events = append(events, event.Stage)
		mu.Unlock()
	}}
	reporter.report(acmejob.ProgressPreparing)
	reporter.report(acmejob.ProgressCARegistration)
	reporter.report(acmejob.ProgressCAObtain)
	provider, progress := trackProvider(&stageTestProvider{}, reporter)
	if err := provider.Present(context.Background(), "api.example.com", "token", "key-auth"); err != nil {
		t.Fatal(err)
	}
	var callbacks sync.WaitGroup
	for range 200 {
		callbacks.Add(1)
		go func() {
			defer callbacks.Done()
			_, _ = progress.preCheck(context.Background(), "", "_acme-challenge.example.", "value", func(context.Context, string, string) (bool, error) {
				return false, nil
			})
		}()
	}
	callbacks.Wait()
	reporter.report(acmejob.ProgressCertificateReceived)

	want := []acmejob.ProgressStage{
		acmejob.ProgressPreparing, acmejob.ProgressCARegistration, acmejob.ProgressCAObtain,
		acmejob.ProgressDNSPresent, acmejob.ProgressDNSPrecheck, acmejob.ProgressCertificateReceived,
	}
	if !slices.Equal(events, want) {
		t.Fatalf("progress events = %#v, want %#v", events, want)
	}
}

func TestWorkerRejectsMalformedInputWithoutSecretsInOutput(t *testing.T) {
	for _, input := range []string{`{}`, `{"unexpected":"secret"}`, `{"settings":{"provider":"exec"},"credentials":{"token":"secret"}}`} {
		var output bytes.Buffer
		code := run(context.Background(), bytes.NewBufferString(input), &output)
		diagnostic, ok := acmejob.DecodeDiagnostic(output.Bytes(), code)
		if code != acmejob.WorkerExitInput || !ok || diagnostic.Stage != "before_dns_check" || diagnostic.Category != "unknown" || bytes.Contains(output.Bytes(), []byte("secret")) {
			t.Fatal("unsafe worker output", code, output.String())
		}
	}
}

func TestWorkerLoggingProcessHelper(t *testing.T) {
	mode := os.Getenv("SB_ACME_LOG_PROCESS")
	if mode == "" {
		return
	}

	if mode == "legacy" {
		// This exactly reproduces the pre-fix main configuration: only the
		// standard loggers were discarded, while lego kept its stdout logger.
		stdlog.SetOutput(io.Discard)
		slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	} else {
		configureWorkerLogging()
	}
	const logSecret = "synthetic-logger-secret"
	stdlog.Print(logSecret)
	slog.Info("synthetic worker log", slog.String("secret", logSecret))
	legolog.Info("synthetic lego info", slog.String("secret", logSecret))
	legolog.Warn("synthetic lego warning", slog.String("secret", logSecret))
	legolog.Error("synthetic lego error", slog.String("secret", logSecret))

	if mode == "success" || mode == "legacy" {
		if err := json.NewEncoder(os.Stdout).Encode(acmejob.Result{Certificate: "synthetic-certificate", PrivateKey: "synthetic-private-key"}); err != nil {
			os.Exit(acmejob.WorkerExitOutput)
		}
		os.Exit(0)
	}
	os.Exit(fail(os.Stdout, acmejob.WorkerExitInput, nil, nil))
}

func TestWorkerLoggingCannotContaminateJSONProtocol(t *testing.T) {
	for _, test := range []struct {
		name         string
		mode         string
		code         int
		body         []byte
		contaminated bool
	}{
		{
			name: "failure", mode: "failure", code: acmejob.WorkerExitInput,
			body: func() []byte {
				body, err := acmejob.EncodeDiagnostic(acmejob.Diagnostic{Version: 1, ExitCode: acmejob.WorkerExitInput, Stage: "before_dns_check", Category: "unknown"})
				if err != nil {
					t.Fatal(err)
				}
				return append(body, '\n')
			}(),
		},
		{
			name: "success", mode: "success", code: 0,
			body: []byte("{\"certificate\":\"synthetic-certificate\",\"private_key\":\"synthetic-private-key\"}\n"),
		},
		{
			name: "legacy_stdout_is_contaminated", mode: "legacy", code: 0,
			body:         []byte("{\"certificate\":\"synthetic-certificate\",\"private_key\":\"synthetic-private-key\"}\n"),
			contaminated: true,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestWorkerLoggingProcessHelper$", "--")
			cmd.Env = append(os.Environ(), "SB_ACME_LOG_PROCESS="+test.mode)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			if test.code == 0 {
				if err != nil {
					t.Fatalf("success helper: %v", err)
				}
			} else {
				exitErr, ok := err.(*exec.ExitError)
				if !ok || exitErr.ExitCode() != test.code {
					t.Fatalf("failure helper: %v", err)
				}
			}
			if test.contaminated {
				if stderr.Len() != 0 || !bytes.Contains(stdout.Bytes(), []byte("synthetic-logger-secret")) || bytes.Equal(stdout.Bytes(), test.body) {
					t.Fatalf("legacy worker protocol unexpectedly stayed clean: stdout=%q stderr=%q", stdout.Bytes(), stderr.Bytes())
				}
				return
			}
			if stderr.Len() != 0 || bytes.Contains(stdout.Bytes(), []byte("synthetic-logger-secret")) || !bytes.Equal(stdout.Bytes(), test.body) {
				t.Fatalf("worker protocol was contaminated: stdout=%q stderr=%q", stdout.Bytes(), stderr.Bytes())
			}
		})
	}
}

func TestWorkerDiagnosticClassifiesTypedACMEAndTransportErrorsWithoutDetails(t *testing.T) {
	secret := "upstream detail https://ca.example/secret-token"
	rate := &acme.RateLimitedError{ProblemDetails: &acme.ProblemDetails{Type: acme.RateLimitedErrorType, HTTPStatus: 429, Detail: secret, URL: secret, Instance: secret}, RetryAfter: 2*time.Hour + 500*time.Millisecond}
	diagnostic := diagnosticForFailure(acmejob.WorkerExitValidation, nil, rate)
	if diagnostic.Stage != "before_dns_check" || diagnostic.Category != "ca_rate_limited" || diagnostic.ProblemType != "rate_limited" || diagnostic.HTTPStatus != 429 || diagnostic.RetryAfterSeconds != 7200 || diagnostic.RetryAfterNanos != 500_000_000 {
		t.Fatalf("rate-limit diagnostic: %#v", diagnostic)
	}
	body, err := acmejob.EncodeDiagnostic(diagnostic)
	if err != nil || bytes.Contains(body, []byte(secret)) {
		t.Fatalf("unsafe diagnostic: %s %v", body, err)
	}
	if decoded, ok := acmejob.DecodeDiagnostic(body, acmejob.WorkerExitValidation); !ok || decoded != diagnostic {
		t.Fatalf("diagnostic round trip: %#v %t", decoded, ok)
	}
	shortRate := &acme.RateLimitedError{ProblemDetails: &acme.ProblemDetails{Type: acme.RateLimitedErrorType, HTTPStatus: 429}, RetryAfter: time.Minute}
	longRate := &acme.RateLimitedError{ProblemDetails: &acme.ProblemDetails{Type: acme.RateLimitedErrorType, HTTPStatus: 429}, RetryAfter: 3 * time.Hour}
	if got := diagnosticForFailure(acmejob.WorkerExitValidation, nil, errors.Join(shortRate, longRate)); got.Category != "ca_rate_limited" || got.RetryAfterSeconds != int64((3*time.Hour)/time.Second) {
		t.Fatalf("largest rate limit was lost: %#v", got)
	}
	// A multi-SAN obtain can have a Present/propagation failure for one name and
	// a typed CA rate limit for another. The worker's operational exit remains
	// provider, while the bounded rate-limit diagnostic must remain usable.
	providerProgress := &issuanceProgress{providerFailed: true}
	if got := diagnosticForFailure(acmejob.WorkerExitProvider, providerProgress, errors.Join(errors.New("provider failure"), longRate)); got.Category != "ca_rate_limited" || got.RetryAfterSeconds != int64((3*time.Hour)/time.Second) {
		t.Fatalf("mixed provider/rate-limit diagnostic was lost: %#v", got)
	} else if body, err := acmejob.EncodeDiagnostic(got); err != nil {
		t.Fatalf("mixed provider/rate-limit diagnostic rejected: %v", err)
	} else if _, ok := acmejob.DecodeDiagnostic(body, acmejob.WorkerExitProvider); !ok {
		t.Fatal("mixed provider/rate-limit diagnostic did not round-trip")
	}

	pending := &issuanceProgress{}
	_, _ = pending.preCheck(context.Background(), "", "pending.example.", "value", func(context.Context, string, string) (bool, error) { return false, context.DeadlineExceeded })
	if got := diagnosticForFailure(acmejob.WorkerExitPropagation, pending, context.DeadlineExceeded); got.Stage != "pending_dns" || got.Category != "transport_timeout" {
		t.Fatalf("pending timeout: %#v", got)
	}
	if got := diagnosticForFailure(acmejob.WorkerExitValidation, nil, tls.RecordHeaderError{}); got.Category != "transport_tls" {
		t.Fatalf("TLS record header: %#v", got)
	}
	if got := diagnosticForFailure(acmejob.WorkerExitValidation, nil, &net.OpError{Op: "dial", Err: timeoutTestError{}}); got.Category != "transport_timeout" {
		t.Fatalf("connection timeout: %#v", got)
	}
}

type timeoutTestError struct{}

func (timeoutTestError) Error() string   { return "synthetic timeout" }
func (timeoutTestError) Timeout() bool   { return true }
func (timeoutTestError) Temporary() bool { return true }
func TestProviderAdaptersConstructWithoutNetwork(t *testing.T) {
	for _, name := range []string{"gcore", "regru", "cloudflare"} {
		req := acmejob.Request{Settings: acmejob.Settings{Provider: name}, Credentials: map[string]string{"token": "test", "username": "test", "password": "test"}}
		if provider, err := providerFor(req); err != nil || provider == nil {
			t.Fatal(name, err)
		}
	}
}

func TestDirectProviderAdaptersUseSharedPropagationBudget(t *testing.T) {
	for name, want := range map[string]time.Duration{
		"gcore": 90 * time.Minute, "cloudflare": 90 * time.Minute, "regru": 4*time.Hour + 15*time.Minute,
	} {
		t.Run(name, func(t *testing.T) {
			credentials := map[string]string{"token": "test"}
			if name == "regru" {
				credentials = map[string]string{"username": "test", "password": "test"}
			}
			provider, err := providerFor(acmejob.Request{Settings: acmejob.Settings{Provider: name}, Credentials: credentials})
			if err != nil {
				t.Fatal(err)
			}
			timed, ok := provider.(challenge.ProviderTimeout)
			if !ok {
				t.Fatal("provider lost propagation timeout")
			}
			if timeout, interval := timed.Timeout(); timeout != want || interval != acmejob.PropagationPollingInterval {
				t.Fatalf("timeout: got %v/%v want %v/%v", timeout, interval, want, acmejob.PropagationPollingInterval)
			}
		})
	}
}

func TestACMEDNSAdapterAndPreflightBeforeCA(t *testing.T) {
	req := acmejob.Request{Settings: acmejob.Settings{Provider: "acmedns", ACMEDNSServer: "https://auth.example.net", Email: "admin@example.com", TermsAccepted: true, Domains: []string{"api.example.com"}}, Credentials: map[string]string{"accounts": `{"api.example.com":{"username":"test-user","password":"test-secret","subdomain":"record1","fulldomain":"record1.auth.example.net"}}`}, RecursiveResolver: workerTestResolver()}
	if provider, err := providerFor(req); err != nil || provider == nil {
		t.Fatal("ACME-DNS construction", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	input, _ := json.Marshal(req)
	var output bytes.Buffer
	// No account key: returning delegation code proves preflight precedes CA setup.
	code := run(ctx, bytes.NewReader(input), &output)
	diagnostic, ok := acmejob.DecodeDiagnostic(output.Bytes(), code)
	if code != 7 || !ok || diagnostic.Stage != "before_dns_check" || bytes.Contains(output.Bytes(), []byte("test-secret")) {
		t.Fatal("unsafe preflight", code)
	}
	req.Settings.Provider = "unsupported"
	if provider, err := providerFor(req); err == nil || provider != nil {
		t.Fatal("unknown provider fell back")
	}
}

func TestYandexAdapterConstructsWithRenewableKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(map[string]string{"id": "synthetickey", "service_account_id": "syntheticaccount", "private_key": string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))})
	req := acmejob.Request{Settings: acmejob.Settings{Provider: "yandexcloud"}, Credentials: map[string]string{"folder_id": "syntheticfolder", "service_account_key": string(raw)}}
	if err := acmejob.ValidateCredentials(req.Settings.Provider, req.Credentials); err != nil {
		t.Fatal(err)
	}
	original := newYandexDNSProvider
	defer func() { newYandexDNSProvider = original }()
	var got *yandexcloud.Config
	newYandexDNSProvider = func(config *yandexcloud.Config) (challenge.Provider, error) {
		copied := *config
		got = &copied
		return &stageTestProvider{}, nil
	}
	if provider, err := providerFor(req); err != nil || provider == nil {
		t.Fatal("Yandex provider construction failed", err)
	}
	if got == nil || got.FolderID != "syntheticfolder" || got.IamToken != base64.StdEncoding.EncodeToString(raw) || got.TTL != 120 || got.PropagationTimeout != acmejob.PropagationTimeout(req.Settings) || got.PollingInterval != acmejob.PropagationPollingInterval {
		t.Fatal("Yandex provider received an unexpected configuration")
	}
}
