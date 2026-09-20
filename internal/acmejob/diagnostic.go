package acmejob

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const diagnosticVersion = 1

// Diagnostic is the bounded, non-secret failure data the one-shot ACME worker
// may return on stdout. It deliberately excludes CA detail text, URLs,
// identifiers, DNS values and provider response bodies.
type Diagnostic struct {
	Version               int    `json:"version"`
	ExitCode              int    `json:"exit_code"`
	Stage                 string `json:"stage"`
	Category              string `json:"category"`
	ProblemType           string `json:"problem_type,omitempty"`
	HTTPStatus            int    `json:"http_status,omitempty"`
	RetryAfterSeconds     int64  `json:"retry_after_seconds,omitempty"`
	RetryAfterNanos       int    `json:"retry_after_nanos,omitempty"`
	RetryAfterUnsupported bool   `json:"retry_after_unsupported,omitempty"`
}

type diagnosticEnvelope struct {
	Diagnostic *Diagnostic `json:"diagnostic"`
}

// WrapDiagnostic retains the safe exit-stage error while making a validated
// diagnostic available to the control plane. The original upstream error is
// intentionally never retained or sent across process boundaries.
func WrapDiagnostic(cause error, diagnostic Diagnostic) error {
	return &diagnosticError{cause: cause, diagnostic: diagnostic}
}

type diagnosticError struct {
	cause      error
	diagnostic Diagnostic
}

func (e *diagnosticError) Error() string { return e.cause.Error() }
func (e *diagnosticError) Unwrap() error { return e.cause }

func DiagnosticFromError(err error) (Diagnostic, bool) {
	var wrapped *diagnosticError
	if !errors.As(err, &wrapped) || !wrapped.diagnostic.validForExit(wrapped.diagnostic.ExitCode) {
		return Diagnostic{}, false
	}
	return wrapped.diagnostic, true
}

// EncodeDiagnostic serializes only a schema-validated envelope. It is used
// only for a nonzero worker exit; successful output remains Result for IPC
// compatibility.
func EncodeDiagnostic(diagnostic Diagnostic) ([]byte, error) {
	if !diagnostic.validForExit(diagnostic.ExitCode) {
		return nil, errors.New("invalid ACME diagnostic")
	}
	return json.Marshal(diagnosticEnvelope{Diagnostic: &diagnostic})
}

// DecodeDiagnostic accepts only the current strict schema. An old worker with
// empty stdout (or malformed/untrusted stdout) safely falls back to its fixed
// exit code in the controller.
func DecodeDiagnostic(body []byte, exitCode int) (Diagnostic, bool) {
	var envelope diagnosticEnvelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&envelope) != nil || envelope.Diagnostic == nil || envelope.Diagnostic.ExitCode != exitCode || !envelope.Diagnostic.validForExit(exitCode) {
		return Diagnostic{}, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return Diagnostic{}, false
	}
	return *envelope.Diagnostic, true
}

func (diagnostic Diagnostic) validForExit(exitCode int) bool {
	if !validWorkerExit(exitCode) || diagnostic.Version != diagnosticVersion || diagnostic.ExitCode != exitCode || !validDiagnosticStage(diagnostic.Stage) || !validDiagnosticCategory(diagnostic.Category) || (diagnostic.ProblemType != "" && !validDiagnosticProblemType(diagnostic.ProblemType)) {
		return false
	}
	if diagnostic.HTTPStatus != 0 && (diagnostic.HTTPStatus < 400 || diagnostic.HTTPStatus > 599) {
		return false
	}
	if diagnostic.RetryAfterSeconds < 0 || diagnostic.RetryAfterNanos < 0 || diagnostic.RetryAfterNanos >= 1_000_000_000 || (diagnostic.RetryAfterSeconds != 0 && diagnostic.Category != "ca_rate_limited") || (diagnostic.RetryAfterNanos != 0 && diagnostic.Category != "ca_rate_limited") {
		return false
	}
	if diagnostic.RetryAfterUnsupported && (diagnostic.Category != "ca_rate_limited" || diagnostic.RetryAfterSeconds != 0 || diagnostic.RetryAfterNanos != 0) {
		return false
	}
	if !validDiagnosticCategoryForExit(diagnostic.Category, exitCode) {
		return false
	}
	return true
}

func validDiagnosticCategoryForExit(category string, exitCode int) bool {
	switch category {
	case "ca_rate_limited", "ca_caa", "ca_dns", "ca_connection", "ca_tls", "ca_unauthorized", "ca_rejected_identifier", "ca_server_internal", "ca_other":
		// Certificate.Obtain may aggregate a typed CA error with a provider or
		// propagation error for another SAN. Preserve the safe CA diagnostic for
		// every operational worker exit instead of losing a Retry-After merely
		// because progress selected provider/propagation as the exit code.
		return exitCode != WorkerExitInput && exitCode != WorkerExitOutput
	default:
		return true
	}
}

func validDiagnosticProblemType(problemType string) bool {
	switch problemType {
	case "rate_limited", "caa", "dns", "connection", "tls", "unauthorized", "rejected_identifier", "server_internal", "account_does_not_exist", "bad_csr", "bad_nonce", "bad_public_key", "bad_signature_algorithm", "external_account_required", "incorrect_response", "invalid_contact", "malformed", "order_not_ready", "unsupported_contact", "unsupported_identifier", "user_action_required", "invalid_profile", "already_replaced":
		return true
	default:
		return false
	}
}

func validWorkerExit(exitCode int) bool {
	switch exitCode {
	case WorkerExitInput, WorkerExitRegistration, WorkerExitProvider, WorkerExitValidation, WorkerExitOutput, WorkerExitDelegation, WorkerExitPropagation:
		return true
	default:
		return false
	}
}

func validDiagnosticStage(stage string) bool {
	switch stage {
	case "before_dns_check", "pending_dns", "after_dns_check":
		return true
	default:
		return false
	}
}

func validDiagnosticCategory(category string) bool {
	switch category {
	case "ca_rate_limited", "ca_caa", "ca_dns", "ca_connection", "ca_tls", "ca_unauthorized", "ca_rejected_identifier", "ca_server_internal", "ca_other", "transport_timeout", "transport_cancelled", "transport_tls", "transport_connection", "transport_dns", "unknown":
		return true
	default:
		return false
	}
}
