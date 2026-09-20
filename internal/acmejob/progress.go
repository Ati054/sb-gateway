package acmejob

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	progressVersion       = 1
	progressMaxLineBytes  = 128
	progressMaxInputLines = 32
)

// ProgressStage is an allowlisted, non-secret transition in one ACME job. It
// deliberately contains neither DNS/CA values nor an upstream error string.
type ProgressStage string

const (
	ProgressPreparing           ProgressStage = "preparing"
	ProgressCARegistration      ProgressStage = "ca_registration"
	ProgressDNSPresent          ProgressStage = "dns_present"
	ProgressDNSPrecheck         ProgressStage = "dns_precheck"
	ProgressCAObtain            ProgressStage = "ca_obtain"
	ProgressCertificateReceived ProgressStage = "certificate_received"
	ProgressLocalInstall        ProgressStage = "local_install"
)

// ProgressEvent travels on the best-effort worker progress pipe, never on the
// strict stdout result protocol. The control plane assigns the timestamp.
type ProgressEvent struct {
	Version int           `json:"version"`
	Stage   ProgressStage `json:"stage"`
}

// Valid permits the controller-only local install stage as well as worker
// stages. It is used for in-memory UI state, not for decoding FD3.
func (event ProgressEvent) Valid() bool {
	if event.Version != progressVersion {
		return false
	}
	switch event.Stage {
	case ProgressPreparing, ProgressCARegistration, ProgressDNSPresent, ProgressDNSPrecheck, ProgressCAObtain, ProgressCertificateReceived, ProgressLocalInstall:
		return true
	default:
		return false
	}
}

func (event ProgressEvent) validWorkerEvent() bool {
	return event.Valid() && event.Stage != ProgressLocalInstall
}

// EncodeProgress emits a strict bounded line for a non-blocking pipe write.
func EncodeProgress(event ProgressEvent) ([]byte, error) {
	if !event.validWorkerEvent() {
		return nil, errors.New("invalid ACME progress event")
	}
	return json.Marshal(event)
}

// DecodeProgress accepts one strict event only. Unknown fields and trailing
// values are rejected so a compromised or incompatible worker cannot smuggle
// arbitrary data into panel state.
func DecodeProgress(body []byte) (ProgressEvent, bool) {
	if len(body) == 0 || len(body) > progressMaxLineBytes {
		return ProgressEvent{}, false
	}
	var event ProgressEvent
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&event) != nil || !event.validWorkerEvent() {
		return ProgressEvent{}, false
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return ProgressEvent{}, false
	}
	return event, true
}

// ConsumeProgress drains an untrusted best-effort pipe. A malformed, oversize
// or noisy stream affects only telemetry: it cannot block or fail issuance.
func ConsumeProgress(input io.Reader, report func(ProgressEvent)) {
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, progressMaxLineBytes), progressMaxLineBytes)
	for count := 0; count < progressMaxInputLines && scanner.Scan(); count++ {
		event, ok := DecodeProgress(scanner.Bytes())
		if !ok {
			return
		}
		if report != nil {
			report(event)
		}
	}
}
