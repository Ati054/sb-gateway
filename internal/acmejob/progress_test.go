package acmejob

import (
	"bytes"
	"strings"
	"testing"
)

func TestProgressCodecAllowsOnlyWorkerEnum(t *testing.T) {
	for _, stage := range []ProgressStage{
		ProgressPreparing, ProgressCARegistration, ProgressCAObtain,
		ProgressDNSPresent, ProgressDNSPrecheck, ProgressCertificateReceived,
	} {
		body, err := EncodeProgress(ProgressEvent{Version: 1, Stage: stage})
		if err != nil {
			t.Fatalf("encode %q: %v", stage, err)
		}
		decoded, ok := DecodeProgress(body)
		if !ok || decoded != (ProgressEvent{Version: 1, Stage: stage}) {
			t.Fatalf("round trip %q: %#v %t", stage, decoded, ok)
		}
	}
	for _, body := range [][]byte{
		[]byte(`{"version":1,"stage":"local_install"}`),
		[]byte(`{"version":2,"stage":"preparing"}`),
		[]byte(`{"version":1,"stage":"unknown"}`),
		[]byte(`{"version":1,"stage":"preparing","detail":"synthetic-secret"}`),
		[]byte(`{"version":1,"stage":"preparing"} trailing`),
	} {
		if _, ok := DecodeProgress(body); ok {
			t.Fatalf("unsafe progress accepted: %q", body)
		}
	}
	if _, err := EncodeProgress(ProgressEvent{Version: 1, Stage: ProgressLocalInstall}); err == nil {
		t.Fatal("controller-only stage was emitted to the worker pipe")
	}
}

func TestConsumeProgressDisablesOnlyTelemetryOnMalformedOrNoisyInput(t *testing.T) {
	valid := `{"version":1,"stage":"preparing"}`
	certificate := `{"version":1,"stage":"certificate_received"}`
	for name, input := range map[string]string{
		"malformed": valid + "\n" + `{"version":1,"stage":"dns_precheck","secret":"never"}` + "\n" + certificate + "\n",
		"oversize":  valid + "\n" + strings.Repeat("x", progressMaxLineBytes+1) + "\n" + certificate + "\n",
		"noisy":     strings.Repeat(valid+"\n", progressMaxInputLines) + certificate + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			var got []ProgressEvent
			ConsumeProgress(bytes.NewBufferString(input), func(event ProgressEvent) { got = append(got, event) })
			if len(got) == 0 || got[0].Stage != ProgressPreparing {
				t.Fatalf("valid prefix lost: %#v", got)
			}
			for _, event := range got {
				if event.Stage == ProgressCertificateReceived {
					t.Fatalf("telemetry continued after %s input: %#v", name, got)
				}
			}
		})
	}
}
