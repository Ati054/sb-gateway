package controlplane

import (
	"net/http"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
)

func TestACMEProgressAcceptsOnlyActiveOperationTuple(t *testing.T) {
	now := time.Date(2026, time.September, 9, 10, 0, 0, 0, time.UTC)
	s := &Server{now: func() time.Time { return now }}
	oldAttempt := now.Add(-time.Minute)
	newAttempt := now
	s.beginACMEProgress("profile", "old", oldAttempt)
	s.noteACMEProgress("profile", "old", oldAttempt, acmejob.ProgressEvent{Version: 1, Stage: acmejob.ProgressPreparing})
	initial, ok := s.currentACMEProgress("profile", acmeRecord{State: "running", Revision: "old", LastAttempt: oldAttempt})
	if !ok {
		t.Fatal("initial progress was not stored")
	}
	now = now.Add(time.Second)
	s.noteACMEProgress("profile", "old", oldAttempt, acmejob.ProgressEvent{Version: 1, Stage: acmejob.ProgressPreparing})
	duplicate, ok := s.currentACMEProgress("profile", acmeRecord{State: "running", Revision: "old", LastAttempt: oldAttempt})
	if !ok || !duplicate.At.Equal(initial.At) {
		t.Fatalf("duplicate changed progress timestamp: before=%#v after=%#v", initial, duplicate)
	}
	s.beginACMEProgress("profile", "new", newAttempt)

	// A draining callback from the prior worker cannot evict a newer job.
	s.noteACMEProgress("profile", "old", oldAttempt, acmejob.ProgressEvent{Version: 1, Stage: acmejob.ProgressCertificateReceived})
	s.noteACMEProgress("profile", "new", newAttempt, acmejob.ProgressEvent{Version: 1, Stage: acmejob.ProgressCAObtain})
	progress, ok := s.currentACMEProgress("profile", acmeRecord{State: "running", Revision: "new", LastAttempt: newAttempt})
	if !ok || progress.Stage != acmejob.ProgressCAObtain {
		t.Fatalf("new operation progress: %#v %t", progress, ok)
	}

	// Clearing the old tuple cannot hide the active replacement.
	s.clearACMEProgress("profile", "old", oldAttempt)
	if _, ok := s.currentACMEProgress("profile", acmeRecord{State: "running", Revision: "new", LastAttempt: newAttempt}); !ok {
		t.Fatal("old clear removed new operation progress")
	}
	s.clearACMEProgress("profile", "new", newAttempt)
	// A late callback after clear cannot resurrect terminal status.
	s.noteACMEProgress("profile", "old", oldAttempt, acmejob.ProgressEvent{Version: 1, Stage: acmejob.ProgressDNSPrecheck})
	if _, ok := s.currentACMEProgress("profile", acmeRecord{State: "running", Revision: "new", LastAttempt: newAttempt}); ok {
		t.Fatal("late callback recreated cleared progress")
	}
	if _, ok := (&Server{now: s.now}).currentACMEProgress("profile", acmeRecord{State: "running", Revision: "new", LastAttempt: newAttempt}); ok {
		t.Fatal("restart restored transient worker progress")
	}
}

func TestACMEStatusExposesOnlyCurrentTransientProgress(t *testing.T) {
	now := time.Date(2026, time.September, 9, 10, 0, 0, 0, time.UTC)
	s := newTestServer(t)
	s.now = func() time.Time { return now }
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		t.Fatal(err)
	}
	record := acmeRecord{
		Revision: "first", State: "running", LastOutcome: "running", LastAttempt: now,
		Settings: acmeTestSettings(), CredentialsRef: "acme/cdn-default/credentials.json",
	}
	state["cdn-default"] = record
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}
	s.beginACMEProgress("cdn-default", record.Revision, record.LastAttempt)
	s.noteACMEProgress("cdn-default", record.Revision, record.LastAttempt, acmejob.ProgressEvent{Version: 1, Stage: acmejob.ProgressDNSPrecheck})
	cookie, _ := bootstrapSession(t, s)
	response := performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	decoded := decodeResponse(t, response)
	if response.Code != http.StatusOK || decoded["operation_stage"] != string(acmejob.ProgressDNSPrecheck) || decoded["operation_stage_at"] == nil {
		t.Fatalf("current progress response: %d %#v", response.Code, decoded)
	}

	// A new LastAttempt makes the old callback invisible even before it drains.
	record.LastAttempt = now.Add(time.Second)
	state["cdn-default"] = record
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}
	response = performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
	decoded = decodeResponse(t, response)
	if _, exists := decoded["operation_stage"]; exists {
		t.Fatalf("stale tuple escaped status: %#v", decoded)
	}

	// Terminal and queued records never expose a cache entry, even if a
	// malicious or late callback carried the current tuple.
	s.beginACMEProgress("cdn-default", record.Revision, record.LastAttempt)
	s.noteACMEProgress("cdn-default", record.Revision, record.LastAttempt, acmejob.ProgressEvent{Version: 1, Stage: acmejob.ProgressDNSPrecheck})
	for _, terminal := range []string{"queued", "failed", "issued"} {
		record.State = terminal
		state["cdn-default"] = record
		if err := s.repository.saveAuxiliary("acme", state); err != nil {
			t.Fatal(err)
		}
		response = performRequest(t, s, http.MethodGet, apiPrefix+"/tls-profiles/cdn-default/acme", nil, nil, cookie)
		decoded = decodeResponse(t, response)
		if _, exists := decoded["operation_stage"]; exists {
			t.Fatalf("%s status exposed transient stage: %#v", terminal, decoded)
		}
	}
}
