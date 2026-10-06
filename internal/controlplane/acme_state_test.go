package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
)

func mustDecodeACMERecord(t *testing.T, raw any) acmeRecord {
	t.Helper()
	record, err := decodeACMERecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestDecodeACMERecordRejectsPartialStateWithoutValues(t *testing.T) {
	for _, raw := range []any{
		"secret-invalid-record", []any{true}, make(chan int),
		map[string]any{"settings": acmeTestSettings(), "state": "queued", "ca_retry_not_before": "secret-invalid-time"},
		map[string]any{"settings": acmeTestSettings(), "state": "queued", "next_attempt": 42},
		map[string]any{"settings": map[string]any{"enabled": "secret-invalid-enabled"}},
	} {
		record, err := decodeACMERecord(raw)
		if !errors.Is(err, errInvalidACMERecord) || !reflect.DeepEqual(record, acmeRecord{}) || strings.Contains(err.Error(), "secret") {
			t.Fatalf("unsafe decoding: record=%#v err=%v", record, err)
		}
	}
	for _, raw := range []any{nil, map[string]any{}, acmeRecord{Settings: acmeTestSettings(), State: "queued"}} {
		if _, err := decodeACMERecord(raw); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCorruptACMERecordBlocksOrdersAndConfiguration(t *testing.T) {
	s := newTestServer(t)
	cookie, csrf := bootstrapSession(t, s)
	queueTestACMEForSession(t, s, cookie, csrf)
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(state["cdn-default"])
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	raw["ca_retry_not_before"] = "secret-invalid-time"
	state["cdn-default"] = raw
	if err := s.repository.saveAuxiliary("acme", state); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.issueACME = func(context.Context, acmejob.Request) (acmejob.Result, error) {
		calls++
		return acmejob.Result{}, nil
	}
	for i := 0; i < 2; i++ {
		if err := s.processOneACME(context.Background()); !errors.Is(err, errInvalidACMERecord) {
			t.Fatalf("corrupt state admitted: %v", err)
		}
	}
	if calls != 0 {
		t.Fatal("corrupt state caused a CA order")
	}
	for _, request := range []struct {
		method string
		body   map[string]any
	}{
		{http.MethodGet, nil},
		{http.MethodPost, map[string]any{"settings": acmeTestSettings(), "credentials": map[string]string{"token": "test-dns-secret"}, "issue": true}},
		{http.MethodPost, map[string]any{"disable": true}},
	} {
		response := performRequest(t, s, request.method, apiPrefix+"/tls-profiles/cdn-default/acme", request.body, map[string]string{csrfHeader: csrf}, cookie)
		if response.Code != http.StatusInternalServerError || strings.Contains(response.Body.String(), "secret-invalid") {
			t.Fatalf("unsafe corrupt state response: %d %s", response.Code, response.Body.String())
		}
	}
	after, err := s.repository.auxiliary("acme")
	if err != nil || !reflect.DeepEqual(state, after) {
		t.Fatalf("corrupt state overwritten: err=%v", err)
	}
	payload, err := s.statusPayload()
	if err != nil {
		t.Fatal(err)
	}
	profile := payload["acme"].(map[string]any)["cdn-default"].(map[string]any)
	if profile["state"] != "invalid" || profile["enabled"] != false {
		t.Fatalf("corruption not visible: %#v", profile)
	}
}

func TestACMESchedulerFailureClassesDoNotContainErrorValues(t *testing.T) {
	for _, test := range []struct {
		err   error
		class string
	}{
		{errInvalidACMERecord, "invalid-record"},
		{errors.Join(acmejob.ErrCAValidation, errors.New("secret-provider-value")), "worker"},
		{errors.New("secret-state-value"), "state-or-install"},
	} {
		if got := acmeSchedulerErrorClass(test.err); got != test.class {
			t.Fatalf("unsafe class: %q", got)
		}
	}
}
