package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestClassifyProbeErrorSeparatesFailoverDecisions(t *testing.T) {
	for _, test := range []struct {
		message string
		want    probeFailureClass
	}{
		{"dial tcp: connect: connection refused", probeFailureFatal},
		{"dial tcp: no route to host", probeFailureFatal},
		{"remote error: tls handshake failure", probeFailureTLS},
		{"lookup endpoint: no such host", probeFailureDNS},
		{"request timed out", probeFailureTimeout},
		{"unexpected EOF", probeFailureTransient},
	} {
		if got := classifyProbeError(errors.New(test.message)); got != test.want {
			t.Fatalf("classify %q = %q, want %q", test.message, got, test.want)
		}
	}
}

func TestThroughputWindowAcceptsOnlyOwnTimedPartialDownload(t *testing.T) {
	const limit = 2 * 1024 * 1024
	for _, test := range []struct {
		name     string
		bytes    int
		probeErr error
		cause    error
		wantBPS  int64
		wantErr  error
	}{
		{"complete", limit, nil, nil, 2 * limit * 8, nil},
		{"own deadline after minimum", 256 * 1024, context.DeadlineExceeded, errSpeedWindowComplete, 2 * 256 * 1024 * 8, errSpeedWindowComplete},
		{"too little at own deadline", 256*1024 - 1, context.DeadlineExceeded, errSpeedWindowComplete, 0, context.DeadlineExceeded},
		{"parent deadline", 256 * 1024, context.DeadlineExceeded, context.DeadlineExceeded, 0, context.DeadlineExceeded},
		{"reset at own deadline", 256 * 1024, errors.New("connection reset"), errSpeedWindowComplete, 0, nil},
		{"unexpected EOF", 256 * 1024, io.ErrUnexpectedEOF, nil, 0, io.ErrUnexpectedEOF},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := finishThroughputProbe(test.bytes, 500*time.Millisecond, limit, test.probeErr, test.cause)
			if got != test.wantBPS {
				t.Fatalf("speed = %d, want %d", got, test.wantBPS)
			}
			if test.name == "reset at own deadline" {
				if err == nil || err.Error() != "connection reset" {
					t.Fatalf("reset error = %v", err)
				}
			} else if !errors.Is(err, test.wantErr) || (test.wantErr == nil && err != nil) {
				t.Fatalf("error = %v, want %v", err, test.wantErr)
			}
		})
	}
}

func TestThroughputWindowMeasuresValidPartialHTTPDownload(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(bytes.Repeat([]byte{'x'}, 256*1024))
		w.(http.Flusher).Flush()
		time.Sleep(200 * time.Millisecond)
	}))
	defer proxy.Close()
	speed, err := measureThroughputOverProxy(context.Background(), proxy.URL,
		"http://speed.invalid/__down?bytes=2097152", 2*1024*1024, 80*time.Millisecond)
	if !errors.Is(err, errSpeedWindowComplete) || speed <= 0 {
		t.Fatalf("partial HTTP 200 probe = (%d, %v), want a time-limited speed", speed, err)
	}
}

func TestUnderlayWANUsesIndependentIPAndHostnameTargets(t *testing.T) {
	if len(underlayWANTargets) < 3 {
		t.Fatalf("underlay WAN target count = %d, want at least 3", len(underlayWANTargets))
	}
	seenHostname := false
	for _, target := range underlayWANTargets {
		if target == "www.gstatic.com:443" {
			seenHostname = true
		}
	}
	if !seenHostname {
		t.Fatal("underlay WAN targets must include an independent hostname path")
	}
}

func TestBackgroundProbeLanesOwnDistinctDynamicOutbounds(t *testing.T) {
	pool := healthPool{Outbounds: map[string]json.RawMessage{"node": json.RawMessage(`{"type":"direct"}`)}}
	tags := map[string]bool{}
	for _, selector := range []string{"outbound-health-background", "outbound-health-background-2", "outbound-health-background-3"} {
		runtime := newXraySelectorRuntime(Options{})
		runtime.pool = pool
		runtime.probeSelector = selector
		installed := false
		runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
			if args[1] == "ado" {
				installed = true
			}
			if args[1] == "lso" {
				if installed {
					return outboundTagsJSON("sb-health-" + shortHash(selector, 8) + "-" + runtime.dynamicDigest("node")), nil
				}
				return outboundTagsJSON(), nil
			}
			return nil, nil
		}
		tag, err := runtime.probeTag("node")
		if err != nil {
			t.Fatal(err)
		}
		if tags[tag] {
			t.Fatalf("parallel selector %q reused dynamic tag %q", selector, tag)
		}
		tags[tag] = true
	}
}

func TestAvailabilityProbeStopsAtFirstSuccessAndFallsBack(t *testing.T) {
	original := healthTargets
	defer func() { healthTargets = original }()
	healthTargets = append(healthTargets[:0:0], original...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	for _, failFirst := range []bool{false, true} {
		var calls atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			call := calls.Add(1)
			if failFirst && call == 1 {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					conn.Close()
				}
				return
			}
			if r.URL.Path == "/gstatic-204" {
				w.WriteHeader(http.StatusNoContent)
			} else {
				w.WriteHeader(http.StatusOK)
			}
		}))
		runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
		runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
		evidence := runtime.ProbeAvailability("direct-wan")
		server.Close()
		got := calls.Load()
		if !evidence.OK || (!failFirst && got != 1) || (failFirst && (got < 2 || got > 3)) {
			t.Fatalf("availability fallback: OK=%t calls=%d failFirst=%t", evidence.OK, got, failFirst)
		}
	}
}

func TestAvailabilityProbeChecksIndependentTargetAfterTimeout(t *testing.T) {
	originalTargets := healthTargets
	originalTimeout := availabilityProbeTimeout
	defer func() {
		healthTargets = originalTargets
		availabilityProbeTimeout = originalTimeout
	}()
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	availabilityProbeTimeout = 20 * time.Millisecond

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/gstatic-204" {
			time.Sleep(100 * time.Millisecond)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	evidence := runtime.ProbeAvailability("direct-wan")
	if !evidence.OK || calls.Load() < 2 || calls.Load() > 3 || evidence.TargetFailures["gstatic-204"] != probeFailureTimeout {
		t.Fatalf("availability fallback: evidence=%#v calls=%d, want independent success", evidence, calls.Load())
	}
}

func TestAvailabilityProbeUsesThirdOriginAfterTwoFailures(t *testing.T) {
	originalTargets, originalTimeout, originalFallback := healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout
	defer func() {
		healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout = originalTargets, originalTimeout, originalFallback
	}()
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	availabilityProbeTimeout = 20 * time.Millisecond
	availabilityFallbackTimeout = 50 * time.Millisecond
	secondCalled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gstatic-204":
			<-r.Context().Done()
		case "/cloudflare-trace":
			close(secondCalled)
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		default:
			select {
			case <-secondCalled:
			case <-r.Context().Done():
				return
			}
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	evidence := runtime.ProbeAvailability("direct-wan")
	if !evidence.OK || evidence.TargetFailures["gstatic-204"] != probeFailureTimeout ||
		evidence.Targets["example-web"] == nil {
		t.Fatalf("third independent origin did not preserve a working route: %#v", evidence)
	}
}

func TestAvailabilityProbeAcceptsSlowFallbackWithinThreeSecondBudget(t *testing.T) {
	originalTargets, originalTimeout, originalFallback := healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout
	defer func() {
		healthTargets, availabilityProbeTimeout, availabilityFallbackTimeout = originalTargets, originalTimeout, originalFallback
	}()
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	availabilityProbeTimeout = 20 * time.Millisecond
	availabilityFallbackTimeout = 60 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(35 * time.Millisecond)
		if r.URL.Path == "/gstatic-204" {
			w.WriteHeader(http.StatusNoContent)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	evidence := runtime.ProbeAvailability("direct-wan")
	if !evidence.OK || evidence.TargetFailures["gstatic-204"] != probeFailureTimeout {
		t.Fatalf("2–3 second path was incorrectly treated as unavailable: %#v", evidence)
	}
}

func TestAvailabilityProbeCancelsAndJoinsFallbackAfterSuccess(t *testing.T) {
	originalTargets := healthTargets
	defer func() { healthTargets = originalTargets }()
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	started := make(chan struct{})
	canceled := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gstatic-204":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
		case "/cloudflare-trace":
			<-started
			w.WriteHeader(http.StatusOK)
		default:
			close(started)
			<-r.Context().Done()
			close(canceled)
		}
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	evidence := runtime.ProbeAvailability("direct-wan")
	if !evidence.OK || evidence.Targets["example-web"] != nil {
		t.Fatalf("canceled sibling was recorded as a failed target: %#v", evidence)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("fallback request continued after the probe returned")
	}
}

func TestAvailabilityProbeRequiresThreeIndependentFailedTargets(t *testing.T) {
	originalTargets := healthTargets
	originalTimeout := availabilityProbeTimeout
	originalFallback := availabilityFallbackTimeout
	defer func() {
		healthTargets = originalTargets
		availabilityProbeTimeout = originalTimeout
		availabilityFallbackTimeout = originalFallback
	}()
	healthTargets = append(healthTargets[:0:0], originalTargets...)
	for i := range healthTargets {
		healthTargets[i].url = "http://probe.invalid/" + healthTargets[i].label
	}
	availabilityProbeTimeout = 20 * time.Millisecond
	availabilityFallbackTimeout = 20 * time.Millisecond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	evidence := runtime.ProbeAvailability("direct-wan")
	if evidence.OK || evidence.Failure != probeFailureTimeout || len(evidence.TargetFailures) != 3 {
		t.Fatalf("availability failure: evidence=%#v, want three different failed targets", evidence)
	}
}

func TestMixedTargetErrorsAreNotFatalNodeEvidence(t *testing.T) {
	if got := classifyTargetFailures([]probeFailureClass{probeFailureTLS, probeFailureTimeout}); got != probeFailureTimeout {
		t.Fatalf("mixed target failures classified as %q, want timeout", got)
	}
	if got := classifyTargetFailures([]probeFailureClass{probeFailureFatal, probeFailureTransient}); got != probeFailureTransient {
		t.Fatalf("mixed target failures classified as %q, want transient", got)
	}
}

func TestXraySelectorSkipsUnchangedMember(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{
		XrayBinary:    "xray",
		XrayAPIServer: "127.0.0.1:10085",
		ProbeURL:      "http://127.0.0.1:1",
	})
	commands := 0
	selected := ""
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands++
		if len(args) > 1 && args[1] == "bo" {
			selected = args[len(args)-1]
			return nil, nil
		}
		return selectorInfo(selected), nil
	}

	if err := runtime.Select("outbound-health-probe", "direct-wan"); err != nil {
		t.Fatal(err)
	}
	if err := runtime.Select("outbound-health-probe", "direct-wan"); err != nil {
		t.Fatal(err)
	}
	if commands != 2 {
		t.Fatalf("unchanged selector launched %d commands, want 2", commands)
	}
	if err := runtime.Select("outbound-health-probe", "block"); err != nil {
		t.Fatal(err)
	}
	if commands != 4 {
		t.Fatalf("changed selector launched %d commands, want 4", commands)
	}
}

func TestHealthProbeSelectsCandidateOnlyOnce(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{
		XrayBinary:    "xray",
		XrayAPIServer: "127.0.0.1:10085",
		ProbeURL:      "http://127.0.0.1:1",
	})
	commands := 0
	selected := ""
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands++
		if len(args) > 1 && args[1] == "bo" {
			selected = args[len(args)-1]
			return nil, nil
		}
		return selectorInfo(selected), nil
	}

	runtime.Probe("direct-wan")
	if commands != 2 {
		t.Fatalf("three-target probe launched %d selector commands, want 2", commands)
	}
}

func TestOfflineReverseProbeDoesNotSelectMissingOutbound(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.pool = healthPool{HealthPolicies: map[string]healthPolicyContract{
		"europe": {Nodes: map[string]healthNode{"reverse-vless-home": {Protocol: "xray-reverse"}}},
	}}
	commands := 0
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands++
		if len(args) > 1 && args[1] == "statsonline" {
			return []byte("user online counter not found"), os.ErrNotExist
		}
		t.Fatalf("offline reverse probe invoked selector command: %v", args)
		return nil, nil
	}
	if evidence := runtime.Probe("reverse-vless-home"); evidence.OK || commands != 1 {
		t.Fatalf("offline reverse evidence=%#v commands=%d", evidence, commands)
	}
}

func TestOnlineReverseProbeMaySelectBridge(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085", ProbeURL: "http://127.0.0.1:1"})
	runtime.pool = healthPool{HealthPolicies: map[string]healthPolicyContract{
		"europe": {Nodes: map[string]healthNode{"reverse-vless-home": {Protocol: "xray-reverse"}}},
	}}
	selected := ""
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "statsonline":
			return []byte(`{"stat":{"name":"user>>>reverse-vless-home>>>online","value":1}}`), nil
		case "bo":
			selected = args[len(args)-1]
			return nil, nil
		case "bi":
			return selectorInfo(selected), nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	runtime.Probe("reverse-vless-home")
	if selected != "reverse-vless-home" {
		t.Fatalf("online reverse bridge was not selected: %q", selected)
	}
}

func TestXraySelectorRejectsSilentRuntimeMismatch(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		if len(args) > 1 && args[1] == "bi" {
			return selectorInfo("reverse-vless-reality"), nil
		}
		return nil, nil
	}
	if err := runtime.Select("europe", "reverse-vless-xhttp"); err == nil {
		t.Fatal("silent Xray mismatch was accepted")
	}
	if runtime.selectorMembers["europe"] != "" {
		t.Fatal("unconfirmed selector member was cached")
	}
}

func TestXrayCurrentDecodesCandidateRemovedFromLatestContract(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	prefix := "sb-urltest-europe-"
	runtime.pool = healthPool{
		HealthPolicies: map[string]healthPolicyContract{"europe": {Candidates: []string{"nl"}}},
		PolicyPrefixes: map[string]string{"europe": prefix},
		Outbounds:      map[string]json.RawMessage{"de": json.RawMessage(`{}`), "nl": json.RawMessage(`{}`)},
	}
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		if args[1] == "lso" {
			return outboundTagsJSON(runtime.dynamicTag(prefix, "de")), nil
		}
		return selectorInfo(runtime.dynamicTag(prefix, "de")), nil
	}
	got, err := runtime.Current("europe")
	if err != nil {
		t.Fatal(err)
	}
	if got != "de" {
		t.Fatalf("removed dynamic member decoded as %q", got)
	}
}

func TestXrayCurrentRestoresMissingSelectedOutboundBeforeConfirming(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	prefix := "sb-urltest-europe-"
	runtime.pool = healthPool{
		HealthPolicies: map[string]healthPolicyContract{"europe": {Candidates: []string{"de"}}},
		PolicyPrefixes: map[string]string{"europe": prefix},
		Outbounds:      map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)},
	}
	tag := runtime.dynamicTag(prefix, "de")
	runtime.loadedDynamic[tag] = true // stale local state after catalog churn
	installed := false
	commands := make([]string, 0)
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		switch args[1] {
		case "bi":
			return selectorInfo(tag), nil
		case "lso":
			if installed {
				return outboundTagsJSON(tag), nil
			}
			return outboundTagsJSON(), nil
		case "ado":
			installed = true
			return nil, nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	if current, err := runtime.Current("europe"); err != nil || current != "de" || !installed {
		t.Fatalf("current=%q installed=%t err=%v", current, installed, err)
	}
	if !reflect.DeepEqual(commands, []string{"bi", "lso", "ado", "lso"}) {
		t.Fatalf("selected outbound was confirmed without checking/restoring it: %v", commands)
	}
}

func TestXrayCurrentRestoresMissingCachedOutboundWithoutHealthContract(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	prefix := "sb-urltest-europe-"
	runtime.pool = healthPool{
		Policies:       map[string][]string{"europe": {"de"}},
		PolicyPrefixes: map[string]string{"europe": prefix},
		Outbounds:      map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)},
	}
	tag := runtime.dynamicTag(prefix, "de")
	runtime.activeByNode["de"] = tag
	runtime.loadedDynamic[tag] = true
	installed := false
	commands := make([]string, 0)
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		switch args[1] {
		case "bi":
			return selectorInfo(tag), nil
		case "lso":
			if installed {
				return outboundTagsJSON(tag), nil
			}
			return outboundTagsJSON(), nil
		case "ado":
			installed = true
			return nil, nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	if current, err := runtime.Current("europe"); err != nil || current != "de" || !installed {
		t.Fatalf("current=%q installed=%t err=%v", current, installed, err)
	}
	if !reflect.DeepEqual(commands, []string{"bi", "lso", "ado", "lso"}) {
		t.Fatalf("cached fallback returned without verifying/restoring handler: %v", commands)
	}
}

func TestXrayCurrentDoesNotConfirmUnrestoredOutbound(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	prefix := "sb-urltest-europe-"
	runtime.pool = healthPool{
		HealthPolicies: map[string]healthPolicyContract{"europe": {Candidates: []string{"de"}}},
		PolicyPrefixes: map[string]string{"europe": prefix},
		Outbounds:      map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)},
	}
	tag := runtime.dynamicTag(prefix, "de")
	runtime.loadedDynamic[tag] = true
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "bi":
			return selectorInfo(tag), nil
		case "lso":
			return outboundTagsJSON(), nil
		case "ado":
			return nil, errors.New("rejected")
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	if current, err := runtime.Current("europe"); err == nil || current != "" || runtime.loadedDynamic[tag] {
		t.Fatalf("missing outbound was marked confirmed: current=%q loaded=%v err=%v", current, runtime.loadedDynamic, err)
	}
}

func TestXraySelectRepairsOverrideWithoutHandler(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	prefix := "sb-urltest-europe-"
	runtime.pool = healthPool{
		Policies:       map[string][]string{"europe": {"de"}},
		PolicyPrefixes: map[string]string{"europe": prefix},
		Outbounds:      map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)},
	}
	tag := runtime.dynamicTag(prefix, "de")
	installed := false
	commands := make([]string, 0)
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		switch args[1] {
		case "bi":
			return selectorInfo(tag), nil
		case "lso":
			return outboundTagsJSON(), nil
		case "ado":
			installed = true
			return nil, nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	if err := runtime.Select("europe", "de"); err != nil || !installed || !runtime.loadedDynamic[tag] {
		t.Fatalf("stale selector was not repaired: installed=%t loaded=%v err=%v", installed, runtime.loadedDynamic, err)
	}
	if !reflect.DeepEqual(commands, []string{"bi", "lso", "ado"}) {
		t.Fatalf("stale selector repair commands=%v", commands)
	}
}

func TestXrayProbeDoesNotReuseMissingActiveNodeOutbound(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.pool = healthPool{Outbounds: map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)}}
	stale := "sb-urltest-europe-stale"
	runtime.activeByNode["de"] = stale
	runtime.loadedDynamic[stale] = true
	installed := ""
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "lso":
			if installed != "" {
				return outboundTagsJSON(installed), nil
			}
			return outboundTagsJSON(), nil
		case "ado":
			installed = "sb-urltest-probe-" + runtime.dynamicDigest("de")
			return nil, nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	got, err := runtime.probeTag("de")
	if err != nil || got != installed || got == stale || runtime.activeByNode["de"] != "" {
		t.Fatalf("probe reused removed handler: got=%q installed=%q active=%q err=%v", got, installed, runtime.activeByNode["de"], err)
	}
}

func TestXrayDynamicTagChangesWhenSameNodeConfigurationChanges(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{})
	runtime.pool = healthPool{Outbounds: map[string]json.RawMessage{
		"de": json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4"}`),
	}}
	first := runtime.dynamicTag("sb-urltest-europe-", "de")
	runtime.pool.Outbounds["de"] = json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.5"}`)
	second := runtime.dynamicTag("sb-urltest-europe-", "de")
	if first == second {
		t.Fatalf("changed outbound reused runtime tag %q", first)
	}
}

func TestXraySelectorSwitchesBeforeRetiringPreviousHandler(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.pool = healthPool{
		Policies:       map[string][]string{"europe": {"de"}},
		PolicyPrefixes: map[string]string{"europe": "sb-urltest-europe-"},
		Outbounds: map[string]json.RawMessage{
			"de": json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4"}`),
		},
	}
	selected := ""
	commands := make([]string, 0)
	installed := make(map[string]bool)
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		switch args[1] {
		case "lso":
			return installedOutboundTagsJSON(installed), nil
		case "ado":
			installed[runtime.dynamicTag("sb-urltest-europe-", "de")] = true
			return nil, nil
		case "bo":
			selected = args[len(args)-1]
			return nil, nil
		case "bi":
			return selectorInfo(selected), nil
		case "rmo":
			return nil, nil
		default:
			return nil, nil
		}
	}
	if err := runtime.Select("europe", "de"); err != nil {
		t.Fatal(err)
	}
	runtime.pool.Outbounds["de"] = json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.5"}`)
	if err := runtime.Select("europe", "de"); err != nil {
		t.Fatal(err)
	}
	want := []string{"bi", "ado", "bo", "bi", "ado", "bo", "bi"}
	if len(commands) < len(want) || !reflect.DeepEqual(commands[:len(want)], want) {
		t.Fatalf("unsafe command order: got %v want prefix %v", commands, want)
	}
}

func TestPriorityServiceSelectorUsesDynamicProviderGeneration(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	selector := "europe-service-claude"
	prefix := "sb-urltest-europe-"
	runtime.pool = healthPool{
		Policies:       map[string][]string{selector: {"de"}},
		PolicyPrefixes: map[string]string{selector: prefix},
		Outbounds: map[string]json.RawMessage{
			"de": json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4"}`),
		},
	}
	selected := ""
	installed := make(map[string]bool)
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "lso":
			return installedOutboundTagsJSON(installed), nil
		case "ado":
			installed[runtime.dynamicTag(prefix, "de")] = true
			return nil, nil
		case "bo":
			selected = args[len(args)-1]
			return nil, nil
		case "bi":
			return selectorInfo(selected), nil
		default:
			return nil, nil
		}
	}
	if err := runtime.Select(selector, "de"); err != nil {
		t.Fatal(err)
	}
	if selected != runtime.dynamicTag(prefix, "de") {
		t.Fatalf("service selector used stale static tag %q", selected)
	}
}

func TestPriorityServiceSelectorAdoptsColdStartDynamicProviderGeneration(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	selector := "europe-service-claude"
	prefix := "sb-urltest-europe-"
	runtime.pool = healthPool{
		Policies:       map[string][]string{selector: {"de"}},
		PolicyPrefixes: map[string]string{selector: prefix},
		Outbounds: map[string]json.RawMessage{
			"de": json.RawMessage(`{"protocol":"freedom","sendThrough":"127.0.0.4"}`),
		},
	}
	wantTag := runtime.dynamicTag(prefix, "de")
	commands := make([]string, 0)
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		if args[1] == "ado" || args[1] == "bo" {
			t.Fatalf("restored selector must not be mutated: %v", args)
		}
		if args[1] == "lso" {
			return outboundTagsJSON(wantTag), nil
		}
		return selectorInfo(wantTag), nil
	}
	if err := runtime.Select(selector, "de"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"bi", "lso"}) {
		t.Fatalf("commands=%v want=[bi lso]", commands)
	}
	if !runtime.loadedDynamic[wantTag] || runtime.activeByPolicy[selector] != wantTag {
		t.Fatalf("restored handler was not adopted: loaded=%v active=%q", runtime.loadedDynamic, runtime.activeByPolicy[selector])
	}
}

func TestHealthContractReloadPreservesLiveXraySelectorCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "urltest-pool.json")
	body := []byte(`{"version":3,"health_policies":{},"outbounds":{}}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := newXraySelectorRuntime(Options{HealthPoolFile: path})
	runtime.xrayPID = processPID("xray")
	runtime.poolSignature = "previous-contract"
	runtime.loadedDynamic["live-dynamic"] = true
	runtime.selectorMembers["europe"] = "live-dynamic"
	_, reset, err := runtime.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if !reset {
		t.Fatal("contract change was not reported to the health controller")
	}
	if !runtime.loadedDynamic["live-dynamic"] || runtime.selectorMembers["europe"] != "live-dynamic" {
		t.Fatalf("pool-only reload discarded live Xray state: %#v %#v", runtime.loadedDynamic, runtime.selectorMembers)
	}
}

func TestPolicyRetirementNeverRemovesReactivatedHandlerAndRetriesCleanup(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	policy := "europe"
	prefix := "sb-urltest-europe-"
	runtime.pool.PolicyPrefixes = map[string]string{policy: prefix}
	a, b, c := prefix+"a", prefix+"b", prefix+"c"
	for _, tag := range []string{a, b, c} {
		runtime.loadedDynamic[tag] = true
	}
	runtime.activeByPolicy[policy] = a
	removed := make([]string, 0)
	failRemoval := true
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		if args[1] == "lso" {
			return outboundTagsJSON(b), nil
		}
		if args[1] != "rmo" {
			t.Fatalf("unexpected Xray command: %v", args)
		}
		removed = append(removed, args[len(args)-1])
		if failRemoval {
			return nil, errors.New("temporary Xray API failure")
		}
		return nil, nil
	}
	if err := runtime.commitPolicySelection(policy, "b", b); err != nil {
		t.Fatal(err)
	}
	if err := runtime.commitPolicySelection(policy, "a", a); err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 || !runtime.loadedDynamic[a] || !reflect.DeepEqual(runtime.retiredByPolicy[policy], []string{b}) {
		t.Fatalf("reactivated handler was not protected: removed=%v retired=%v", removed, runtime.retiredByPolicy[policy])
	}
	if err := runtime.commitPolicySelection(policy, "c", c); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{b}) || !runtime.loadedDynamic[b] {
		t.Fatalf("failed cleanup lost handler ownership: removed=%v loaded=%v", removed, runtime.loadedDynamic)
	}
	failRemoval = false
	poolPath := filepath.Join(t.TempDir(), "pool.json")
	if err := os.WriteFile(poolPath, []byte(`{"version":3}`), 0o600); err != nil {
		t.Fatal(err)
	}
	runtime.opts.HealthPoolFile = poolPath
	if _, _, err := runtime.Reload(); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(removed, []string{b, b}) || runtime.loadedDynamic[b] || !runtime.loadedDynamic[a] || !runtime.loadedDynamic[c] || !reflect.DeepEqual(runtime.retiredByPolicy[policy], []string{a}) {
		t.Fatalf("retry did not keep only the newest retired handler: removed=%v retired=%v loaded=%v", removed, runtime.retiredByPolicy[policy], runtime.loadedDynamic)
	}
}

func TestPendingOutboundReconcilesLostSelectorAcknowledgement(t *testing.T) {
	for _, selectedDespiteError := range []bool{false, true} {
		t.Run(fmt.Sprintf("selected=%t", selectedDespiteError), func(t *testing.T) {
			runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
			runtime.pool = healthPool{
				Policies:       map[string][]string{"europe": {"de"}},
				PolicyPrefixes: map[string]string{"europe": "sb-urltest-europe-"},
				Outbounds: map[string]json.RawMessage{
					"de": json.RawMessage(`{"protocol":"freedom"}`),
				},
			}
			tag := runtime.policyRuntimeTag("europe", "de")
			selected := "block"
			installed := make(map[string]bool)
			removed := make([]string, 0)
			runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
				switch args[1] {
				case "bi":
					return selectorInfo(selected), nil
				case "lso":
					if installed[tag] {
						return outboundTagsJSON(tag), nil
					}
					return outboundTagsJSON(), nil
				case "ado":
					installed[tag] = true
					return nil, nil
				case "bo":
					if selectedDespiteError {
						selected = tag
					}
					return nil, errors.New("selector acknowledgement lost")
				case "rmo":
					removed = append(removed, args[len(args)-1])
					delete(installed, tag)
					return nil, nil
				default:
					t.Fatalf("unexpected Xray command: %v", args)
					return nil, nil
				}
			}
			if err := runtime.Select("europe", "de"); err == nil || !installed[tag] || len(runtime.pendingDynamic) != 1 {
				t.Fatalf("uncertain add was lost: installed=%v pending=%v err=%v", installed, runtime.pendingDynamic, err)
			}
			runtime.reconcilePendingOutbounds()
			if len(runtime.pendingDynamic) != 0 {
				t.Fatalf("uncertain add was not reconciled: %v", runtime.pendingDynamic)
			}
			if selectedDespiteError {
				if !installed[tag] || runtime.activeByPolicy["europe"] != tag || len(removed) != 0 {
					t.Fatalf("confirmed selected handler was removed: installed=%v active=%q removed=%v", installed, runtime.activeByPolicy["europe"], removed)
				}
			} else if installed[tag] || !reflect.DeepEqual(removed, []string{tag}) {
				t.Fatalf("unused handler survived failed selector update: installed=%v removed=%v", installed, removed)
			}
		})
	}
}

func TestPendingOutboundReconcilesLostAddAcknowledgement(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.pool = healthPool{
		Policies:       map[string][]string{"europe": {"de"}},
		PolicyPrefixes: map[string]string{"europe": "sb-urltest-europe-"},
		Outbounds:      map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)},
	}
	tag := runtime.policyRuntimeTag("europe", "de")
	installed, listCalls, removals := false, 0, 0
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "bi":
			return selectorInfo("block"), nil
		case "ado":
			installed = true
			return nil, errors.New("add acknowledgement lost")
		case "lso":
			listCalls++
			if listCalls == 1 {
				return nil, errors.New("list temporarily unavailable")
			}
			return outboundTagsJSON(tag), nil
		case "rmo":
			removals++
			installed = false
			return nil, nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	if err := runtime.Select("europe", "de"); err == nil || !installed || len(runtime.pendingDynamic) != 1 {
		t.Fatalf("uncertain add lost ownership: installed=%t pending=%v err=%v", installed, runtime.pendingDynamic, err)
	}
	runtime.reconcilePendingOutbounds()
	if installed || removals != 1 || len(runtime.pendingDynamic) != 0 {
		t.Fatalf("orphan was not removed after API recovery: installed=%t removals=%d pending=%v", installed, removals, runtime.pendingDynamic)
	}
}

func TestRetiredOutboundFailureDoesNotBlockOtherCleanup(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.retiredByPolicy["europe"] = []string{"bad", "good", "newest"}
	for _, tag := range runtime.retiredByPolicy["europe"] {
		runtime.loadedDynamic[tag] = true
	}
	var attempted []string
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		if args[1] == "lso" {
			return outboundTagsJSON("bad"), nil
		}
		if args[1] != "rmo" {
			t.Fatalf("unexpected Xray command: %v", args)
		}
		tag := args[len(args)-1]
		attempted = append(attempted, tag)
		if tag == "bad" {
			return nil, errors.New("selective removal failure")
		}
		return nil, nil
	}
	runtime.pruneRetiredOutbounds("europe")
	if !reflect.DeepEqual(attempted, []string{"bad", "good"}) || !reflect.DeepEqual(runtime.retiredByPolicy["europe"], []string{"bad", "newest"}) || runtime.loadedDynamic["good"] {
		t.Fatalf("head-of-line failure retained unrelated outbound: attempts=%v retired=%v loaded=%v", attempted, runtime.retiredByPolicy["europe"], runtime.loadedDynamic)
	}
}

func TestRemovedOutboundAcknowledgementLossIsConfirmedByReadback(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	tag := "sb-urltest-retired"
	runtime.loadedDynamic[tag] = true
	runtime.activeByNode["old-node"] = tag
	runtime.pendingDynamic[tag] = pendingOutbound{selector: "europe", nodeID: "old-node"}
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "rmo":
			return nil, errors.New("remove acknowledgement lost")
		case "lso":
			return outboundTagsJSON(), nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	if err := runtime.removeOutbound(tag); err != nil {
		t.Fatal(err)
	}
	if runtime.loadedDynamic[tag] || runtime.activeByNode["old-node"] != "" || len(runtime.pendingDynamic) != 0 {
		t.Fatalf("confirmed removal retained state: loaded=%v active=%v pending=%v", runtime.loadedDynamic, runtime.activeByNode, runtime.pendingDynamic)
	}
}

func TestCleanupBacklogBlocksNewGenerationsWithoutChangingSelectedHandler(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.pool = healthPool{
		Policies:       map[string][]string{"europe": {"de"}},
		PolicyPrefixes: map[string]string{"europe": "sb-urltest-europe-"},
		Outbounds:      map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)},
	}
	runtime.activeByPolicy["europe"] = "current"
	runtime.selectorMembers["europe"] = "current"
	for index := range maxCleanupBacklogPerPolicy + 1 {
		tag := fmt.Sprintf("retired-%d", index)
		runtime.retiredByPolicy["europe"] = append(runtime.retiredByPolicy["europe"], tag)
		runtime.loadedDynamic[tag] = true
	}
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		t.Fatalf("cleanup backlog must block mutation, got %v", args)
		return nil, nil
	}
	if err := runtime.Select("europe", "de"); err == nil || !strings.Contains(err.Error(), "cleanup backlog") {
		t.Fatalf("new generation was not blocked: %v", err)
	}
	if runtime.activeByPolicy["europe"] != "current" || len(runtime.pendingDynamic) != 0 {
		t.Fatalf("blocked creation changed live state: active=%v pending=%v", runtime.activeByPolicy, runtime.pendingDynamic)
	}

	delete(runtime.loadedDynamic, runtime.retiredByPolicy["europe"][0])
	runtime.retiredByPolicy["europe"] = runtime.retiredByPolicy["europe"][1:]
	adds := 0
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "ado":
			adds++
			return nil, nil
		default:
			t.Fatalf("unexpected Xray command: %v", args)
			return nil, nil
		}
	}
	if _, err := runtime.policyTag("europe", "de"); err != nil || adds != 1 {
		t.Fatalf("cleanup space did not admit one new tag: adds=%d err=%v", adds, err)
	}
}

func TestCleanupBacklogHasGlobalLimitAcrossPolicies(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	for policy := range maxCleanupBacklogGlobal / maxCleanupBacklogPerPolicy {
		id := fmt.Sprintf("policy-%d", policy)
		for index := range maxCleanupBacklogPerPolicy + 1 {
			runtime.retiredByPolicy[id] = append(runtime.retiredByPolicy[id], fmt.Sprintf("retired-%d-%d", policy, index))
		}
	}
	perPolicy, global := runtime.cleanupBacklog("new-policy")
	if perPolicy != 0 || global != maxCleanupBacklogGlobal {
		t.Fatalf("wrong cleanup backlog: policy=%d global=%d", perPolicy, global)
	}
	runtime.pool.PolicyPrefixes = map[string]string{"new-policy": "sb-urltest-new-"}
	runtime.pool.Outbounds = map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)}
	if _, err := runtime.policyTag("new-policy", "de"); err == nil || !strings.Contains(err.Error(), "cleanup backlog") {
		t.Fatalf("global cleanup cap did not block a new tag: %v", err)
	}
}

func TestRestartInventoryBoundsUnknownHandlersWithoutRemovingThem(t *testing.T) {
	const prefix = "sb-urltest-0123456789ab-"
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.pool = healthPool{
		PolicyPrefixes: map[string]string{"europe": prefix},
		Outbounds:      map[string]json.RawMessage{"de": json.RawMessage(`{"protocol":"freedom"}`)},
	}
	var tags []string
	for index := range maxLiveDynamicPerPolicy {
		tags = append(tags, fmt.Sprintf("%s%012x", prefix, index))
	}
	removed := false
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "lso":
			return outboundTagsJSON(tags...), nil
		case "rmo":
			removed = true
			return nil, nil
		default:
			t.Fatalf("inventory cap must block mutation, got %v", args)
			return nil, nil
		}
	}
	if err := runtime.loadDynamicInventory(); err != nil {
		t.Fatal(err)
	}
	if len(runtime.unknownDynamic) != maxLiveDynamicPerPolicy {
		t.Fatalf("unknown handlers = %d, want %d", len(runtime.unknownDynamic), maxLiveDynamicPerPolicy)
	}
	if _, err := runtime.policyTag("europe", "de"); err == nil || !strings.Contains(err.Error(), "inventory limit") {
		t.Fatalf("new handler was not blocked by prior monitor generations: %v", err)
	}
	if removed {
		t.Fatal("ownership-unknown handler was removed")
	}
	if err := runtime.admitDynamicTag(tags[0], prefix); err != nil {
		t.Fatalf("existing handler should remain usable at limit: %v", err)
	}
}

func TestRestartInventoryRequiresSuccessfulReadback(t *testing.T) {
	runtime := newXraySelectorRuntime(Options{XrayBinary: "xray", XrayAPIServer: "127.0.0.1:10085"})
	runtime.xrayPID = 123
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		if args[1] != "lso" {
			t.Fatalf("unexpected mutation before inventory: %v", args)
		}
		return nil, errors.New("Xray API unavailable")
	}
	if err := runtime.loadDynamicInventory(); err == nil || runtime.inventoryLoaded {
		t.Fatalf("failed inventory was accepted: loaded=%t err=%v", runtime.inventoryLoaded, err)
	}
	if err := runtime.admitDynamicTag("sb-urltest-0123456789ab-000000000000", "sb-urltest-0123456789ab-"); err == nil {
		t.Fatal("new outbound admitted without a restart inventory")
	}
}

func selectorInfo(selected string) []byte {
	line := ""
	if selected != "" {
		line = "    1   " + selected + "\n"
	}
	return []byte("  - Selecting Override:\n" + line + "  - Selects:\n")
}

func outboundTagsJSON(tags ...string) []byte {
	outbounds := make([]map[string]string, 0, len(tags))
	for _, tag := range tags {
		outbounds = append(outbounds, map[string]string{"tag": tag})
	}
	body, _ := json.Marshal(map[string]any{"outbounds": outbounds})
	return body
}

func installedOutboundTagsJSON(installed map[string]bool) []byte {
	tags := make([]string, 0, len(installed))
	for tag, present := range installed {
		if present {
			tags = append(tags, tag)
		}
	}
	return outboundTagsJSON(tags...)
}
