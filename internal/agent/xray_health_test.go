package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
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
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
			if failFirst && calls == 1 {
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
		want := 1
		if failFirst {
			want = 2
		}
		if !evidence.OK || calls != want {
			t.Fatalf("availability fallback: OK=%t calls=%d want=%d", evidence.OK, calls, want)
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
	if !evidence.OK || calls.Load() != 2 || evidence.TargetFailures["gstatic-204"] != probeFailureTimeout {
		t.Fatalf("availability fallback: evidence=%#v calls=%d, want independent success", evidence, calls.Load())
	}
}

func TestAvailabilityProbeRequiresTwoIndependentFailedTargets(t *testing.T) {
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
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()
	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	evidence := runtime.ProbeAvailability("direct-wan")
	if evidence.OK || evidence.Failure != probeFailureTimeout || calls.Load() != 2 || len(evidence.TargetFailures) != 2 {
		t.Fatalf("availability failure: evidence=%#v calls=%d, want two different failed targets", evidence, calls.Load())
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
