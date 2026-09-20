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
		runtime.command = func(context.Context, time.Duration, string, ...string) ([]byte, error) { return nil, nil }
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

func TestAvailabilityProbeStopsAfterFirstTimeout(t *testing.T) {
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

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	runtime := newXraySelectorRuntime(Options{ProbeURL: server.URL})
	runtime.selectorMembers["outbound-health-probe"] = "direct-wan"
	evidence := runtime.ProbeAvailability("direct-wan")
	if evidence.OK || evidence.Failure != probeFailureTimeout || calls != 1 {
		t.Fatalf("availability timeout: evidence=%#v calls=%d, want one timeout", evidence, calls)
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
	runtime.command = func(_ context.Context, _ time.Duration, _ string, _ ...string) ([]byte, error) {
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
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		commands = append(commands, args[1])
		switch args[1] {
		case "ado":
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
	runtime.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "ado":
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
		return selectorInfo(wantTag), nil
	}
	if err := runtime.Select(selector, "de"); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commands, []string{"bi"}) {
		t.Fatalf("commands=%v want=[bi]", commands)
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

func selectorInfo(selected string) []byte {
	line := ""
	if selected != "" {
		line = "    1   " + selected + "\n"
	}
	return []byte("  - Selecting Override:\n" + line + "  - Selects:\n")
}
