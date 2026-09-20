package watchdog

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"
)

func TestStartupGraceEndsAsSoonAsCurrentXrayIsReady(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "xray-selectors-ready")
	if err := os.WriteFile(marker, []byte("123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if !waitForStartupReady(context.Background(), marker, 30*time.Second) {
		t.Fatal("ready startup marker was rejected")
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("ready startup marker still paid fixed grace: %s", elapsed)
	}
}

func TestStartupGraceRemainsABoundedFallback(t *testing.T) {
	started := time.Now()
	if !waitForStartupReady(context.Background(), filepath.Join(t.TempDir(), "missing"), 20*time.Millisecond) {
		t.Fatal("expired grace must allow the watchdog to diagnose startup")
	}
	if elapsed := time.Since(started); elapsed < 15*time.Millisecond || elapsed > 250*time.Millisecond {
		t.Fatalf("unexpected bounded grace duration: %s", elapsed)
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if waitForStartupReady(cancelled, filepath.Join(t.TempDir(), "missing"), time.Second) {
		t.Fatal("cancelled startup wait continued")
	}
}

func TestFirstHealthyDataplaneDoesNotPayRecoveryHysteresis(t *testing.T) {
	if got := recoverySuccessThreshold(3, false); got != 1 {
		t.Fatalf("first readiness threshold=%d, want 1", got)
	}
	if got := recoverySuccessThreshold(3, true); got != 3 {
		t.Fatalf("live recovery threshold=%d, want configured 3", got)
	}
}

func TestBoundedInt(t *testing.T) {
	tests := []struct {
		value    string
		expected int
	}{
		{"10", 10},
		{"0", 5},
		{"301", 5},
		{"invalid", 5},
		{"123456", 5},
	}
	for _, test := range tests {
		if actual := boundedInt(test.value, 5, 5, 300); actual != test.expected {
			t.Fatalf("boundedInt(%q)=%d, want %d", test.value, actual, test.expected)
		}
	}
}

func TestFailureThresholdForReasons(t *testing.T) {
	tests := []struct {
		name     string
		base     int
		reasons  []string
		expected int
	}{
		{name: "configured endpoint only", base: 3, reasons: []string{"api_configured"}, expected: controlPlaneThreshold},
		{name: "readiness endpoint only", base: 3, reasons: []string{"api_ready"}, expected: controlPlaneThreshold},
		{name: "both API reasons", base: 3, reasons: []string{"api_configured", "api_ready"}, expected: controlPlaneThreshold},
		{name: "dataplane failure stays fast", base: 3, reasons: []string{"api_ready", "core_process"}, expected: 3},
		{name: "custom threshold is preserved", base: 30, reasons: []string{"api_ready"}, expected: 30},
		{name: "healthy", base: 3, reasons: nil, expected: 3},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if actual := failureThresholdForReasons(test.base, test.reasons); actual != test.expected {
				t.Fatalf("failureThresholdForReasons(%d, %v)=%d, want %d", test.base, test.reasons, actual, test.expected)
			}
		})
	}
}

func TestFailureClassSeparatesControlPlaneAndDataplaneStreaks(t *testing.T) {
	if got := classifyFailure([]string{"api_configured", "api_ready"}); got != failureClassControlPlane {
		t.Fatalf("API-only class=%q, want %q", got, failureClassControlPlane)
	}
	for _, reasons := range [][]string{{"core_process"}, {"api_ready", "tcp_listener"}, nil} {
		if got := classifyFailure(reasons); got != failureClassDataPlane {
			t.Fatalf("dataplane class for %v=%q, want %q", reasons, got, failureClassDataPlane)
		}
	}
	class, count := nextFailureStreak(failureClassControlPlane, 23, []string{"api_ready", "tcp_listener"})
	if class != failureClassDataPlane || count != 1 {
		t.Fatalf("class transition=(%q, %d), want (%q, 1)", class, count, failureClassDataPlane)
	}
	class, count = nextFailureStreak(class, count, []string{"tun_interface"})
	if class != failureClassDataPlane || count != 2 {
		t.Fatalf("continued dataplane streak=(%q, %d), want (%q, 2)", class, count, failureClassDataPlane)
	}
}

func TestParseSettingsFileDoesNotExecuteShell(t *testing.T) {
	path := filepath.Join(t.TempDir(), "watchdog.env")
	body := "# generated\nSB_WATCHDOG_INTERVAL_SECONDS=15\nUNKNOWN=$(touch /tmp/nope)\nSB_WATCHDOG_FAILURE_THRESHOLD='4'\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	values, err := parseSettingsFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if values["SB_WATCHDOG_INTERVAL_SECONDS"] != "15" || values["SB_WATCHDOG_FAILURE_THRESHOLD"] != "4" {
		t.Fatalf("unexpected settings: %#v", values)
	}
}

func TestParsesGeneratedListenerInventories(t *testing.T) {
	directory := t.TempDir()
	xray := filepath.Join(directory, "xray.json")
	dns := filepath.Join(directory, "policy-dns.json")
	if err := os.WriteFile(xray, []byte(`{"inbounds":[{"protocol":"vless","port":443},{"protocol":"hysteria2","port":2446},{"protocol":"dokodemo-door"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dns, []byte(`{"lanes":[{"port":5301},{"port":5302},{"port":"bad"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	listeners, err := parseXrayListeners(xray)
	if err != nil {
		t.Fatal(err)
	}
	wantListeners := []listener{{"tcp", 443}, {"udp", 2446}}
	if !reflect.DeepEqual(listeners, wantListeners) {
		t.Fatalf("listeners=%#v, want %#v", listeners, wantListeners)
	}
	ports, err := parseDNSPorts(dns)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ports, []int{5301, 5302}) {
		t.Fatalf("ports=%#v", ports)
	}
}

func TestFileSignatureReusesHashUntilMetadataChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	if err := os.WriteFile(path, []byte(`{"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fileStamp, contentSignature, err := fileSignature(path, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if fileStamp == "" || contentSignature == "" {
		t.Fatalf("empty signatures: file=%q content=%q", fileStamp, contentSignature)
	}

	stableFileSignature, stableContentSignature, err := fileSignature(path, fileStamp, contentSignature)
	if err != nil {
		t.Fatal(err)
	}
	if stableFileSignature != fileStamp || stableContentSignature != contentSignature {
		t.Fatal("unchanged file did not reuse its signatures")
	}

	if err := os.WriteFile(path, []byte(`{"version":22}`), 0o600); err != nil {
		t.Fatal(err)
	}
	changedFileSignature, changedContentSignature, err := fileSignature(path, fileStamp, contentSignature)
	if err != nil {
		t.Fatal(err)
	}
	if changedFileSignature == fileStamp || changedContentSignature == contentSignature {
		t.Fatal("changed file kept a stale signature")
	}
}

func TestPolicyRuleMatchingIsExact(t *testing.T) {
	output := "0: from all lookup local\n1100: from all fwmark 0x2 lookup 1002\n"
	if !hasPolicyRule(output, "1100", "1002", "2") {
		t.Fatal("expected policy rule to match")
	}
	if hasPolicyRule(output, "110", "1002", "2") || hasPolicyRule(output, "1100", "100", "2") || hasPolicyRule(output, "1100", "1002", "1") {
		t.Fatal("partial rule must not match")
	}
}

func TestTransparentRulesRequireTCPAndUDP(t *testing.T) {
	complete := "meta l4proto tcp tproxy to :12345 meta mark set 0x1 accept\nmeta l4proto udp tproxy to :12345 meta mark set 0x1 accept\n"
	if !hasTransparentRules(complete, "12345") {
		t.Fatal("complete transparent rules did not match")
	}
	if hasTransparentRules("meta l4proto tcp tproxy to :12345 accept", "12345") || hasTransparentRules(complete, "12346") {
		t.Fatal("incomplete or wrong-port transparent rules matched")
	}
}

func TestParseXrayListenersIncludesBothTransparentProtocols(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray.json")
	body := []byte(`{"inbounds":[{"protocol":"dokodemo-door","port":12345,"settings":{"network":"tcp,udp"}}]}`)
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	listeners, err := parseXrayListeners(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []listener{{protocol: "tcp", port: 12345}, {protocol: "udp", port: 12345}}
	if !reflect.DeepEqual(listeners, want) {
		t.Fatalf("listeners=%#v, want %#v", listeners, want)
	}
}

func TestRestartHistoryPrunesAndWritesAtomically(t *testing.T) {
	now := time.Unix(2_000_000, 0)
	path := filepath.Join(t.TempDir(), "watchdog-restarts")
	body := "1999999\n1999900\n1990000\ninvalid\n2000001\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	evidencePath := filepath.Join(t.TempDir(), "watchdog-last-restart.json")
	r := &runner{opts: Options{RestartFile: path, RestartEvidence: evidencePath}}
	if err := r.pruneRestarts(now); err != nil {
		t.Fatal(err)
	}
	if r.restarts != 2 {
		t.Fatalf("restarts=%d, want 2", r.restarts)
	}
	if err := r.recordRestart(now, []string{"tcp_listener"}, 3, 3); err != nil {
		t.Fatal(err)
	}
	if r.restarts != 3 {
		t.Fatalf("restarts=%d, want 3", r.restarts)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o, want 600", info.Mode().Perm())
	}
	evidence, err := os.ReadFile(evidencePath)
	if err != nil {
		t.Fatal(err)
	}
	wantEvidence := `{"timestamp":2000000,"reasons":["tcp_listener"],"failure_count":3,"threshold":3}` + "\n"
	if string(evidence) != wantEvidence {
		t.Fatalf("evidence=%q, want %q", evidence, wantEvidence)
	}

	if err := r.pruneRestarts(now.Add(2 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if r.restarts != 0 {
		t.Fatalf("expired restarts=%d, want 0", r.restarts)
	}
}

func TestApplyGuardAcceptsLiveHeartbeatAndRemovesExpiredGuard(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "apply-in-progress")
	r := &runner{opts: Options{ApplyGuardFile: path}}

	live := []byte(fmt.Sprintf("%d %d %d\n", os.Getpid(), now.Add(-2*time.Minute).Unix(), now.Add(-10*time.Second).Unix()))
	if err := os.WriteFile(path, live, 0o600); err != nil {
		t.Fatal(err)
	}
	if !r.applyActive(now) {
		t.Fatal("live apply guard was not accepted")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("live apply guard was removed: %v", err)
	}

	expired := []byte(fmt.Sprintf("%d %d %d\n", os.Getpid(), now.Add(-2*time.Minute).Unix(), now.Add(-91*time.Second).Unix()))
	if err := os.WriteFile(path, expired, 0o600); err != nil {
		t.Fatal(err)
	}
	if r.applyActive(now) {
		t.Fatal("expired apply guard was accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expired apply guard remained: %v", err)
	}
}
