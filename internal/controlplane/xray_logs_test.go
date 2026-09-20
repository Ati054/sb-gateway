package controlplane

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

func TestXrayLogsRequireSessionAndReturnBoundedTail(t *testing.T) {
	server := newTestServer(t)
	root := t.TempDir()
	errorLog := filepath.Join(root, "xray-error.log")
	processLog := filepath.Join(root, "xray-process.log")
	server.opts.Runtime.XrayErrorLog = errorLog
	server.opts.Runtime.XrayProcessLog = processLog
	if err := os.WriteFile(errorLog, []byte("first\nsecond\nthird\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(processLog, []byte("panic detail\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	unauthorized := performRequest(t, server, http.MethodGet, apiPrefix+"/runtime/xray-logs", nil, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("log endpoint accepted an unauthenticated request: %d", unauthorized.Code)
	}
	cookie, _ := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/runtime/xray-logs?source=error&lines=2", nil, nil, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("log endpoint returned %d: %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	lines, ok := body["lines"].([]any)
	if !ok || len(lines) != 2 || lines[0] != "second" || lines[1] != "third" {
		t.Fatalf("unexpected log tail: %#v", body["lines"])
	}
	if body["truncated"] != true || body["available"] != true {
		t.Fatalf("tail metadata is incomplete: %#v", body)
	}

	process := performRequest(t, server, http.MethodGet, apiPrefix+"/runtime/xray-logs?source=process", nil, nil, cookie)
	if !strings.Contains(process.Body.String(), "panic detail") {
		t.Fatalf("process log was not selected: %s", process.Body.String())
	}
	invalid := performRequest(t, server, http.MethodGet, apiPrefix+"/runtime/xray-logs?source=custom", nil, nil, cookie)
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("custom log path selector was accepted: %d", invalid.Code)
	}
}

func TestXrayLogsTreatMissingFileAsEmptyState(t *testing.T) {
	server := newTestServer(t)
	server.opts.Runtime.XrayErrorLog = filepath.Join(t.TempDir(), "missing.log")
	cookie, _ := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/runtime/xray-logs", nil, nil, cookie)
	body := decodeResponse(t, response)
	if response.Code != http.StatusOK || body["available"] != false {
		t.Fatalf("missing log did not produce an empty state: %d %#v", response.Code, body)
	}
}

func TestAppliedDebugLevelGetsPersistentExpiry(t *testing.T) {
	server := newTestServer(t)
	now := time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	config := map[string]any{"system": map[string]any{"logging": map[string]any{
		"xray_level": "debug", "xray_debug_timeout_minutes": 15,
	}}}
	revision := strings.Repeat("a", 64)
	server.noteXrayLoggingApplied(config, revision)
	state, err := server.repository.auxiliary(xrayLoggingStateName)
	if err != nil {
		t.Fatal(err)
	}
	if state["level"] != "debug" || state["revision"] != revision || state["debug_expires_at"] != now.Add(15*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("debug expiry state is incomplete: %#v", state)
	}
}

func TestReapplyingUnchangedDebugDoesNotExtendExpiry(t *testing.T) {
	server := newTestServer(t)
	now := time.Date(2026, time.September, 15, 12, 0, 0, 0, time.UTC)
	server.now = func() time.Time { return now }
	config := map[string]any{"system": map[string]any{"logging": map[string]any{
		"xray_level": "debug", "xray_debug_timeout_minutes": 15,
	}}}
	server.noteXrayLoggingApplied(config, strings.Repeat("a", 64))
	want := now.Add(15 * time.Minute).Format(time.RFC3339Nano)
	now = now.Add(10 * time.Minute)
	server.noteXrayLoggingApplied(config, strings.Repeat("b", 64))
	state, err := server.repository.auxiliary(xrayLoggingStateName)
	if err != nil {
		t.Fatal(err)
	}
	if state["debug_expires_at"] != want {
		t.Fatalf("an unrelated Apply extended the debug deadline: %#v", state)
	}
}

func TestExpiredDebugLevelAppliesWarningAndRestartsOnlyRuntime(t *testing.T) {
	server := newTestServer(t)
	active := routerOSReadyConfig(t)
	setConfiguredXrayLogLevel(active, "debug")
	activeRevision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{
		Revision: activeRevision, RuntimeRevision: strings.Repeat("1", 64),
		Actor: "test", CommittedAt: server.now(),
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("2", 64)}
	server.runtime = runtime
	server.applyRouterOS = func(
		ctx context.Context, _ map[string]any, _, _ string,
		health func(context.Context) error,
		finalize func(context.Context, routeros.BackupRef) error,
	) (routerOSApplyOutput, error) {
		if err := health(ctx); err != nil {
			return routerOSApplyOutput{}, err
		}
		backup := routeros.BackupRef{Export: "safe.rsc", Binary: "safe.backup"}
		if err := finalize(ctx, backup); err != nil {
			return routerOSApplyOutput{}, err
		}
		return routerOSApplyOutput{Backup: backup, Kind: "delta"}, nil
	}

	if err := server.resetExpiredXrayDebug(context.Background(), activeRevision); err != nil {
		t.Fatal(err)
	}
	updated, err := server.repository.loadActive()
	if err != nil {
		t.Fatal(err)
	}
	if level := configuredXrayLogLevel(updated); level != "warning" {
		t.Fatalf("expired debug remained active: %q", level)
	}
	if runtime.activateCalls != 1 || runtime.commitCalls != 1 {
		t.Fatalf("runtime-only reset was not committed: %#v", runtime)
	}
	state, err := server.repository.auxiliary(xrayLoggingStateName)
	if err != nil || state["level"] != "warning" {
		t.Fatalf("logging state did not return to warning: %#v, %v", state, err)
	}
}
