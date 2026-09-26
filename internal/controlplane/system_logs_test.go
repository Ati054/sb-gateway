package controlplane

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSystemLogsExposeOnlyFixedBoundedSources(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	root := t.TempDir()
	systemLog := filepath.Join(root, "control-plane.log")
	nginxLog := filepath.Join(root, "nginx-error.log")
	if err := os.WriteFile(systemLog, []byte("ordinary line\nimage update scheduled\nrecovery archive ready\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(nginxLog, []byte("upstream prematurely closed connection\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	server.opts.Runtime.ControlPlaneLog = systemLog
	server.opts.Runtime.NginxErrorLog = nginxLog

	for source, want := range map[string]string{
		"system": "recovery archive ready", "nginx": "upstream prematurely", "lifecycle": "image update scheduled",
	} {
		response := performRequest(t, server, http.MethodGet, apiPrefix+"/runtime/system-logs?source="+source+"&lines=2", nil, nil, cookie)
		if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), want) {
			t.Fatalf("%s log response: %d %s", source, response.Code, response.Body.String())
		}
		if source == "lifecycle" && strings.Contains(response.Body.String(), "ordinary line") {
			t.Fatalf("lifecycle log leaked unrelated lines: %s", response.Body.String())
		}
	}

	invalid := performRequest(t, server, http.MethodGet, apiPrefix+"/runtime/system-logs?source=/etc/passwd", nil, nil, cookie)
	if invalid.Code != http.StatusUnprocessableEntity {
		t.Fatalf("custom path accepted: %d %s", invalid.Code, invalid.Body.String())
	}
}

func TestRoutingLogShowsOnlyRecentHealthEvents(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	path := filepath.Join(t.TempDir(), "control-plane.log")
	body := "agent: route-health {\"event\":\"probe-failed\",\"policy\":\"pc\"}\n" +
		strings.Repeat("ordinary control-plane line\n", 700) +
		"agent: route-health {\"event\":\"switch\",\"policy\":\"All\"}\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	server.opts.Runtime.ControlPlaneLog = path
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/runtime/system-logs?source=routing&lines=2", nil, nil, cookie)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "probe-failed") ||
		!strings.Contains(response.Body.String(), "switch") || strings.Contains(response.Body.String(), "ordinary control-plane line") {
		t.Fatalf("routing log filter: %d %s", response.Code, response.Body.String())
	}
}
