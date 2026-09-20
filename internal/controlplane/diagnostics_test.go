package controlplane

import (
	"context"
	"net/http"
	"testing"
)

type diagnosticsController struct {
	probes [][]string
	err    error
}

func (controller *diagnosticsController) Restart(context.Context, []string) error { return nil }
func (controller *diagnosticsController) Probe(_ context.Context, names []string) error {
	controller.probes = append(controller.probes, append([]string(nil), names...))
	return controller.err
}

func TestNativeDiagnosticsReportsUnconfiguredStateWithoutExternalProbe(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/diagnostics", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("diagnostics failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	checks := body["checks_performed"].(map[string]any)
	if body["ok"] != true || checks["config_validation"].(map[string]any)["passed"] != true {
		t.Fatalf("valid unconfigured state rejected: %#v", body)
	}
	if checks["routeros_discovery"].(map[string]any)["performed"] != false || checks["runtime_network_probes"].(map[string]any)["performed"] != false {
		t.Fatalf("diagnostics claimed unperformed I/O: %#v", checks)
	}
}

func TestStatusPayloadRemainsCompatibleAfterExtraction(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/status", nil, nil, cookie)
	if response.Code != http.StatusOK || decodeResponse(t, response)["state"] != "unconfigured" {
		t.Fatalf("status contract changed: %d %s", response.Code, response.Body.String())
	}
}
