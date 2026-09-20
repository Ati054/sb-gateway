package controlplane

import (
	"context"
	"net/http"
	"time"
)

func (server *Server) diagnostics(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireCSRF(response, request); !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	validation := validateCurrentConfig(config)
	status, err := server.statusPayload()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	active, err := server.repository.activeRevision()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	lkg, err := server.repository.lkgRevision()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}

	routerConfigured := routerOSCredentialsConfigured(config, server.secrets)
	routerPassed := false
	routerReason := "RouterOS credentials are not configured."
	if routerConfigured {
		routerReason = ""
		probeContext, cancel := context.WithTimeout(request.Context(), 20*time.Second)
		stack, stackErr := server.newRouterOSStack(config)
		if stackErr == nil {
			routerPassed = stack.REST.Health(probeContext) == nil
			stack.REST.CloseIdleConnections()
		}
		cancel()
		if !routerPassed {
			routerReason = "Authenticated RouterOS REST health check failed."
		}
	}

	runtimePerformed := active != "" && server.opts.Controller != nil
	runtimePassed := false
	runtimeReason := "No active generation is running under the native process controller."
	if runtimePerformed {
		probeContext, cancel := context.WithTimeout(request.Context(), 12*time.Second)
		runtimePassed = server.opts.Controller.Probe(probeContext, []string{"nginx", "dns", "xray", "monitor"}) == nil
		cancel()
		if runtimePassed {
			runtimeReason = ""
		} else {
			runtimeReason = "One or more native runtime components failed their bounded probe."
		}
	}
	pointersConsistent := active == "" || active == lkg
	ok := validation.Valid && pointersConsistent && (!routerConfigured || routerPassed) && (!runtimePerformed || runtimePassed)
	checks := map[string]any{
		"config_validation":           map[string]any{"performed": true, "passed": validation.Valid},
		"routeros_discovery":          map[string]any{"performed": routerConfigured, "passed": routerPassed, "reason": routerReason},
		"candidate_binary_validation": map[string]any{"performed": runtimePerformed, "passed": runtimePassed, "reason": runtimeReason},
		"runtime_network_probes": map[string]any{
			"performed": false, "passed": nil,
			"reason": "Diagnostics does not initiate external Internet traffic; watchdog evidence is reported separately in status.",
		},
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"ok": ok, "scope": "control-plane-only", "check": validation.payload(), "status": status,
		"checks_performed": checks,
		"state_storage":    map[string]any{"active_pointer": active != "", "lkg_pointer": lkg != "", "pointers_consistent": pointersConsistent},
		"secrets": map[string]any{
			"routeros_credentials_provisioned": routerConfigured,
			"management_token_provisioned":     server.secrets.exists("management-api-token"),
		},
	})
}

func routerOSCredentialsConfigured(config map[string]any, secrets *secretStore) bool {
	router := objectAt(config, "routeros")
	for _, field := range []string{"username_secret_ref", "password_secret_ref"} {
		reference, _ := router[field].(string)
		if reference == "" || !secrets.exists(reference) {
			return false
		}
	}
	return true
}
