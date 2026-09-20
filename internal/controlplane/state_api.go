package controlplane

import (
	"bytes"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

var apiCollections = map[string]string{
	"tls-profiles":          "tls_profiles",
	"local-clients":         "local_clients",
	"remote-users":          "remote_users",
	"reverse-vless-exits":   "reverse_vless_exits",
	"networks":              "networks",
	"policies":              "policies",
	"subscriptions":         "subscriptions",
	"subscription-reserves": "subscription_reserves",
	"transports":            "transports",
}

var ruleOrder = []struct {
	id          string
	description string
}{
	{"container-outage-local-fail-open", "When the container/TPROXY dataplane is unavailable, local clients either keep WAN access or remain LAN-only according to their own setting."},
	{"container-outage-local-direct-allowlist", "A LAN-only local client may still reach only its own explicit direct-site allowlist."},
	{"container-outage-remote-fail-closed", "Remote VLESS sessions never receive a home-WAN direct fallback."},
	{"internal-destination-bypass", "Routed LAN/VPN destinations bypass public service rules."},
	{"remote-direct-service", "A service explicitly allowed for this remote identity uses the home WAN."},
	{"remote-direct-domain", "A domain explicitly allowed for this remote identity uses the home WAN."},
	{"remote-public-vless", "Authenticated remote public traffic uses its assigned VLESS policy."},
	{"local-direct-service", "A selected service pack bypasses the full VLESS tunnel through RouterOS WAN."},
	{"local-direct-domain", "A selected local domain bypasses the full VLESS tunnel through RouterOS WAN."},
	{"local-service-vless", "Selected services from managed local clients use VLESS."},
	{"local-public-wan", "Other public traffic from managed local clients uses the home WAN."},
	{"unmanaged-default", "Unmanaged RouterOS traffic remains untouched."},
}

//go:embed default-config.json
var defaultConfigJSON []byte

func (server *Server) getDraft() (map[string]any, error) {
	config, err := server.repository.loadDraft()
	if errors.Is(err, os.ErrNotExist) || len(config) == 0 {
		config, err = server.repository.loadActive()
	}
	if errors.Is(err, os.ErrNotExist) || len(config) == 0 {
		config, err = decodeObject(defaultConfigJSON)
	}
	if err != nil {
		return nil, err
	}
	withRuntimeNetworkFacts(config)
	return config, nil
}

func decodeObject(body []byte) (map[string]any, error) {
	value := map[string]any{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	return value, nil
}

func withRuntimeNetworkFacts(config map[string]any) {
	system := objectAt(config, "system")
	networking := objectAt(system, "networking")
	gateway := strings.TrimSpace(os.Getenv("SB_ROUTEROS_GATEWAY"))
	containerAddress := strings.TrimSpace(os.Getenv("SB_CONTAINER_ADDRESS"))
	tunAddress := strings.TrimSpace(os.Getenv("SB_TUN_ADDRESS"))
	setEmpty(networking, "routeros_gateway", gateway)
	setEmpty(networking, "container_dns", gateway)
	setEmpty(networking, "container_address", containerAddress)
	setEmpty(networking, "tun_address", tunAddress)
	dns := objectAt(config, "dns")
	if gateway != "" && dns["address_confirmed"] != true {
		dns["internal_server"] = gateway
	}
}

func (server *Server) readiness(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireReadinessAuth(response, request); !ok {
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
	runtimeStatus, err := server.repository.runtimeStatus()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	configured := active != ""
	consistent := !configured || lkg == active
	status := http.StatusOK
	if !consistent {
		status = http.StatusServiceUnavailable
	}
	server.writeJSON(response, status, map[string]any{
		"ready": consistent, "configured": configured,
		"last_known_good_consistent": consistent,
		"container_healthy":          nestedValue(runtimeStatus, "container", "healthy"),
		"watchdog":                   valueOrEmpty(runtimeStatus["watchdog"]),
		"outage_policy_active":       server.outagePolicyForActive(),
	})
}

func (server *Server) routerReadiness(response http.ResponseWriter, request *http.Request) {
	active, err := server.repository.loadActive()
	if errors.Is(err, os.ErrNotExist) {
		active = nil
	} else if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	ready, payload := server.routerReadinessState(active)
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	server.writeJSON(response, status, payload)
}

func (server *Server) routerReadinessState(active map[string]any) (bool, map[string]any) {
	ttl := routerReadinessLeaseTTL(active)
	marker := envOr("SB_ROUTER_READY_MARKER", "/run/sb-gateway/router-ready")
	age := -1
	ready := false
	if body, readErr := os.ReadFile(marker); readErr == nil {
		text := strings.TrimSpace(string(body))
		if len(text) <= 12 {
			if issued, parseErr := strconv.ParseInt(text, 10, 64); parseErr == nil {
				age = int(server.now().Unix() - issued)
				ready = active != nil && age >= 0 && age <= ttl
			}
		}
	}
	mountsWritable, blockedMounts := server.checkPersistentMounts()
	ready = ready && mountsWritable
	payload := map[string]any{
		"ready": ready, "configured": active != nil,
		"lease_age_seconds": nil, "lease_ttl_seconds": ttl,
		"outage_policy_active":       outagePolicy(active),
		"persistent_mounts_writable": mountsWritable,
	}
	if len(blockedMounts) != 0 {
		payload["blocked_persistent_mounts"] = blockedMounts
	}
	if age >= 0 {
		payload["lease_age_seconds"] = age
	}
	return ready, payload
}

// trafficReadiness is deliberately stricter than the image probation health
// endpoint. A new container may be healthy enough to keep while its selected
// full-tunnel exits are still being restored. RouterOS keeps the diversion
// gate disabled (ordinary WAN or the configured fail-closed rule) until every
// enabled local full-tunnel policy has a confirmed, non-blocking selector.
func (server *Server) trafficReadiness(response http.ResponseWriter, request *http.Request) {
	active, err := server.repository.loadActive()
	if errors.Is(err, os.ErrNotExist) {
		active = nil
	} else if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	baseReady, payload := server.routerReadinessState(active)
	selector, err := server.repository.auxiliary("selector-health")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	required, pending := trafficReadyPolicies(active, selector, server.trafficReadyAfter)
	ready := baseReady && len(pending) == 0
	payload["ready"] = ready
	payload["traffic_ready"] = ready
	payload["required_local_policies"] = required
	payload["pending_local_policies"] = pending
	status := http.StatusOK
	if !ready {
		status = http.StatusServiceUnavailable
	}
	server.writeJSON(response, status, payload)
}

func trafficReadyPolicies(active, selector map[string]any, notBefore time.Time) ([]string, []string) {
	requiredSet := make(map[string]bool)
	for _, client := range objects(active["local_clients"]) {
		if !boolDefault(client, "enabled", true) {
			continue
		}
		policyID := strings.TrimSpace(text(client["policy_id"]))
		policy := enabledClientPolicy(active, policyID)
		if policy == nil {
			continue
		}
		requiredSet[policyID] = true
	}
	required := make([]string, 0, len(requiredSet))
	for policyID := range requiredSet {
		required = append(required, policyID)
	}
	sort.Strings(required)
	pending := make([]string, 0)
	for _, policyID := range required {
		item, _ := selector[policyID].(map[string]any)
		selected := strings.TrimSpace(text(item["runtime_selected"]))
		observed, observedErr := time.Parse(time.RFC3339Nano, strings.TrimSpace(text(item["runtime_observed_at"])))
		fresh := notBefore.IsZero() || (observedErr == nil && !observed.Before(notBefore))
		if item["runtime_confirmed"] != true || selected == "" || selected == "block" || !fresh {
			pending = append(pending, policyID)
		}
	}
	return required, pending
}

func routerReadinessLeaseTTL(active map[string]any) int {
	interval := boundedJSONInt(nestedValue(active, "watchdog", "interval_seconds"), 5, 1, 300)
	// The in-container watchdog refreshes the marker every interval. Two missed
	// refreshes plus a small scheduling allowance are enough to withdraw the
	// lease; RouterOS still applies its own failure threshold before fail-open.
	// Keeping the two hysteresis layers independent avoids the former 45s lease
	// multiplying into roughly a minute before ordinary WAN access returned.
	ttl := interval*2 + 5
	if ttl < 15 {
		ttl = 15
	}
	if ttl > 900 {
		ttl = 900
	}
	return ttl
}

func (server *Server) status(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireReadAuth(response, request); !ok {
		return
	}
	if request.URL.Query().Get("view") == "subscriptions" {
		state, err := server.repository.auxiliary("subscription-nodes")
		if err != nil {
			server.internalStateError(response, request, err)
			return
		}
		compact := make(map[string]any, len(state))
		for id, raw := range state {
			item, _ := raw.(map[string]any)
			compact[id] = map[string]any{"provider": valueOrEmpty(item["provider"]), "refreshed_at": item["refreshed_at"]}
		}
		server.writeJSON(response, http.StatusOK, map[string]any{"subscriptions": compact})
		return
	}
	if request.URL.Query().Get("view") == "selectors" {
		selector, err := server.repository.auxiliary("selector-health")
		if err != nil {
			server.internalStateError(response, request, err)
			return
		}
		compact := make(map[string]any, len(selector))
		for id, raw := range selector {
			item, _ := raw.(map[string]any)
			fields := make(map[string]any)
			for _, key := range []string{"runtime_selected", "runtime_confirmed", "runtime_observed_at", "runtime_error", "candidate_labels", "candidate_nodes", "candidate_count", "availability_ok", "shortlist"} {
				if value, exists := item[key]; exists {
					fields[key] = value
				}
			}
			// An empty error must clear an earlier failure in the UI merge.
			if fields["runtime_error"] == nil {
				fields["runtime_error"] = ""
			}
			compact[id] = fields
		}
		metadata, err := server.repository.metadata()
		if err != nil {
			server.internalStateError(response, request, err)
			return
		}
		server.writeJSON(response, http.StatusOK, map[string]any{"selector_health": compact, "runtime_revision": metadata["runtime_revision"]})
		return
	}
	payload, err := server.statusPayload()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.writeJSON(response, http.StatusOK, payload)
}

func (server *Server) statusPayload() (map[string]any, error) {
	active, err := server.repository.activeRevision()
	if err != nil {
		return nil, err
	}
	runtimeStatus, err := server.repository.runtimeStatus()
	if err != nil {
		return nil, err
	}
	metadata, err := server.repository.metadata()
	if err != nil {
		return nil, err
	}
	selector, err := server.repository.auxiliary("selector-health")
	if err != nil {
		return nil, err
	}
	cdnState, err := server.repository.auxiliary("cdn-feeds")
	if err != nil {
		return nil, err
	}
	cdnStatus := map[string]any{}
	for provider, raw := range cdnState {
		record, _ := raw.(map[string]any)
		cdnStatus[provider] = map[string]any{"state": record["state"], "last_attempt_at": record["last_attempt_at"], "last_success_at": record["last_success_at"], "ipv4_count": len(cdnCachedValues(record["cidrs"]))}
	}
	acmeState, err := server.repository.auxiliary("acme")
	if err != nil {
		return nil, err
	}
	acmeStatus := map[string]any{}
	for id, raw := range acmeState {
		record := decodeACMERecord(raw)
		acmeStatus[id] = map[string]any{"enabled": record.Settings.Enabled, "state": record.State, "metadata": record.Metadata}
	}
	container, _ := runtimeStatus["container"].(map[string]any)
	watchdog, _ := runtimeStatus["watchdog"].(map[string]any)
	state := "degraded"
	if active == "" {
		state = "unconfigured"
	} else if container["healthy"] == true && watchdog["state"] != "failed" && watchdog["state"] != "tripped" {
		state = "healthy"
	}
	return map[string]any{
		"state": state, "container": valueOrEmpty(container), "watchdog": valueOrEmpty(watchdog),
		"routing":         map[string]any{"local_on_outage": "wan-direct", "remote_on_outage": "drop"},
		"active_revision": nullableString(active), "last_apply": publicApplyMetadata(metadata), "selector_health": selector,
		"cdn_feeds": cdnStatus,
		"acme":      acmeStatus,
	}, nil
}

func publicApplyMetadata(metadata map[string]any) map[string]any {
	result := make(map[string]any, len(metadata))
	for key, value := range metadata {
		if key != "routeros_source" {
			result[key] = value
		}
	}
	return result
}

func (server *Server) clientTelemetry(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	touch(envOr("SB_CLIENT_TELEMETRY_INTEREST", "/run/sb-gateway/client-telemetry-interest"))
	state, err := server.repository.auxiliary("client-telemetry")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	snapshot, ok := state["snapshot"].(map[string]any)
	if !ok {
		snapshot = map[string]any{"generated_at": nil, "clients": []any{}}
	}
	server.writeJSON(response, http.StatusOK, snapshot)
}

func (server *Server) currentDraft(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	envelope, err := server.draftEnvelope(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.writeJSON(response, http.StatusOK, envelope)
}

func (server *Server) draftEnvelope(config map[string]any) (map[string]any, error) {
	revision, err := revisionFor(config)
	if err != nil {
		return nil, err
	}
	active, err := server.repository.activeRevision()
	if err != nil {
		return nil, err
	}
	pending := 0
	if active != revision {
		pending = 1
	}
	validation := server.validationFor(config, revision).payload()
	return map[string]any{
		"config": redactValue(config, "", false), "revision": revision, "validation": validation,
		"pending_change_count": pending, "pending_config_change_count": pending,
		"pending_config_path_count": pending, "pending_config_changes": []any{},
		"runtime_update_required": false, "runtime_update_only": false,
		"has_active_configuration": active != "",
	}, nil
}

func (server *Server) checkDraft(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	body := map[string]any{}
	if request.Body != http.NoBody && request.ContentLength != 0 {
		var ok bool
		body, ok = server.readObject(response, request, maxRequestBytes)
		if !ok {
			return
		}
	}
	config, hasConfig := body["config"].(map[string]any)
	if !hasConfig {
		var err error
		config, err = server.getDraft()
		if err != nil {
			server.internalStateError(response, request, err)
			return
		}
	}
	server.writeJSON(response, http.StatusOK, validateCurrentConfig(config).payload())
}

func (server *Server) putDraft(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	config := body
	if nested, exists := body["config"]; exists {
		var valid bool
		config, valid = nested.(map[string]any)
		if !valid {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_config", "Config must be an object.")
			return
		}
	}
	server.configMu.Lock()
	defer server.configMu.Unlock()
	server.persistDraft(response, request, payload, config, "draft.save")
}

func (server *Server) patchDraft(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	sections := map[string]any{}
	if raw, exists := body["sections"]; exists {
		var valid bool
		sections, valid = raw.(map[string]any)
		if !valid {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_patch", "Sections must be an object.")
			return
		}
	} else {
		section, sectionOK := body["section"].(string)
		value, valueOK := body["value"]
		if !sectionOK || !valueOK {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_patch", "Provide sections or section and value.")
			return
		}
		sections[section] = value
	}
	if len(sections) == 0 {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_patch", "At least one settings section is required.")
		return
	}
	allowed := map[string]bool{
		"system": true, "routeros": true, "watchdog": true, "ingress": true, "dns": true,
		"security": true, "public_exposure": true, "updates": true, "storage": true, "service_packs": true,
		"tls_profiles": true, "local_clients": true, "remote_users": true, "reverse_vless_exits": true,
		"networks": true, "policies": true, "subscriptions": true, "subscription_reserves": true, "transports": true,
	}
	for section := range sections {
		if !allowed[section] {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "unknown_section", "Unknown settings section.")
			return
		}
	}

	server.configMu.Lock()
	defer server.configMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	for section, value := range sections {
		config[section] = cloneJSONValue(value)
	}
	server.persistDraft(response, request, payload, config, "draft.patch")
}

func (server *Server) resetDraft(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	server.configMu.Lock()
	defer server.configMu.Unlock()
	activeRevision, err := server.repository.activeRevision()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	if activeRevision == "" {
		server.writeErrorResponse(response, request, http.StatusConflict, "active_configuration_missing", "There is no applied configuration to restore.")
		return
	}
	active, err := server.repository.loadActive()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	result := validateCurrentConfigRevision(active, activeRevision)
	if !result.Valid {
		server.writeValidationError(response, request, result)
		return
	}
	if _, err := server.repository.saveDraft(active); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.rememberValidation(result)
	server.audit(request, fmt.Sprint(payload["sub"]), "draft.reset", "ok", map[string]any{"revision": activeRevision})
	envelope, err := server.draftEnvelope(active)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	envelope["subscription_snapshot_restored"] = false
	server.writeJSON(response, http.StatusOK, envelope)
}

func (server *Server) persistDraft(response http.ResponseWriter, request *http.Request, payload map[string]any, config map[string]any, action string) {
	normalizeXHTTPModeCompatibility(config)
	pendingSecret, err := server.prepareDraftSecrets(config)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_subscription_origin_header", err.Error())
		return
	}
	result := validateCurrentConfig(config)
	if !result.Valid {
		server.writeValidationError(response, request, result)
		return
	}
	if pendingSecret != nil {
		if err := server.secrets.write(pendingSecret.reference, pendingSecret.value, pendingSecret.overwrite); err != nil {
			server.writeErrorResponse(response, request, http.StatusInternalServerError, "secret_store_failed", "Subscription origin header secret could not be stored.")
			return
		}
	}
	revision, err := server.repository.saveDraft(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	result.Revision = revision
	server.rememberValidation(result)
	server.audit(request, fmt.Sprint(payload["sub"]), action, "ok", map[string]any{"revision": revision})
	envelope, err := server.draftEnvelope(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.writeJSON(response, http.StatusOK, envelope)
}

type pendingDraftSecret struct {
	reference string
	value     string
	overwrite bool
}

func (server *Server) prepareDraftSecrets(config map[string]any) (*pendingDraftSecret, error) {
	ingress, ok := config["ingress"].(map[string]any)
	if !ok {
		return nil, nil
	}
	raw, supplied := ingress["subscription_origin_header_value"]
	delete(ingress, "subscription_origin_header_value")
	if !runtimeconfig.SubscriptionEndpointEnabled(config) || ingress["subscription_endpoint_mode"] != "separate" || ingress["subscription_origin_protection_mode"] != "secret-header" {
		return nil, nil
	}
	reference, _ := ingress["subscription_origin_header_secret_ref"].(string)
	if reference == "" {
		reference = "ingress/subscription-origin-header"
	}
	if !validSecretReference(reference) {
		return nil, errors.New("Subscription origin header secret reference is invalid.")
	}
	ingress["subscription_origin_header_secret_ref"] = reference
	if supplied {
		value, ok := raw.(string)
		if !ok || len(value) < 24 || len(value) > 256 || strings.IndexFunc(value, func(character rune) bool { return character < 33 }) >= 0 {
			return nil, errors.New("Subscription origin header secret must contain 24 to 256 visible characters without spaces.")
		}
		return &pendingDraftSecret{reference: reference, value: value, overwrite: server.secrets.exists(reference)}, nil
	} else if !server.secrets.exists(reference) {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err != nil {
			return nil, errors.New("Subscription origin header secret could not be generated.")
		}
		return &pendingDraftSecret{reference: reference, value: base64.RawURLEncoding.EncodeToString(bytes)}, nil
	}
	return nil, nil
}

func (server *Server) writeValidationError(response http.ResponseWriter, request *http.Request, result configValidation) {
	requestID, _ := request.Context().Value(requestIDKey{}).(string)
	server.writeJSON(response, http.StatusUnprocessableEntity, map[string]any{"error": map[string]any{
		"code": "validation_failed", "message": "Configuration validation failed.",
		"details": result.Errors, "request_id": requestID,
	}})
}

func (server *Server) listCollection(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	collection, ok := apiCollections[request.PathValue("collection")]
	if !ok {
		server.writeErrorResponse(response, request, http.StatusNotFound, "not_found", "API route was not found.")
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	revision, err := revisionFor(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	items, _ := config[collection].([]any)
	if items == nil {
		items = []any{}
	}
	server.writeJSON(response, http.StatusOK, map[string]any{"items": redactValue(items, "", false), "revision": revision})
}

func (server *Server) getCollectionItem(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	collection, ok := apiCollections[request.PathValue("collection")]
	if !ok {
		server.writeErrorResponse(response, request, http.StatusNotFound, "not_found", "API route was not found.")
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	entityID := request.PathValue("entity")
	items, _ := config[collection].([]any)
	for _, raw := range items {
		item, isObject := raw.(map[string]any)
		if isObject && fmt.Sprint(item["id"]) == entityID {
			revision, revisionErr := revisionFor(config)
			if revisionErr != nil {
				server.internalStateError(response, request, revisionErr)
				return
			}
			server.writeJSON(response, http.StatusOK, map[string]any{"item": redactValue(item, "", false), "revision": revision})
			return
		}
	}
	server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "The requested object does not exist.")
}

func (server *Server) overview(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	payload, err := server.overviewPayload(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.writeJSON(response, http.StatusOK, payload)
}

func (server *Server) bootstrapState(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	draft, err := server.draftEnvelope(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	overview, err := server.overviewPayload(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{"draft": draft, "overview": overview})
}

func (server *Server) overviewPayload(config map[string]any) (map[string]any, error) {
	draftRevision, err := revisionFor(config)
	if err != nil {
		return nil, err
	}
	activeRevision, err := server.repository.activeRevision()
	if err != nil {
		return nil, err
	}
	runtimeStatus, err := server.repository.runtimeStatus()
	if err != nil {
		return nil, err
	}
	metadata, err := server.repository.metadata()
	if err != nil {
		return nil, err
	}
	audit, err := server.repository.recentAudit(200)
	if err != nil {
		return nil, err
	}
	recentAudit := audit
	if len(recentAudit) > 10 {
		recentAudit = recentAudit[len(recentAudit)-10:]
	}
	recentEvents := make([]map[string]any, 0, 5)
	for index := len(audit) - 1; index >= 0 && len(recentEvents) < 5; index-- {
		if !strings.HasPrefix(fmt.Sprint(audit[index]["action"]), "auth.") {
			recentEvents = append(recentEvents, audit[index])
		}
	}
	counts := make(map[string]any, len(apiCollections))
	for _, collection := range apiCollections {
		items, _ := config[collection].([]any)
		counts[collection] = len(items)
	}
	pending := 0
	if activeRevision != draftRevision {
		pending = 1
	}
	routerOS := cloneJSONValue(objectAt(config, "routeros")).(map[string]any)
	routerOS["last_tested_baseline"] = "7.21.5"
	routerOS["summary_source"] = "import"
	routerOS["live_available"] = false
	container, _ := runtimeStatus["container"].(map[string]any)
	watchdogState, _ := runtimeStatus["watchdog"].(map[string]any)
	state := "degraded"
	if activeRevision == "" {
		state = "unconfigured"
	} else if container["healthy"] == true && watchdogState["state"] != "failed" && watchdogState["state"] != "tripped" {
		state = "healthy"
	}
	compiledOrder := make([]any, 0, len(ruleOrder))
	for index, item := range ruleOrder {
		compiledOrder = append(compiledOrder, map[string]any{"priority": (index + 1) * 100, "id": item.id, "description": item.description})
	}
	return map[string]any{
		"status": map[string]any{
			"state": state, "container": valueOrEmpty(container), "watchdog": valueOrEmpty(watchdogState),
			"routing":         map[string]any{"local_on_outage": "wan-direct", "remote_on_outage": "drop"},
			"active_revision": nullableString(activeRevision), "last_apply": metadata,
		},
		"counts": counts, "active_revision": nullableString(activeRevision), "draft_revision": draftRevision,
		"pending_change_count": pending, "pending_config_change_count": pending,
		"pending_config_path_count": pending, "pending_config_changes": []any{},
		"runtime_update_required": false, "runtime_update_only": false,
		"routeros": redactValue(routerOS, "", false), "build": runtimeBuildInfo(),
		"connection_address": server.connectionAddress(config),
		"outage_policy":      outagePolicy(config), "rule_order": compiledOrder,
		"recent_audit": recentAudit, "recent_events": recentEvents,
	}, nil
}

func (server *Server) lifecycleStatus(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	server.lifecycleMu.Lock()
	defer server.lifecycleMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	operation, err := server.repository.auxiliary("lifecycle-operation")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	operation = server.reconcileLifecycleOperation(request.Context(), config, operation)
	storage := objectAt(config, "storage")
	updates := objectAt(config, "updates")
	root := strings.TrimSpace(fmt.Sprint(storage["root"]))
	if root == "<nil>" {
		root = ""
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"routeros_live": map[string]any{}, "storage_root": root, "configured_storage_root": root,
		"settings": redactValue(updates, "", false), "operation": redactValue(operation, "", false),
		"supported_update_sources": []any{"registry", "browser-upload", "local-file"},
		"registry_requires_digest": true, "browser_upload_hash_verification": true,
		"browser_upload_architecture_verification": "arm64", "local_file_hash_verification": "streamed-once-content-addressed",
	})
}

func runtimeBuildInfo() map[string]any {
	running := false
	paths, _ := filepath.Glob("/proc/[0-9]*/comm")
	for _, path := range paths {
		if body, err := os.ReadFile(path); err == nil && strings.TrimSpace(string(body)) == "xray" {
			running = true
			break
		}
	}
	version := envOr("SB_XRAY_VERSION", "26.9.9")
	runtimeCore := "starting"
	if running {
		runtimeCore = "xray"
	}
	return map[string]any{
		"container_version": envOr("SB_GATEWAY_VERSION", "1.5.57"),
		"image_revision":    envOr("SB_GATEWAY_REVISION", "uncommitted"),
		"active_core":       "xray", "active_core_name": "Xray-core", "active_core_version": version,
		"selected_core": "xray", "runtime_core": runtimeCore, "core_matches_selection": running,
		"bundled_core_versions": map[string]any{"xray": version},
	}
}

func (server *Server) recordWatchdog(response http.ResponseWriter, request *http.Request) {
	if !server.managementBearer(request) {
		server.writeErrorResponse(response, request, http.StatusUnauthorized, "management_bearer_required", "Management bootstrap authentication is required.")
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	state := fmt.Sprint(body["state"])
	allowed := map[string]bool{"starting": true, "healthy": true, "degraded": true, "recovering": true, "applying": true, "tripped": true, "failed": true, "unknown": true}
	if !allowed[state] {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_watchdog_state", "Invalid watchdog state.")
		return
	}
	restarts, validRestarts := optionalJSONInt(body, "restarts", 0, 0, 1<<30)
	failures, validFailures := optionalJSONInt(body, "failure_count", 0, 0, 1<<30)
	configuredMaximum := 6
	if active, activeErr := server.repository.loadActive(); activeErr == nil {
		configuredMaximum = boundedJSONInt(nestedValue(active, "watchdog", "max_restarts_per_hour"), 6, 1, 60)
	}
	maximum, validMaximum := optionalJSONInt(body, "max_restarts_per_hour", configuredMaximum, 1, 60)
	if !validRestarts || !validFailures || !validMaximum {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_watchdog_counters", "Watchdog counters and restart budget are invalid.")
		return
	}
	now := server.now().UTC().Format(time.RFC3339Nano)
	healthy, _ := body["container_healthy"].(bool)
	containerHealthy := any(nil)
	if _, exists := body["container_healthy"].(bool); exists {
		containerHealthy = healthy
	}
	lastAction := strings.TrimSpace(fmt.Sprint(body["last_action"]))
	if lastAction == "<nil>" || lastAction == "" {
		lastAction = ""
	}
	if len(lastAction) > 128 {
		lastAction = lastAction[:128]
	}
	watchdog := map[string]any{
		"enabled": true, "state": state, "restarts": restarts,
		"max_restarts_per_hour": maximum, "budget_remaining": max(0, maximum-restarts),
		"failure_count": failures, "last_action": nullableString(lastAction), "updated_at": now,
	}
	status := map[string]any{"container": map[string]any{"healthy": containerHealthy, "last_probe": now}, "watchdog": watchdog}
	if err := server.repository.saveAuxiliary("runtime-status", status); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	status["ok"] = true
	server.writeJSON(response, http.StatusOK, status)
}

func (server *Server) requireReadinessAuth(response http.ResponseWriter, request *http.Request) (map[string]any, bool) {
	if session, ok := server.session(request); ok {
		return session, true
	}
	if server.managementBearer(request) {
		return map[string]any{"sub": "watchdog"}, true
	}
	server.writeErrorResponse(response, request, http.StatusUnauthorized, "authentication_required", "Readiness authentication is required.")
	return nil, false
}

func (server *Server) requireReadAuth(response http.ResponseWriter, request *http.Request) (map[string]any, bool) {
	if session, ok := server.session(request); ok {
		return session, true
	}
	if server.managementBearer(request) {
		return map[string]any{"sub": "management-bootstrap"}, true
	}
	server.writeErrorResponse(response, request, http.StatusUnauthorized, "management_bearer_required", "Management bootstrap authentication is required.")
	return nil, false
}

func (server *Server) internalStateError(response http.ResponseWriter, request *http.Request, err error) {
	log.Printf("control-plane state error: %v", err)
	server.writeErrorResponse(response, request, http.StatusInternalServerError, "state_error", "Persistent gateway state is unavailable.")
}

func (server *Server) outagePolicyForActive() map[string]any {
	active, err := server.repository.loadActive()
	if err != nil {
		return outagePolicy(nil)
	}
	return outagePolicy(active)
}

func outagePolicy(config map[string]any) map[string]any {
	lanOnly := make([]string, 0)
	policies := make(map[string]map[string]any)
	if values, ok := config["policies"].([]any); ok {
		for _, value := range values {
			if item, ok := value.(map[string]any); ok {
				policies[fmt.Sprint(item["id"])] = item
			}
		}
	}
	if values, ok := config["local_clients"].([]any); ok {
		for _, value := range values {
			client, ok := value.(map[string]any)
			if !ok || client["enabled"] == false {
				continue
			}
			mode := fmt.Sprint(client["container_outage"])
			if mode == "" || mode == "<nil>" {
				mode = fmt.Sprint(policies[fmt.Sprint(client["policy_id"])]["container_outage"])
			}
			if mode == "lan_only" {
				lanOnly = append(lanOnly, fmt.Sprint(client["id"]))
			}
		}
	}
	sort.Strings(lanOnly)
	return map[string]any{"local": "per-client", "local_default": "fail-open-wan", "local_lan_only_clients": lanOnly, "remote": "fail-closed"}
}

func objectAt(value map[string]any, key string) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if object, ok := value[key].(map[string]any); ok {
		return object
	}
	object := map[string]any{}
	value[key] = object
	return object
}

func nestedValue(value map[string]any, keys ...string) any {
	var current any = value
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current = object[key]
	}
	return current
}

func setEmpty(value map[string]any, key, candidate string) {
	if candidate != "" && (value[key] == nil || value[key] == "") {
		value[key] = candidate
	}
}

func boundedJSONInt(value any, fallback, minimum, maximum int) int {
	parsed, ok := jsonInt(value)
	if !ok || parsed < int64(minimum) || parsed > int64(maximum) {
		return fallback
	}
	return int(parsed)
}

func optionalJSONInt(value map[string]any, key string, fallback, minimum, maximum int) (int, bool) {
	raw, exists := value[key]
	if !exists {
		return fallback, true
	}
	parsed, ok := jsonInt(raw)
	if !ok || parsed < int64(minimum) || parsed > int64(maximum) {
		return 0, false
	}
	return int(parsed), true
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func valueOrEmpty(value any) any {
	if value == nil {
		return map[string]any{}
	}
	return value
}
