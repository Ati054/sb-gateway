package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type planChange struct {
	Operation string `json:"operation"`
	Path      string `json:"path"`
	Before    any    `json:"before"`
	After     any    `json:"after"`
}

type planStep struct {
	Order       int    `json:"order"`
	Kind        string `json:"kind"`
	Description string `json:"description"`
	Reversible  bool   `json:"reversible"`
}

func (server *Server) planDraft(response http.ResponseWriter, request *http.Request) {
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
	config, provided := body["config"].(map[string]any)
	if _, exists := body["config"]; exists && !provided {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_config", "Config must be an object.")
		return
	}
	if !provided {
		var err error
		config, err = server.getDraft()
		if err != nil {
			server.internalStateError(response, request, err)
			return
		}
	}
	payload, err := server.buildPlan(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.writeJSON(response, http.StatusOK, payload)
}

func (server *Server) buildPlan(config map[string]any) (map[string]any, error) {
	revision, err := revisionFor(config)
	if err != nil {
		return nil, err
	}
	check := validateCurrentConfigRevision(config, revision)
	activeRevision, err := server.repository.activeRevision()
	if err != nil {
		return nil, err
	}
	active := map[string]any{}
	if activeRevision != "" {
		active, err = server.repository.loadGeneration(activeRevision)
		if err != nil {
			return nil, err
		}
	}
	changes := flattenPlanChanges(active, config, "$")
	if changes == nil {
		changes = make([]planChange, 0)
	}
	idempotent := check.Valid && activeRevision == revision && len(changes) == 0
	metadata, err := server.repository.metadata()
	if err != nil {
		return nil, err
	}
	committedRouterOS, _ := metadata["routeros_source"].(string)
	if activeRevision != "" && committedRouterOS == "" {
		idempotent = false
	}
	routerOSChanged := !idempotent && planTouchesRouterOS(changes)
	if check.Valid && activeRevision != "" && !routerOSChanged {
		currentNodes, nodeErr := server.routerOSPlanNodes(config)
		if nodeErr != nil {
			return nil, nodeErr
		}
		// Apply renders the active RouterOS candidate from its committed node
		// snapshot and the desired candidate from current nodes. Plan must use
		// exactly the same inputs or the UI can advertise runtime_fast while
		// Apply correctly enters RouterOS Safe Mode.
		beforeNodes := server.routerOSNodesForRevision(activeRevision, currentNodes)
		afterNodes := server.routerOSNodesForRevision(revision, currentNodes)
		before := committedRouterOS
		var beforeErr error
		if before == "" {
			before, beforeErr = runtimeconfig.RenderRouterOSTrafficCandidate(active, beforeNodes, server.opts.Runtime.RuleSetDir)
		}
		after, afterErr := runtimeconfig.RenderRouterOSTrafficCandidate(config, afterNodes, server.opts.Runtime.RuleSetDir)
		if beforeErr != nil || afterErr != nil {
			check.Valid = false
			check.Errors = append(check.Errors, validationIssue{
				Path: "routeros", Code: "render",
				Message: "RouterOS managed candidate could not be rendered from the current configuration.",
			})
		} else {
			routerOSChanged = committedRouterOS == "" || before != after
			if routerOSChanged {
				idempotent = false
			}
		}
	}

	mode := "runtime_fast"
	steps := runtimePlanSteps()
	switch {
	case idempotent:
		mode = "unchanged"
		steps = []planStep{{1, "verify", "Configuration already matches the active revision.", true}}
	case routerOSChanged || activeRevision == "":
		mode = "routeros_safe_mode"
		steps = routerOSPlanSteps()
	}
	return map[string]any{
		"valid": check.Valid, "revision": revision, "idempotent": idempotent,
		"changes": redactPlanChanges(changes), "steps": steps, "apply_mode": mode,
		"routeros_changed": routerOSChanged || (activeRevision == "" && !idempotent),
		"requires_backup":  mode == "routeros_safe_mode", "connectivity_risk": false,
		"requires_runtime_guard": mode != "unchanged", "may_reconnect_proxy": mode != "unchanged",
		"check": check.payload(),
	}, nil
}

func redactPlanChanges(changes []planChange) []planChange {
	result := make([]planChange, len(changes))
	for index, change := range changes {
		result[index] = change
		result[index].Before = redactValue(change.Before, change.Path, false)
		result[index].After = redactValue(change.After, change.Path, false)
	}
	return result
}

func (server *Server) routerOSPlanNodes(config map[string]any) ([]map[string]any, error) {
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		return nil, err
	}
	return runtimeSubscriptionNodes(config, state), nil
}

func flattenPlanChanges(before, after any, path string) []planChange {
	if equalJSON(before, after) {
		return nil
	}
	beforeMap, beforeIsMap := before.(map[string]any)
	afterMap, afterIsMap := after.(map[string]any)
	if beforeIsMap && afterIsMap {
		keys := make([]string, 0, len(beforeMap)+len(afterMap))
		seen := make(map[string]struct{}, len(beforeMap)+len(afterMap))
		for key := range beforeMap {
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
		for key := range afterMap {
			if _, exists := seen[key]; !exists {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		changes := make([]planChange, 0)
		for _, key := range keys {
			child := path + "." + key
			oldValue, oldExists := beforeMap[key]
			newValue, newExists := afterMap[key]
			switch {
			case !oldExists:
				changes = append(changes, planChange{"add", child, nil, cloneJSONValue(newValue)})
			case !newExists:
				changes = append(changes, planChange{"remove", child, cloneJSONValue(oldValue), nil})
			default:
				changes = append(changes, flattenPlanChanges(oldValue, newValue, child)...)
			}
		}
		return changes
	}
	beforeArray, beforeIsArray := before.([]any)
	afterArray, afterIsArray := after.([]any)
	if beforeIsArray && afterIsArray && arraysHaveIDs(beforeArray) && arraysHaveIDs(afterArray) {
		oldItems := indexPlanItems(beforeArray)
		newItems := indexPlanItems(afterArray)
		ids := make([]string, 0, len(oldItems)+len(newItems))
		seen := make(map[string]struct{}, len(oldItems)+len(newItems))
		for id := range oldItems {
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
		for id := range newItems {
			if _, exists := seen[id]; !exists {
				ids = append(ids, id)
			}
		}
		sort.Strings(ids)
		changes := make([]planChange, 0)
		for _, id := range ids {
			child := fmt.Sprintf("%s[id=%s]", path, id)
			oldValue, oldExists := oldItems[id]
			newValue, newExists := newItems[id]
			switch {
			case !oldExists:
				changes = append(changes, planChange{"add", child, nil, cloneJSONValue(newValue)})
			case !newExists:
				changes = append(changes, planChange{"remove", child, cloneJSONValue(oldValue), nil})
			default:
				changes = append(changes, flattenPlanChanges(oldValue, newValue, child)...)
			}
		}
		return changes
	}
	return []planChange{{"replace", path, cloneJSONValue(before), cloneJSONValue(after)}}
}

func equalJSON(left, right any) bool {
	// In-memory defaults use int; HTTP/loaded JSON may use float64 or
	// json.Number. Equal numeric settings must not trigger RouterOS Apply.
	if isJSONNumber(left) && isJSONNumber(right) {
		l, le := json.Marshal(left)
		r, re := json.Marshal(right)
		return le == nil && re == nil && bytes.Equal(l, r)
	}
	return reflect.DeepEqual(left, right)
}

func isJSONNumber(value any) bool {
	switch value.(type) {
	case int, int64, int32, uint, uint64, uint32, float32, float64, json.Number:
		return true
	}
	return false
}

func arraysHaveIDs(values []any) bool {
	for _, value := range values {
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		if _, ok := object["id"].(string); !ok {
			return false
		}
	}
	return len(values) > 0
}

func indexPlanItems(values []any) map[string]map[string]any {
	result := make(map[string]map[string]any, len(values))
	for _, value := range values {
		object := value.(map[string]any)
		result[object["id"].(string)] = object
	}
	return result
}

func planTouchesRouterOS(changes []planChange) bool {
	prefixes := []string{"$.system.networking", "$.routeros", "$.dns", "$.watchdog", "$.local_clients", "$.networks"}
	for _, change := range changes {
		for _, prefix := range prefixes {
			if strings.HasPrefix(change.Path, prefix) {
				return true
			}
		}
	}
	return false
}

func runtimePlanSteps() []planStep {
	return []planStep{
		{1, "render", "Render native runtime files.", true},
		{2, "validate", "Validate the candidate without changing RouterOS.", true},
		{3, "activate", "Atomically publish changed runtime files.", true},
		{4, "probe", "Run bounded runtime health probes.", true},
		{5, "commit", "Mark the healthy runtime candidate last-known-good.", true},
	}
}

func routerOSPlanSteps() []planStep {
	return []planStep{
		{1, "backup", "Create RouterOS export and binary backup.", true},
		{2, "render", "Render native runtime and RouterOS candidates.", true},
		{3, "validate", "Validate generated candidates and RouterOS capabilities.", true},
		{4, "apply", "Apply only SB-GATEWAY managed objects under Safe Mode.", true},
		{5, "probe", "Run health and managed-route safety probes.", true},
		{6, "commit", "Atomically mark the candidate last-known-good.", true},
	}
}
