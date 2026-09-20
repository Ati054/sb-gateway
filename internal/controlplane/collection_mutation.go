package controlplane

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

var uuidValuePattern = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

var nativeMutableCollections = map[string]bool{
	"tls_profiles":          true,
	"local_clients":         true,
	"remote_users":          true,
	"reverse_vless_exits":   true,
	"networks":              true,
	"policies":              true,
	"subscriptions":         true,
	"subscription_reserves": true,
	"transports":            true,
}

type pendingEntitySecret struct {
	reference string
	value     string
	overwrite bool
}

type previousEntitySecret struct {
	reference string
	value     string
	existed   bool
}

func (server *Server) createCollectionItem(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	collection, ok := server.mutableCollection(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	item := body
	if nested, exists := body["item"]; exists {
		item, ok = nested.(map[string]any)
		if !ok {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_item", "Item must be an object.")
			return
		}
	}
	item = cloneJSONObject(item)
	entityID, _ := item["id"].(string)
	if !entityIDPattern.MatchString(entityID) {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_id", "Entity ID format is invalid.")
		return
	}

	server.configMu.Lock()
	defer server.configMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	items, ok := config[collection].([]any)
	if !ok {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_collection", "Entity collection has an invalid shape.")
		return
	}
	if findEntityIndex(items, entityID) >= 0 {
		server.writeErrorResponse(response, request, http.StatusConflict, "already_exists", "Entity ID already exists.")
		return
	}
	if collection == "transports" {
		if err := server.prepareConnectionBinding(config, item); err != nil {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "wan_inventory_unavailable", err.Error())
			return
		}
	}
	prepared, secrets, err := server.prepareEntitySecrets(collection, item, true)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_entity_secret", err.Error())
		return
	}
	config[collection] = append(items, prepared)
	server.commitEntityMutation(response, request, payload, config, collection, entityID, "create", prepared, secrets)
}

func (server *Server) updateCollectionItem(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	collection, ok := server.mutableCollection(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	item := body
	if nested, exists := body["item"]; exists {
		item, ok = nested.(map[string]any)
		if !ok {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_item", "Item must be an object.")
			return
		}
	}
	item = cloneJSONObject(item)
	entityID := request.PathValue("entity")
	if !entityIDPattern.MatchString(entityID) {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_id", "Entity ID format is invalid.")
		return
	}
	item["id"] = entityID

	server.configMu.Lock()
	defer server.configMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	items, ok := config[collection].([]any)
	if !ok {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_collection", "Entity collection has an invalid shape.")
		return
	}
	index := findEntityIndex(items, entityID)
	if index < 0 {
		server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "The requested object does not exist.")
		return
	}
	if collection == "tls_profiles" {
		// Issuance may finish while an editor holds an older profile. Omitted
		// certificate fields retain the current pair; uploads replace it below.
		previous, _ := items[index].(map[string]any)
		for _, field := range []string{"certificate_secret_ref", "private_key_secret_ref", "certificate_metadata"} {
			if _, supplied := item[field]; !supplied {
				if value, exists := previous[field]; exists {
					item[field] = value
				}
			}
		}
	}
	if collection == "transports" {
		if err := server.prepareConnectionBinding(config, item); err != nil {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "wan_inventory_unavailable", err.Error())
			return
		}
	}
	prepared, secrets, err := server.prepareEntitySecrets(collection, item, false)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_entity_secret", err.Error())
		return
	}
	items[index] = prepared
	config[collection] = items
	server.commitEntityMutation(response, request, payload, config, collection, entityID, "update", prepared, secrets)
}

func (server *Server) deleteCollectionItem(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	collection, ok := apiCollections[request.PathValue("collection")]
	if !ok {
		server.writeErrorResponse(response, request, http.StatusNotFound, "not_found", "API route was not found.")
		return
	}
	entityID := request.PathValue("entity")
	if !entityIDPattern.MatchString(entityID) {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_id", "Entity ID format is invalid.")
		return
	}

	server.configMu.Lock()
	defer server.configMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	items, ok := config[collection].([]any)
	if !ok {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_collection", "Entity collection has an invalid shape.")
		return
	}
	index := findEntityIndex(items, entityID)
	if index < 0 {
		server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "The requested object does not exist.")
		return
	}
	config[collection] = append(items[:index:index], items[index+1:]...)
	objectAt(config, "system")["deployment_ready"] = false
	validation := validateCurrentConfig(config)
	if !validation.Valid {
		server.writeValidationError(response, request, validation)
		return
	}
	revision, err := server.repository.saveDraft(config)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.rememberValidation(validation)
	actor := fmt.Sprint(payload["sub"])
	server.audit(request, actor, collection+".delete", "ok", map[string]any{"id": entityID, "secrets_retained": true})
	server.writeJSON(response, http.StatusOK, map[string]any{"deleted": true, "id": entityID, "revision": revision})
}

func (server *Server) mutableCollection(response http.ResponseWriter, request *http.Request) (string, bool) {
	collection, ok := apiCollections[request.PathValue("collection")]
	if !ok {
		server.writeErrorResponse(response, request, http.StatusNotFound, "not_found", "API route was not found.")
		return "", false
	}
	if !nativeMutableCollections[collection] {
		server.writeErrorResponse(response, request, http.StatusNotImplemented, "native_collection_mutation_unavailable", "This collection still requires native secret provisioning before it can be changed.")
		return "", false
	}
	return collection, true
}

func (server *Server) commitEntityMutation(response http.ResponseWriter, request *http.Request, payload, config map[string]any, collection, entityID, action string, item map[string]any, secrets []pendingEntitySecret) {
	normalizeXHTTPModeCompatibility(config)
	objectAt(config, "system")["deployment_ready"] = false
	validation := validateCurrentConfig(config)
	if !validation.Valid {
		server.writeValidationError(response, request, validation)
		return
	}
	undo, err := server.writeEntitySecrets(secrets)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "secret_store_failed", "Entity secrets could not be stored.")
		return
	}
	revision, err := server.repository.saveDraft(config)
	if err != nil {
		_ = undo()
		server.internalStateError(response, request, err)
		return
	}
	server.rememberValidation(validation)
	actor := fmt.Sprint(payload["sub"])
	server.audit(request, actor, collection+"."+action, "ok", map[string]any{"id": entityID})
	server.writeJSON(response, http.StatusOK, map[string]any{
		"item": redactValue(item, "", false), "revision": revision,
	})
}

func (server *Server) prepareEntitySecrets(collection string, item map[string]any, create bool) (map[string]any, []pendingEntitySecret, error) {
	entityID := fmt.Sprint(item["id"])
	pending := make([]pendingEntitySecret, 0, 3)
	switch collection {
	case "tls_profiles":
		var err error
		pending, err = server.prepareTLSProfileSecrets(item, entityID, create, pending)
		if err != nil {
			return nil, nil, err
		}
	case "reverse_vless_exits":
		var err error
		pending, err = server.prepareUUIDSecret(item, entityID, "reverse-vless-exits/"+entityID+".uuid", "uuid_secret_ref", create, pending)
		if err != nil {
			return nil, nil, fmt.Errorf("Reverse VLESS UUID is invalid: %w", err)
		}
	case "remote_users":
		var err error
		pending, err = server.prepareUUIDSecret(item, entityID, "remote-users/"+entityID+".uuid", "uuid_secret_ref", create, pending)
		if err != nil {
			return nil, nil, fmt.Errorf("UUID is invalid: %w", err)
		}
		pathRef := stringDefault(item["subscription_path_secret_ref"], "remote-users/"+entityID+".subscription-path")
		if !validSecretReference(pathRef) {
			return nil, nil, errors.New("subscription path secret reference is invalid")
		}
		if !server.secrets.exists(pathRef) {
			value, randomErr := randomURLToken(32)
			if randomErr != nil {
				return nil, nil, randomErr
			}
			pending = append(pending, pendingEntitySecret{reference: pathRef, value: value})
		}
		item["subscription_path_secret_ref"] = pathRef
		rawPassword, supplied := item["hysteria2_password"]
		delete(item, "hysteria2_password")
		hysteriaRef := stringDefault(item["hysteria2_password_secret_ref"], "remote-users/"+entityID+".hysteria2-password")
		if !validSecretReference(hysteriaRef) {
			return nil, nil, errors.New("Hysteria 2 password secret reference is invalid")
		}
		if supplied {
			value, ok := rawPassword.(string)
			if !ok || len(value) < 16 || len(value) > 256 {
				return nil, nil, errors.New("Hysteria 2 password must contain 16 to 256 characters")
			}
			pending = append(pending, pendingEntitySecret{reference: hysteriaRef, value: value, overwrite: !create || server.secrets.exists(hysteriaRef)})
		} else if !server.secrets.exists(hysteriaRef) {
			value, randomErr := randomURLToken(32)
			if randomErr != nil {
				return nil, nil, randomErr
			}
			pending = append(pending, pendingEntitySecret{reference: hysteriaRef, value: value})
		}
		item["hysteria2_password_secret_ref"] = hysteriaRef
		delete(item, "generate_hysteria2_password")
	case "subscriptions":
		rawURL, supplied := item["url"]
		delete(item, "url")
		reference := stringDefault(item["url_secret_ref"], "subscriptions/"+entityID+".url")
		if !validSecretReference(reference) {
			return nil, nil, errors.New("subscription URL secret reference is invalid")
		}
		if supplied {
			value, ok := rawURL.(string)
			parsed, parseErr := url.Parse(value)
			if !ok || parseErr != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
				return nil, nil, errors.New("subscription URL must use HTTPS")
			}
			if server.secrets.exists(reference) {
				previous, readErr := server.secrets.read(reference, true)
				if readErr != nil {
					return nil, nil, readErr
				}
				if previous != value {
					token, randomErr := randomURLToken(12)
					if randomErr != nil {
						return nil, nil, randomErr
					}
					reference = "subscriptions/" + entityID + "/urls/" + token + ".url"
				}
			}
			pending = append(pending, pendingEntitySecret{reference: reference, value: value, overwrite: server.secrets.exists(reference)})
		}
		item["url_secret_ref"] = reference
	case "subscription_reserves":
		var err error
		pending, err = server.prepareSubscriptionReserve(item, entityID, create, pending)
		if err != nil {
			return nil, nil, err
		}
	case "transports":
		var err error
		pending, err = server.prepareTransportSecrets(item, entityID, create, pending)
		if err != nil {
			return nil, nil, err
		}
	}
	delete(item, "password")
	delete(item, "token")
	delete(item, "secret")
	return item, pending, nil
}

func (server *Server) prepareUUIDSecret(item map[string]any, entityID, defaultRef, refField string, create bool, pending []pendingEntitySecret) ([]pendingEntitySecret, error) {
	rawUUID, supplied := item["uuid"]
	delete(item, "uuid")
	reference := stringDefault(item[refField], defaultRef)
	if !validSecretReference(reference) {
		return nil, errors.New("secret reference is invalid")
	}
	generate := create && !supplied
	if explicit, ok := item["generate_uuid"].(bool); ok {
		generate = explicit
	}
	delete(item, "generate_uuid")
	if supplied {
		value, ok := rawUUID.(string)
		if !ok || !uuidValuePattern.MatchString(value) {
			return nil, errors.New("expected an RFC 4122 UUID")
		}
		pending = append(pending, pendingEntitySecret{reference: reference, value: strings.ToLower(value), overwrite: !create || (reference == defaultRef && server.secrets.exists(reference))})
	} else if generate && !server.secrets.exists(reference) {
		value, err := randomUUIDv4()
		if err != nil {
			return nil, err
		}
		pending = append(pending, pendingEntitySecret{reference: reference, value: value})
	}
	item[refField] = reference
	return pending, nil
}

func (server *Server) writeEntitySecrets(pending []pendingEntitySecret) (func() error, error) {
	previous := make([]previousEntitySecret, 0, len(pending))
	rollback := func() error {
		var result error
		for index := len(previous) - 1; index >= 0; index-- {
			entry := previous[index]
			if entry.existed {
				result = errors.Join(result, server.secrets.write(entry.reference, entry.value, true))
			} else {
				result = errors.Join(result, server.secrets.remove(entry.reference))
			}
		}
		return result
	}
	seen := make(map[string]struct{}, len(pending))
	for _, entry := range pending {
		if _, duplicate := seen[entry.reference]; duplicate {
			_ = rollback()
			return nil, errors.New("duplicate secret write")
		}
		seen[entry.reference] = struct{}{}
		oldValue, err := server.secrets.read(entry.reference, false)
		if err != nil {
			_ = rollback()
			return nil, err
		}
		existed := oldValue != ""
		previous = append(previous, previousEntitySecret{reference: entry.reference, value: oldValue, existed: existed})
		if err := server.secrets.write(entry.reference, entry.value, entry.overwrite); err != nil {
			_ = rollback()
			return nil, err
		}
	}
	return rollback, nil
}

func findEntityIndex(items []any, entityID string) int {
	for index, raw := range items {
		item, ok := raw.(map[string]any)
		if ok && item["id"] == entityID {
			return index
		}
	}
	return -1
}

func stringDefault(value any, fallback string) string {
	if result, ok := value.(string); ok && result != "" {
		return result
	}
	return fallback
}

func randomURLToken(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func randomUUIDv4() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	value[6] = value[6]&0x0f | 0x40
	value[8] = value[8]&0x3f | 0x80
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		value[0:4], value[4:6], value[6:8], value[8:10], value[10:16]), nil
}
