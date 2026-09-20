package controlplane

import (
	"net/http"
	"strings"
)

func (server *Server) revealSubscriptionURL(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	item, ok := server.draftEntity(response, request, "subscriptions", request.PathValue("subscription"))
	if !ok {
		return
	}
	reference, _ := item["url_secret_ref"].(string)
	value, err := server.secrets.read(strings.TrimSpace(reference), false)
	if err != nil || !strings.HasPrefix(value, "https://") {
		server.writeErrorResponse(response, request, http.StatusNotFound, "subscription_url_not_provisioned", "The subscription URL is not available in SecretStore.")
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"subscription_id": request.PathValue("subscription"), "url": value,
	})
}

func (server *Server) revealTransportHTTPPath(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireCSRF(response, request); !ok {
		return
	}
	transportID := request.PathValue("transport")
	item, ok := server.draftEntity(response, request, "transports", transportID)
	if !ok {
		return
	}
	kind, _ := item["kind"].(string)
	if kind != "ws" && kind != "httpupgrade" && kind != "xhttp" && kind != "xhttp-reality" {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "http_path_not_supported", "This transport does not use an HTTP path.")
		return
	}
	reference, _ := item["path_secret_ref"].(string)
	value, err := server.secrets.read(strings.TrimSpace(reference), false)
	if err != nil || !strings.HasPrefix(value, "/") {
		server.writeErrorResponse(response, request, http.StatusNotFound, "http_path_not_provisioned", "The HTTP path is not available in SecretStore.")
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{"transport_id": transportID, "path": value})
}

func (server *Server) draftEntity(response http.ResponseWriter, request *http.Request, collection, entityID string) (map[string]any, bool) {
	if !entityIDPattern.MatchString(entityID) {
		server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "The requested object does not exist.")
		return nil, false
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return nil, false
	}
	for _, raw := range collectionArray(config[collection]) {
		item, ok := raw.(map[string]any)
		if ok && item["id"] == entityID {
			return item, true
		}
	}
	server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "The requested object does not exist.")
	return nil, false
}
