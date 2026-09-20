package controlplane

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

var subscriptionTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

type subscriptionPublicEndpoint struct {
	ID, Kind, BaseURL string
}

func (server *Server) remoteSubscriptionLink(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	server.configMu.Lock()
	defer server.configMu.Unlock()
	result, err := server.buildRemoteSubscriptionLink(request.PathValue("user"), false)
	if err != nil {
		server.subscriptionLinkError(response, request, err)
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "remote_users.subscription_link", "ok", map[string]any{
		"id": request.PathValue("user"), "active": result["active"], "transport_count": result["transport_count"],
	})
	server.writeJSON(response, http.StatusOK, result)
}

func (server *Server) rotateRemoteSubscriptionLink(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	server.configMu.Lock()
	defer server.configMu.Unlock()
	result, err := server.buildRemoteSubscriptionLink(request.PathValue("user"), true)
	if err != nil {
		server.subscriptionLinkError(response, request, err)
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "remote_users.subscription_link_rotated", "ok", map[string]any{"id": request.PathValue("user")})
	server.writeJSON(response, http.StatusOK, result)
}

type subscriptionLinkError struct {
	status  int
	code    string
	message string
}

func (failure subscriptionLinkError) Error() string { return failure.message }

func (server *Server) subscriptionLinkError(response http.ResponseWriter, request *http.Request, err error) {
	var failure subscriptionLinkError
	if errors.As(err, &failure) {
		server.writeErrorResponse(response, request, failure.status, failure.code, failure.message)
		return
	}
	server.internalStateError(response, request, err)
}

func (server *Server) buildRemoteSubscriptionLink(userID string, rotate bool) (map[string]any, error) {
	if !entityIDPattern.MatchString(userID) {
		return nil, subscriptionLinkError{http.StatusNotFound, "entity_not_found", "The requested object does not exist."}
	}
	draft, err := server.getDraft()
	if err != nil {
		return nil, err
	}
	draftUser := entityFromConfig(draft, "remote_users", userID, false)
	if draftUser == nil {
		return nil, subscriptionLinkError{http.StatusNotFound, "entity_not_found", "The requested object does not exist."}
	}
	active, err := server.repository.loadActive()
	if errors.Is(err, os.ErrNotExist) {
		active = nil
	} else if err != nil {
		return nil, err
	}
	activeUser := entityFromConfig(active, "remote_users", userID, true)
	effective, effectiveUser := draft, draftUser
	if activeUser != nil {
		effective, effectiveUser = active, activeUser
	}
	endpoints, err := subscriptionBaseURLs(effective)
	if err != nil {
		return nil, err
	}
	reference := stringDefault(effectiveUser["subscription_path_secret_ref"], "remote-users/"+userID+".subscription-path")
	if !validSecretReference(reference) {
		return nil, subscriptionLinkError{http.StatusUnprocessableEntity, "subscription_path_invalid", "The subscription token reference is invalid."}
	}
	token, readErr := server.secrets.read(reference, false)
	if readErr != nil {
		return nil, readErr
	}
	if rotate || !subscriptionTokenPattern.MatchString(token) {
		token, err = randomURLToken(32)
		if err != nil {
			return nil, err
		}
		if err := server.secrets.write(reference, token, server.secrets.exists(reference)); err != nil {
			return nil, err
		}
	}
	excluded := make(map[string]struct{})
	for _, transportID := range stringArray(effectiveUser["excluded_transports"]) {
		excluded[transportID] = struct{}{}
	}
	kinds := make([]any, 0)
	for _, raw := range collectionArray(effective["transports"]) {
		transport, ok := raw.(map[string]any)
		id, _ := transport["id"].(string)
		if !ok || transport["enabled"] == false {
			continue
		}
		if _, skip := excluded[id]; skip {
			continue
		}
		kinds = append(kinds, stringDefault(transport["kind"], ""))
	}
	urls := make([]any, len(endpoints))
	for index, endpoint := range endpoints {
		urls[index] = map[string]any{
			"id": endpoint.ID, "kind": endpoint.Kind, "url": endpoint.BaseURL + "/" + token, "primary": index == 0,
		}
	}
	return map[string]any{
		"user_id": userID, "user_enabled": draftUser["enabled"] != false,
		"url": endpoints[0].BaseURL + "/" + token, "urls": urls,
		"active": activeUser != nil, "transport_count": len(kinds), "transport_kinds": kinds,
		"updates_after_apply": true,
	}, nil
}

func subscriptionBaseURLs(config map[string]any) ([]subscriptionPublicEndpoint, error) {
	if config == nil {
		return nil, subscriptionLinkError{http.StatusUnprocessableEntity, "subscription_hostname_missing", "Configure a public subscription hostname before creating a subscription link."}
	}
	if !runtimeconfig.SubscriptionEndpointEnabled(config) {
		return nil, subscriptionLinkError{http.StatusConflict, "subscription_publication_disabled", "Subscription publication is disabled."}
	}
	ingress, _ := config["ingress"].(map[string]any)
	mode := stringDefault(ingress["subscription_endpoint_mode"], "separate")
	primary := stringDefault(ingress["subscription_primary_endpoint"], "cdn")
	originPort := positiveInt(ingress["subscription_listen_port"], positiveInt(ingress["public_listen_port"], 443))
	publicPort := positiveInt(ingress["subscription_public_port"], originPort)
	result := make([]subscriptionPublicEndpoint, 0, 2)
	if mode == "separate" || mode == "direct" || mode == "direct-and-cdn" {
		hostname := strings.TrimSpace(stringDefault(ingress["subscription_hostname"], ""))
		if hostname != "" {
			id, kind := "cdn", "cdn"
			if mode != "separate" {
				id, kind = "direct", "direct"
			}
			port := originPort
			if mode == "separate" {
				port = publicPort
			}
			endpoint, err := makeSubscriptionEndpoint(id, kind, hostname, port)
			if err != nil {
				return nil, err
			}
			result = append(result, endpoint)
		}
	}
	if mode == "reuse-cdn" || mode == "direct-and-cdn" {
		cdnAdded := false
		if mode == "direct-and-cdn" {
			cdnHostname := strings.TrimSpace(stringDefault(ingress["subscription_cdn_hostname"], ""))
			if cdnHostname != "" {
				row, buildErr := makeSubscriptionEndpoint("cdn", "cdn", cdnHostname, publicPort)
				if buildErr != nil {
					return nil, buildErr
				}
				result = append(result, row)
				cdnAdded = true
			}
		}
		if !cdnAdded {
			transportID := stringDefault(ingress["subscription_transport_id"], "")
			deploymentID := stringDefault(ingress["subscription_deployment_id"], "")
			transport := entityFromConfig(config, "transports", transportID, true)
			if transport != nil {
				for _, endpoint := range reverseExportTransportsWithID(transport) {
					if endpoint.id != deploymentID {
						continue
					}
					row, buildErr := makeSubscriptionEndpoint("cdn", "cdn", stringDefault(endpoint.value["hostname"], ""), positiveInt(endpoint.value["listen_port"], 443))
					if buildErr != nil {
						return nil, buildErr
					}
					result = append(result, row)
					break
				}
			}
		}
	}
	if len(result) == 0 {
		return nil, subscriptionLinkError{http.StatusUnprocessableEntity, "subscription_hostname_missing", "Configure a public subscription hostname before creating a subscription link."}
	}
	sort.SliceStable(result, func(left, right int) bool {
		return result[left].ID == primary && result[right].ID != primary
	})
	return result, nil
}

type identifiedTransport struct {
	id    string
	value map[string]any
}

func reverseExportTransportsWithID(transport map[string]any) []identifiedTransport {
	configured, configuredOK := transport["cdn_deployments"].([]any)
	if !configuredOK || len(configured) == 0 {
		return []identifiedTransport{{id: "primary", value: transport}}
	}
	result := make([]identifiedTransport, 0, len(configured))
	for index, raw := range configured {
		deployment, ok := raw.(map[string]any)
		if !ok || deployment["enabled"] == false {
			continue
		}
		id := stringDefault(deployment["id"], fmt.Sprintf("cdn-%d", index+1))
		result = append(result, identifiedTransport{id: id, value: deployment})
	}
	return result
}

func makeSubscriptionEndpoint(id, kind, hostname string, port int) (subscriptionPublicEndpoint, error) {
	if !validReverseExportHostname(hostname) || strings.Count(hostname, ".") < 1 || port < 1 || port > 65535 {
		return subscriptionPublicEndpoint{}, subscriptionLinkError{http.StatusUnprocessableEntity, "subscription_hostname_missing", "Configure a valid public subscription hostname and port."}
	}
	suffix := ""
	if port != 443 {
		suffix = fmt.Sprintf(":%d", port)
	}
	return subscriptionPublicEndpoint{ID: id, Kind: kind, BaseURL: "https://" + hostname + suffix}, nil
}

func validateSubscriptionBaseURL(raw string) (string, error) {
	parsed, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return "", subscriptionLinkError{http.StatusInternalServerError, "subscription_base_url_invalid", "The subscription base URL override is invalid."}
	}
	if parsed.Scheme == "http" {
		address, parseErr := netip.ParseAddr(parsed.Hostname())
		if parseErr != nil || !(address.IsPrivate() || address.IsLoopback() || address.IsLinkLocalUnicast()) {
			return "", subscriptionLinkError{http.StatusInternalServerError, "subscription_base_url_insecure", "Plain HTTP subscription override is restricted to private literal IP addresses."}
		}
	}
	return strings.TrimRight(raw, "/"), nil
}

func entityFromConfig(config map[string]any, collection, entityID string, enabledOnly bool) map[string]any {
	if config == nil {
		return nil
	}
	for _, raw := range collectionArray(config[collection]) {
		item, ok := raw.(map[string]any)
		if ok && item["id"] == entityID && (!enabledOnly || item["enabled"] != false) {
			return item
		}
	}
	return nil
}
