package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

// Keep the existing complete JSON inventory response, but encode each public
// row directly. In particular, do not construct a full private node graph and
// then a second public graph merely to display a provider's inventory.
func (server *Server) subscriptionCatalogNodes(response http.ResponseWriter, request *http.Request, subscription, entry map[string]any) {
	ref, err := decodeSubscriptionCatalogRef(entry["catalog_ref"])
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	reader, release, err := server.secrets.catalogReaders.acquire(server.secrets.subscriptionCatalogRoot(), ref)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	defer release()
	statuses, err := server.repository.auxiliary("subscription-runtime-status")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	header, err := json.Marshal(map[string]any{"subscription_id": subscription["id"], "provider": valueOrEmpty(entry["provider"]), "runtime_update": valueOrEmpty(statuses[subscriptionText(subscription["id"])]), "node_count": ref.Count, "generation": ref.Generation})
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(http.StatusOK)
	if _, err = response.Write(header[:len(header)-1]); err != nil {
		return
	}
	if _, err = fmt.Fprint(response, `,"nodes":[`); err != nil {
		return
	}
	encoder := json.NewEncoder(response)
	encoder.SetEscapeHTML(false)
	first, pending := true, 0
	cities := make(map[string]bool)
	err = reader.WalkMetadata(request.Context(), func(row subscriptioncatalog.MetadataRecord) error {
		var node map[string]any
		if json.Unmarshal(row.Data, &node) != nil || node == nil {
			return errors.New("invalid subscription catalog public metadata")
		}
		if node["subscription_id"] != subscription["id"] || scopedSubscriptionNodeID(subscriptionText(subscription["id"]), subscriptionText(node["provider_node_id"])) != row.ID {
			return errors.New("subscription catalog public scope mismatch")
		}
		node["id"] = node["provider_node_id"]
		public := subscriptionNodeMetadata(subscription, []any{node})
		if len(public) != 1 {
			return errors.New("invalid subscription catalog public row")
		}
		metadata, _ := public[0].(map[string]any)
		if city := subscriptionText(metadata["city"]); city != "" {
			cities[city] = true
		} else {
			pending++
		}
		if !first {
			if _, err := fmt.Fprint(response, ","); err != nil {
				return err
			}
		}
		first = false
		return encoder.Encode(metadata)
	})
	if err != nil {
		return
	} // An interrupted response is never a partial successful catalog.
	values := make([]string, 0, len(cities))
	for city := range cities {
		values = append(values, city)
	}
	sort.Slice(values, func(i, j int) bool { return strings.ToLower(values[i]) < strings.ToLower(values[j]) })
	if _, err = fmt.Fprint(response, `],"cities":`); err != nil {
		return
	}
	if err = encoder.Encode(values); err != nil {
		return
	}
	_, _ = fmt.Fprintf(response, ",\"locations_pending\":%d}\n", pending)
}

func (server *Server) renderRouterOSTrafficCandidate(config map[string]any, nodes []map[string]any) (string, error) {
	legacy, catalog, err := splitSubscriptionCatalogNodes(server.secrets, nodes)
	if err != nil {
		return "", err
	}
	return runtimeconfig.RenderRouterOSTrafficCandidateWithCatalog(config, legacy, catalog, server.opts.Runtime.RuleSetDir)
}

func (server *Server) subscriptionEndpointBypass(config map[string]any, nodes []map[string]any) ([]string, error) {
	legacy, catalog, err := splitSubscriptionCatalogNodes(server.secrets, nodes)
	if err != nil {
		return nil, err
	}
	return runtimeconfig.RouterOSEndpointBypassWithCatalog(config, legacy, catalog)
}
