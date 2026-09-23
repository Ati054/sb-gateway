package controlplane

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSubscriptionBytes = 8 << 20
	defaultSubscriptionNodes = 500
	// One manual refresh may briefly wait behind the bounded scheduler refresh
	// before starting its own 30-second channel budget. Leave enough time for
	// both operations and for the structured result to reach nginx.
	subscriptionRefreshResponseTimeout = 2 * time.Minute
)

func isSubscriptionRefreshRequest(request *http.Request) bool {
	return request.Method == http.MethodPost &&
		strings.HasPrefix(request.URL.Path, apiPrefix+"/subscriptions/") &&
		strings.HasSuffix(request.URL.Path, "/refresh")
}

type subscriptionFetchFunc func(context.Context, string, int) ([]byte, http.Header, error)
type subscriptionProxyFetchFunc func(context.Context, string, string, int) ([]byte, http.Header, error)
type subscriptionExitSelector func(context.Context, map[string]any, string) error

type subscriptionRefreshChannel struct {
	Kind, Outbound, Label string
}

type subscriptionCommitError struct{ err error }

func (failure subscriptionCommitError) Error() string { return failure.err.Error() }
func (failure subscriptionCommitError) Unwrap() error { return failure.err }

var blockedSubscriptionNetworks = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"), netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"), netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"), netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"), netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"), netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b:1::/48"), netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"), netip.MustParsePrefix("2001:10::/28"),
	netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func newSubscriptionFetcher() subscriptionFetchFunc {
	dialer := &net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy: nil, ForceAttemptHTTP2: true, MaxIdleConns: 4, MaxIdleConnsPerHost: 2,
		MaxConnsPerHost: 2, MaxResponseHeaderBytes: 64 << 10,
		IdleConnTimeout: 60 * time.Second, TLSHandshakeTimeout: 8 * time.Second,
		ResponseHeaderTimeout: 12 * time.Second, ExpectContinueTimeout: time.Second,
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errors.New("subscription destination is invalid")
		}
		addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("subscription destination cannot be resolved")
		}
		for _, candidate := range addresses {
			if !publicSubscriptionIP(candidate) {
				continue
			}
			connection, dialErr := dialer.DialContext(ctx, network, net.JoinHostPort(candidate.String(), port))
			if dialErr == nil {
				return connection, nil
			}
		}
		return nil, errors.New("subscription destination has no reachable public address")
	}
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("subscription redirects are disabled")
		},
	}
	return func(ctx context.Context, value string, maxBytes int) ([]byte, http.Header, error) {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return nil, nil, &subscriptionParseError{code: "invalid_scheme", message: "Subscription URL must use HTTPS without embedded credentials."}
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, parsed.String(), nil)
		if err != nil {
			return nil, nil, &subscriptionParseError{code: "invalid_scheme", message: "Subscription URL is invalid."}
		}
		request.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.1")
		request.Header.Set("User-Agent", "sb-gateway-subscription/1")
		response, err := client.Do(request)
		if err != nil {
			return nil, nil, &subscriptionParseError{code: "unavailable", message: "Subscription provider is unavailable."}
		}
		defer response.Body.Close()
		return readSubscriptionResponse(response, maxBytes)
	}
}

func newSubscriptionProxyFetcher() subscriptionProxyFetchFunc {
	return func(ctx context.Context, value, proxyAddress string, maxBytes int) ([]byte, http.Header, error) {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil {
			return nil, nil, &subscriptionParseError{code: "invalid_scheme", message: "Subscription URL must use HTTPS without embedded credentials."}
		}
		resolved, err := resolvePublicSubscriptionIP(ctx, parsed.Hostname())
		if err != nil {
			return nil, nil, err
		}
		proxyURL, err := url.Parse(proxyAddress)
		if err != nil || proxyURL.Scheme != "http" || proxyURL.Hostname() != "127.0.0.1" {
			return nil, nil, &subscriptionParseError{code: "unavailable", message: "Local subscription proxy is invalid."}
		}
		port := parsed.Port()
		if port == "" {
			port = "443"
		}
		originalHost := parsed.Host
		requestURL := *parsed
		requestURL.Host = net.JoinHostPort(resolved.String(), port)
		transport := &http.Transport{
			Proxy: http.ProxyURL(proxyURL), ForceAttemptHTTP2: false, DisableKeepAlives: true,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: parsed.Hostname()},
			TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 12 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
		}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("subscription redirects are disabled")
		}}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
		if err != nil {
			return nil, nil, &subscriptionParseError{code: "invalid_scheme", message: "Subscription URL is invalid."}
		}
		request.Host = originalHost
		request.Header.Set("Accept", "text/plain, application/json;q=0.9, */*;q=0.1")
		request.Header.Set("User-Agent", "sb-gateway-subscription/1")
		response, err := client.Do(request)
		if err != nil {
			return nil, nil, &subscriptionParseError{code: "unavailable", message: "Subscription provider is unavailable through the selected exit."}
		}
		defer response.Body.Close()
		return readSubscriptionResponse(response, maxBytes)
	}
}

func resolvePublicSubscriptionIP(ctx context.Context, hostname string) (netip.Addr, error) {
	addresses, err := net.DefaultResolver.LookupNetIP(ctx, "ip", hostname)
	if err != nil {
		return netip.Addr{}, &subscriptionParseError{code: "unavailable", message: "Subscription destination cannot be resolved."}
	}
	for _, address := range addresses {
		if publicSubscriptionIP(address) {
			return address.Unmap(), nil
		}
	}
	return netip.Addr{}, &subscriptionParseError{code: "non_public_destination", message: "Subscription destination is not public."}
}

func readSubscriptionResponse(response *http.Response, maxBytes int) ([]byte, http.Header, error) {
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, response.Header.Clone(), &subscriptionParseError{code: "upstream_http_" + strconv.Itoa(response.StatusCode), message: "Subscription provider rejected the request."}
	}
	if response.ContentLength > int64(maxBytes) {
		return nil, response.Header.Clone(), &subscriptionParseError{code: "too_large", message: "Subscription response exceeds the configured limit."}
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, int64(maxBytes)+1))
	if err != nil {
		return nil, response.Header.Clone(), &subscriptionParseError{code: "unavailable", message: "Subscription response could not be read."}
	}
	if len(body) > maxBytes {
		return nil, response.Header.Clone(), &subscriptionParseError{code: "too_large", message: "Subscription response exceeds the configured limit."}
	}
	return body, response.Header.Clone(), nil
}

func publicSubscriptionIP(value netip.Addr) bool {
	value = value.Unmap()
	if !value.IsValid() || !value.IsGlobalUnicast() {
		return false
	}
	for _, prefix := range blockedSubscriptionNetworks {
		if prefix.Contains(value) {
			return false
		}
	}
	return true
}

func (server *Server) refreshSubscription(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	subscriptionID := request.PathValue("subscription")
	server.subscriptionMu.Lock()
	defer server.subscriptionMu.Unlock()
	subscription, ok := server.draftEntity(response, request, "subscriptions", subscriptionID)
	if !ok {
		return
	}
	result, err := server.refreshSubscriptionNow(request.Context(), subscription)
	if err != nil {
		var commitFailure subscriptionCommitError
		if errors.As(err, &commitFailure) {
			server.audit(request, fmt.Sprint(payload["sub"]), "subscriptions.refresh", "rejected", map[string]any{"id": subscriptionID, "error_type": "state_commit"})
			server.internalStateError(response, request, commitFailure.err)
			return
		}
		server.subscriptionRefreshError(response, request, subscriptionID, fmt.Sprint(payload["sub"]), err)
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "subscriptions.refresh", "ok", map[string]any{"id": subscriptionID, "nodes": result["nodes"], "fingerprint": result["fingerprint"]})
	server.writeJSON(response, http.StatusOK, result)
}

func (server *Server) refreshSubscriptionNow(parent context.Context, subscription map[string]any) (map[string]any, error) {
	reference, _ := subscription["url_secret_ref"].(string)
	value, err := server.secrets.read(strings.TrimSpace(reference), true)
	if err != nil {
		return nil, errors.New("subscription URL is not provisioned")
	}
	maxNodes := boundedSubscriptionInteger(subscription["max_nodes"], defaultSubscriptionNodes, 1, defaultSubscriptionNodes)
	maxBytes := boundedSubscriptionInteger(subscription["max_download_bytes"], defaultSubscriptionBytes, 1024, defaultSubscriptionBytes)
	timeoutSeconds := boundedSubscriptionInteger(subscription["download_timeout_seconds"], 30, 2, 30)
	ctx, cancel := context.WithTimeout(parent, time.Duration(timeoutSeconds)*time.Second)
	defer cancel()
	channels, err := server.subscriptionRefreshChannels(subscription)
	if err != nil || len(channels) == 0 {
		if err == nil {
			err = &subscriptionParseError{code: "no_refresh_channel", message: "Subscription has no enabled refresh channel."}
		}
		return nil, err
	}
	var body []byte
	var headers http.Header
	var nodes []map[string]any
	var selected subscriptionRefreshChannel
	for _, channel := range channels {
		if channel.Outbound == "direct-wan" {
			body, headers, err = server.fetchSubscription(ctx, value, maxBytes)
		} else {
			if err = server.selectUpdateExit(ctx, subscription, channel.Outbound); err == nil {
				body, headers, err = server.fetchViaProxy(ctx, value, "http://127.0.0.1:19080", maxBytes)
			}
		}
		if err == nil {
			nodes, err = parseProxySubscription(body, maxNodes)
		}
		if err == nil && len(nodes) > 0 {
			selected = channel
			break
		}
		if terminalSubscriptionRefreshError(err) {
			break
		}
	}
	if err != nil || len(nodes) == 0 {
		if err == nil {
			err = &subscriptionParseError{code: "invalid_content", message: "Subscription contains no valid nodes."}
		}
		return nil, err
	}
	result, err := server.commitSubscriptionNodes(subscription, body, headers, nodes, selected)
	if err != nil {
		return nil, subscriptionCommitError{err: err}
	}
	return result, nil
}

func (server *Server) subscriptionRefreshError(response http.ResponseWriter, request *http.Request, id, actor string, err error) {
	code := "invalid_content"
	var parsed *subscriptionParseError
	if errors.As(err, &parsed) {
		code = parsed.code
	}
	server.audit(request, actor, "subscriptions.refresh", "rejected", map[string]any{"id": id, "error_code": code})
	server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "subscription_refresh_failed", "Subscription download or validation failed; prior nodes remain unchanged.")
}

func (server *Server) commitSubscriptionNodes(subscription map[string]any, body []byte, headers http.Header, nodes []map[string]any, channel subscriptionRefreshChannel) (map[string]any, error) {
	// Download and parsing may run in the background, but publishing a new node
	// inventory is a state mutation. Do not wait while holding subscriptionMu:
	// a concurrent Apply/recovery owns mutationMu and must finish first.
	if !server.mutationMu.TryLock() {
		return nil, errors.New("another configuration-changing operation is in progress")
	}
	defer server.mutationMu.Unlock()
	if conflict, err := server.stateMutationConflict(mutationSubscription); err != nil {
		return nil, err
	} else if conflict != "" {
		return nil, errors.New("another configuration-changing operation is in progress")
	}
	server.configMu.Lock()
	defer server.configMu.Unlock()
	subscriptionID := fmt.Sprint(subscription["id"])
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		return nil, err
	}
	oldEntry, _ := state[subscriptionID].(map[string]any)
	previous := map[string]map[string]any{}
	endpointOldCounts := map[string]int{}
	logicalOldCounts := map[string]int{}
	for _, old := range objectNodes(oldEntry["nodes"]) {
		previous[stableSubscriptionIdentity(old)] = old
		endpointOldCounts[subscriptionEndpointIdentity(old)]++
		logicalOldCounts[subscriptionLogicalIdentity(old)]++
	}
	activeRevision, err := server.repository.activeRevision()
	if err != nil {
		return nil, err
	}
	// Prefer the applied identity during migration from position-based IDs.
	endpointAppliedCounts := map[string]int{}
	logicalAppliedCounts := map[string]int{}
	for _, old := range server.routerOSNodesForRevision(activeRevision, nil) {
		if subscriptionText(old["subscription_id"]) == subscriptionID && strings.HasPrefix(subscriptionText(old["id"]), subscriptionID+"-") {
			copy := cloneJSONObject(old)
			copy["id"] = strings.TrimPrefix(subscriptionText(old["id"]), subscriptionID+"-")
			previous[stableSubscriptionIdentity(copy)] = copy
			endpointAppliedCounts[subscriptionEndpointIdentity(copy)]++
			logicalAppliedCounts[subscriptionLogicalIdentity(copy)]++
		}
	}
	endpointPrevious := map[string][]map[string]any{}
	logicalPrevious := map[string][]map[string]any{}
	for _, old := range previous {
		endpointKey := subscriptionEndpointIdentity(old)
		endpointPrevious[endpointKey] = append(endpointPrevious[endpointKey], old)
		key := subscriptionLogicalIdentity(old)
		logicalPrevious[key] = append(logicalPrevious[key], old)
	}
	endpointCounts := map[string]int{}
	logicalCounts := map[string]int{}
	for _, node := range nodes {
		endpointCounts[subscriptionEndpointIdentity(node)]++
		logicalCounts[subscriptionLogicalIdentity(node)]++
	}
	usedIDs := map[string]bool{}
	fingerprintBytes := sha256.Sum256(body)
	fingerprint := hex.EncodeToString(fingerprintBytes[:])
	generation := fingerprint[:16]
	pending := make([]pendingEntitySecret, 0, len(nodes)*2)
	storedNodes := make([]any, 0, len(nodes))
	for _, source := range nodes {
		node := cloneJSONObject(source)
		identity := stableSubscriptionIdentity(node)
		node["stable_identity"], node["selection_identity"] = identity, identity
		old := previous[identity]
		if key := subscriptionEndpointIdentity(node); old == nil && endpointCounts[key] == 1 && endpointOldCounts[key] <= 1 && endpointAppliedCounts[key] <= 1 && len(endpointPrevious[key]) == 1 {
			old = endpointPrevious[key][0]
		}
		if key := subscriptionLogicalIdentity(node); old == nil && logicalCounts[key] == 1 && logicalOldCounts[key] <= 1 && logicalAppliedCounts[key] <= 1 && len(logicalPrevious[key]) == 1 {
			old = logicalPrevious[key][0]
		}
		if old != nil && !usedIDs[subscriptionText(old["id"])] {
			node["id"] = old["id"]
			node["selection_identity"] = stringDefault(old["selection_identity"], identity)
		}
		baseID := subscriptionText(node["id"])
		for suffix := 2; usedIDs[subscriptionText(node["id"])]; suffix++ {
			node["id"] = fmt.Sprintf("%s-%d", baseID, suffix)
		}
		usedIDs[subscriptionText(node["id"])] = true
		nodeID := fmt.Sprint(node["id"])
		if node["protocol"] == "hysteria2" {
			password := fmt.Sprint(node["_password"])
			delete(node, "_password")
			passwordRef := fmt.Sprintf("subscriptions/%s/generations/%s/%s.hysteria2-password", subscriptionID, generation, nodeID)
			pending = append(pending, pendingEntitySecret{reference: passwordRef, value: password, overwrite: true})
			node["password_secret_ref"] = passwordRef
			if obfsPassword, exists := node["_obfs_password"].(string); exists && obfsPassword != "" {
				delete(node, "_obfs_password")
				obfsRef := fmt.Sprintf("subscriptions/%s/generations/%s/%s.hysteria2-obfs-password", subscriptionID, generation, nodeID)
				pending = append(pending, pendingEntitySecret{reference: obfsRef, value: obfsPassword, overwrite: true})
				node["obfs_password_secret_ref"] = obfsRef
			}
		} else {
			uuid := fmt.Sprint(node["_uuid"])
			delete(node, "_uuid")
			uuidRef := fmt.Sprintf("subscriptions/%s/generations/%s/%s.uuid", subscriptionID, generation, nodeID)
			pending = append(pending, pendingEntitySecret{reference: uuidRef, value: uuid, overwrite: true})
			node["uuid_secret_ref"] = uuidRef
		}
		node["subscription_id"] = subscriptionID
		node["subscription_display_name"] = stringDefault(subscription["display_name"], subscriptionID)
		storedNodes = append(storedNodes, node)
	}
	if activeRevision != "" {
		snapshotName := "subscription-nodes-" + activeRevision
		snapshot, snapshotErr := server.repository.auxiliary(snapshotName)
		if snapshotErr != nil {
			return nil, snapshotErr
		}
		if len(snapshot) == 0 {
			activeConfig, loadErr := server.repository.loadGeneration(activeRevision)
			if loadErr != nil {
				return nil, loadErr
			}
			activeNodes := runtimeSubscriptionNodes(activeConfig, state)
			values := make([]any, len(activeNodes))
			for index := range activeNodes {
				values[index] = cloneJSONObject(activeNodes[index])
			}
			if err := server.repository.saveAuxiliary(snapshotName, map[string]any{"revision": activeRevision, "nodes": values}); err != nil {
				return nil, err
			}
		}
	}
	undo, err := server.writeEntitySecrets(pending)
	if err != nil {
		return nil, err
	}
	provider := subscriptionProviderMetadata(headers)
	refreshedAt := server.now().UTC().Format(time.RFC3339Nano)
	state[subscriptionID] = map[string]any{
		"source_revision": mustSubscriptionSourceRevision(subscription),
		"subscription_id": subscriptionID, "fingerprint": fingerprint, "refreshed_at": refreshedAt,
		"nodes": storedNodes, "provider": provider,
		"update_channel": map[string]any{"kind": channel.Kind, "outbound": channel.Outbound, "label": channel.Label},
	}
	if err := server.repository.saveAuxiliary("subscription-nodes", state); err != nil {
		_ = undo()
		return nil, err
	}
	select {
	case server.subscriptionWake <- struct{}{}:
	default:
	}
	if err := server.pruneSubscriptionArtifacts(state); err != nil {
		log.Printf("subscription artifact retention deferred: %v", err)
	}
	countries, cities := subscriptionLocations(storedNodes)
	return map[string]any{
		"ok": true, "subscription_id": subscriptionID, "nodes": len(storedNodes),
		"countries": countries, "cities": cities, "locations_pending": countPendingLocations(storedNodes),
		"fingerprint": fingerprint, "provider": provider, "refreshed_at": refreshedAt,
		"update_channel": map[string]any{"kind": channel.Kind, "outbound": channel.Outbound, "label": channel.Label},
		"activated":      false, "message": "Узлы загружены. Для действующей подписки runtime обновится автоматически; новая подписка подключается после Apply.",
	}, nil
}

func (server *Server) subscriptionRefreshChannels(subscription map[string]any) ([]subscriptionRefreshChannel, error) {
	result := make([]subscriptionRefreshChannel, 0, 12)
	seen := map[string]struct{}{}
	add := func(channel subscriptionRefreshChannel) {
		if len(result) >= 12 || channel.Outbound == "" {
			return
		}
		if _, exists := seen[channel.Outbound]; exists {
			return
		}
		seen[channel.Outbound] = struct{}{}
		result = append(result, channel)
	}
	if subscription["refresh_via_direct"] != false {
		add(subscriptionRefreshChannel{Kind: "direct", Outbound: "direct-wan", Label: "Прямой WAN"})
	}
	if subscription["refresh_via_vpn"] == false {
		return result, nil
	}
	activeRevision, err := server.repository.activeRevision()
	if err != nil || activeRevision == "" {
		return result, err
	}
	active, err := server.repository.loadGeneration(activeRevision)
	if err != nil {
		return nil, err
	}
	if subscription["refresh_via_active_outbounds"] != false {
		health, healthErr := server.repository.auxiliary("selector-health")
		if healthErr != nil {
			return nil, healthErr
		}
		candidateSet := map[string]struct{}{}
		for _, raw := range health {
			entry, _ := raw.(map[string]any)
			selected := subscriptionText(entry["selected"])
			if selected != "" && selected != "block" && selected != "direct-wan" {
				candidateSet[selected] = struct{}{}
			}
			availability, _ := entry["availability_ok"].(map[string]any)
			for candidate, available := range availability {
				if available == true && candidate != "block" && candidate != "direct-wan" {
					candidateSet[candidate] = struct{}{}
				}
			}
		}
		state, stateErr := server.repository.auxiliary("subscription-nodes")
		if stateErr != nil {
			return nil, stateErr
		}
		nodeSubscription := map[string]string{}
		nodeLabel := map[string]string{}
		for _, node := range runtimeSubscriptionNodes(active, state) {
			id := subscriptionText(node["id"])
			nodeSubscription[id] = subscriptionText(node["subscription_id"])
			nodeLabel[id] = stringDefault(node["label"], id)
		}
		keys := make([]string, 0, len(candidateSet))
		for candidate := range candidateSet {
			keys = append(keys, candidate)
		}
		currentID := subscriptionText(subscription["id"])
		sort.Slice(keys, func(left, right int) bool {
			leftOwn, rightOwn := nodeSubscription[keys[left]] == currentID, nodeSubscription[keys[right]] == currentID
			if leftOwn != rightOwn {
				return !leftOwn
			}
			return keys[left] < keys[right]
		})
		for _, candidate := range keys {
			add(subscriptionRefreshChannel{Kind: "active-vpn", Outbound: candidate, Label: stringDefault(nodeLabel[candidate], candidate)})
		}
	}
	if subscription["refresh_via_independent_reserves"] == true {
		for _, reserve := range collectionArray(active["subscription_reserves"]) {
			item, _ := reserve.(map[string]any)
			if item["enabled"] == false {
				continue
			}
			node, _ := item["node"].(map[string]any)
			add(subscriptionRefreshChannel{Kind: "independent-vless", Outbound: subscriptionText(node["id"]), Label: stringDefault(item["display_name"], subscriptionText(node["label"]))})
		}
	}
	return result, nil
}

func (server *Server) selectSubscriptionUpdateExit(ctx context.Context, _ map[string]any, outbound string) error {
	return selectSubscriptionXrayOutbound(ctx, server.opts.Runtime, outbound, runSubscriptionXrayCommand, server.repository)
}

func terminalSubscriptionRefreshError(err error) bool {
	var parsed *subscriptionParseError
	if !errors.As(err, &parsed) {
		return false
	}
	if parsed.code == "invalid_scheme" || parsed.code == "non_public_destination" || parsed.code == "too_large" || parsed.code == "too_many_nodes" {
		return true
	}
	return parsed.code == "upstream_http_400" || parsed.code == "upstream_http_401" || parsed.code == "upstream_http_404"
}

func (server *Server) subscriptionNodes(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	subscription, ok := server.draftEntity(response, request, "subscriptions", request.PathValue("subscription"))
	if !ok {
		return
	}
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	entry, _ := state[fmt.Sprint(subscription["id"])].(map[string]any)
	nodes := subscriptionNodeMetadata(subscription, collectionArray(entry["nodes"]))
	runtimeStatus, err := server.repository.auxiliary("subscription-runtime-status")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	_, cities := subscriptionLocations(nodes)
	server.writeJSON(response, http.StatusOK, map[string]any{
		"subscription_id": subscription["id"], "nodes": nodes, "cities": cities,
		"locations_pending": countPendingLocations(nodes), "provider": valueOrEmpty(entry["provider"]),
		"runtime_update": valueOrEmpty(runtimeStatus[fmt.Sprint(subscription["id"])]),
	})
}

func boundedSubscriptionInteger(value any, fallback, minimum, maximum int) int {
	parsed, ok := jsonInteger(value)
	if !ok {
		return fallback
	}
	if parsed < minimum {
		return minimum
	}
	if parsed > maximum {
		return maximum
	}
	return parsed
}

func subscriptionProviderMetadata(headers http.Header) map[string]any {
	result := map[string]any{}
	values := map[string]int64{}
	for _, field := range strings.Split(headers.Get("Subscription-Userinfo"), ";") {
		parts := strings.SplitN(strings.TrimSpace(field), "=", 2)
		if len(parts) != 2 {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
		if err == nil && value >= 0 {
			values[strings.ToLower(strings.TrimSpace(parts[0]))] = value
		}
	}
	if expiry := values["expire"]; expiry > 0 {
		result["expires_at"] = time.Unix(expiry, 0).UTC().Format(time.RFC3339)
	}
	if total, exists := values["total"]; exists {
		upload, download := values["upload"], values["download"]
		used := upload + download
		remaining := total - used
		if remaining < 0 {
			remaining = 0
		}
		result["usage"] = map[string]any{"upload_bytes": upload, "download_bytes": download, "used_bytes": used, "total_bytes": total, "remaining_bytes": remaining}
	}
	return result
}

func subscriptionLocations(nodes []any) ([]string, []string) {
	countrySet, citySet := map[string]struct{}{}, map[string]struct{}{}
	for _, raw := range nodes {
		node, _ := raw.(map[string]any)
		if country := subscriptionText(node["country"]); country != "" {
			countrySet[country] = struct{}{}
		}
		if city := subscriptionText(node["city"]); city != "" {
			citySet[city] = struct{}{}
		}
	}
	countries, cities := make([]string, 0, len(countrySet)), make([]string, 0, len(citySet))
	for value := range countrySet {
		countries = append(countries, value)
	}
	for value := range citySet {
		cities = append(cities, value)
	}
	sort.Strings(countries)
	sort.Slice(cities, func(left, right int) bool { return strings.ToLower(cities[left]) < strings.ToLower(cities[right]) })
	return countries, cities
}

func countPendingLocations(nodes []any) int {
	result := 0
	for _, raw := range nodes {
		node, _ := raw.(map[string]any)
		if subscriptionText(node["city"]) == "" {
			result++
		}
	}
	return result
}

func subscriptionNodeMetadata(subscription map[string]any, values []any) []any {
	result := make([]any, 0, len(values))
	subscriptionID := fmt.Sprint(subscription["id"])
	for _, raw := range values {
		node, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		node = withSubscriptionLocationOverride(cloneJSONObject(node), subscription)
		protocol := subscriptionNodeProtocol(node)
		providerKey := fmt.Sprint(node["location_key"])
		identity := stringDefault(node["selection_identity"], providerKey)
		result = append(result, map[string]any{
			"id":                    scopedSubscriptionNodeID(subscriptionID, fmt.Sprint(node["id"])),
			"location_key":          scopedSubscriptionLocation(subscriptionID, identity, protocol),
			"legacy_location_key":   scopedSubscriptionLocation(subscriptionID, providerKey, protocol),
			"provider_location_key": providerKey, "label": node["label"], "country": node["country"],
			"city": node["city"], "city_source": stringDefault(node["city_source"], "unknown"),
			"transport": subscriptionTransport(node), "protocol": protocol, "subscription_id": subscriptionID,
			"subscription_display_name": stringDefault(subscription["display_name"], subscriptionID), "enabled": node["enabled"] != false,
		})
	}
	return result
}

func runtimeSubscriptionNodes(config, state map[string]any) []map[string]any {
	result := make([]map[string]any, 0)
	for _, rawSubscription := range collectionArray(config["subscriptions"]) {
		subscription, ok := rawSubscription.(map[string]any)
		if !ok || subscription["enabled"] == false {
			continue
		}
		subscriptionID := subscriptionText(subscription["id"])
		entry, _ := state[subscriptionID].(map[string]any)
		for _, rawNode := range collectionArray(entry["nodes"]) {
			node, ok := rawNode.(map[string]any)
			if !ok || node["enabled"] == false {
				continue
			}
			node = withSubscriptionLocationOverride(cloneJSONObject(node), subscription)
			providerKey := subscriptionText(node["location_key"])
			identity := stringDefault(node["selection_identity"], providerKey)
			protocol := subscriptionNodeProtocol(node)
			node["id"] = scopedSubscriptionNodeID(subscriptionID, subscriptionText(node["id"]))
			node["legacy_selection_key"] = scopedSubscriptionLocation(subscriptionID, providerKey, protocol)
			node["selection_key"] = scopedSubscriptionLocation(subscriptionID, identity, protocol)
			node["subscription_id"] = subscriptionID
			node["subscription_display_name"] = stringDefault(subscription["display_name"], subscriptionID)
			result = append(result, node)
		}
	}
	return result
}

func withSubscriptionLocationOverride(node, subscription map[string]any) map[string]any {
	overrides, _ := subscription["location_overrides"].(map[string]any)
	baseKey := subscriptionText(node["location_key"])
	scopedKey := scopedSubscriptionLocation(subscriptionText(subscription["id"]), baseKey, subscriptionText(node["protocol"]))
	override, _ := overrides[scopedKey].(map[string]any)
	if override == nil {
		override, _ = overrides[baseKey].(map[string]any)
	}
	if city := cleanSubscriptionLocation(subscriptionText(override["city"])); city != "" {
		node["city"], node["city_source"] = city, "manual"
	}
	if country := strings.ToUpper(subscriptionText(override["country"])); reserveCountryPattern.MatchString(country) {
		node["country"] = country
	}
	return node
}

func subscriptionNodeProtocol(node map[string]any) string {
	protocol := stringDefault(node["protocol"], "vless")
	tls, _ := node["tls"].(map[string]any)
	reality, _ := tls["reality"].(map[string]any)
	if protocol == "vless" && reality != nil && reality["enabled"] != false {
		return "reality"
	}
	return protocol
}

func subscriptionTransport(node map[string]any) string {
	transport, _ := node["transport"].(map[string]any)
	return stringDefault(transport["type"], "tcp")
}

func scopedSubscriptionLocation(subscriptionID, location, protocol string) string {
	digest := sha256.Sum256([]byte(strings.ToLower(subscriptionID) + ":" + strings.ToLower(protocol) + ":" + strings.ToLower(location)))
	return hex.EncodeToString(digest[:])[:16]
}

func scopedSubscriptionNodeID(subscriptionID, nodeID string) string {
	combined := subscriptionID + "-" + nodeID
	if len(combined) <= 64 {
		return combined
	}
	digest := sha256.Sum256([]byte(combined))
	return strings.TrimRight(combined[:53], "-") + "-" + hex.EncodeToString(digest[:])[:10]
}

func subscriptionText(value any) string {
	text, _ := value.(string)
	return text
}
