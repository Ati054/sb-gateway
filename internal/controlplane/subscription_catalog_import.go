package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

type subscriptionCatalogDraftGuardKey struct{}

var errSubscriptionSourceChanged = errors.New("subscription source changed during refresh")

type subscriptionCatalogPublicationUnconfirmed struct{ cause error }

func (failure subscriptionCatalogPublicationUnconfirmed) Error() string {
	return "complete subscription catalog is visible but durable publication is unconfirmed"
}
func (failure subscriptionCatalogPublicationUnconfirmed) Unwrap() error { return failure.cause }

// Imports are staged without mutation admission. Only the final source pointer
// replacement holds the configuration lock. Both the old and applied identity
// generations are checked again before publishing a completed new generation.
type subscriptionCatalogBase struct {
	entry            map[string]any
	entryRevision    string
	activeRevision   string
	metadataRevision string
	snapshotName     string
	snapshotRevision string
	activeConfig     map[string]any
	activeNodes      []map[string]any
	previousRows     []map[string]any
}

func (server *Server) subscriptionCatalogBase(id string) (subscriptionCatalogBase, error) {
	var result subscriptionCatalogBase
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		return result, err
	}
	result.entry, _ = state[id].(map[string]any)
	result.entryRevision, err = revisionFor(result.entry)
	if err != nil {
		return result, err
	}
	result.activeRevision, err = server.repository.activeRevision()
	if err != nil {
		return result, err
	}
	metadata, err := server.repository.metadata()
	if err != nil {
		return result, err
	}
	result.metadataRevision, err = revisionFor(metadata)
	if err != nil {
		return result, err
	}
	if result.activeRevision == "" {
		return result, nil
	}
	result.activeConfig, err = server.repository.loadGeneration(result.activeRevision)
	if err != nil {
		return result, err
	}
	snapshot := stringDefault(metadata["node_snapshot_revision"], result.activeRevision)
	if !safeRevision(snapshot) {
		return result, errors.New("invalid committed subscription snapshot")
	}
	result.snapshotName = "subscription-nodes-" + snapshot
	value, err := server.repository.auxiliary(result.snapshotName)
	if err != nil {
		return result, err
	}
	result.snapshotRevision, err = revisionFor(value)
	if err != nil {
		return result, err
	}
	if len(value) == 0 {
		result.activeNodes = runtimeSubscriptionNodes(result.activeConfig, state)
	} else if value["revision"] == snapshot {
		result.activeNodes = objectNodes(value["nodes"])
	} else {
		return result, errors.New("committed subscription snapshot mismatch")
	}
	for _, node := range result.activeNodes {
		if subscriptionText(node["subscription_id"]) == id {
			result.previousRows = append(result.previousRows, node)
		}
	}
	return result, nil
}

func (server *Server) catalogScratch() (string, func(), error) {
	root, err := server.secrets.path("subscription-catalogs")
	if err != nil {
		return "", nil, err
	}
	if err = os.MkdirAll(root, 0o700); err != nil {
		return "", nil, errors.New("subscription catalog storage is unavailable")
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return "", nil, errors.New("invalid subscription catalog storage")
	}
	path, err := os.MkdirTemp(root, ".prepare-")
	if err != nil {
		return "", nil, errors.New("subscription catalog staging is unavailable")
	}
	// path is allocated here, not derived from provider data or a manifest.
	return path, func() { _ = os.RemoveAll(path) }, nil
}

func subscriptionCatalogRecord(subscription, source map[string]any, secrets map[string]string) (subscriptioncatalog.Record, error) {
	var record subscriptioncatalog.Record
	node := cloneJSONObject(source)
	if secrets == nil {
		secrets = make(map[string]string)
		for _, field := range []struct{ input, output, marker string }{
			{"_uuid", "uuid_secret_ref", "@catalog:uuid"},
			{"_password", "password_secret_ref", "@catalog:password"},
			{"_obfs_password", "obfs_password_secret_ref", "@catalog:obfs-password"},
		} {
			if value, ok := node[field.input].(string); ok && value != "" {
				secrets[field.marker] = value
				node[field.output] = field.marker
			}
			delete(node, field.input)
		}
	}
	id := subscriptionText(subscription["id"])
	identity := stableSubscriptionIdentity(node)
	node["stable_identity"] = identity
	if subscriptionText(node["selection_identity"]) == "" {
		node["selection_identity"] = identity
	}
	node["subscription_id"] = id
	node["subscription_display_name"] = stringDefault(subscription["display_name"], id)
	record.ID = scopedSubscriptionNodeID(id, subscriptionText(node["id"]))
	record.Stable = subscriptionCatalogIdentity(identity)
	record.Endpoint = subscriptionCatalogIdentity(subscriptionEndpointIdentity(node))
	record.Logical = subscriptionCatalogIdentity(subscriptionLogicalIdentity(node))
	fingerprint, err := subscriptionConnectionFingerprint(node, secrets)
	if err != nil {
		return record, err
	}
	metadata := map[string]any{
		"id": record.ID, "provider_node_id": node["id"], "subscription_id": id,
		"label": node["label"], "country": node["country"], "city": node["city"], "city_source": node["city_source"],
		"protocol": node["protocol"], "display_protocol": subscriptionNodeProtocol(node),
		"transport_type": subscriptionTransport(node), "transport": map[string]any{"type": subscriptionTransport(node)},
		"server": node["server"], "server_port": node["server_port"], "enabled": node["enabled"] != false,
		"location_key": node["location_key"], "selection_identity": node["selection_identity"],
		"selection_key":          scopedSubscriptionLocation(id, subscriptionText(node["selection_identity"]), subscriptionNodeProtocol(node)),
		"legacy_selection_key":   scopedSubscriptionLocation(id, subscriptionText(node["location_key"]), subscriptionNodeProtocol(node)),
		"definition_fingerprint": fingerprint,
	}
	if subscriptionNodeProtocol(node) == "reality" {
		metadata["tls"] = map[string]any{"reality": map[string]any{"enabled": true}}
	}
	record.Node, err = canonicalJSON(node)
	if err == nil {
		record.Secrets, err = canonicalJSON(secrets)
	}
	if err == nil {
		record.Metadata, err = canonicalJSON(metadata)
	}
	return record, err
}

func (server *Server) buildRawSubscriptionCatalog(ctx context.Context, subscription map[string]any, body []byte, maxNodes int, root string) (subscriptioncatalog.Ref, error) {
	builder, err := subscriptioncatalog.NewBuilder(root, subscriptioncatalog.DefaultLimits())
	if err != nil {
		return subscriptioncatalog.Ref{}, err
	}
	defer builder.Abort()
	_, err = walkProxySubscription(ctx, body, subscriptionWalkOptions{MaxNodes: maxNodes, MaxBytes: defaultSubscriptionBytes, MaxLineBytes: 64 << 10, MaxIndexBytes: 64 << 20}, func(node map[string]any) error {
		record, err := subscriptionCatalogRecord(subscription, node, nil)
		if err != nil {
			return err
		}
		return builder.Append(ctx, record)
	})
	if err != nil {
		return subscriptioncatalog.Ref{}, err
	}
	return builder.Seal(ctx)
}

// Legacy sources are bounded by the old import ceiling. New generations use
// the on-disk indexes directly, so migration does not reload their node maps.
func (server *Server) openPreviousSubscriptionCatalog(ctx context.Context, subscription map[string]any, entry map[string]any, rows []map[string]any, scoped bool, scratch string) (*subscriptioncatalog.Reader, func(), error) {
	if reference, exists := entry["catalog_ref"]; exists {
		ref, err := decodeSubscriptionCatalogRef(reference)
		if err != nil {
			return nil, nil, err
		}
		return server.secrets.catalogReaders.acquire(server.secrets.subscriptionCatalogRoot(), ref)
	}
	if scoped {
		for _, row := range rows {
			if reference, exists := row[subscriptionCatalogSentinel]; exists {
				ref, err := decodeSubscriptionCatalogRef(reference)
				if err != nil {
					return nil, nil, err
				}
				return server.secrets.catalogReaders.acquire(server.secrets.subscriptionCatalogRoot(), ref)
			}
		}
	} else {
		rows = objectNodes(entry["nodes"])
	}
	if len(rows) == 0 {
		return nil, func() {}, nil
	}
	path, err := os.MkdirTemp(scratch, "legacy-")
	if err != nil {
		return nil, nil, errors.New("subscription migration staging is unavailable")
	}
	builder, err := subscriptioncatalog.NewBuilder(path, subscriptioncatalog.DefaultLimits())
	if err != nil {
		return nil, nil, err
	}
	defer builder.Abort()
	for _, original := range rows {
		node := cloneJSONObject(original)
		if subscriptionText(node["selection_identity"]) == "" && subscriptionText(node["location_key"]) != "" {
			node["selection_identity"] = node["location_key"]
		}
		if scoped {
			baseID, err := previousSubscriptionBaseID(subscriptionText(subscription["id"]), node)
			if err != nil {
				return nil, nil, err
			}
			node["id"] = baseID
		}
		record, err := subscriptionCatalogRecord(subscription, node, map[string]string{})
		if err != nil {
			return nil, nil, err
		}
		if err = builder.Append(ctx, record); err != nil {
			return nil, nil, err
		}
	}
	ref, err := builder.Seal(ctx)
	if err != nil {
		return nil, nil, err
	}
	reader, err := subscriptioncatalog.Open(path, ref)
	if err != nil {
		return nil, nil, err
	}
	return reader, func() { _ = reader.Close() }, nil
}

// Scoped IDs may be hash-shortened. Recover a legacy base only from a checked
// original secret reference or a reversible scope; never guess an inverse hash.
func previousSubscriptionBaseID(sourceID string, node map[string]any) (string, error) {
	runtimeID := subscriptionText(node["id"])
	if base := subscriptionText(node["provider_node_id"]); base != "" && scopedSubscriptionNodeID(sourceID, base) == runtimeID {
		return base, nil
	}
	for _, field := range []string{"uuid_secret_ref", "password_secret_ref", "obfs_password_secret_ref"} {
		parts := strings.Split(subscriptionText(node[field]), "/")
		if len(parts) != 5 || parts[0] != "subscriptions" || parts[1] != sourceID || parts[2] != "generations" || !subscriptionGenerationName.MatchString(parts[3]) {
			continue
		}
		for _, suffix := range []string{".uuid", ".hysteria2-password", ".hysteria2-obfs-password"} {
			if strings.HasSuffix(parts[4], suffix) {
				base := strings.TrimSuffix(parts[4], suffix)
				if scopedSubscriptionNodeID(sourceID, base) == runtimeID {
					return base, nil
				}
			}
		}
	}
	if strings.HasPrefix(runtimeID, sourceID+"-") {
		base := strings.TrimPrefix(runtimeID, sourceID+"-")
		if scopedSubscriptionNodeID(sourceID, base) == runtimeID {
			return base, nil
		}
	}
	return "", errors.New("legacy subscription identity cannot be safely recovered")
}

type subscriptionIdentityLookup interface {
	LookupUnique(context.Context, subscriptioncatalog.Kind, subscriptioncatalog.Key) (subscriptioncatalog.Record, error)
}

func subscriptionBulkIdentityLookup(reader *subscriptioncatalog.Reader) (subscriptionIdentityLookup, func(), error) {
	if reader == nil {
		return nil, func() {}, nil
	}
	session, err := reader.NewBulkLookupSession()
	if err != nil {
		return nil, nil, err
	}
	return session, func() { _ = session.Close() }, nil
}

func previousSubscriptionIdentity(ctx context.Context, old, applied subscriptionIdentityLookup, kind subscriptioncatalog.Kind, key subscriptioncatalog.Key) (map[string]any, error) {
	var selected subscriptioncatalog.Record
	found := false
	for _, reader := range []subscriptionIdentityLookup{old, applied} {
		if reader == nil {
			continue
		}
		record, err := reader.LookupUnique(ctx, kind, key)
		if errors.Is(err, subscriptioncatalog.ErrNotFound) {
			continue
		}
		if errors.Is(err, subscriptioncatalog.ErrAmbiguous) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		if found && kind != subscriptioncatalog.Stable && selected.Stable != record.Stable {
			return nil, nil
		}
		selected, found = record, true
	}
	if !found {
		return nil, nil
	}
	var result map[string]any
	if json.Unmarshal(selected.Node, &result) != nil || result == nil {
		return nil, errors.New("invalid previous subscription identity")
	}
	return result, nil
}

func (server *Server) reconcileSubscriptionCatalog(ctx context.Context, subscription map[string]any, raw *subscriptioncatalog.Reader, old, applied *subscriptioncatalog.Reader) (subscriptioncatalog.Ref, error) {
	oldLookup, closeOldLookup, err := subscriptionBulkIdentityLookup(old)
	if err != nil {
		return subscriptioncatalog.Ref{}, err
	}
	defer closeOldLookup()
	appliedLookup, closeAppliedLookup, err := subscriptionBulkIdentityLookup(applied)
	if err != nil {
		return subscriptioncatalog.Ref{}, err
	}
	defer closeAppliedLookup()
	builder, err := subscriptioncatalog.NewBuilder(server.secrets.subscriptionCatalogRoot(), subscriptioncatalog.DefaultLimits())
	if err != nil {
		return subscriptioncatalog.Ref{}, err
	}
	defer builder.Abort()
	used := make(map[[32]byte]struct{})
	err = raw.Walk(ctx, func(record subscriptioncatalog.Record) error {
		var node map[string]any
		var secrets map[string]string
		if json.Unmarshal(record.Node, &node) != nil || json.Unmarshal(record.Secrets, &secrets) != nil {
			return errors.New("invalid staged subscription node")
		}
		previous, err := previousSubscriptionIdentity(ctx, oldLookup, appliedLookup, subscriptioncatalog.Stable, record.Stable)
		if err != nil {
			return err
		}
		for _, match := range []struct {
			kind subscriptioncatalog.Kind
			key  subscriptioncatalog.Key
		}{{subscriptioncatalog.Endpoint, record.Endpoint}, {subscriptioncatalog.Logical, record.Logical}} {
			if previous != nil {
				break
			}
			uniqueErr := raw.CheckUnique(ctx, match.kind, match.key)
			if errors.Is(uniqueErr, subscriptioncatalog.ErrAmbiguous) {
				continue
			}
			if uniqueErr != nil {
				return uniqueErr
			}
			previous, err = previousSubscriptionIdentity(ctx, oldLookup, appliedLookup, match.kind, match.key)
			if err != nil {
				return err
			}
		}
		identity := subscriptionText(node["stable_identity"])
		if previous != nil {
			if _, exists := used[sha256.Sum256([]byte(subscriptionText(previous["id"])))]; !exists {
				node["id"] = previous["id"]
				node["selection_identity"] = stringDefault(previous["selection_identity"], identity)
			}
		}
		base := subscriptionText(node["id"])
		for suffix := 2; ; suffix++ {
			key := sha256.Sum256([]byte(subscriptionText(node["id"])))
			if _, exists := used[key]; !exists {
				used[key] = struct{}{}
				break
			}
			node["id"] = fmt.Sprintf("%s-%d", base, suffix)
		}
		final, err := subscriptionCatalogRecord(subscription, node, secrets)
		if err != nil {
			return err
		}
		return builder.Append(ctx, final)
	})
	if err != nil {
		return subscriptioncatalog.Ref{}, err
	}
	return builder.Seal(ctx)
}

func (server *Server) commitSubscriptionCatalog(ctx context.Context, subscription map[string]any, fingerprint string, ref subscriptioncatalog.Ref, base subscriptionCatalogBase, headers http.Header, channel subscriptionRefreshChannel) (map[string]any, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !server.mutationMu.TryLock() {
		return nil, errSubscriptionCommitBusy
	}
	defer server.mutationMu.Unlock()
	if conflict, err := server.stateMutationConflict(mutationSubscription); err != nil {
		return nil, err
	} else if conflict != "" {
		return nil, errSubscriptionCommitBusy
	}
	server.configMu.Lock()
	defer server.configMu.Unlock()
	id := subscriptionText(subscription["id"])
	if guard, _ := ctx.Value(subscriptionCatalogDraftGuardKey{}).(string); guard != "" {
		draft, err := server.getDraft()
		if err != nil {
			return nil, err
		}
		matched := false
		for _, item := range collectionArray(draft["subscriptions"]) {
			current, _ := item.(map[string]any)
			if subscriptionText(current["id"]) == id {
				matched = mustSubscriptionSourceRevision(current) == guard
				break
			}
		}
		if !matched {
			return nil, errSubscriptionSourceChanged
		}
	} else if len(base.activeConfig) != 0 {
		for _, item := range collectionArray(base.activeConfig["subscriptions"]) {
			current, _ := item.(map[string]any)
			if subscriptionText(current["id"]) == id && mustSubscriptionSourceRevision(current) != mustSubscriptionSourceRevision(subscription) {
				return nil, errSubscriptionSourceChanged
			}
		}
	}
	// Admission is checked before the potentially slow compatibility snapshot;
	// the existing source/active/snapshot checks below run again after it.
	if err := server.subscriptionCatalogCompatibilityAdmission(id, base); err != nil {
		return nil, err
	}
	if err := server.ensureSubscriptionCatalogCompatibility(ctx, base.activeConfig); err != nil {
		return nil, err
	}
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		return nil, err
	}
	current, _ := state[id].(map[string]any)
	revision, err := revisionFor(current)
	if err != nil || revision != base.entryRevision {
		return nil, errSubscriptionCommitBusy
	}
	active, err := server.repository.activeRevision()
	if err != nil || active != base.activeRevision {
		return nil, errSubscriptionCommitBusy
	}
	metadata, err := server.repository.metadata()
	if err != nil {
		return nil, err
	}
	metadataRevision, err := revisionFor(metadata)
	if err != nil || metadataRevision != base.metadataRevision {
		return nil, errSubscriptionCommitBusy
	}
	if base.snapshotName != "" {
		snapshot, err := server.repository.auxiliary(base.snapshotName)
		if err != nil {
			return nil, err
		}
		snapshotRevision, err := revisionFor(snapshot)
		if err != nil || snapshotRevision != base.snapshotRevision {
			return nil, errSubscriptionCommitBusy
		}
		if len(snapshot) == 0 {
			if err = server.saveSubscriptionSnapshot(base.activeRevision, base.activeNodes); err != nil {
				return nil, err
			}
		}
	}
	// No cancellation after the durable pointer replacement starts. All files
	// are complete and integrity-checked; a failure retains the prior pointer.
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	provider := subscriptionProviderMetadata(headers)
	refreshedAt := server.now().UTC().Format(time.RFC3339Nano)
	refBytes, err := canonicalJSON(ref)
	if err != nil {
		return nil, err
	}
	refObject, err := decodeObject(refBytes)
	if err != nil {
		return nil, err
	}
	state[id] = map[string]any{"source_revision": mustSubscriptionSourceRevision(subscription), "subscription_id": id, "fingerprint": fingerprint, "refreshed_at": refreshedAt, "catalog_ref": refObject, "provider": provider, "update_channel": map[string]any{"kind": channel.Kind, "outbound": channel.Outbound, "label": channel.Label}}
	if err = server.repository.saveAuxiliary("subscription-nodes", state); err != nil {
		// Rename is the visibility boundary. A directory-sync/cache failure can
		// happen after it; never report that the old pointer was retained when
		// a fresh disk read proves a complete new catalog is already visible.
		path := filepath.Join(server.repository.root, "subscription-nodes.json")
		actual, readErr := readJSONObject(path)
		if readErr == nil && equalJSONObject(actual, state) {
			server.repository.mu.Lock()
			delete(server.repository.cache, path)
			server.repository.subscriptionMetadataCache = cachedSubscriptionMetadata{}
			server.repository.mu.Unlock()
			return nil, subscriptionCatalogPublicationUnconfirmed{cause: err}
		}
		return nil, err
	}
	select {
	case server.subscriptionWake <- struct{}{}:
	default:
	}
	return map[string]any{"ok": true, "subscription_id": id, "nodes": int(ref.Count), "fingerprint": fingerprint, "provider": provider, "refreshed_at": refreshedAt, "update_channel": map[string]any{"kind": channel.Kind, "outbound": channel.Outbound, "label": channel.Label}, "activated": false, "message": subscriptionRefreshActivationMessage(base.activeConfig, subscription)}, nil
}

func (server *Server) importSubscriptionCatalog(ctx context.Context, subscription map[string]any, body []byte, headers http.Header, maxNodes int, channel subscriptionRefreshChannel) (result map[string]any, resultErr error) {
	defer func() {
		if resultErr == nil {
			return
		}
		var parsed *subscriptionParseError
		var committed subscriptionCommitError
		if errors.As(resultErr, &parsed) || errors.As(resultErr, &committed) || errors.Is(resultErr, context.Canceled) || errors.Is(resultErr, context.DeadlineExceeded) {
			return
		}
		// Local catalog storage or identity errors are not invalid provider data.
		resultErr = subscriptionCommitError{err: resultErr}
	}()
	scratch, cleanup, err := server.catalogScratch()
	if err != nil {
		return nil, err
	}
	defer cleanup()
	fingerprintBytes := sha256.Sum256(body)
	rawRef, err := server.buildRawSubscriptionCatalog(ctx, subscription, body, maxNodes, scratch)
	if err != nil {
		return nil, err
	}
	raw, err := subscriptioncatalog.Open(scratch, rawRef)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	base, err := server.subscriptionCatalogBase(subscriptionText(subscription["id"]))
	if err != nil {
		return nil, err
	}
	old, closeOld, err := server.openPreviousSubscriptionCatalog(ctx, subscription, base.entry, nil, false, scratch)
	if err != nil {
		return nil, err
	}
	defer closeOld()
	applied, closeApplied, err := server.openPreviousSubscriptionCatalog(ctx, subscription, nil, base.previousRows, true, scratch)
	if err != nil {
		return nil, err
	}
	defer closeApplied()
	ref, err := server.reconcileSubscriptionCatalog(ctx, subscription, raw, old, applied)
	if err != nil {
		return nil, err
	}
	defer func() {
		if resultErr != nil {
			server.cleanupUnpublishedSubscriptionCatalog(ctx, ref)
		}
	}()
	reader, release, err := server.secrets.catalogReaders.acquire(server.secrets.subscriptionCatalogRoot(), ref)
	if err != nil {
		return nil, err
	}
	defer release()
	countries, cities, pending, err := subscriptionCatalogLocations(ctx, reader, subscription)
	if err != nil {
		return nil, err
	}
	result, err = server.commitSubscriptionCatalog(ctx, subscription, hex.EncodeToString(fingerprintBytes[:]), ref, base, headers, channel)
	if err != nil {
		return nil, subscriptionCommitError{err: err}
	}
	// Summary contains only distinct display strings, not node definitions.
	// Keep it out of the small durable pointer document.
	result["countries"], result["cities"], result["locations_pending"] = countries, cities, pending
	return result, nil
}

func subscriptionCatalogLocations(ctx context.Context, reader *subscriptioncatalog.Reader, subscription map[string]any) ([]string, []string, int, error) {
	countrySet, citySet := make(map[string]bool), make(map[string]bool)
	pending := 0
	err := reader.WalkMetadata(ctx, func(row subscriptioncatalog.MetadataRecord) error {
		var node map[string]any
		if json.Unmarshal(row.Data, &node) != nil {
			return errors.New("invalid subscription catalog metadata")
		}
		node = withSubscriptionLocationOverride(node, subscription)
		if country := subscriptionText(node["country"]); country != "" {
			countrySet[country] = true
		}
		if city := subscriptionText(node["city"]); city != "" {
			citySet[city] = true
		} else {
			pending++
		}
		return nil
	})
	countries, cities := make([]string, 0, len(countrySet)), make([]string, 0, len(citySet))
	for country := range countrySet {
		countries = append(countries, country)
	}
	for city := range citySet {
		cities = append(cities, city)
	}
	sort.Strings(countries)
	sort.Slice(cities, func(i, j int) bool { return strings.ToLower(cities[i]) < strings.ToLower(cities[j]) })
	return countries, cities, pending, err
}
