package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"path/filepath"
	"sync"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

const subscriptionCatalogSentinel = "_subscription_catalog"

// Catalog roots come from the configured secret store, never a downloaded
// manifest or a node. A snapshot carries only immutable references and the
// approved provider's selection options, not an expanded private object graph.
func (store *secretStore) subscriptionCatalogRoot() string {
	return filepath.Join(store.root, "subscription-catalogs")
}

func decodeSubscriptionCatalogRef(value any) (subscriptioncatalog.Ref, error) {
	var ref subscriptioncatalog.Ref
	body, err := json.Marshal(value)
	if err != nil || json.Unmarshal(body, &ref) != nil || ref.Schema != subscriptioncatalog.SchemaVersion || len(ref.Generation) != 64 || ref.Count < 1 || ref.Count > math.MaxInt {
		return ref, errors.New("invalid subscription catalog reference")
	}
	decoded, err := hex.DecodeString(ref.Generation)
	if err != nil || len(decoded) != sha256.Size || hex.EncodeToString(decoded) != ref.Generation {
		return ref, errors.New("invalid subscription catalog reference")
	}
	return ref, nil
}

func subscriptionCatalogNode(subscription map[string]any, reference any) map[string]any {
	options := make(map[string]any)
	for _, name := range []string{"id", "enabled", "display_name", "location_overrides"} {
		if value, exists := subscription[name]; exists {
			options[name] = value
		}
	}
	return map[string]any{
		subscriptionCatalogSentinel: reference,
		"subscription_id":           subscription["id"], "subscription_options": options,
	}
}

// Readers validate immutable generations once and are shared across metadata
// scans and single-node lookups. Active readers are leased: eviction never
// closes a descriptor under a running scan or secret lookup.
type subscriptionCatalogReaders struct {
	mu      sync.Mutex
	clock   uint64
	entries map[string]*subscriptionCatalogReaderEntry
}

type subscriptionCatalogReaderEntry struct {
	ref     subscriptioncatalog.Ref
	reader  *subscriptioncatalog.Reader
	users   int
	lastUse uint64
}

func (cache *subscriptionCatalogReaders) acquire(root string, ref subscriptioncatalog.Ref) (*subscriptioncatalog.Reader, func(), error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.entries == nil {
		cache.entries = make(map[string]*subscriptionCatalogReaderEntry)
	}
	cache.clock++
	if entry := cache.entries[ref.Generation]; entry != nil {
		if !equalJSONObject(map[string]any{"ref": entry.ref}, map[string]any{"ref": ref}) {
			return nil, nil, errors.New("subscription catalog generation mismatch")
		}
		entry.users++
		entry.lastUse = cache.clock
		return entry.reader, cache.release(entry), nil
	}
	reader, err := subscriptioncatalog.Open(root, ref)
	if err != nil {
		return nil, nil, errors.New("subscription catalog is unavailable")
	}
	if len(cache.entries) >= 8 {
		var oldest *subscriptionCatalogReaderEntry
		for _, candidate := range cache.entries {
			if candidate.users == 0 && (oldest == nil || candidate.lastUse < oldest.lastUse) {
				oldest = candidate
			}
		}
		if oldest != nil {
			delete(cache.entries, oldest.ref.Generation)
			_ = oldest.reader.Close()
		} else {
			return reader, func() { _ = reader.Close() }, nil
		}
	}
	entry := &subscriptionCatalogReaderEntry{ref: ref, reader: reader, users: 1, lastUse: cache.clock}
	cache.entries[ref.Generation] = entry
	return reader, cache.release(entry), nil
}

func (cache *subscriptionCatalogReaders) release(entry *subscriptionCatalogReaderEntry) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			cache.mu.Lock()
			entry.users--
			cache.mu.Unlock()
		})
	}
}

type subscriptionRuntimeCatalogSource struct {
	ref     subscriptioncatalog.Ref
	options map[string]any
}

type subscriptionRuntimeCatalog struct {
	store   *secretStore
	sources []subscriptionRuntimeCatalogSource
}

func splitSubscriptionCatalogNodes(store *secretStore, nodes []map[string]any) ([]map[string]any, runtimeconfig.RuntimeNodeCatalog, error) {
	legacy := make([]map[string]any, 0, len(nodes))
	catalog := &subscriptionRuntimeCatalog{store: store}
	for _, node := range nodes {
		value, isCatalog := node[subscriptionCatalogSentinel]
		if !isCatalog {
			legacy = append(legacy, node)
			continue
		}
		ref, err := decodeSubscriptionCatalogRef(value)
		if err != nil {
			return nil, nil, err
		}
		options, ok := node["subscription_options"].(map[string]any)
		if !ok || subscriptionText(options["id"]) == "" || options["id"] != node["subscription_id"] {
			return nil, nil, errors.New("invalid subscription catalog scope")
		}
		if options["enabled"] != false {
			catalog.sources = append(catalog.sources, subscriptionRuntimeCatalogSource{ref: ref, options: options})
		}
	}
	if len(catalog.sources) == 0 {
		return legacy, nil, nil
	}
	return legacy, catalog, nil
}

func (catalog *subscriptionRuntimeCatalog) References() []subscriptioncatalog.Ref {
	refs := make([]subscriptioncatalog.Ref, 0, len(catalog.sources))
	seen := make(map[string]bool)
	for _, source := range catalog.sources {
		if !seen[source.ref.Generation] {
			seen[source.ref.Generation] = true
			refs = append(refs, source.ref)
		}
	}
	return refs
}

func (catalog *subscriptionRuntimeCatalog) InventoryCount() int {
	count := 0
	for _, source := range catalog.sources {
		if source.ref.Count > uint64(math.MaxInt-count) {
			return math.MaxInt
		}
		count += int(source.ref.Count)
	}
	return count
}

func (catalog *subscriptionRuntimeCatalog) WalkMetadata(ctx context.Context, emit func(runtimeconfig.RuntimeCatalogNode) error) error {
	for _, source := range catalog.sources {
		reader, release, err := catalog.store.catalogReaders.acquire(catalog.store.subscriptionCatalogRoot(), source.ref)
		if err != nil {
			return err
		}
		err = reader.WalkMetadata(ctx, func(row subscriptioncatalog.MetadataRecord) error {
			var metadata map[string]any
			if json.Unmarshal(row.Data, &metadata) != nil || metadata == nil {
				return errors.New("invalid subscription catalog metadata")
			}
			if metadata["subscription_id"] != source.options["id"] || scopedSubscriptionNodeID(subscriptionText(source.options["id"]), subscriptionText(metadata["provider_node_id"])) != row.ID {
				return errors.New("subscription catalog node scope mismatch")
			}
			metadata = withSubscriptionLocationOverride(metadata, source.options)
			metadata["id"] = row.ID
			metadata["subscription_id"] = source.options["id"]
			metadata["subscription_display_name"] = stringDefault(source.options["display_name"], subscriptionText(source.options["id"]))
			fingerprint := subscriptionText(metadata["definition_fingerprint"])
			delete(metadata, "definition_fingerprint")
			if metadata["enabled"] == false {
				return nil
			}
			return emit(runtimeconfig.RuntimeCatalogNode{ID: row.ID, Generation: source.ref.Generation, Fingerprint: fingerprint, Metadata: metadata})
		})
		release()
		if err != nil {
			return err
		}
	}
	return nil
}

func (catalog *subscriptionRuntimeCatalog) LookupDefinition(ctx context.Context, id string) (subscriptioncatalog.Record, error) {
	for _, source := range catalog.sources {
		reader, release, err := catalog.store.catalogReaders.acquire(catalog.store.subscriptionCatalogRoot(), source.ref)
		if err != nil {
			return subscriptioncatalog.Record{}, err
		}
		record, err := reader.Get(ctx, id)
		release()
		if errors.Is(err, subscriptioncatalog.ErrNotFound) {
			continue
		}
		if err == nil {
			err = runtimeconfig.ValidateCatalogRecordSource(record, subscriptionText(source.options["id"]))
		}
		return record, err
	}
	return subscriptioncatalog.Record{}, subscriptioncatalog.ErrNotFound
}

func subscriptionCatalogIdentity(value string) subscriptioncatalog.Key {
	return subscriptioncatalog.Key(sha256.Sum256([]byte(value)))
}

func subscriptionConnectionFingerprint(node map[string]any, secrets map[string]string) (string, error) {
	connection := cloneJSONObject(node)
	for _, name := range []string{"id", "label", "enabled", "subscription_id", "subscription_display_name", "selection_identity", "selection_key", "legacy_selection_key", "stable_identity", "country", "city", "city_source", "location_key", "credential_identity"} {
		delete(connection, name)
	}
	body, err := canonicalJSON(map[string]any{"kind": runtimeconfig.CatalogFingerprintKind, "node": connection, "secrets": secrets})
	if err != nil {
		return "", errors.New("invalid subscription connection definition")
	}
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:]), nil
}
