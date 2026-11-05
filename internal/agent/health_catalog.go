package agent

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

const (
	catalogDefinitionCacheBytes   = 2 << 20
	catalogDefinitionCacheEntries = 32
	catalogReaderCacheEntries     = 8
)

func (pool *healthPool) UnmarshalJSON(body []byte) error {
	type plain healthPool
	var decoded plain
	if err := json.Unmarshal(body, &decoded); err != nil {
		return err
	}
	if decoded.Version >= 5 {
		for generation, ref := range decoded.Catalogs {
			if !catalogDigest(generation) || generation != ref.Generation {
				return errors.New("invalid health catalog generation")
			}
		}
		for id, definition := range decoded.CatalogDefinitions {
			if id == "" || !catalogDigest(definition.Fingerprint) || definition.FingerprintKind != runtimeconfig.CatalogFingerprintKind {
				return errors.New("invalid health catalog definition")
			}
			if _, ok := decoded.Catalogs[definition.Generation]; !ok {
				return errors.New("missing health catalog generation")
			}
		}
		// Every contract borrows one immutable typed metadata index. Candidate
		// membership is still its explicit ordered IDs, never this global map.
		for id, contract := range decoded.HealthPolicies {
			contract.Nodes = decoded.Nodes
			decoded.HealthPolicies[id] = contract
		}
	}
	*pool = healthPool(decoded)
	return nil
}

func (pool healthPool) MarshalJSON() ([]byte, error) {
	type plain healthPool
	copy := plain(pool)
	if pool.Version >= 5 {
		copy.HealthPolicies = make(map[string]healthPolicyContract, len(pool.HealthPolicies))
		for id, contract := range pool.HealthPolicies {
			contract.Nodes = nil
			copy.HealthPolicies[id] = contract
		}
	}
	return json.Marshal(copy)
}

func catalogDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, b := range value {
		if !(b >= '0' && b <= '9' || b >= 'a' && b <= 'f') {
			return false
		}
	}
	return true
}

type catalogDefinitionCacheEntry struct {
	body json.RawMessage
	used uint64
}

type catalogReaderCacheEntry struct {
	reader *subscriptioncatalog.Reader
	ref    subscriptioncatalog.Ref
	used   uint64
}

// Shared by all lanes through healthPoolCache. Locks protect the reader lifetime
// and serialize bounded record materialization; no full record file is cached.
type catalogDefinitionCache struct {
	mu      sync.Mutex
	clock   uint64
	bytes   int
	bodies  map[string]catalogDefinitionCacheEntry
	readers map[string]catalogReaderCacheEntry
	closed  bool
}

func (cache *catalogDefinitionCache) close() {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	for _, entry := range cache.readers {
		_ = entry.reader.Close()
	}
	cache.readers = nil
	cache.bodies = nil
	cache.bytes = 0
	cache.closed = true
}

func (cache *healthPoolCache) closeDefinitions() {
	cache.mu.Lock()
	definitions := cache.definitions
	cache.mu.Unlock()
	if definitions != nil {
		definitions.close()
	}
}

func (cache *catalogDefinitionCache) lookup(ctx context.Context, root, id string, definition runtimeconfig.CatalogDefinition, ref subscriptioncatalog.Ref) (json.RawMessage, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	if cache.closed {
		return nil, errors.New("catalog definition cache is closed")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if root == "" || definition.Generation != ref.Generation || definition.FingerprintKind != runtimeconfig.CatalogFingerprintKind {
		return nil, errors.New("catalog definition identity is invalid")
	}
	cache.clock++
	key := root + "\x00" + ref.Generation + "\x00" + id + "\x00" + definition.Fingerprint
	if entry, ok := cache.bodies[key]; ok {
		entry.used = cache.clock
		cache.bodies[key] = entry
		return entry.body, nil
	}
	if cache.readers == nil {
		cache.readers = make(map[string]catalogReaderCacheEntry)
	}
	readerKey := root + "\x00" + ref.Generation
	entry, ok := cache.readers[readerKey]
	if ok && entry.ref != ref {
		return nil, errors.New("catalog reference changed without generation change")
	}
	if !ok {
		if len(cache.readers) >= catalogReaderCacheEntries {
			oldest := ""
			var used uint64
			for k, item := range cache.readers {
				if oldest == "" || item.used < used {
					oldest, used = k, item.used
				}
			}
			_ = cache.readers[oldest].reader.Close()
			delete(cache.readers, oldest)
		}
		reader, err := subscriptioncatalog.Open(root, ref)
		if err != nil {
			return nil, errors.New("catalog generation is unavailable")
		}
		entry.reader = reader
		entry.ref = ref
	}
	entry.used = cache.clock
	cache.readers[readerKey] = entry
	record, err := entry.reader.Get(ctx, id)
	if err != nil || record.ID != id {
		return nil, errors.New("catalog node definition is unavailable")
	}
	var metadata struct {
		Fingerprint string `json:"definition_fingerprint"`
	}
	if json.Unmarshal(record.Metadata, &metadata) != nil || metadata.Fingerprint != definition.Fingerprint {
		return nil, errors.New("catalog definition fingerprint mismatch")
	}
	body, err := runtimeconfig.RenderCatalogOutbound(record)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(body) > catalogDefinitionCacheBytes {
		return body, nil
	}
	if cache.bodies == nil {
		cache.bodies = make(map[string]catalogDefinitionCacheEntry)
	}
	for len(cache.bodies) >= catalogDefinitionCacheEntries || cache.bytes+len(body) > catalogDefinitionCacheBytes {
		oldest := ""
		var used uint64
		for k, item := range cache.bodies {
			if oldest == "" || item.used < used {
				oldest, used = k, item.used
			}
		}
		cache.bytes -= len(cache.bodies[oldest].body)
		delete(cache.bodies, oldest)
	}
	cache.bodies[key] = catalogDefinitionCacheEntry{body: body, used: cache.clock}
	cache.bytes += len(body)
	return body, nil
}

func (pool healthPool) hasDefinition(id string) bool {
	_, catalog := pool.CatalogDefinitions[id]
	return catalog || len(pool.Outbounds[id]) != 0
}

func (runtime *xraySelectorRuntime) outboundDefinition(id string) (json.RawMessage, error) {
	if definition, ok := runtime.pool.CatalogDefinitions[id]; ok {
		ref, exists := runtime.pool.Catalogs[definition.Generation]
		if !exists {
			return nil, errors.New("catalog generation is not in the health contract")
		}
		if runtime.poolCache == nil {
			runtime.poolCache = &healthPoolCache{}
		}
		runtime.poolCache.mu.Lock()
		if runtime.poolCache.definitions == nil {
			runtime.poolCache.definitions = &catalogDefinitionCache{}
		}
		cache := runtime.poolCache.definitions
		runtime.poolCache.mu.Unlock()
		root := runtime.opts.SubscriptionCatalogRoot
		if root == "" {
			root = "/config/secrets/subscription-catalogs"
		}
		return cache.lookup(runtime.requestContext(), root, id, definition, ref)
	}
	body := runtime.pool.Outbounds[id]
	if len(body) == 0 {
		return nil, errors.New("outbound definition is unavailable")
	}
	return body, nil
}
