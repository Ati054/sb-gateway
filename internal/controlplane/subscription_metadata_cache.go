package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const subscriptionMetadataCacheMaxBytes = 64 << 10

type cachedSubscriptionMetadata struct {
	source os.FileInfo
	value  map[string]any
}

// Schedulers and provider counters need metadata, never the full node graph.
// Cache only this projection, keyed to the same atomic file generation.
func (repository *stateRepository) subscriptionMetadata() (map[string]any, error) {
	file, err := os.Open(filepath.Join(repository.root, "subscription-nodes.json"))
	if errors.Is(err, os.ErrNotExist) {
		repository.mu.Lock()
		repository.subscriptionMetadataCache = cachedSubscriptionMetadata{}
		repository.mu.Unlock()
		return map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 64<<20 {
		return nil, errors.New("subscription metadata exceeds the regular-file limit")
	}
	readCache := func() map[string]any {
		repository.mu.RLock()
		cached := repository.subscriptionMetadataCache
		repository.mu.RUnlock()
		if cached.source != nil && os.SameFile(info, cached.source) && info.Size() == cached.source.Size() && info.ModTime().Equal(cached.source.ModTime()) {
			return cloneJSONObject(cached.value)
		}
		return nil
	}
	if cached := readCache(); cached != nil {
		return cached, nil
	}
	repository.subscriptionMetadataMu.Lock()
	defer repository.subscriptionMetadataMu.Unlock()
	if cached := readCache(); cached != nil {
		return cached, nil
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	var records map[string]json.RawMessage
	if err := decoder.Decode(&records); err != nil {
		return nil, err
	}
	projection := make(map[string]any, len(records))
	for id, raw := range records {
		body := bytes.TrimSpace(raw)
		if len(body) == 0 || body[0] != '{' {
			projection[id] = nil
			continue
		}
		var fields struct {
			Provider    any `json:"provider"`
			RefreshedAt any `json:"refreshed_at"`
		}
		entry := json.NewDecoder(bytes.NewReader(body))
		entry.UseNumber()
		if err := entry.Decode(&fields); err != nil {
			return nil, err
		}
		projection[id] = map[string]any{"provider": fields.Provider, "refreshed_at": fields.RefreshedAt}
	}
	body, err := canonicalJSON(projection)
	if err != nil {
		return nil, err
	}
	repository.mu.Lock()
	if len(body) <= subscriptionMetadataCacheMaxBytes {
		repository.subscriptionMetadataCache = cachedSubscriptionMetadata{source: info, value: projection}
	} else {
		repository.subscriptionMetadataCache = cachedSubscriptionMetadata{}
	}
	repository.mu.Unlock()
	return cloneJSONObject(projection), nil
}
