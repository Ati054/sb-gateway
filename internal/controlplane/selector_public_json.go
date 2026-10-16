package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const selectorPublicCacheMaxBytes = 4 << 20

type cachedPublicSelectorJSON struct {
	info os.FileInfo
	body json.RawMessage
}

func (repository *stateRepository) publicSelectorJSON() (json.RawMessage, error) {
	file, err := os.Open(filepath.Join(repository.root, "selector-health.json"))
	if errors.Is(err, os.ErrNotExist) {
		repository.mu.Lock()
		repository.selectorPublicCache = cachedPublicSelectorJSON{}
		repository.mu.Unlock()
		return json.RawMessage(`{}`), nil
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
		return nil, errors.New("public selector status exceeds the regular-file limit")
	}
	readCache := func() json.RawMessage {
		repository.mu.RLock()
		defer repository.mu.RUnlock()
		cached := repository.selectorPublicCache
		if cached.info != nil && os.SameFile(info, cached.info) && info.Size() == cached.info.Size() && info.ModTime().Equal(cached.info.ModTime()) {
			return bytes.Clone(cached.body)
		}
		return nil
	}
	if cached := readCache(); cached != nil {
		return cached, nil
	}
	// Serialize cache misses without holding the repository lock while decoding.
	repository.selectorPublicMu.Lock()
	defer repository.selectorPublicMu.Unlock()
	if cached := readCache(); cached != nil {
		return cached, nil
	}
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	var records map[string]map[string]json.RawMessage
	if err := decoder.Decode(&records); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("public selector status contains trailing JSON")
	}
	for _, record := range records {
		for field := range record {
			if retiredSelectorHealthField(field) {
				delete(record, field)
			}
		}
		for _, nested := range []struct {
			field   string
			retired func(string) bool
		}{
			{"quality_thresholds", retiredQualityThreshold},
			{"optimization_last_result", func(field string) bool { return field == "active_speed_bps" || field == "candidate_speed_bps" }},
		} {
			body := bytes.TrimSpace(record[nested.field])
			if len(body) == 0 || body[0] != '{' {
				continue
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				return nil, err
			}
			changed := false
			for field := range fields {
				if nested.retired(field) {
					delete(fields, field)
					changed = true
				}
			}
			if changed {
				encoded, err := json.Marshal(fields)
				if err != nil {
					return nil, err
				}
				record[nested.field] = encoded
			}
		}
	}
	body, err := json.Marshal(records)
	if err != nil {
		return nil, err
	}
	repository.mu.Lock()
	if len(body) <= selectorPublicCacheMaxBytes {
		repository.selectorPublicCache = cachedPublicSelectorJSON{info: info, body: bytes.Clone(body)}
	} else {
		repository.selectorPublicCache = cachedPublicSelectorJSON{}
	}
	repository.mu.Unlock()
	// Keep histories encoded: expansion into maps costs far more than the wire
	// bytes. Returned buffers are detached; callers cannot mutate the cache.
	return body, nil
}
