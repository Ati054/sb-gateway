package controlplane

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

type selectorReadiness struct {
	Selected  string `json:"runtime_selected"`
	Observed  string `json:"runtime_observed_at"`
	Confirmed bool   `json:"runtime_confirmed"`
}

type cachedSelectorReadiness struct {
	info   os.FileInfo
	values map[string]selectorReadiness
}

// Readiness never needs labels, probe histories or subscription node metadata.
// Keep its projection separate from the general mutable JSON document cache.
func (repository *stateRepository) selectorReadiness() (map[string]any, error) {
	file, err := os.Open(filepath.Join(repository.root, "selector-health.json"))
	if errors.Is(err, os.ErrNotExist) {
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
		return nil, errors.New("selector readiness state exceeds the regular-file limit")
	}
	repository.mu.RLock()
	cached := repository.readiness
	if cached.info != nil && os.SameFile(info, cached.info) && info.Size() == cached.info.Size() && info.ModTime() == cached.info.ModTime() {
		result := readinessProjection(cached.values)
		repository.mu.RUnlock()
		return result, nil
	}
	repository.mu.RUnlock()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	var values map[string]selectorReadiness
	if err := decoder.Decode(&values); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("selector readiness state contains trailing JSON")
	}
	repository.mu.Lock()
	repository.readiness = cachedSelectorReadiness{info: info, values: values}
	repository.mu.Unlock()
	return readinessProjection(values), nil
}

func readinessProjection(values map[string]selectorReadiness) map[string]any {
	result := make(map[string]any, len(values))
	for id, value := range values {
		result[id] = map[string]any{"runtime_selected": value.Selected, "runtime_observed_at": value.Observed, "runtime_confirmed": value.Confirmed}
	}
	return result
}
