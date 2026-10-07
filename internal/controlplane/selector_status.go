package controlplane

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// Unknown fields, especially probe histories, must never enter the polling
// cache. Raw messages preserve the existing API types and optional fields.
type compactSelectorRecord struct {
	Selected    json.RawMessage `json:"runtime_selected"`
	Confirmed   json.RawMessage `json:"runtime_confirmed"`
	Observed    json.RawMessage `json:"runtime_observed_at"`
	Error       json.RawMessage `json:"runtime_error"`
	Labels      json.RawMessage `json:"candidate_labels"`
	Nodes       json.RawMessage `json:"candidate_nodes"`
	Count       json.RawMessage `json:"candidate_count"`
	Available   json.RawMessage `json:"availability_ok"`
	Shortlist   json.RawMessage `json:"shortlist"`
	Comparisons json.RawMessage `json:"latency_comparisons"`
}

type cachedSelectorStatus struct {
	info  os.FileInfo
	value map[string]any
}

func (repository *stateRepository) selectorStatus() (map[string]any, error) {
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
		return nil, errors.New("selector status exceeds the regular-file limit")
	}
	repository.mu.RLock()
	cached := repository.selectors
	if cached.info != nil && os.SameFile(info, cached.info) && info.Size() == cached.info.Size() && info.ModTime() == cached.info.ModTime() {
		result := cloneJSONObject(cached.value)
		repository.mu.RUnlock()
		return result, nil
	}
	repository.mu.RUnlock()
	decoder := json.NewDecoder(io.LimitReader(file, 64<<20))
	var records map[string]compactSelectorRecord
	if err := decoder.Decode(&records); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("selector status contains trailing JSON")
	}
	result := make(map[string]any, len(records))
	for id, record := range records {
		fields := map[string]json.RawMessage{
			"runtime_selected": record.Selected, "runtime_confirmed": record.Confirmed,
			"runtime_observed_at": record.Observed, "runtime_error": record.Error,
			"candidate_labels": record.Labels, "candidate_nodes": record.Nodes,
			"candidate_count": record.Count, "availability_ok": record.Available,
			"shortlist": record.Shortlist, "latency_comparisons": record.Comparisons,
		}
		item := make(map[string]any, len(fields))
		for key, body := range fields {
			if body == nil {
				continue
			}
			value := json.NewDecoder(bytes.NewReader(body))
			value.UseNumber()
			var decoded any
			if err := value.Decode(&decoded); err != nil {
				return nil, err
			}
			item[key] = decoded
		}
		// Missing values must clear stale facts in the panel's polling merge.
		if item["runtime_error"] == nil {
			item["runtime_error"] = ""
		}
		if _, exists := item["latency_comparisons"]; !exists {
			item["latency_comparisons"] = nil
		}
		result[id] = item
	}
	repository.mu.Lock()
	repository.selectors = cachedSelectorStatus{info: info, value: result}
	repository.mu.Unlock()
	return cloneJSONObject(result), nil
}
