package controlplane

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func decodeSelectorJSON(t testing.TB, body []byte) map[string]any {
	t.Helper()
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestPublicSelectorJSONMatchesLegacyAndRetainsHistory(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "selector-health.json")
	body := `{"route":{"runtime_selected":"node-a","runtime_confirmed":true,"samples":{"node-a":[{"ok":true,"delay_ms":300}]},"daily_samples":{"node-a":[` + strings.Repeat(`{"at":1,"ok":true,"delay_ms":300},`, 12000) + `{"at":2,"ok":true,"delay_ms":301}]},"history_days":{"node-a":{"2026-01-01":{"latency_samples":[300,301]}}},"quality_thresholds":{"failure_threshold":2,"speed_bytes":99},"optimization_last_result":{"candidate":"node-a","active_speed_bps":42},"speed_samples_bps":[1,2],"counter":9007199254740999}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if len(body) <= stateDocumentCacheMaxBytes {
		t.Fatal("fixture did not bypass generic document cache")
	}
	legacy, err := repository.auxiliary("selector-health")
	if err != nil {
		t.Fatal(err)
	}
	got, err := repository.publicSelectorJSON()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decodeSelectorJSON(t, got), publicSelectorHealth(legacy)) {
		t.Fatal("encoded projection changed public status/history/numeric values")
	}
	if repository.selectorPublicCache.info == nil || len(repository.cache) != 0 {
		t.Fatal("encoded cache missing or large history expanded into generic cache")
	}
	if len(objectAt(decodeSelectorJSON(t, got), "route")["daily_samples"].(map[string]any)) != 1 {
		t.Fatal("daily samples needed by reset statistics were removed")
	}
	got[0] = '!'
	again, err := repository.publicSelectorJSON()
	if err != nil || len(again) == 0 || again[0] != '{' {
		t.Fatal("caller mutated encoded cache")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeAtomic(path, []byte(strings.ReplaceAll(body, "node-a", "node-b")), 0600, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	again, err = repository.publicSelectorJSON()
	if err != nil || text(objectAt(decodeSelectorJSON(t, again), "route")["runtime_selected"]) != "node-b" {
		t.Fatal("same-size/mtime atomic replacement used stale public status")
	}
}

func TestPublicSelectorJSONRejectsInvalidAndClearsDeletedCache(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "selector-health.json")
	if err := os.WriteFile(path, []byte(`{"route":{"runtime_selected":"node-a"}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.publicSelectorJSON(); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{`{"route":`, `{} {}`, `{"route":42}`} {
		if err := writeAtomic(path, []byte(invalid), 0600, false); err != nil {
			t.Fatal(err)
		}
		if _, err := repository.publicSelectorJSON(); err == nil {
			t.Fatalf("corrupt JSON served from stale cache: %s", invalid)
		}
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	got, err := repository.publicSelectorJSON()
	if err != nil || string(got) != "{}" || repository.selectorPublicCache.info != nil {
		t.Fatal("deleted source retained cached facts")
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.publicSelectorJSON(); err == nil {
		t.Fatal("non-regular source accepted")
	}
}

func TestPublicSelectorJSONBoundsRetentionAndConcurrentReaders(t *testing.T) {
	repository, err := newStateRepository(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(repository.root, "selector-health.json")
	body := `{"route":{"history_days":{"values":[` + strings.Repeat(`100,`, 10000) + `100]},"runtime_selected":"node-a"}}`
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var wait sync.WaitGroup
	for i := 0; i < 8; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for j := 0; j < 4; j++ {
				got, err := repository.publicSelectorJSON()
				if err != nil || !bytes.Contains(got, []byte(`"runtime_selected":"node-a"`)) {
					t.Errorf("concurrent public status: %v", err)
					return
				}
				got[0] = '!'
			}
		}()
	}
	wait.Wait()
	large := `{"route":{"history_days":{"notes":"` + strings.Repeat("x", selectorPublicCacheMaxBytes+1) + `"}}}`
	if err := writeAtomic(path, []byte(large), 0600, false); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.publicSelectorJSON(); err != nil {
		t.Fatal(err)
	}
	if repository.selectorPublicCache.info != nil || len(repository.selectorPublicCache.body) != 0 {
		t.Fatal("oversized encoded history retained")
	}
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(64<<20 + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.publicSelectorJSON(); err == nil {
		t.Fatal("oversized input accepted")
	}
}

func TestFullStatusUsesEncodedCacheAndStillRequiresAuthentication(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	if err := server.repository.saveAuxiliary("selector-health", map[string]any{"route": map[string]any{"runtime_selected": "node-a", "runtime_confirmed": true, "daily_samples": map[string]any{"node-a": []any{map[string]any{"at": 1, "ok": true, "delay_ms": 300}}}}}); err != nil {
		t.Fatal(err)
	}
	if got := performRequest(t, server, http.MethodGet, apiPrefix+"/status", nil, nil); got.Code != http.StatusUnauthorized {
		t.Fatal("full status accepted without session")
	}
	got := performRequest(t, server, http.MethodGet, apiPrefix+"/status", nil, nil, cookie)
	if got.Code != http.StatusOK {
		t.Fatal(got.Body.String())
	}
	item := objectAt(objectAt(decodeResponse(t, got), "selector_health"), "route")
	if item["runtime_selected"] != "node-a" || item["daily_samples"] == nil || server.repository.selectorPublicCache.info == nil {
		t.Fatal("full status did not use compatible encoded cache")
	}
}

func BenchmarkSelectorPublicJSON(b *testing.B) {
	repository, err := newStateRepository(b.TempDir())
	if err != nil {
		b.Fatal(err)
	}
	var daily, days strings.Builder
	daily.WriteString("{")
	days.WriteString("{")
	for n := 0; n < 32; n++ {
		if n > 0 {
			daily.WriteByte(',')
			days.WriteByte(',')
		}
		fmt.Fprintf(&daily, `"node-%d":[`, n)
		daily.WriteString(strings.Repeat(`{"at":1,"ok":true,"delay_ms":300},`, 1439))
		daily.WriteString(`{"at":2,"ok":true,"delay_ms":301}]`)
		fmt.Fprintf(&days, `"node-%d":{`, n)
		for d := 0; d < 30; d++ {
			if d > 0 {
				days.WriteByte(',')
			}
			fmt.Fprintf(&days, `"2026-01-%02d":{"samples":1440,"successes":1440,"failures":0,"latency_samples":[`, d+1)
			days.WriteString(strings.Repeat("300,", 255))
			days.WriteString("300]}")
		}
		days.WriteByte('}')
	}
	daily.WriteByte('}')
	days.WriteByte('}')
	body := []byte(`{"route":{"runtime_selected":"node-0","daily_samples":` + daily.String() + `,"history_days":` + days.String() + `}}`)
	if len(body) <= stateDocumentCacheMaxBytes || len(body) > selectorPublicCacheMaxBytes {
		b.Fatal("fixture not representative of bounded large history")
	}
	if err := os.WriteFile(filepath.Join(repository.root, "selector-health.json"), body, 0600); err != nil {
		b.Fatal(err)
	}
	for _, mode := range []string{"expanded-legacy", "encoded-cached", "encoded-miss"} {
		b.Run(mode, func(b *testing.B) {
			repository.selectorPublicCache = cachedPublicSelectorJSON{}
			if mode != "expanded-legacy" {
				if _, err := repository.publicSelectorJSON(); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			b.SetBytes(int64(len(body)))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				var selector any
				var err error
				if mode == "expanded-legacy" {
					var object map[string]any
					object, err = repository.auxiliary("selector-health")
					selector = publicSelectorHealth(object)
				} else {
					if mode == "encoded-miss" {
						repository.mu.Lock()
						repository.selectorPublicCache = cachedPublicSelectorJSON{}
						repository.mu.Unlock()
					}
					selector, err = repository.publicSelectorJSON()
				}
				if err != nil {
					b.Fatal(err)
				}
				if _, err := json.Marshal(map[string]any{"selector_health": selector}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
