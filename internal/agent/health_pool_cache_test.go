package agent

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestHealthPoolCacheSharedImmutableGenerations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pool.json")
	stamp := time.Now()
	publish := func(version int, id string) {
		t.Helper()
		body, err := json.Marshal(healthPool{Version: version, Outbounds: map[string]json.RawMessage{id: json.RawMessage(`{"protocol":"freedom"}`)}})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+".next", body, 0600); err != nil {
			t.Fatal(err)
		}
		// Same-size, same-time replacements must still invalidate the cache.
		if err := os.Chtimes(path+".next", stamp, stamp); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".next", path); err != nil {
			t.Fatal(err)
		}
	}
	publish(4, "first")
	cache := &healthPoolCache{}
	lanes := make([]*xraySelectorRuntime, 11)
	var join sync.WaitGroup
	for i := range lanes {
		lanes[i] = newXraySelectorRuntime(Options{HealthPoolFile: path})
		lanes[i].poolCache = cache
		join.Add(1)
		go func(lane *xraySelectorRuntime) {
			defer join.Done()
			if _, reset, err := lane.Reload(); err != nil || !reset {
				t.Errorf("initial reset=%v error=%v", reset, err)
			}
		}(lanes[i])
	}
	join.Wait()
	first := lanes[0].pool.Outbounds["first"]
	for _, lane := range lanes {
		if len(first) == 0 || &first[0] != &lane.pool.Outbounds["first"][0] {
			t.Fatal("inventory copied between lanes")
		}
		if _, reset, err := lane.Reload(); err != nil || reset {
			t.Fatalf("unchanged reset=%v error=%v", reset, err)
		}
	}
	lanes[0].loadedDynamic["private"] = true
	if lanes[1].loadedDynamic["private"] {
		t.Fatal("lane ownership was shared")
	}
	publish(2, "invalid")
	if _, _, err := lanes[0].Reload(); err == nil {
		t.Fatal("invalid contract accepted")
	}
	if lanes[0].pool.Outbounds["first"] == nil {
		t.Fatal("invalid contract replaced snapshot")
	}
	publish(4, "other")
	for _, lane := range lanes {
		if _, reset, err := lane.Reload(); err != nil || !reset {
			t.Fatalf("new generation reset=%v error=%v", reset, err)
		}
		if lane.pool.Outbounds["first"] != nil || lane.pool.Outbounds["other"] == nil {
			t.Fatal("obsolete inventory retained")
		}
	}
	if string(first) != `{"protocol":"freedom"}` {
		t.Fatal("old in-flight snapshot mutated")
	}
}

func BenchmarkHealthPoolLaneInventory(b *testing.B) {
	for _, count := range []int{100, 1000, 5000} {
		for _, shared := range []bool{false, true} {
			b.Run(fmt.Sprintf("nodes=%d/shared=%v", count, shared), func(b *testing.B) {
				pool := healthPool{Version: 4, Outbounds: make(map[string]json.RawMessage)}
				for i := 0; i < count; i++ {
					pool.Outbounds[fmt.Sprintf("node-%05d", i)] = json.RawMessage(`{"protocol":"freedom","settings":{},"streamSettings":{"network":"tcp"}}`)
				}
				body, err := json.Marshal(pool)
				if err != nil {
					b.Fatal(err)
				}
				path := filepath.Join(b.TempDir(), "pool.json")
				if err := os.WriteFile(path, body, 0600); err != nil {
					b.Fatal(err)
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					cache := &healthPoolCache{}
					lanes := make([]*xraySelectorRuntime, 11)
					for j := range lanes {
						lanes[j] = newXraySelectorRuntime(Options{HealthPoolFile: path})
						if shared {
							lanes[j].poolCache = cache
						}
						if _, _, err := lanes[j].Reload(); err != nil {
							b.Fatal(err)
						}
					}
					runtime.KeepAlive(lanes)
				}
			})
		}
	}
}
