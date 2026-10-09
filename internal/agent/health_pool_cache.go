package agent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
)

// Parsed inventory is immutable; handler ownership and evidence belong to lanes.
type healthPoolCache struct {
	mu          sync.Mutex
	path        string
	info        os.FileInfo
	changeStamp string
	snapshot    healthPoolSnapshot
}

type healthPoolSnapshot struct {
	pool          healthPool
	signature     string
	fileSignature string
	mtime         int64
}

func (cache *healthPoolCache) load(path string) (healthPoolSnapshot, error) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	info, err := os.Stat(path)
	if err != nil {
		return healthPoolSnapshot{}, err
	}
	stamp := fmt.Sprintf("%d|%d", info.ModTime().UnixNano(), info.Size())
	if cache.path == path && cache.info != nil && os.SameFile(cache.info, info) && stamp == cache.snapshot.fileSignature && cache.changeStamp == healthPoolChangeStamp(info) {
		return cache.snapshot, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return healthPoolSnapshot{}, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil {
		return healthPoolSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return healthPoolSnapshot{}, errors.New("invalid health pool file")
	}
	body, err := io.ReadAll(file)
	if err != nil {
		return healthPoolSnapshot{}, err
	}
	sum := sha256.Sum256(body)
	signature := hex.EncodeToString(sum[:])
	snapshot := cache.snapshot
	if cache.path != path || signature != snapshot.signature {
		var pool healthPool
		if err := json.Unmarshal(body, &pool); err != nil {
			return healthPoolSnapshot{}, err
		}
		if pool.Version < 3 {
			return healthPoolSnapshot{}, errors.New("health pool contract predates the 1.6.15 release baseline")
		}
		for id, contract := range pool.HealthPolicies {
			contract.Policy.LatencyMeasurement = "gstatic-head-v1"
			pool.HealthPolicies[id] = contract
		}
		snapshot.pool, snapshot.signature = pool, signature
	}
	snapshot.fileSignature = fmt.Sprintf("%d|%d", info.ModTime().UnixNano(), info.Size())
	snapshot.mtime = info.ModTime().UnixNano()
	cache.path, cache.info, cache.snapshot = path, info, snapshot
	cache.changeStamp = healthPoolChangeStamp(info)
	return snapshot, nil
}
