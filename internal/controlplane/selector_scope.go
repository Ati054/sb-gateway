package controlplane

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// The compiler omits health selectors for static direct and empty routes.
// Read their scope from the same published pool used by the health worker,
// rather than waiting for observations that those routes cannot produce.
type localSelectorScopeRuntime interface {
	localSelectorPolicyIDs() ([]string, error)
}

type localSelectorScopeCache struct {
	mu   sync.Mutex
	info os.FileInfo
	ids  []string
}

func (runtime *nativeRuntime) localSelectorPolicyIDs() ([]string, error) {
	cache := &runtime.selectorScope
	cache.mu.Lock()
	defer cache.mu.Unlock()
	file, err := os.Open(runtime.options.XrayHealthPool)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > 32<<20 {
		return nil, errors.New("selector scope is not a bounded regular file")
	}
	if cache.info != nil && os.SameFile(cache.info, info) && cache.info.Size() == info.Size() && cache.info.ModTime().Equal(info.ModTime()) {
		return append([]string{}, cache.ids...), nil
	}
	var pool struct {
		LocalPolicyIDs *[]string `json:"local_policy_ids"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, (32<<20)+1))
	if err := decoder.Decode(&pool); err != nil {
		return nil, err
	}
	if pool.LocalPolicyIDs == nil {
		return nil, errors.New("published pool is missing local selector scope")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, errors.New("published selector scope has trailing data")
	}
	ids := append([]string{}, (*pool.LocalPolicyIDs)...)
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return nil, errors.New("published selector scope contains an empty policy")
		}
	}
	cache.info, cache.ids = info, ids
	return append([]string{}, ids...), nil
}

func (server *Server) scopedTrafficReadyPolicies(active, selector map[string]any, notBefore time.Time) ([]string, []string, error) {
	reader, ok := server.runtime.(localSelectorScopeRuntime)
	if !ok {
		required, pending := trafficReadyPolicies(active, selector, notBefore)
		return required, pending, nil
	}
	ids, err := reader.localSelectorPolicyIDs()
	if err != nil {
		return nil, nil, err
	}
	scope := make(map[string]bool, len(ids))
	for _, id := range ids {
		scope[id] = true
	}
	required, pending := trafficReadyPoliciesInScope(active, selector, notBefore, scope)
	return required, pending, nil
}
