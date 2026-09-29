package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"sort"
	"strings"
)

// Availability is a transaction requirement, not a global property of the
// health worker. An unrelated remote-only policy may legitimately be block.
// Compare forwarding inputs before publication and keep this scope unchanged
// until the exact target generation has been acknowledged.
type hotPolicyPool struct {
	SHA256         string                         `json:"-"`
	LocalPolicyIDs []string                       `json:"local_policy_ids"`
	Policies       map[string]hotForwardingPolicy `json:"health_policies"`
	PolicyPrefixes map[string]string              `json:"policy_prefixes"`
}

type hotRuntimeScope struct {
	PoolSHA256       string
	RequiredPolicies []string
}

type hotForwardingPolicy struct {
	Mode       string   `json:"mode"`
	Candidates []string `json:"candidates"`
	Groups     []struct {
		Selector string   `json:"selector"`
		Members  []string `json:"members"`
	} `json:"groups"`
	Policy struct {
		ServiceIDs    []string            `json:"candidate_service_ids"`
		ServiceAccess map[string][]string `json:"candidate_service_access"`
	} `json:"policy"`
	Nodes map[string]struct {
		Fingerprint string `json:"fingerprint"`
		Protocol    string `json:"protocol"`
	} `json:"nodes"`
}

func readHotPolicyPool(path string) (hotPolicyPool, error) {
	var pool hotPolicyPool
	file, err := os.Open(path)
	if err != nil {
		return pool, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return pool, err
	}
	if !info.Mode().IsRegular() || info.Size() > 32<<20 {
		return pool, errors.New("hot policy pool is not a bounded regular file")
	}
	digest := sha256.New()
	decoder := json.NewDecoder(io.TeeReader(io.LimitReader(file, (32<<20)+1), digest))
	if err := decoder.Decode(&pool); err != nil {
		return pool, fmt.Errorf("decode hot policy pool: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return pool, errors.New("hot policy pool has trailing data")
	}
	pool.SHA256 = hex.EncodeToString(digest.Sum(nil))
	return pool, nil
}

func hotPolicyScope(previousPath, targetPath string) (hotRuntimeScope, error) {
	previous, err := readHotPolicyPool(previousPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return hotRuntimeScope{}, err
	}
	target, err := readHotPolicyPool(targetPath)
	if err != nil {
		return hotRuntimeScope{}, err
	}
	return hotRuntimeScope{target.SHA256, requiredHotPolicies(previous, target)}, nil
}

func requiredHotPolicies(previous, target hotPolicyPool) []string {
	required := make(map[string]bool)
	for _, id := range target.LocalPolicyIDs {
		if id = strings.TrimSpace(id); id != "" {
			required[id] = true
		}
	}
	for id, policy := range target.Policies {
		old, exists := previous.Policies[id]
		if !exists || !reflect.DeepEqual(old, policy) || previous.PolicyPrefixes[id] != target.PolicyPrefixes[id] {
			required[id] = true
		}
	}
	result := make([]string, 0, len(required))
	for id := range required {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func hotPolicyScopeReady(required []string, selections map[string]string) bool {
	for _, id := range required {
		selected := strings.TrimSpace(selections[id])
		if selected == "" || selected == "block" {
			return false
		}
	}
	return true
}
