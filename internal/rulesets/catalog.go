package rulesets

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

//go:embed service-packs.json
var servicePackCatalog []byte

var upstreamNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

type ServicePack struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Category         string   `json:"category"`
	UpstreamName     *string  `json:"upstream_name"`
	FallbackDomains  []string `json:"fallback_domains"`
	Description      string   `json:"description"`
	UpdateMode       string   `json:"update_mode"`
	Broad            bool     `json:"broad"`
	IPCIDRs          []string `json:"ip_cidrs"`
	SniffedProtocols []string `json:"sniffed_protocols"`
	AlwaysDirect     bool     `json:"always_direct"`
	IncludedPackIDs  []string `json:"included_pack_ids"`
	TCPPorts         []int    `json:"tcp_ports"`
	TCPPortRanges    []string `json:"tcp_port_ranges"`
	UDPPorts         []int    `json:"udp_ports"`
	UDPPortRanges    []string `json:"udp_port_ranges"`
}

func Catalog() ([]ServicePack, error) {
	var packs []ServicePack
	if err := json.Unmarshal(servicePackCatalog, &packs); err != nil {
		return nil, fmt.Errorf("decode embedded service-pack catalog: %w", err)
	}
	seen := make(map[string]struct{}, len(packs))
	for _, pack := range packs {
		if pack.ID == "" || !upstreamNamePattern.MatchString(pack.ID) {
			return nil, fmt.Errorf("invalid service-pack id %q", pack.ID)
		}
		if _, exists := seen[pack.ID]; exists {
			return nil, fmt.Errorf("duplicate service-pack id %q", pack.ID)
		}
		seen[pack.ID] = struct{}{}
	}
	for _, pack := range packs {
		for _, dependency := range pack.IncludedPackIDs {
			if _, exists := seen[dependency]; !exists {
				return nil, fmt.Errorf("service-pack %q has unknown dependency %q", pack.ID, dependency)
			}
		}
	}
	return packs, nil
}

func CustomPack(upstream, name string) (ServicePack, error) {
	normalized := strings.ToLower(strings.TrimSpace(upstream))
	if !upstreamNamePattern.MatchString(normalized) {
		return ServicePack{}, fmt.Errorf("invalid upstream rule-set name")
	}
	fallback := []string(nil)
	if normalized == "binance" {
		fallback = []string{"token.awswaf.com"}
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = normalized
	}
	return ServicePack{
		ID: normalized, Name: name, Category: "Пользовательский",
		UpstreamName: &normalized, FallbackDomains: fallback, UpdateMode: "catalog",
	}, nil
}

func catalogIndex(packs []ServicePack) map[string]ServicePack {
	result := make(map[string]ServicePack, len(packs))
	for _, pack := range packs {
		result[pack.ID] = pack
	}
	return result
}

func dependencyIDs(id string, index map[string]ServicePack) []string {
	result := make([]string, 0)
	visiting := make(map[string]bool)
	var visit func(string)
	visit = func(current string) {
		if visiting[current] {
			return
		}
		for _, existing := range result {
			if existing == current {
				return
			}
		}
		pack, exists := index[current]
		if !exists {
			return
		}
		visiting[current] = true
		result = append(result, current)
		for _, dependency := range pack.IncludedPackIDs {
			visit(dependency)
		}
		delete(visiting, current)
	}
	visit(id)
	return result
}

func reviewedRuleCount(pack ServicePack, index map[string]ServicePack) int {
	count := 0
	for _, id := range dependencyIDs(pack.ID, index) {
		current := index[id]
		count += len(current.FallbackDomains) + len(current.IPCIDRs) + len(current.SniffedProtocols)
		count += len(current.TCPPorts) + len(current.TCPPortRanges) + len(current.UDPPorts) + len(current.UDPPortRanges)
	}
	return count
}

// ReviewedRuleCounts computes all bounded built-in counts in one catalog pass.
// The control plane retains the tiny integer map and avoids rebuilding the
// dependency index for every UI lookup.
func ReviewedRuleCounts(catalog []ServicePack) map[string]int {
	index := catalogIndex(catalog)
	result := make(map[string]int, len(catalog))
	for _, pack := range catalog {
		result[pack.ID] = reviewedRuleCount(pack, index)
	}
	return result
}
