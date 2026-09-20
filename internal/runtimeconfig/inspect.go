package runtimeconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
)

const maxXrayConfigBytes = 32 << 20

type Balancer struct {
	Tag      string
	Outbound string
	Members  []string
}

type WireGuardEgress struct {
	Address  string
	Priority int
}

type xrayConfig struct {
	Outbounds []struct {
		Protocol         string `json:"protocol"`
		Tag              string `json:"tag"`
		Inet4BindAddress string `json:"inet4_bind_address"`
		SendThrough      string `json:"sendThrough"`
	} `json:"outbounds"`
	Routing struct {
		Balancers []struct {
			Tag      string   `json:"tag"`
			Selector []string `json:"selector"`
		} `json:"balancers"`
	} `json:"routing"`
}

func ReadXray(path string) ([]Balancer, []WireGuardEgress, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxXrayConfigBytes+1))
	var config xrayConfig
	if err := decoder.Decode(&config); err != nil {
		return nil, nil, fmt.Errorf("decode Xray config: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, nil, errors.New("Xray config must contain one JSON document")
	}
	if info, statErr := file.Stat(); statErr != nil || info.Size() > maxXrayConfigBytes {
		return nil, nil, errors.New("Xray config exceeds the safety limit")
	}

	balancers := make([]Balancer, 0, len(config.Routing.Balancers))
	for _, item := range config.Routing.Balancers {
		if item.Tag == "" || len(item.Selector) == 0 || item.Selector[0] == "" {
			continue
		}
		balancers = append(balancers, Balancer{Tag: item.Tag, Outbound: item.Selector[0], Members: item.Selector})
	}

	pool := netip.MustParsePrefix("198.18.0.0/15")
	addresses := make([]string, 0)
	seen := make(map[netip.Addr]struct{})
	for _, outbound := range config.Outbounds {
		if outbound.Protocol != "freedom" || !strings.HasPrefix(outbound.Tag, "wg-egress-") {
			continue
		}
		addressText := outbound.Inet4BindAddress
		if addressText == "" {
			addressText = outbound.SendThrough
		}
		address, parseErr := netip.ParseAddr(addressText)
		if parseErr != nil || !address.Is4() || !pool.Contains(address) {
			return nil, nil, errors.New("invalid managed WireGuard egress source address")
		}
		if _, exists := seen[address]; exists {
			return nil, nil, errors.New("duplicate managed WireGuard egress source address")
		}
		seen[address] = struct{}{}
		addresses = append(addresses, address.String())
	}
	// Preserve the original Python contract, which sorted the rendered address
	// strings before assigning stable policy-rule priorities.
	sort.Strings(addresses)
	egress := make([]WireGuardEgress, len(addresses))
	for index, address := range addresses {
		egress[index] = WireGuardEgress{Address: address, Priority: 1001 + index}
	}
	return balancers, egress, nil
}
