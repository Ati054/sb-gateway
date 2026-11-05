package runtimeconfig

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

type ManagedDNSOwner string

const (
	ManagedDNSOwnerNone ManagedDNSOwner = "none"
	ManagedDNSOwnerXray ManagedDNSOwner = "xray"
	ManagedDNSOwnerGo   ManagedDNSOwner = "go"
)

// ValidateManagedDNSOwnership accepts coherent legacy and current artifact
// pairs. Source configuration is still needed to distinguish disabled hijack
// from a legacy pair missing its expected listener; this function does not
// infer that intent from absent sockets.
func ValidateManagedDNSOwnership(xrayBody, policyDNSBody []byte) (ManagedDNSOwner, error) {
	xrayBody = bytes.TrimSpace(xrayBody)
	policyDNSBody = bytes.TrimSpace(policyDNSBody)
	if len(xrayBody) != 0 && xrayBody[0] != '{' || len(policyDNSBody) != 0 && policyDNSBody[0] != '{' {
		return "", errors.New("managed DNS runtime artifacts must be JSON objects")
	}
	var core struct {
		Inbounds []struct {
			Tag      string          `json:"tag"`
			Listen   string          `json:"listen"`
			Port     json.RawMessage `json:"port"`
			Protocol string          `json:"protocol"`
		} `json:"inbounds"`
	}
	if len(bytes.TrimSpace(xrayBody)) != 0 {
		if err := json.Unmarshal(xrayBody, &core); err != nil {
			return "", fmt.Errorf("managed DNS Xray contract: %w", err)
		}
	}
	coreOwner := false
	for _, inbound := range core.Inbounds {
		usesPort, err := xrayPortIncludesManagedDNS(inbound.Port)
		if err != nil {
			return "", err
		}
		if !usesPort && inbound.Tag != managedDNSInbound {
			continue
		}
		if coreOwner || !usesPort || inbound.Tag != managedDNSInbound || inbound.Protocol != "dokodemo-door" {
			return "", errors.New("managed DNS has an unexpected Xray listener")
		}
		address, err := netip.ParseAddr(inbound.Listen)
		if err != nil || !validManagedDNSAddress(address) {
			return "", errors.New("managed DNS Xray listener has no explicit container address")
		}
		coreOwner = true
	}
	var dns struct {
		Version           int                      `json:"version"`
		LaneLayoutVersion int                      `json:"lane_layout_version"`
		ManagedIngress    *PolicyDNSManagedIngress `json:"managed_ingress"`
	}
	if len(bytes.TrimSpace(policyDNSBody)) == 0 {
		if coreOwner {
			return "", errors.New("managed DNS Xray listener has no resolver artifact")
		}
		return ManagedDNSOwnerNone, nil
	}
	if err := json.Unmarshal(policyDNSBody, &dns); err != nil {
		return "", fmt.Errorf("managed DNS resolver contract: %w", err)
	}
	if dns.Version < 0 || dns.Version > 2 || dns.LaneLayoutVersion < 0 || dns.LaneLayoutVersion > 2 {
		return "", errors.New("managed DNS artifact contract is not supported")
	}
	if dns.LaneLayoutVersion == 2 && coreOwner {
		return "", errors.New("managed DNS artifacts disagree about listener ownership")
	}
	if dns.ManagedIngress == nil {
		if coreOwner {
			return ManagedDNSOwnerXray, nil
		}
		return ManagedDNSOwnerNone, nil
	}
	if dns.LaneLayoutVersion != 2 || coreOwner || len(bytes.TrimSpace(xrayBody)) == 0 || len(dns.ManagedIngress.Listeners) == 0 {
		return "", errors.New("managed DNS Go ingress has an incompatible runtime pair")
	}
	seen := make(map[netip.Addr]struct{}, len(dns.ManagedIngress.Listeners))
	for _, listener := range dns.ManagedIngress.Listeners {
		address, err := netip.ParseAddr(listener.Host)
		if err != nil || !validManagedDNSAddress(address) || listener.Port != ManagedDNSPort {
			return "", errors.New("managed DNS Go listener has an invalid container endpoint")
		}
		address = address.Unmap()
		if _, exists := seen[address]; exists {
			return "", errors.New("managed DNS Go listener is duplicated")
		}
		seen[address] = struct{}{}
	}
	return ManagedDNSOwnerGo, nil
}

func xrayPortIncludesManagedDNS(raw json.RawMessage) (bool, error) {
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return false, nil
	}
	var value string
	if raw[0] == '"' {
		if err := json.Unmarshal(raw, &value); err != nil {
			return false, fmt.Errorf("managed DNS Xray port: %w", err)
		}
	} else {
		value = string(raw)
	}
	includes := false
	for _, item := range strings.Split(value, ",") {
		bounds := strings.Split(strings.TrimSpace(item), "-")
		if len(bounds) < 1 || len(bounds) > 2 {
			return false, errors.New("managed DNS Xray port range is invalid")
		}
		low, err := strconv.Atoi(strings.TrimSpace(bounds[0]))
		if err != nil || low < 1 || low > 65535 {
			return false, errors.New("managed DNS Xray port is invalid")
		}
		high := low
		if len(bounds) == 2 {
			high, err = strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err != nil || high < low || high > 65535 {
				return false, errors.New("managed DNS Xray port range is invalid")
			}
		}
		includes = includes || low <= ManagedDNSPort && ManagedDNSPort <= high
	}
	return includes, nil
}
