package runtimeconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const telemetryTable = "sb_gateway_client_telemetry"

func RenderWatchdogEnvironment(config map[string]any) ([]byte, error) {
	watchdog := objectValue(config["watchdog"])
	fields := []struct {
		name     string
		key      string
		fallback int
	}{
		{"SB_WATCHDOG_INTERVAL_SECONDS", "interval_seconds", 5},
		{"SB_WATCHDOG_FAILURE_THRESHOLD", "failure_threshold", 3},
		{"SB_WATCHDOG_RECOVERY_THRESHOLD", "recovery_threshold", 3},
		{"SB_WATCHDOG_MAX_RESTARTS_PER_HOUR", "max_restarts_per_hour", 6},
	}
	var body strings.Builder
	body.Grow(160)
	for _, field := range fields {
		value, err := integerDefault(watchdog[field.key], field.fallback)
		if err != nil {
			return nil, fmt.Errorf("watchdog.%s: %w", field.key, err)
		}
		fmt.Fprintf(&body, "%s=%d\n", field.name, value)
	}
	return []byte(body.String()), nil
}

// TelemetryCounterNames returns stable nft-safe counter names shared with the
// Go telemetry collector.
func TelemetryCounterNames(clientID string) (string, string) {
	digest := sha256.Sum256([]byte(clientID))
	prefix := hex.EncodeToString(digest[:])[:16]
	return "c_" + prefix + "_u", "c_" + prefix + "_d"
}

func RenderClientTelemetryNFT(config map[string]any) ([]byte, error) {
	type client struct {
		id       string
		networks []string
	}
	type counterRule struct {
		clientID string
		network  string
		bits     int
	}
	clients := make([]client, 0)
	rules := make([]counterRule, 0)
	for _, value := range enabledObjects(config["local_clients"]) {
		id := textValue(value["id"])
		if id == "" {
			continue
		}
		networks := make([]string, 0)
		seen := make(map[string]struct{})
		for _, raw := range stringSlice(value["source_cidrs"]) {
			prefix, err := netip.ParsePrefix(raw)
			if err != nil || !prefix.Addr().Is4() {
				continue
			}
			network := prefix.Masked().String()
			if _, ok := seen[network]; ok {
				continue
			}
			seen[network] = struct{}{}
			networks = append(networks, network)
			rules = append(rules, counterRule{clientID: id, network: network, bits: prefix.Bits()})
		}
		if len(networks) != 0 {
			clients = append(clients, client{id: id, networks: networks})
		}
	}
	// A packet belongs to the most specific configured client scope. Keep this
	// independent of card creation order so an exact /32 device is never
	// swallowed by an earlier all-LAN /24 counter. Stable ordering preserves the
	// saved order for equally specific, non-overlapping scopes.
	sort.SliceStable(rules, func(left, right int) bool {
		return rules[left].bits > rules[right].bits
	})

	lines := []string{"table inet " + telemetryTable + " {"}
	for _, client := range clients {
		uplink, downlink := TelemetryCounterNames(client.id)
		lines = append(lines, "  counter "+uplink+" { }", "  counter "+downlink+" { }")
	}
	lines = append(lines, "  chain client_uplink {")
	for _, rule := range rules {
		uplink, _ := TelemetryCounterNames(rule.clientID)
		lines = append(lines, "    ip saddr "+rule.network+" counter name "+uplink+" return")
	}
	lines = append(lines, "  }", "  chain client_downlink {")
	for _, rule := range rules {
		_, downlink := TelemetryCounterNames(rule.clientID)
		lines = append(lines, "    ip daddr "+rule.network+" counter name "+downlink+" return")
	}
	lines = append(lines,
		"  }",
		"  chain prerouting {",
		"    type filter hook prerouting priority raw; policy accept;",
		"    jump client_uplink",
		"  }",
		"  chain output {",
		"    type filter hook output priority raw; policy accept;",
		"    jump client_downlink",
		"  }",
		"}",
		"",
	)
	return []byte(strings.Join(lines, "\n")), nil
}

func RenderTransparentExclusions(config map[string]any) ([]byte, error) {
	values := make([]string, 0)
	seen := make(map[string]struct{})
	for _, network := range enabledObjects(config["networks"]) {
		kind := textValue(network["kind"])
		if kind == "" {
			kind = "internal"
		}
		if kind != "internal" && kind != "management" {
			continue
		}
		for _, cidr := range stringSlice(network["cidrs"]) {
			if _, ok := seen[cidr]; ok {
				continue
			}
			seen[cidr] = struct{}{}
			values = append(values, cidr)
		}
	}
	networking := objectValue(objectValue(config["system"])["networking"])
	containerAddress := strings.TrimSpace(textValue(networking["container_address"]))
	if containerAddress != "" {
		prefix, err := netip.ParsePrefix(containerAddress)
		if err != nil || !prefix.Addr().Is4() {
			return nil, errors.New("system.networking.container_address must be a valid IPv4 interface")
		}
		cidr := prefix.Masked().String()
		if _, ok := seen[cidr]; !ok {
			values = append(values, cidr)
		}
	}
	if len(values) == 0 {
		return []byte{}, nil
	}
	return []byte(strings.Join(values, "\n") + "\n"), nil
}

func integerDefault(value any, fallback int) (int, error) {
	if value == nil {
		return fallback, nil
	}
	switch typed := value.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(string(typed), 10, 32)
		return int(parsed), err
	case float64:
		parsed := int(typed)
		if float64(parsed) != typed {
			return 0, errors.New("must be an integer")
		}
		return parsed, nil
	case int:
		return typed, nil
	case int64:
		return int(typed), nil
	default:
		return 0, errors.New("must be an integer")
	}
}
