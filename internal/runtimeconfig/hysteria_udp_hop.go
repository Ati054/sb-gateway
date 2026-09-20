package runtimeconfig

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type PortRange struct {
	Start int
	End   int
}

type HysteriaUDPHop struct {
	Enabled     bool
	PortStart   int
	PortEnd     int
	IntervalMin int
	IntervalMax int
	Excluded    []int
	Ranges      []PortRange
}

func ParseHysteriaUDPHop(transport map[string]any) (HysteriaUDPHop, error) {
	hop := objectValue(objectValue(transport["xray_hysteria"])["udp_hop"])
	if hop == nil || hop["enabled"] != true {
		return HysteriaUDPHop{}, nil
	}
	start, startErr := requiredInteger(hop["port_start"])
	end, endErr := requiredInteger(hop["port_end"])
	minimum, minimumErr := requiredInteger(hop["interval_min"])
	maximum, maximumErr := requiredInteger(hop["interval_max"])
	if startErr != nil || endErr != nil || minimumErr != nil || maximumErr != nil {
		return HysteriaUDPHop{}, errors.New("UDP hopping ports and intervals must be integers")
	}
	if start < 1024 || end < start || end > 65535 || end-start > 1000 {
		return HysteriaUDPHop{}, errors.New("UDP hopping range must contain at most 1001 ports between 1024 and 65535")
	}
	if minimum < 5 || maximum < minimum || maximum > 3600 {
		return HysteriaUDPHop{}, errors.New("UDP hopping interval must be an ordered range from 5 to 3600 seconds")
	}

	excludedSet := make(map[int]bool)
	for _, raw := range strings.Split(textValue(hop["excluded_ports"]), ",") {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		port, err := strconv.Atoi(raw)
		if err != nil || port < start || port > end {
			return HysteriaUDPHop{}, fmt.Errorf("excluded UDP port %q is outside the hopping range", raw)
		}
		excludedSet[port] = true
	}
	excluded := make([]int, 0, len(excludedSet))
	for port := range excludedSet {
		excluded = append(excluded, port)
	}
	sort.Ints(excluded)

	ranges := make([]PortRange, 0, len(excluded)+1)
	rangeStart := start
	for _, port := range excluded {
		if rangeStart < port {
			ranges = append(ranges, PortRange{Start: rangeStart, End: port - 1})
		}
		rangeStart = port + 1
	}
	if rangeStart <= end {
		ranges = append(ranges, PortRange{Start: rangeStart, End: end})
	}
	if len(ranges) == 0 {
		return HysteriaUDPHop{}, errors.New("UDP hopping exclusions cannot remove every port")
	}
	if len(ranges) > 64 {
		return HysteriaUDPHop{}, errors.New("UDP hopping exclusions cannot create more than 64 forwarding ranges")
	}
	return HysteriaUDPHop{
		Enabled: true, PortStart: start, PortEnd: end,
		IntervalMin: minimum, IntervalMax: maximum,
		Excluded: excluded, Ranges: ranges,
	}, nil
}

func (hop HysteriaUDPHop) PortList(separator string) string {
	parts := make([]string, 0, len(hop.Ranges))
	for _, item := range hop.Ranges {
		if item.Start == item.End {
			parts = append(parts, strconv.Itoa(item.Start))
		} else {
			parts = append(parts, fmt.Sprintf("%d%s%d", item.Start, separator, item.End))
		}
	}
	return strings.Join(parts, ",")
}
