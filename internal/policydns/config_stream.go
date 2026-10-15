package policydns

import (
	"encoding/json"
	"errors"
	"io"

	"github.com/sb-gateway/sb-gateway/internal/domainset"
)

const maxRuntimeConfigBytes = 32 << 20

// Decode one lane at a time, interning large membership before reading its siblings.
func decodeRuntimeConfig(input io.Reader) (rawConfig, error) {
	var raw rawConfig
	reader := &io.LimitedReader{R: input, N: maxRuntimeConfigBytes + 1}
	decoder := json.NewDecoder(reader)
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return raw, errors.New("policy DNS config must be a JSON object")
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return raw, err
		}
		key, ok := token.(string)
		if !ok || seen[key] {
			return raw, errors.New("duplicate or invalid policy DNS field")
		}
		seen[key] = true
		switch key {
		case "lanes":
			err = decodeRuntimeLanes(decoder, &raw)
		case "domain_sets":
			var sets map[string]domainset.Set
			if err = decoder.Decode(&sets); err == nil {
				for id, set := range sets {
					if raw.DomainSets == nil {
						raw.DomainSets = make(map[string]domainset.Set)
					}
					if previous, exists := raw.DomainSets[id]; exists && previous.ID() != set.ID() {
						return raw, errors.New("conflicting shared DNS domain set")
					}
					raw.DomainSets[id] = set
				}
			}
		case "servers":
			err = decoder.Decode(&raw.Servers)
		case "version":
			err = decoder.Decode(&raw.Version)
		case "timeout_seconds":
			err = decoder.Decode(&raw.TimeoutSeconds)
		default:
			var ignored json.RawMessage
			err = decoder.Decode(&ignored)
		}
		if err != nil {
			return raw, err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return raw, err
	}
	var extra json.RawMessage
	if err := decoder.Decode(&extra); err != io.EOF {
		return raw, errors.New("trailing policy DNS data")
	}
	if reader.N <= 0 {
		return raw, errors.New("policy DNS config exceeds size limit")
	}
	return raw, nil
}

func decodeRuntimeLanes(decoder *json.Decoder, raw *rawConfig) error {
	start, err := decoder.Token()
	if err != nil {
		return err
	}
	if start == nil {
		return nil
	}
	if start != json.Delim('[') {
		return errors.New("policy DNS lanes must be an array")
	}
	for decoder.More() {
		var lane laneConfig
		if err := decoder.Decode(&lane); err != nil {
			return err
		}
		for n := range lane.Rules {
			rule := &lane.Rules[n]
			if rule.DomainSet != "" || len(rule.Domain)+len(rule.DomainSuffix) < domainset.ShareThreshold {
				continue
			}
			set := domainset.Set{Domain: rule.Domain, DomainSuffix: rule.DomainSuffix}
			id := set.ID()
			if raw.DomainSets == nil {
				raw.DomainSets = make(map[string]domainset.Set)
			}
			if _, exists := raw.DomainSets[id]; !exists {
				raw.DomainSets[id] = set
			}
			rule.DomainSet, rule.Domain, rule.DomainSuffix = id, nil, nil
		}
		raw.Lanes = append(raw.Lanes, lane)
	}
	_, err = decoder.Token()
	return err
}
