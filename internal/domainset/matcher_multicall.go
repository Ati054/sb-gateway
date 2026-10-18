//go:build xray_multicall

package domainset

import (
	"strings"

	"github.com/xtls/xray-core/common/geodata/strmatcher"
)

const nativeMatcherName = "mph"

type mphIndex struct {
	group   *strmatcher.MphMatcherGroup
	values  []uint32
	literal map[string][]uint32
}

func compileMembership(exact, suffix []membership) (membershipMatcher, error) {
	// Occurrence IDs preserve duplicates that Xray otherwise deduplicates by value.
	i := &mphIndex{group: strmatcher.NewMphMatcherGroup(), values: make([]uint32, 0, len(exact)+len(suffix))}
	for _, entry := range exact {
		// Xray gives leading-dot Full patterns subdomain semantics. DNS exact
		// rules are literal, including legacy noncanonical names.
		if strings.HasPrefix(entry.name, ".") {
			if i.literal == nil {
				i.literal = make(map[string][]uint32)
			}
			i.literal[entry.name] = append(i.literal[entry.name], entry.id)
			continue
		}
		i.group.AddFullMatcher(strmatcher.FullMatcher(entry.name), uint32(len(i.values)))
		i.values = append(i.values, entry.id)
	}
	for _, entry := range suffix {
		i.group.AddDomainMatcher(strmatcher.DomainMatcher(entry.name), uint32(len(i.values)))
		i.values = append(i.values, entry.id)
	}
	if err := i.group.Build(); err != nil {
		// A failed MPH placement must not reject a previously valid DNS config.
		return compileMapMembership(exact, suffix), nil
	}
	return i, nil
}

func (i *mphIndex) Match(name string, visit func(uint32)) {
	for _, id := range i.literal[name] {
		visit(id)
	}
	for _, value := range i.group.Match(name) {
		visit(i.values[value])
	}
}
