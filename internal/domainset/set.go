// Package domainset keeps immutable domain membership separate from route decisions.
package domainset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
)

const ShareThreshold = 64

type Set struct {
	Domain       []string `json:"domain"`
	DomainSuffix []string `json:"domain_suffix"`
}

func (s Set) ID() string {
	body, _ := json.Marshal(s)
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

type Index struct{ matcher membershipMatcher }

type membershipMatcher interface {
	Match(string, func(uint32))
}

type membership struct {
	name string
	id   uint32
}

func Compile(sets map[string]Set) (*Index, map[string]uint32, error) {
	return compileWith(sets, compileMembership)
}

func compileWith(sets map[string]Set, build func([]membership, []membership) (membershipMatcher, error)) (*Index, map[string]uint32, error) {
	if len(sets) == 0 {
		return nil, nil, nil
	}
	ids := make(map[string]uint32, len(sets))
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	exactCount, suffixCount := 0, 0
	for n, name := range names {
		set := sets[name]
		if set.ID() != name || len(set.Domain)+len(set.DomainSuffix) == 0 {
			return nil, nil, errors.New("invalid shared DNS domain set")
		}
		ids[name] = uint32(n + 1)
		exactCount += len(set.Domain)
		suffixCount += len(set.DomainSuffix)
	}
	exact := make([]membership, 0, exactCount)
	suffix := make([]membership, 0, suffixCount)
	for _, name := range names {
		set, id := sets[name], ids[name]
		for _, value := range set.Domain {
			if value != "" {
				key := strings.ToLower(value)
				exact = append(exact, membership{key, id})
			}
		}
		for _, value := range set.DomainSuffix {
			if key := strings.ToLower(strings.Trim(value, ".")); key != "" {
				suffix = append(suffix, membership{key, id})
			}
		}
	}
	matcher, err := build(exact, suffix)
	if err != nil {
		return nil, nil, err
	}
	return &Index{matcher: matcher}, ids, nil
}

func (i *Index) Match(name string, visit func(uint32)) {
	if i == nil || i.matcher == nil {
		return
	}
	i.matcher.Match(name, visit)
}
