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

type Index struct{ exact, suffix map[string][]uint32 }

func Compile(sets map[string]Set) (*Index, map[string]uint32, error) {
	if len(sets) == 0 {
		return nil, nil, nil
	}
	index := &Index{exact: make(map[string][]uint32), suffix: make(map[string][]uint32)}
	ids := make(map[string]uint32, len(sets))
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	for n, name := range names {
		set := sets[name]
		if set.ID() != name || len(set.Domain)+len(set.DomainSuffix) == 0 {
			return nil, nil, errors.New("invalid shared DNS domain set")
		}
		id := uint32(n + 1)
		ids[name] = id
		for _, value := range set.Domain {
			if value != "" {
				key := strings.ToLower(value)
				index.exact[key] = append(index.exact[key], id)
			}
		}
		for _, value := range set.DomainSuffix {
			if key := strings.ToLower(strings.Trim(value, ".")); key != "" {
				index.suffix[key] = append(index.suffix[key], id)
			}
		}
	}
	return index, ids, nil
}

func (i *Index) Match(name string, visit func(uint32)) {
	if i == nil {
		return
	}
	for _, id := range i.exact[name] {
		visit(id)
	}
	for suffix := name; suffix != ""; {
		for _, id := range i.suffix[suffix] {
			visit(id)
		}
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		suffix = suffix[dot+1:]
	}
}
