package domainset

import (
	"cmp"
	"errors"
	"math"
	"slices"
	"sort"
	"strings"
)

// A test-only alternative to quantify the cost of binary search versus MPH.
type compactIndex struct{ exact, suffix table }

type table struct {
	names   []byte
	ends    []boundary
	members []uint32
}

type boundary struct{ name, member uint32 }

func compileTable(entries []membership) (table, error) {
	slices.SortFunc(entries, func(a, b membership) int {
		if order := strings.Compare(a.name, b.name); order != 0 {
			return order
		}
		return cmp.Compare(a.id, b.id)
	})
	var size uint64
	unique := 0
	for n, entry := range entries {
		if n == 0 || entries[n-1].name != entry.name {
			size += uint64(len(entry.name))
			unique++
		}
	}
	if size > math.MaxUint32 || uint64(len(entries)) > math.MaxUint32 {
		return table{}, errors.New("shared DNS domain index exceeds 32-bit offsets")
	}
	t := table{names: make([]byte, 0, int(size)), ends: make([]boundary, 0, unique), members: make([]uint32, 0, len(entries))}
	for n, entry := range entries {
		if n == 0 || entries[n-1].name != entry.name {
			t.names = append(t.names, entry.name...)
			t.ends = append(t.ends, boundary{name: uint32(len(t.names))})
		}
		t.members = append(t.members, entry.id)
		t.ends[len(t.ends)-1].member = uint32(len(t.members))
	}
	return t, nil
}

func (t *table) match(name string, visit func(uint32)) {
	n := sort.Search(len(t.ends), func(n int) bool {
		start := uint32(0)
		if n > 0 {
			start = t.ends[n-1].name
		}
		return string(t.names[start:t.ends[n].name]) >= name
	})
	if n == len(t.ends) {
		return
	}
	start, member := uint32(0), uint32(0)
	if n > 0 {
		start, member = t.ends[n-1].name, t.ends[n-1].member
	}
	if string(t.names[start:t.ends[n].name]) == name {
		for _, id := range t.members[member:t.ends[n].member] {
			visit(id)
		}
	}
}

func compileCompact(exact, suffix []membership) (membershipMatcher, error) {
	index := &compactIndex{}
	var err error
	if index.exact, err = compileTable(exact); err != nil {
		return nil, err
	}
	if index.suffix, err = compileTable(suffix); err != nil {
		return nil, err
	}
	return index, nil
}

func (i *compactIndex) Match(name string, visit func(uint32)) {
	i.exact.match(name, visit)
	for suffix := name; suffix != ""; {
		i.suffix.match(suffix, visit)
		dot := strings.IndexByte(suffix, '.')
		if dot < 0 {
			break
		}
		suffix = suffix[dot+1:]
	}
}
