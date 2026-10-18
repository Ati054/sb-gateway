//go:build xray_multicall

package domainset

import (
	"runtime"
	"slices"
	"testing"
)

func TestMulticallUsesMPHWithoutForcedGC(t *testing.T) {
	sets := benchmarkSets(250)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	index, _, err := Compile(sets)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	mph, ok := index.matcher.(*mphIndex)
	if !ok || mph.group == nil || len(mph.literal) != 0 {
		t.Fatal("packaged DNS index did not use the native MPH group")
	}
	if after.NumForcedGC != before.NumForcedGC {
		t.Fatal("membership compilation forced process-wide garbage collection")
	}
}

func TestMulticallHashCollisionKeepsLegacyMembership(t *testing.T) {
	a := Set{Domain: []string{"\x80"}, DomainSuffix: []string{"\x80\x00"}}
	b := Set{Domain: a.DomainSuffix, DomainSuffix: a.Domain}
	sets := map[string]Set{a.ID(): a, b.ID(): b}
	index, _, err := Compile(sets)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := index.matcher.(*mapMembership); !ok {
		t.Fatal("MPH collision did not use the legacy fallback")
	}
	reference := compileMap(sets)
	for _, query := range []string{"0", "\ufffd", "\ufffd\x00", "www.\ufffd"} {
		var got, want []uint32
		index.Match(query, func(id uint32) { got = append(got, id) })
		reference.Match(query, func(id uint32) { want = append(want, id) })
		if !slices.Equal(got, want) {
			t.Fatalf("%q: got %v, want %v", query, got, want)
		}
	}
}
