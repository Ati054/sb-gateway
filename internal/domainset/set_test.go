package domainset

import (
	"testing"
)

func TestSharedMembershipHandlesOverlapsAndBoundaries(t *testing.T) {
	a := Set{Domain: []string{"exact.example"}, DomainSuffix: []string{"suffix.example"}}
	b := Set{Domain: []string{"exact.example"}, DomainSuffix: []string{"other.example"}}
	index, ids, err := Compile(map[string]Set{a.ID(): a, b.ID(): b})
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"exact.example": 2, "www.suffix.example": 1, "suffix.example": 1, "evilsuffix.example": 0, "sub.exact.example": 0} {
		found := make(map[uint32]bool)
		index.Match(name, func(id uint32) { found[id] = true })
		if len(found) != want {
			t.Fatalf("%s matches %d, want %d", name, len(found), want)
		}
	}
	if ids[a.ID()] == ids[b.ID()] {
		t.Fatal("distinct sets share identity")
	}
	if _, _, err := Compile(map[string]Set{"wrong": a}); err == nil {
		t.Fatal("bad content ID accepted")
	}
}
