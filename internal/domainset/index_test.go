package domainset

import (
	"fmt"
	"runtime"
	"runtime/metrics"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
)

// Keep the previous implementation as a behavioral and performance reference.
type mapIndex struct{ exact, suffix map[string][]uint32 }

func compileMap(sets map[string]Set) *mapIndex {
	i := &mapIndex{make(map[string][]uint32), make(map[string][]uint32)}
	names := make([]string, 0, len(sets))
	for name := range sets {
		names = append(names, name)
	}
	sort.Strings(names)
	for n, name := range names {
		if sets[name].ID() != name {
			panic("invalid benchmark domain set")
		}
		for _, value := range sets[name].Domain {
			if value != "" {
				key := strings.ToLower(value)
				i.exact[key] = append(i.exact[key], uint32(n+1))
			}
		}
		for _, value := range sets[name].DomainSuffix {
			if key := strings.ToLower(strings.Trim(value, ".")); key != "" {
				i.suffix[key] = append(i.suffix[key], uint32(n+1))
			}
		}
	}
	return i
}

func (i *mapIndex) Match(name string, visit func(uint32)) {
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

func TestIndexMatchesReference(t *testing.T) {
	a := Set{Domain: []string{"EXAMPLE.com", "exact.example.com", "exact.example.com", "", "trailing.", ".literal.com"}, DomainSuffix: []string{".EXAMPLE.com.", "com", "example.com", ".", "", "xn--e1afmkfd.xn--p1ai"}}
	b := Set{Domain: []string{"example.com", strings.Repeat("long", 100)}, DomainSuffix: []string{"example.com", "deep.example.com", "пример.рф"}}
	sets := map[string]Set{a.ID(): a, b.ID(): b}
	i, _, err := Compile(sets)
	if err != nil {
		t.Fatal(err)
	}
	reference := compileMap(sets)
	for _, name := range []string{"", "com", "example.com", "EXAMPLE.com", "exact.example.com", "www.deep.example.com", "evilexample.com", "www.example.com.", "trailing.", ".example.com", ".literal.com", "www.literal.com", "x..example.com", "www.xn--e1afmkfd.xn--p1ai", "www.пример.рф", strings.Repeat("long", 100), "zzz", "aaa"} {
		var got, want []uint32
		i.Match(name, func(id uint32) { got = append(got, id) })
		reference.Match(name, func(id uint32) { want = append(want, id) })
		if !slices.Equal(got, want) {
			t.Errorf("%q: got %v, want %v", name, got, want)
		}
	}
}

func TestIndexConcurrentMatch(t *testing.T) {
	set := Set{Domain: []string{"example.com"}, DomainSuffix: []string{"example.com", "com"}}
	i, _, err := Compile(map[string]Set{set.ID(): set})
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			for range 1000 {
				count := 0
				i.Match("example.com", func(uint32) { count++ })
				if count != 3 {
					t.Error("concurrent match lost membership")
					return
				}
			}
		})
	}
	workers.Wait()
}

func TestCompactLookupAllocations(t *testing.T) {
	i, err := compileCompact([]membership{{strings.Repeat("long", 100), 1}}, []membership{{"example.com", 2}})
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"www.example.com", strings.Repeat("long", 100), strings.Repeat("missing.", 50)} {
		if got := testing.AllocsPerRun(100, func() { i.Match(query, func(uint32) {}) }); got != 0 {
			t.Fatalf("match allocated %v times for %q", got, query)
		}
	}
}

func TestIndexEmptyAndImmutable(t *testing.T) {
	i, ids, err := Compile(nil)
	if i != nil || ids != nil || err != nil {
		t.Fatal("empty input must retain nil behavior")
	}
	i.Match("example.com", func(uint32) { t.Fatal("nil index matched") })
	new(Index).Match("example.com", func(uint32) { t.Fatal("zero index matched") })
	set := Set{DomainSuffix: []string{"example.com"}}
	i, _, err = Compile(map[string]Set{set.ID(): set})
	if err != nil {
		t.Fatal(err)
	}
	set.DomainSuffix[0] = "other.com"
	count := 0
	i.Match("example.com", func(uint32) { count++ })
	if count != 1 {
		t.Fatal("compiled membership changed with its input")
	}
	for _, invalid := range []Set{{}, {Domain: []string{"example.com"}}} {
		if _, _, err := Compile(map[string]Set{"wrong": invalid}); err == nil {
			t.Fatal("invalid set accepted")
		}
	}
}

func TestIndexCatalogParity(t *testing.T) {
	sets := benchmarkSets(250)
	deep := Set{DomainSuffix: []string{"com"}}
	for name := "com"; len(deep.DomainSuffix) < 32; {
		name = "a." + name
		deep.DomainSuffix = append(deep.DomainSuffix, name)
	}
	sets[deep.ID()] = deep
	i, _, err := Compile(sets)
	if err != nil {
		t.Fatal(err)
	}
	reference := compileMap(sets)
	for _, set := range sets {
		for _, names := range [][]string{set.Domain, set.DomainSuffix} {
			for _, name := range names {
				for _, query := range []string{name, "www." + name, "evil" + name, name + ".", "unmatched.example"} {
					var got, want []uint32
					i.Match(query, func(id uint32) { got = append(got, id) })
					reference.Match(query, func(id uint32) { want = append(want, id) })
					if !slices.Equal(got, want) {
						t.Fatalf("%q: got %v, want %v", query, got, want)
					}
				}
			}
		}
	}
}

func FuzzIndexMatchesReference(f *testing.F) {
	f.Add("a.example.com\nEXAMPLE.com\nexample.com\n", "example.com\ncom", "www.example.com")
	f.Add("\x00\xff", ".\n..", "a..")
	f.Fuzz(func(t *testing.T, exact, suffix, query string) {
		if len(exact)+len(suffix)+len(query) > 16384 {
			t.Skip()
		}
		a := Set{Domain: strings.Split(exact, "\n"), DomainSuffix: strings.Split(suffix, "\n")}
		b := Set{Domain: strings.Split(suffix, "\n"), DomainSuffix: strings.Split(exact, "\n")}
		sets := map[string]Set{a.ID(): a, b.ID(): b}
		i, _, err := Compile(sets)
		if err != nil {
			t.Fatal(err)
		}
		reference := compileMap(sets)
		var got, want []uint32
		i.Match(query, func(id uint32) { got = append(got, id) })
		reference.Match(query, func(id uint32) { want = append(want, id) })
		if !slices.Equal(got, want) {
			t.Fatalf("got %v, want %v", got, want)
		}
	})
}

func benchmarkSets(count int) map[string]Set {
	sets := make(map[string]Set)
	for group := 0; group < 8; group++ {
		set := Set{}
		for n := 0; n < count; n++ {
			name := fmt.Sprintf("host%06d.service%02d.example", n, group)
			if n%4 == 0 {
				set.Domain = append(set.Domain, name)
			} else {
				set.DomainSuffix = append(set.DomainSuffix, name)
			}
		}
		set.DomainSuffix = append(set.DomainSuffix, "shared.example")
		sets[set.ID()] = set
	}
	return sets
}

type benchmarkCompiler struct {
	name  string
	build func(map[string]Set) membershipMatcher
}

func benchmarkCompilers() []benchmarkCompiler {
	compilers := []benchmarkCompiler{
		{"map", func(sets map[string]Set) membershipMatcher { return compileMap(sets) }},
		{"compact", func(sets map[string]Set) membershipMatcher {
			i, _, err := compileWith(sets, compileCompact)
			if err != nil {
				panic(err)
			}
			return i
		}},
	}
	if nativeMatcherName != "map" {
		compilers = append(compilers, benchmarkCompiler{nativeMatcherName, func(sets map[string]Set) membershipMatcher {
			i, _, err := Compile(sets)
			if err != nil {
				panic(err)
			}
			return i
		}})
	}
	return compilers
}

func BenchmarkDomainLookup(b *testing.B) {
	sets := benchmarkSets(12500)
	queries := []string{"host000000.service00.example", "www.host000001.service04.example", "www.shared.example", "www.absent.service00.example", "a.b.c.d.e.host000003.service07.example"}
	for _, impl := range benchmarkCompilers() {
		index := impl.build(sets)
		for n, query := range queries {
			b.Run(fmt.Sprintf("%s/query%d", impl.name, n), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					index.Match(query, func(uint32) {})
				}
			})
		}
	}
}

var retainedIndex any

func BenchmarkDomainStorage(b *testing.B) {
	for _, impl := range benchmarkCompilers() {
		b.Run(impl.name, func(b *testing.B) {
			retainedIndex = nil
			runtime.GC()
			runtime.GC() // clear sync.Pool victims, including temporary JSON buffers
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			scan := []metrics.Sample{{Name: "/gc/scan/heap:bytes"}}
			metrics.Read(scan)
			beforeScan := scan[0].Value.Uint64()
			for b.Loop() {
				sets := benchmarkSets(12500)
				retainedIndex = impl.build(sets)
			}
			b.StopTimer()
			runtime.GC()
			runtime.GC()
			runtime.ReadMemStats(&after)
			metrics.Read(scan)
			b.ReportMetric(float64(int64(after.HeapAlloc)-int64(before.HeapAlloc)), "retained-B")
			b.ReportMetric(float64(int64(scan[0].Value.Uint64())-int64(beforeScan)), "scan-B")
		})
	}
	retainedIndex = nil
}
