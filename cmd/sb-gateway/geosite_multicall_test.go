//go:build xray_multicall

package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
	"github.com/xtls/xray-core/common/geodata"
)

func TestGeoSiteNativeMatcherSharesCompiledMembership(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XRAY_LOCATION_ASSET", root)
	fields := map[string][]string{"domain_suffix": {"suffix.example.test"}, "domain": {"exact.example.test"}, "domain_keyword": {"unique-video-marker"}, "domain_regex": {"^img[0-9]+\\.example\\.test$"}}
	prefix := strings.ToLower(filepath.Base(root))
	for i := 0; i < 5000; i++ {
		fields["domain_suffix"] = append(fields["domain_suffix"], fmt.Sprintf("%s-%d.example.test", prefix, i))
	}
	ref, err := geoipasset.PublishDomains(root, fields)
	if err != nil {
		t.Fatal(err)
	}
	rules, err := geodata.ParseDomainRules([]string{ref}, geodata.Domain_Substr)
	if err != nil {
		t.Fatal(err)
	}
	var before, first, second runtime.MemStats
	runtime.ReadMemStats(&before)
	a, err := geodata.DomainReg.BuildDomainMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&first)
	b, err := geodata.DomainReg.BuildDomainMatcher(rules)
	if err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&second)
	for _, m := range []geodata.DomainMatcher{a, b} {
		for _, name := range []string{"suffix.example.test", "sub.suffix.example.test", "exact.example.test", "img12.example.test", "a-unique-video-marker.test"} {
			if !m.MatchAny(name) {
				t.Fatalf("native GeoSite did not match %s", name)
			}
		}
		if m.MatchAny("unmatched.example.test") {
			t.Fatal("unexpected GeoSite match")
		}
	}
	runtime.KeepAlive(a)
	firstBytes, secondBytes := first.TotalAlloc-before.TotalAlloc, second.TotalAlloc-first.TotalAlloc
	if firstBytes == 0 || secondBytes >= firstBytes/4 {
		t.Fatalf("second matcher rebuilt membership: first=%d second=%d", firstBytes, secondBytes)
	}
	t.Logf("compiled matcher allocations first=%d second=%d", firstBytes, secondBytes)
}
