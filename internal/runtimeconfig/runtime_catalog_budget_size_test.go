package runtimeconfig

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func catalogBudgetEncodedLength(t *testing.T, value any) int64 {
	t.Helper()
	var body bytes.Buffer
	encoder := json.NewEncoder(&body)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		t.Fatal(err)
	}
	return int64(body.Len() - 1) // Encoder adds one newline.
}

func TestCatalogJSONStringBytesMatchesEncoder(t *testing.T) {
	values := []string{"", "ascii", "https://host/path?a=1&b=<tag>", "\"\\/\b\f\n\r\t", "\x00\x01\x1f\x7f", "русский 日本語 😀", "\u2028\u2029\ufffd", string([]byte{0xff, 0xfe, 0xc0, 0xaf, 0xed, 0xa0, 0x80}), strings.Repeat("<>&/", 1024)}
	for _, value := range values {
		if got, want := catalogJSONStringBytes(value), catalogBudgetEncodedLength(t, value); got != want {
			t.Fatalf("JSON length mismatch for bytes %x: got %d want %d", []byte(value), got, want)
		}
	}
	// Every possible byte plus neighboring UTF-8 exposes short-control escapes,
	// invalid byte replacement and valid/invalid multi-byte boundary handling.
	for b := 0; b < 256; b++ {
		value := "界" + string([]byte{byte(b)}) + "\u2028"
		if got, want := catalogJSONStringBytes(value), catalogBudgetEncodedLength(t, value); got != want {
			t.Fatalf("byte %d: got %d want %d", b, got, want)
		}
	}
	value := "<>&/\x00\xff\u2028😀"
	if allocations := testing.AllocsPerRun(100, func() { _ = catalogJSONStringBytes(value) }); allocations != 0 {
		t.Fatalf("string size scan allocated: %v", allocations)
	}
}

func TestCatalogNodePoolJSONBytesMatchesEncodedObjects(t *testing.T) {
	base := catalogPlanNode{meta: catalogHealthNode{Label: "<label>\"\x00", Country: "ZZ", Protocol: "reality", Transport: "tcp", SubscriptionID: "source", Fingerprint: "kind:" + strings.Repeat("f", 64)}, definition: CatalogDefinition{Generation: strings.Repeat("a", 64), Fingerprint: strings.Repeat("b", 64), FingerprintKind: CatalogFingerprintKind}, server: "2001:db8::1", port: 443}
	for _, variant := range []string{"dynamic", "static", "dns-server", "unsupported-transport", "hysteria2", "minimal"} {
		t.Run(variant, func(t *testing.T) {
			item := base
			switch variant {
			case "static":
				item.static = true
			case "dns-server":
				item.server = "example.invalid"
			case "unsupported-transport":
				item.meta.Transport = "quic"
			case "hysteria2":
				item.meta.Protocol = "hysteria2"
			case "minimal":
				item = catalogPlanNode{meta: catalogHealthNode{Label: "plain", Country: "ZZ"}}
			}
			id := "source-\"node"
			key := catalogBudgetEncodedLength(t, id) + 2
			want := key + catalogBudgetEncodedLength(t, item.meta)
			if item.definition.Generation != "" && !item.static {
				want += key + catalogBudgetEncodedLength(t, item.definition)
			}
			// Expected eligibility is specified by each fixture, independently of
			// the implementation's target predicate.
			if variant == "dynamic" || variant == "static" {
				want += key + catalogBudgetEncodedLength(t, map[string]any{"address": item.server, "port": item.port})
			}
			if got := catalogNodePoolJSONBytes(id, item); got != want {
				t.Fatalf("pool JSON estimate: got %d want %d", got, want)
			}
			if got := catalogPlanNodeWorkingBytes(id, item); got <= 2*want {
				t.Fatal("working estimate omitted retained typed/maps/string storage")
			}
		})
	}
}

func TestCatalogWorkingBytesChargeActualEscapeExpansion(t *testing.T) {
	plain := catalogPlanNode{meta: catalogHealthNode{Label: strings.Repeat("x", 1024), Country: "ZZ"}}
	html := plain
	html.meta.Label = strings.Repeat("<", 1024)
	control := plain
	control.meta.Label = strings.Repeat("\x00", 1024)
	if catalogPlanNodeWorkingBytes("node", plain) != catalogPlanNodeWorkingBytes("node", html) {
		t.Fatal("HTML was charged as six-fold escaped output")
	}
	// Same retained byte count; only the two encoded copies expand by five.
	if delta := catalogPlanNodeWorkingBytes("node", control) - catalogPlanNodeWorkingBytes("node", plain); delta != 2*5*1024 {
		t.Fatalf("control expansion charge: %d", delta)
	}
}
