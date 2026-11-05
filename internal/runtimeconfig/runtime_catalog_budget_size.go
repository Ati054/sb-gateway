package runtimeconfig

import (
	"net/netip"
	"unicode/utf8"
	"unsafe"
)

// catalogJSONStringBytes counts the quoted encoding/json representation with
// Encoder.SetEscapeHTML(false). In particular, HTML and '/' are not escaped,
// while invalid UTF-8 bytes become the UTF-8 replacement rune and U+2028/U+2029
// remain escaped in the maintained encoder.
// It does not allocate or retain the input. See the maintained Go JSONv2
// encoder's jsonwire.AppendQuote implementation.
func catalogJSONStringBytes(value string) int64 {
	n := int64(2)
	for i := 0; i < len(value); {
		b := value[i]
		if b < utf8.RuneSelf {
			switch b {
			case '"', '\\', '\b', '\f', '\n', '\r', '\t':
				n += 2
			default:
				if b < 0x20 {
					n += 6
				} else {
					n++
				}
			}
			i++
			continue
		}
		r, width := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && width == 1 {
			n += 3
		} else if r == '\u2028' || r == '\u2029' {
			n += 6
		} else {
			n += int64(width)
		}
		i += width
	}
	return n
}

func catalogJSONFieldBytes(name, value string) int64 {
	// All callers supply fixed ASCII field names that need no escaping.
	return int64(len(name)+3) + catalogJSONStringBytes(value)
}

func catalogMetadataJSONBytes(meta catalogHealthNode) int64 {
	n := int64(2) + catalogJSONFieldBytes("label", meta.Label) + 1 + catalogJSONFieldBytes("country", meta.Country)
	for _, field := range [4]struct{ name, value string }{{"protocol", meta.Protocol}, {"transport", meta.Transport}, {"subscription_id", meta.SubscriptionID}, {"fingerprint", meta.Fingerprint}} {
		if field.value != "" {
			n += 1 + catalogJSONFieldBytes(field.name, field.value)
		}
	}
	return n
}

func catalogDefinitionJSONBytes(definition CatalogDefinition) int64 {
	return 2 + catalogJSONFieldBytes("generation", definition.Generation) + 1 + catalogJSONFieldBytes("fingerprint", definition.Fingerprint) + 1 + catalogJSONFieldBytes("fingerprint_kind", definition.FingerprintKind)
}

func catalogPlanNodeHasTarget(item catalogPlanNode) bool {
	if item.meta.Protocol != "vless" && item.meta.Protocol != "reality" || item.meta.Transport == "kcp" || item.meta.Transport == "quic" || item.port < 1 || item.port > 65535 {
		return false
	}
	_, err := netip.ParseAddr(item.server)
	return err == nil
}

// catalogNodePoolJSONBytes covers this node's entries in nodes,
// catalog_definitions and dial_targets. A trailing comma per entry is charged
// conservatively. Policy membership arrays/fan-out have their own admission.
func catalogNodePoolJSONBytes(id string, item catalogPlanNode) int64 {
	key := catalogJSONStringBytes(id) + 2 // colon and trailing comma
	n := key + catalogMetadataJSONBytes(item.meta)
	if item.definition.Generation != "" && !item.static {
		n += key + catalogDefinitionJSONBytes(item.definition)
	}
	if catalogPlanNodeHasTarget(item) {
		digits := int64(1)
		for port := item.port; port >= 10; port /= 10 {
			digits++
		}
		n += key + 2 + catalogJSONFieldBytes("address", item.server) + 1 + int64(len(`"port":`)) + digits
	}
	return n
}

// catalogMapEntryWorkingBytes models the maintained Go Swiss-map layout:
// 8 slots / 7 average occupied, plus an old table coexisting with a doubled
// replacement (3 groups). Values over 128 bytes are stored indirectly.
// It is an admission estimate, not an exact Go heap/cgroup upper bound.
func catalogMapEntryWorkingBytes(valueBytes int64) int64 {
	const stringBytes = int64(unsafe.Sizeof(""))
	const pointerBytes = int64(unsafe.Sizeof(uintptr(0)))
	indirect := int64(0)
	if valueBytes > 128 {
		indirect = valueBytes
		valueBytes = pointerBytes
	}
	slot := stringBytes + valueBytes + 1 // key, value and control byte
	return indirect + (24*slot+6)/7
}

func catalogPlanNodeWorkingBytes(id string, item catalogPlanNode) int64 {
	// Typed plan cell (indirect in its map), pool metadata map, order slice,
	// and each retained string's bytes. Aliased/shared strings are deliberately
	// charged again; no generic six-fold JSON expansion is assumed.
	n := catalogMapEntryWorkingBytes(int64(unsafe.Sizeof(item))) + catalogMapEntryWorkingBytes(int64(unsafe.Sizeof(item.meta))) + int64(unsafe.Sizeof(""))
	for _, value := range [11]string{id, item.meta.Label, item.meta.Country, item.meta.Protocol, item.meta.Transport, item.meta.SubscriptionID, item.meta.Fingerprint, item.definition.Generation, item.definition.Fingerprint, item.definition.FingerprintKind, item.server} {
		if len(value) > 0 {
			n += (int64(len(value)) + 15) &^ 15
		}
	}
	if item.definition.Generation != "" && !item.static {
		n += catalogMapEntryWorkingBytes(int64(unsafe.Sizeof(item.definition)))
	}
	if catalogPlanNodeHasTarget(item) {
		const pointerBytes = int64(unsafe.Sizeof(uintptr(0)))
		const stringBytes = int64(unsafe.Sizeof(""))
		const interfaceBytes = int64(unsafe.Sizeof(any(nil)))
		// Outer targets entry, one small eight-slot map (including controls),
		// map header allowance, boxed address string and boxed port integer.
		n += catalogMapEntryWorkingBytes(interfaceBytes) + 8*(stringBytes+interfaceBytes) + 8 + 8*pointerBytes + stringBytes + pointerBytes
	}
	// encoding/json's encode state and the destination bytes.Buffer may coexist.
	return n + 2*catalogNodePoolJSONBytes(id, item)
}
