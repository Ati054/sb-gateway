package releasecontract

import "testing"

func TestCatalogCapabilityComesFromExplicitLabel(t *testing.T) {
	if schema, ok := CatalogSchema(nil); schema != 0 || !ok {
		t.Fatal("absent label must remain legacy")
	}
	for _, entry := range []struct {
		label  string
		schema int
		ok     bool
	}{{"", 0, false}, {"0", 0, true}, {"1", 1, true}, {"2", 0, false}, {"01", 0, false}, {"true", 0, false}, {" 1", 0, false}} {
		labels := map[string]string{"org.opencontainers.image.version": "99.0.0", SubscriptionCatalogSchemaLabel: entry.label}
		if schema, ok := CatalogSchema(labels); schema != entry.schema || ok != entry.ok {
			t.Fatalf("label %q: schema=%d ok=%v", entry.label, schema, ok)
		}
	}
}
