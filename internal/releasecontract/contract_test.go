package releasecontract

import "testing"

func TestCompatibleAllowsSkippedReleaseSchemas(t *testing.T) {
	labels := map[string]string{
		"org.opencontainers.image.title": ImageTitle,
		LifecycleVersionLabel:            LifecycleVersion,
		ConfigSchemaLabel:                "4",
		MinimumConfigSchemaLabel:         "1",
	}
	if schema, minimum, ok := Compatible(labels, 1); !ok || schema != 4 || minimum != 1 {
		t.Fatalf("compatible skipped release rejected: schema=%d minimum=%d ok=%v", schema, minimum, ok)
	}
}

func TestCompatibleRejectsContractAndMigrationGaps(t *testing.T) {
	tests := []map[string]string{
		{
			"org.opencontainers.image.title": ImageTitle,
			LifecycleVersionLabel:            "2",
			ConfigSchemaLabel:                "1",
			MinimumConfigSchemaLabel:         "1",
		},
		{
			"org.opencontainers.image.title": ImageTitle,
			LifecycleVersionLabel:            LifecycleVersion,
			ConfigSchemaLabel:                "4",
			MinimumConfigSchemaLabel:         "2",
		},
	}
	for _, labels := range tests {
		if _, _, ok := Compatible(labels, 1); ok {
			t.Fatalf("incompatible release contract accepted: %#v", labels)
		}
	}
}
