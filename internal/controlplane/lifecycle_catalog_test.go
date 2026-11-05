package controlplane

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/releasecontract"
)

func TestImageCatalogCapabilityRequiresCheckedArchiveLabel(t *testing.T) {
	for _, entry := range []struct {
		label  string
		schema int
		valid  bool
	}{{"", 0, true}, {"0", 0, true}, {"1", 1, true}, {"2", 0, false}, {"01", 0, false}} {
		t.Run("schema-"+entry.label, func(t *testing.T) {
			// The shared archive fixture deletes labels whose override is empty.
			body := dockerImageArchive(t, "arm64", "99.0.0", "layer", map[string]string{releasecontract.SubscriptionCatalogSchemaLabel: entry.label})
			observation := dockerImageCapability{CatalogSchema: 99}
			_, _, _, err := inspectDockerImageStream(bytes.NewReader(body), io.Discard, &observation)
			if entry.valid {
				if err != nil || observation.CatalogSchema != entry.schema {
					t.Fatalf("schema=%d error=%v", observation.CatalogSchema, err)
				}
			} else if err == nil || observation.CatalogSchema != 99 {
				t.Fatal("unsupported archive published a capability")
			}
		})
	}
	body := dockerImageArchive(t, "amd64", "99.0.0", "layer", map[string]string{releasecontract.SubscriptionCatalogSchemaLabel: "1"})
	observation := dockerImageCapability{CatalogSchema: 99}
	if _, _, _, err := inspectDockerImageStream(bytes.NewReader(body), io.Discard, &observation); err == nil || observation.CatalogSchema != 99 {
		t.Fatal("wrong platform published a capability")
	}
}

func TestImageCatalogCapabilityPersistsWithVerifiedUpload(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	config, err := server.getDraft()
	if err != nil {
		t.Fatal(err)
	}
	config["storage"] = map[string]any{"root": "usb1/sb-gateway"}
	if _, err := server.repository.saveDraft(config); err != nil {
		t.Fatal(err)
	}
	body := dockerImageArchive(t, "arm64", "99.0.0", "layer", map[string]string{releasecontract.SubscriptionCatalogSchemaLabel: "1"})
	response := uploadImageRequest(t, server, cookie, csrf, "candidate.tar", body)
	if response.Code != http.StatusOK {
		t.Fatalf("upload status=%d", response.Code)
	}
	verification, err := server.repository.auxiliary("lifecycle-image-verifications")
	if err != nil {
		t.Fatal(err)
	}
	if len(objectAt(verification, "images")) != 1 {
		t.Fatal("verified image record is missing")
	}
	for reference := range objectAt(verification, "images") {
		if _, err := server.validateVerifiedLocalImage("usb1/sb-gateway", reference); err != nil {
			t.Fatal(err)
		}
		if schema, err := server.verifiedLocalImageCatalogSchema(reference); err != nil || schema != 1 {
			t.Fatalf("schema=%d error=%v", schema, err)
		}
	}
}

func TestImageCatalogCapabilityRejectsMalformedPersistedValue(t *testing.T) {
	server := newTestServer(t)
	for _, entry := range []struct {
		value any
		want  int
		ok    bool
	}{{nil, 0, true}, {float64(0), 0, true}, {float64(1), 1, true}, {float64(2), 0, false}, {"1", 0, false}, {float64(1.5), 0, false}} {
		record := map[string]any{}
		if entry.value != nil {
			record["catalog_schema"] = entry.value
		}
		if err := server.repository.saveAuxiliary("lifecycle-image-verifications", map[string]any{"images": map[string]any{"image": record}}); err != nil {
			t.Fatal(err)
		}
		schema, err := server.verifiedLocalImageCatalogSchema("image")
		if (err == nil) != entry.ok || schema != entry.want {
			t.Fatalf("value=%v schema=%d error=%v", entry.value, schema, err)
		}
	}
}
