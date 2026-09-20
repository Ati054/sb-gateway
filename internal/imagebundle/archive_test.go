package imagebundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNormalizeBuildKitArchiveForRouterOS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "image.tar")
	layerPayload := tarPayload(t, "test.txt", []byte("routeros-layer-test\n"))
	var compressed bytes.Buffer
	gzipWriter, err := gzip.NewWriterLevel(&compressed, gzip.BestSpeed)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter.Header.ModTime = time.Unix(0, 0)
	if _, err := gzipWriter.Write(layerPayload); err != nil {
		t.Fatal(err)
	}
	if err := gzipWriter.Close(); err != nil {
		t.Fatal(err)
	}
	diffID := "sha256:" + hash(layerPayload)
	config := map[string]any{
		"architecture": "arm64", "os": "linux", "rootfs": map[string]any{"diff_ids": []string{diffID}},
		"config": map[string]any{"Labels": map[string]string{
			"org.opencontainers.image.version": "1.5.10", "org.opencontainers.image.revision": "abc123",
			"org.opencontainers.image.source": "local", "org.opencontainers.image.title": "sb-gateway",
			"io.sb-gateway.lifecycle.version": "1", "io.sb-gateway.config.schema": "1", "io.sb-gateway.config.minimum-schema": "1",
			"io.sb-gateway.dependency.xray.version": "26.7.28",
		}},
	}
	configBody, _ := json.Marshal(config)
	configName := "blobs/sha256/" + hash(configBody)
	layerName := "blobs/sha256/" + hash(compressed.Bytes())
	manifestBody, _ := json.Marshal([]manifestEntry{{Config: configName, RepoTags: []string{"sb-gateway:1.5.10-arm64"}, Layers: []string{layerName}}})
	writeArchive(t, path, map[string][]byte{configName: configBody, layerName: compressed.Bytes(), "manifest.json": manifestBody})
	if err := Normalize(path); err != nil {
		t.Fatal(err)
	}
	details, err := Validate(path, "sb-gateway:1.5.10-arm64", "1.5.10")
	if err != nil {
		t.Fatal(err)
	}
	if details.Platform != "linux/arm64" || details.Revision != "abc123" || !classicConfigPattern.MatchString(details.DockerConfig) {
		t.Fatalf("details = %#v", details)
	}
	manifest, err := readTarEntry(path, "manifest.json", maxMetadataBytes)
	if err != nil || bytes.Contains(manifest, []byte("blobs/sha256")) {
		t.Fatalf("manifest was not normalized: %s, %v", manifest, err)
	}
}

func TestNormalizeRejectsLayerDigestMismatch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.tar")
	config := map[string]any{
		"architecture": "arm64", "os": "linux", "rootfs": map[string]any{"diff_ids": []string{"sha256:" + hash([]byte("different"))}},
	}
	configBody, _ := json.Marshal(config)
	configName := "blobs/sha256/" + hash(configBody)
	layer := []byte("not-a-gzip-layer")
	layerName := "blobs/sha256/" + hash(layer)
	manifestBody, _ := json.Marshal([]manifestEntry{{Config: configName, RepoTags: []string{"sb-gateway:test"}, Layers: []string{layerName}}})
	writeArchive(t, path, map[string][]byte{configName: configBody, layerName: layer, "manifest.json": manifestBody})
	if err := Normalize(path); err == nil {
		t.Fatal("invalid layer diff ID accepted")
	}
}

func TestValidateRejectsMissingReleaseContract(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing-contract.tar")
	layer := tarPayload(t, "test.txt", []byte("release-contract\n"))
	config := map[string]any{
		"architecture": "arm64", "os": "linux", "rootfs": map[string]any{"diff_ids": []string{"sha256:" + hash(layer)}},
		"config": map[string]any{"Labels": map[string]string{
			"org.opencontainers.image.title": "sb-gateway", "org.opencontainers.image.version": "1.5.84",
		}},
	}
	configBody, _ := json.Marshal(config)
	configName := hash(configBody) + ".json"
	layerName := hash(layer) + "/layer.tar"
	manifestBody, _ := json.Marshal([]manifestEntry{{
		Config: configName, RepoTags: []string{"sb-gateway:1.5.84-arm64"}, Layers: []string{layerName},
	}})
	writeArchive(t, path, map[string][]byte{configName: configBody, layerName: layer, "manifest.json": manifestBody})
	if _, err := Validate(path, "sb-gateway:1.5.84-arm64", "1.5.84"); err == nil {
		t.Fatal("image without release contract was accepted")
	}
}

func TestValidateRejectsForbiddenReleasePayload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "forbidden.tar")
	layer := tarPayload(t, "opt/sb-gateway/tests/runtime.test.mjs", []byte("not for release\n"))
	config := map[string]any{
		"architecture": "arm64", "os": "linux", "rootfs": map[string]any{"diff_ids": []string{"sha256:" + hash(layer)}},
		"config": map[string]any{"Labels": map[string]string{
			"org.opencontainers.image.title": "sb-gateway", "org.opencontainers.image.version": "1.6.0",
			"io.sb-gateway.lifecycle.version": "1", "io.sb-gateway.config.schema": "1", "io.sb-gateway.config.minimum-schema": "1",
		}},
	}
	configBody, _ := json.Marshal(config)
	configName := hash(configBody) + ".json"
	layerName := hash(layer) + "/layer.tar"
	manifestBody, _ := json.Marshal([]manifestEntry{{
		Config: configName, RepoTags: []string{"sb-gateway:1.6.0-arm64"}, Layers: []string{layerName},
	}})
	writeArchive(t, path, map[string][]byte{configName: configBody, layerName: layer, "manifest.json": manifestBody})
	if _, err := Validate(path, "sb-gateway:1.6.0-arm64", "1.6.0"); err == nil || !strings.Contains(err.Error(), "forbidden release payload") {
		t.Fatalf("forbidden release payload accepted: %v", err)
	}
}

func TestNormalizePodmanFlatArchiveForRouterOS(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "podman.tar")
	layerPayload := tarPayload(t, "podman.txt", []byte("flat-layer\n"))
	diffID := "sha256:" + hash(layerPayload)
	config := map[string]any{
		"architecture": "arm64", "os": "linux", "rootfs": map[string]any{"diff_ids": []string{diffID}},
		"config": map[string]any{"Labels": map[string]string{
			"org.opencontainers.image.version": "1.5.11", "org.opencontainers.image.revision": "podman123",
			"org.opencontainers.image.title": "sb-gateway", "io.sb-gateway.lifecycle.version": "1",
			"io.sb-gateway.config.schema": "1", "io.sb-gateway.config.minimum-schema": "1",
		}},
	}
	configBody, _ := json.Marshal(config)
	configName := hash(configBody) + ".json"
	layerName := hash(layerPayload) + ".tar"
	manifestBody, _ := json.Marshal([]manifestEntry{{
		Config: configName, RepoTags: []string{"localhost/sb-gateway:1.5.11-arm64"}, Layers: []string{layerName},
	}})
	writeArchive(t, path, map[string][]byte{configName: configBody, layerName: layerPayload, "manifest.json": manifestBody})
	if err := Normalize(path); err != nil {
		t.Fatal(err)
	}
	details, err := Validate(path, "localhost/sb-gateway:1.5.11-arm64", "1.5.11")
	if err != nil {
		t.Fatal(err)
	}
	if details.Revision != "podman123" || !classicConfigPattern.MatchString(details.DockerConfig) {
		t.Fatalf("details = %#v", details)
	}
	if matches, err := filepath.Glob(filepath.Join(root, ".routeros-layers-*")); err != nil || len(matches) != 0 {
		t.Fatalf("temporary layer directories remain: %v, %v", matches, err)
	}
}

func tarPayload(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := tar.NewWriter(&output)
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func writeArchive(t *testing.T, path string, entries map[string][]byte) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	writer := tar.NewWriter(file)
	for _, name := range []string{"manifest.json"} {
		body, ok := entries[name]
		if ok {
			if err := writeTarBytes(writer, name, body); err != nil {
				t.Fatal(err)
			}
			delete(entries, name)
		}
	}
	for name, body := range entries {
		if err := writeTarBytes(writer, name, body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
}

func hash(body []byte) string {
	digest := sha256.Sum256(body)
	return hex.EncodeToString(digest[:])
}
