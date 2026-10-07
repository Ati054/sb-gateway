package main

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func recoveryArchive(t *testing.T, platform string) (string, string) {
	t.Helper()
	hash := func(body []byte) string { sum := sha256.Sum256(body); return hex.EncodeToString(sum[:]) }
	var layer bytes.Buffer
	layerWriter := tar.NewWriter(&layer)
	if err := layerWriter.Close(); err != nil {
		t.Fatal(err)
	}
	config, err := json.Marshal(map[string]any{
		"architecture": platform, "os": "linux", "rootfs": map[string]any{"diff_ids": []string{"sha256:" + hash(layer.Bytes())}},
		"config": map[string]any{"Labels": map[string]string{
			"org.opencontainers.image.title": "sb-gateway", "org.opencontainers.image.version": "1.6.45-rc.2",
			"io.sb-gateway.lifecycle.version": "1", "io.sb-gateway.config.schema": "1", "io.sb-gateway.config.minimum-schema": "1",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	configName, layerName := hash(config)+".json", hash(layer.Bytes())+"/layer.tar"
	manifest, err := json.Marshal([]map[string]any{{"Config": configName, "RepoTags": []string{"sb-gateway:1.6.45-rc.2-arm64"}, "Layers": []string{layerName}}})
	if err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	writer := tar.NewWriter(&archive)
	for name, body := range map[string][]byte{configName: config, layerName: layer.Bytes(), "manifest.json": manifest} {
		if err := writer.WriteHeader(&tar.Header{Name: name, Size: int64(len(body)), Mode: 0600}); err != nil {
			t.Fatal(err)
		}
		if _, err := writer.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "image.tar")
	if err := os.WriteFile(path, archive.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	return path, hash(archive.Bytes())
}

func TestRecoveryCLIValidatesArchiveAndRefusesOverwrite(t *testing.T) {
	archive, checksum := recoveryArchive(t, "arm64")
	destination := filepath.Join(t.TempDir(), "recovery.rsc")
	args := []string{"--archive", archive, "--sha256", checksum, "--version", "1.6.45-rc.2", "--storage-root", "usb1/sb-gateway", "--container-ip", "172.31.255.2", "--router-identity", "MikroTik", "--output", destination}
	var output bytes.Buffer
	if err := run(args, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "ARCHIVE_VERIFIED=PASS") {
		t.Fatal("verification receipt missing")
	}
	before, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if err := run(args, &output); err == nil {
		t.Fatal("existing output overwritten")
	}
	after, err := os.ReadFile(destination)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing output changed")
	}
	if err := run(args[:len(args)-2], &output); err == nil {
		t.Fatal("missing output accepted")
	}
	args[3] = strings.Repeat("0", 64)
	if err := run(args, &output); err == nil {
		t.Fatal("wrong checksum accepted")
	}
}

func TestRecoveryCLIRejectsWrongPlatform(t *testing.T) {
	archive, checksum := recoveryArchive(t, "amd64")
	destination := filepath.Join(t.TempDir(), "recovery.rsc")
	args := []string{"--archive", archive, "--sha256", checksum, "--version", "1.6.45-rc.2", "--storage-root", "usb1/sb-gateway", "--container-ip", "172.31.255.2", "--router-identity", "MikroTik", "--output", destination}
	if err := run(args, &bytes.Buffer{}); err == nil {
		t.Fatal("wrong platform accepted")
	}
	if _, err := os.Stat(destination); !os.IsNotExist(err) {
		t.Fatal("failed validation created output")
	}
}
