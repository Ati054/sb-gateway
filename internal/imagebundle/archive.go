package imagebundle

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/releasecontract"
)

const maxMetadataBytes = int64(4 << 20)

var (
	digestPattern        = regexp.MustCompile(`^[a-f0-9]{64}$`)
	modernBlobPattern    = regexp.MustCompile(`^blobs/sha256/([a-f0-9]{64})$`)
	flatLayerPattern     = regexp.MustCompile(`^([a-f0-9]{64})\.tar$`)
	classicConfigPattern = regexp.MustCompile(`^[a-f0-9]{64}\.json$`)
)

type manifestEntry struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
	Layers   []string `json:"Layers"`
}

type imageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

type Details struct {
	DockerConfig               string   `json:"docker_config"`
	RepoTags                   []string `json:"repo_tags"`
	Platform                   string   `json:"platform"`
	Version                    string   `json:"version"`
	Revision                   string   `json:"revision"`
	Source                     string   `json:"source"`
	XrayVersion                string   `json:"xray_version"`
	XrayRevision               string   `json:"xray_revision"`
	LifecycleVersion           string   `json:"lifecycle_version"`
	ConfigSchemaVersion        int      `json:"config_schema_version"`
	MinimumConfigSchemaVersion int      `json:"minimum_config_schema_version"`
}

// Normalize converts BuildKit's blob-oriented Docker exporter into the
// classic uncompressed docker-save layout accepted by RouterOS. Layer payloads
// are streamed through temporary files; RAM use does not follow image size.
func Normalize(path string) (result error) {
	manifestBody, err := readTarEntry(path, "manifest.json", maxMetadataBytes)
	if err != nil {
		return err
	}
	var manifest []manifestEntry
	if err := json.Unmarshal(manifestBody, &manifest); err != nil || len(manifest) != 1 {
		return errors.New("Docker archive must contain exactly one image")
	}
	entry := &manifest[0]
	modern := modernBlobPattern.FindStringSubmatch(entry.Config)
	if modern == nil && classicLayers(entry.Layers) {
		return nil
	}
	configBody, err := readTarEntry(path, entry.Config, maxMetadataBytes)
	if err != nil {
		return err
	}
	configDigest := strings.TrimSuffix(entry.Config, ".json")
	if modern != nil {
		configDigest = modern[1]
	}
	if !digestPattern.MatchString(configDigest) || digest(configBody) != configDigest {
		return errors.New("Docker archive image config digest mismatch")
	}
	var config imageConfig
	if err := json.Unmarshal(configBody, &config); err != nil {
		return errors.New("Docker archive image config is invalid")
	}
	if len(entry.Layers) == 0 || len(entry.Layers) != len(config.RootFS.DiffIDs) {
		return errors.New("Docker archive layer metadata is inconsistent")
	}
	temporaryRoot, err := os.MkdirTemp(filepath.Dir(path), ".routeros-layers-*")
	if err != nil {
		return err
	}
	defer func() {
		if cleanupErr := removeTemporaryTree(temporaryRoot); result == nil && cleanupErr != nil {
			result = cleanupErr
		}
	}()
	layers, err := extractLayers(path, temporaryRoot, entry.Layers, config.RootFS.DiffIDs)
	if err != nil {
		return err
	}
	replacement, err := os.CreateTemp(filepath.Dir(path), ".routeros-image-*.tmp")
	if err != nil {
		return err
	}
	replacementPath := replacement.Name()
	defer os.Remove(replacementPath)
	w := tar.NewWriter(replacement)
	classicConfig := configDigest + ".json"
	if err := writeTarBytes(w, classicConfig, configBody); err != nil {
		replacement.Close()
		return err
	}
	legacyLayers := make([]string, 0, len(layers))
	previousChain := ""
	for index, layer := range layers {
		chain := strings.TrimPrefix(config.RootFS.DiffIDs[index], "sha256:")
		if previousChain != "" {
			chain = digest([]byte("sha256:" + previousChain + " " + config.RootFS.DiffIDs[index]))
		}
		if err := writeTarBytes(w, chain+"/VERSION", []byte("1.0")); err != nil {
			replacement.Close()
			return err
		}
		metadata := map[string]string{"id": chain, "os": config.OS}
		if previousChain != "" {
			metadata["parent"] = previousChain
		}
		metadataBody, _ := json.Marshal(metadata)
		if err := writeTarBytes(w, chain+"/json", metadataBody); err != nil {
			replacement.Close()
			return err
		}
		legacyName := chain + "/layer.tar"
		if err := writeTarFile(w, legacyName, layer); err != nil {
			replacement.Close()
			return err
		}
		legacyLayers = append(legacyLayers, legacyName)
		previousChain = chain
	}
	entry.Config = classicConfig
	entry.Layers = legacyLayers
	normalizedManifest, _ := json.Marshal(manifest)
	if err := writeTarBytes(w, "manifest.json", normalizedManifest); err != nil {
		replacement.Close()
		return err
	}
	repositories := make(map[string]map[string]string)
	for _, repoTag := range entry.RepoTags {
		separator := strings.LastIndexByte(repoTag, ':')
		if separator <= 0 || separator == len(repoTag)-1 {
			continue
		}
		repository, tag := repoTag[:separator], repoTag[separator+1:]
		if repositories[repository] == nil {
			repositories[repository] = make(map[string]string)
		}
		repositories[repository][tag] = previousChain
	}
	repositoriesBody, _ := json.Marshal(repositories)
	if err := writeTarBytes(w, "repositories", repositoriesBody); err != nil {
		replacement.Close()
		return err
	}
	if err := w.Close(); err != nil {
		replacement.Close()
		return err
	}
	if err := replacement.Sync(); err != nil {
		replacement.Close()
		return err
	}
	if err := replacement.Close(); err != nil {
		return err
	}
	if err := os.Rename(replacementPath, path); err != nil {
		return err
	}
	return nil
}

func removeTemporaryTree(path string) error {
	var err error
	for attempt := 0; attempt < 10; attempt++ {
		err = os.RemoveAll(path)
		if err == nil {
			if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
				return nil
			} else if statErr != nil {
				err = statErr
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("remove temporary image layers: %w", err)
}

func classicLayers(names []string) bool {
	if len(names) == 0 {
		return false
	}
	for _, name := range names {
		parts := strings.Split(name, "/")
		if len(parts) != 2 || parts[1] != "layer.tar" || !digestPattern.MatchString(parts[0]) {
			return false
		}
	}
	return true
}

func Validate(path, expectedImage, expectedVersion string) (Details, error) {
	manifestBody, err := readTarEntry(path, "manifest.json", maxMetadataBytes)
	if err != nil {
		return Details{}, err
	}
	var manifest []manifestEntry
	if err := json.Unmarshal(manifestBody, &manifest); err != nil || len(manifest) != 1 {
		return Details{}, errors.New("Docker archive must contain exactly one image")
	}
	entry := manifest[0]
	if !classicConfigPattern.MatchString(entry.Config) {
		return Details{}, errors.New("Docker archive image config is not RouterOS-compatible")
	}
	configBody, err := readTarEntry(path, entry.Config, maxMetadataBytes)
	if err != nil {
		return Details{}, err
	}
	var config imageConfig
	if err := json.Unmarshal(configBody, &config); err != nil {
		return Details{}, errors.New("Docker image config is invalid")
	}
	if digest(configBody) != strings.TrimSuffix(entry.Config, ".json") {
		return Details{}, errors.New("Docker image config digest mismatch")
	}
	if config.OS != "linux" || config.Architecture != "arm64" {
		return Details{}, fmt.Errorf("wrong image platform: %s/%s; expected linux/arm64", config.OS, config.Architecture)
	}
	foundTag := false
	for _, tag := range entry.RepoTags {
		foundTag = foundTag || tag == expectedImage
	}
	if !foundTag {
		return Details{}, fmt.Errorf("Docker archive does not contain expected tag %s", expectedImage)
	}
	labels := config.Config.Labels
	if labels["org.opencontainers.image.version"] != expectedVersion {
		return Details{}, errors.New("wrong SB Gateway version label")
	}
	configSchema, minimumSchema, compatible := releasecontract.Compatible(labels, releasecontract.ConfigSchemaVersion)
	if !compatible {
		return Details{}, errors.New("wrong SB Gateway release contract")
	}
	if configSchema != releasecontract.ConfigSchemaVersion {
		return Details{}, errors.New("wrong SB Gateway configuration schema contract")
	}
	if err := validateClassicLayers(path, entry.Layers, config.RootFS.DiffIDs); err != nil {
		return Details{}, err
	}
	return Details{
		DockerConfig: entry.Config, RepoTags: entry.RepoTags, Platform: "linux/arm64", Version: expectedVersion,
		Revision:                   valueOr(labels["org.opencontainers.image.revision"], "unknown"),
		Source:                     valueOr(labels["org.opencontainers.image.source"], "unknown"),
		XrayVersion:                valueOr(labels["io.sb-gateway.dependency.xray.version"], "unknown"),
		XrayRevision:               valueOr(labels["io.sb-gateway.dependency.xray.revision"], "unknown"),
		LifecycleVersion:           labels[releasecontract.LifecycleVersionLabel],
		ConfigSchemaVersion:        configSchema,
		MinimumConfigSchemaVersion: minimumSchema,
	}, nil
}

func validateClassicLayers(path string, names, diffIDs []string) error {
	if len(names) == 0 || len(names) != len(diffIDs) {
		return errors.New("Docker archive layer metadata is inconsistent")
	}
	indices := make(map[string]int, len(names))
	for index, name := range names {
		parts := strings.Split(name, "/")
		if len(parts) != 2 || parts[1] != "layer.tar" || !digestPattern.MatchString(parts[0]) || indices[name] != 0 {
			return errors.New("Docker archive classic layer name is invalid or duplicated")
		}
		if !strings.HasPrefix(diffIDs[index], "sha256:") || !digestPattern.MatchString(strings.TrimPrefix(diffIDs[index], "sha256:")) {
			return errors.New("Docker archive has an invalid layer diff ID")
		}
		indices[name] = index + 1
	}
	archive, err := os.Open(path)
	if err != nil {
		return err
	}
	defer archive.Close()
	reader := tar.NewReader(archive)
	seen := make([]bool, len(names))
	buffer := make([]byte, 1<<20)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("output is not an uncompressed Docker image tar")
		}
		position, wanted := indices[header.Name]
		if !wanted {
			continue
		}
		index := position - 1
		if seen[index] || !header.FileInfo().Mode().IsRegular() {
			return errors.New("Docker archive classic layer is invalid or duplicated")
		}
		seen[index] = true
		hash := sha256.New()
		layerInput := io.TeeReader(reader, hash)
		layerReader := tar.NewReader(layerInput)
		for {
			layerHeader, layerErr := layerReader.Next()
			if errors.Is(layerErr, io.EOF) {
				break
			}
			if layerErr != nil {
				return errors.New("Docker image layer is not a valid tar archive")
			}
			if forbidden := forbiddenReleasePayloadPath(layerHeader.Name); forbidden != "" {
				return fmt.Errorf("Docker image contains forbidden release payload %s", forbidden)
			}
		}
		if _, err := io.CopyBuffer(io.Discard, layerInput, buffer); err != nil {
			return err
		}
		if "sha256:"+hex.EncodeToString(hash.Sum(nil)) != diffIDs[index] {
			return errors.New("Docker archive classic layer diff ID mismatch")
		}
	}
	for _, present := range seen {
		if !present {
			return errors.New("Docker archive classic layer is missing")
		}
	}
	return nil
}

func forbiddenReleasePayloadPath(name string) string {
	clean := strings.TrimPrefix(pathpkg.Clean("/"+strings.TrimPrefix(name, "./")), "/")
	lower := strings.ToLower(clean)
	if lower == "." || lower == "" {
		return ""
	}
	for _, root := range []string{".git", ".lab", ".agents", "tests"} {
		if lower == root || strings.HasPrefix(lower, root+"/") {
			return clean
		}
	}
	if !strings.HasPrefix(lower, "opt/sb-gateway/") {
		return ""
	}
	base := pathpkg.Base(lower)
	if base == "xray.smoke.json" || strings.HasSuffix(base, "_test.go") ||
		strings.Contains(base, ".test.") || strings.Contains(base, ".spec.") ||
		strings.HasSuffix(base, ".map") || strings.HasPrefix(base, ".env") ||
		strings.HasSuffix(base, ".pem") || strings.HasSuffix(base, ".key") ||
		strings.HasSuffix(base, ".p12") || strings.HasSuffix(base, ".pfx") {
		return clean
	}
	return ""
}

func SHA256File(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	buffer := make([]byte, 1<<20)
	if _, err := io.CopyBuffer(hash, file, buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type extractedLayer struct {
	path string
	size int64
}

func extractLayers(archivePath, temporaryRoot string, names, diffIDs []string) ([]extractedLayer, error) {
	indices := make(map[string]int, len(names))
	for index, name := range names {
		modern := modernBlobPattern.FindStringSubmatch(name)
		flat := flatLayerPattern.FindStringSubmatch(name)
		if (modern == nil && flat == nil) || indices[name] != 0 {
			return nil, errors.New("Docker archive layer name is invalid or duplicated")
		}
		if flat != nil && flat[1] != strings.TrimPrefix(diffIDs[index], "sha256:") {
			return nil, errors.New("Docker archive flat layer name does not match its diff ID")
		}
		indices[name] = index + 1
		if !strings.HasPrefix(diffIDs[index], "sha256:") || !digestPattern.MatchString(strings.TrimPrefix(diffIDs[index], "sha256:")) {
			return nil, errors.New("Docker archive has an invalid layer diff ID")
		}
	}
	archive, err := os.Open(archivePath)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	reader := tar.NewReader(archive)
	result := make([]extractedLayer, len(names))
	seen := make([]bool, len(names))
	buffer := make([]byte, 1<<20)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("output is not an uncompressed Docker image tar")
		}
		position, wanted := indices[header.Name]
		if !wanted {
			continue
		}
		index := position - 1
		if seen[index] || !header.FileInfo().Mode().IsRegular() {
			return nil, errors.New("Docker archive layer is missing, duplicated or not a file")
		}
		seen[index] = true
		destination, err := os.CreateTemp(temporaryRoot, fmt.Sprintf("layer-%03d-*", index))
		if err != nil {
			return nil, err
		}
		rawHash := sha256.New()
		buffered := bufio.NewReader(io.TeeReader(reader, rawHash))
		prefix, peekErr := buffered.Peek(2)
		var source io.Reader = buffered
		var compressed *gzip.Reader
		if peekErr == nil && len(prefix) == 2 && prefix[0] == 0x1f && prefix[1] == 0x8b {
			compressed, err = gzip.NewReader(buffered)
			if err != nil {
				destination.Close()
				return nil, err
			}
			source = compressed
		}
		diffHash := sha256.New()
		size, copyErr := io.CopyBuffer(io.MultiWriter(destination, diffHash), source, buffer)
		if compressed != nil {
			_ = compressed.Close()
		}
		_, drainErr := io.CopyBuffer(io.Discard, buffered, buffer)
		syncErr := destination.Sync()
		closeErr := destination.Close()
		if copyErr != nil || drainErr != nil || syncErr != nil || closeErr != nil {
			return nil, errors.Join(copyErr, drainErr, syncErr, closeErr)
		}
		modern := modernBlobPattern.FindStringSubmatch(header.Name)
		if modern != nil && hex.EncodeToString(rawHash.Sum(nil)) != modern[1] {
			return nil, errors.New("Docker archive blob digest mismatch")
		}
		if "sha256:"+hex.EncodeToString(diffHash.Sum(nil)) != diffIDs[index] {
			return nil, errors.New("Docker archive layer diff ID mismatch")
		}
		result[index] = extractedLayer{path: destination.Name(), size: size}
	}
	for index := range seen {
		if !seen[index] {
			return nil, errors.New("Docker archive layer is missing")
		}
	}
	return result, nil
}

func readTarEntry(path, wanted string, limit int64) ([]byte, error) {
	archive, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer archive.Close()
	reader := tar.NewReader(archive)
	var body []byte
	found := false
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("output is not an uncompressed Docker image tar")
		}
		if header.Name != wanted {
			continue
		}
		if found || !header.FileInfo().Mode().IsRegular() || header.Size < 0 || header.Size > limit {
			return nil, fmt.Errorf("Docker archive entry %s is invalid", wanted)
		}
		body = make([]byte, header.Size)
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, err
		}
		found = true
	}
	if !found {
		return nil, fmt.Errorf("Docker archive is missing %s", wanted)
	}
	return body, nil
}

func writeTarBytes(writer *tar.Writer, name string, body []byte) error {
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), Format: tar.FormatPAX}); err != nil {
		return err
	}
	_, err := writer.Write(body)
	return err
}

func writeTarFile(writer *tar.Writer, name string, layer extractedLayer) error {
	if err := writer.WriteHeader(&tar.Header{Name: name, Mode: 0o644, Size: layer.size, Format: tar.FormatPAX}); err != nil {
		return err
	}
	file, err := os.Open(layer.path)
	if err != nil {
		return err
	}
	defer file.Close()
	buffer := make([]byte, 1<<20)
	written, err := io.CopyBuffer(writer, file, buffer)
	if err != nil {
		return err
	}
	if written != layer.size {
		return errors.New("temporary layer size changed")
	}
	return nil
}

func digest(body []byte) string {
	value := sha256.Sum256(body)
	return hex.EncodeToString(value[:])
}

func valueOr(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
