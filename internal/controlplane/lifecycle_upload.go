package controlplane

import (
	"archive/tar"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/releasecontract"
)

const (
	defaultMaxImageUploadBytes = int64(2 << 30)
	maxImageMetadataBytes      = int64(4 << 20)
	maxImageJSONFiles          = 16
)

var (
	lifecycleUploadNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,126}\.tar$`)
	lifecycleStoredNamePattern = regexp.MustCompile(`^sb-gateway-upload-[a-f0-9]{16}\.tar$`)
	lifecycleVersionPattern    = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$`)
	lifecycleStoragePattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._/-]{2,190}$`)
)

type dockerSaveManifest struct {
	Config   string   `json:"Config"`
	RepoTags []string `json:"RepoTags"`
}

type dockerImageConfig struct {
	Architecture string `json:"architecture"`
	OS           string `json:"os"`
	Config       struct {
		Labels map[string]string `json:"Labels"`
	} `json:"config"`
}

func (server *Server) preflightLifecycleImageUpload(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireCSRF(response, request); !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	name := strings.TrimSpace(text(body["filename"]))
	size, sizeOK := numberToInt64(body["size_bytes"])
	if !lifecycleUploadNamePattern.MatchString(name) || filepath.Base(name) != name {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_image_filename", "Choose a .tar file with a simple filename.")
		return
	}
	if !sizeOK || size < 1024 || size > maxLifecycleImageUploadBytes() {
		server.writeErrorResponse(response, request, http.StatusRequestEntityTooLarge, "invalid_image_size", "The selected container archive size is outside the supported range.")
		return
	}
	server.lifecycleMu.Lock()
	defer server.lifecycleMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	operation, err := server.repository.auxiliary("lifecycle-operation")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	operation = server.reconcileLifecycleOperation(request.Context(), config, operation)
	if lifecycleOperationActive(operation) {
		server.writeErrorResponse(response, request, http.StatusConflict, "image_update_already_running", "Wait for the current image update to finish.")
		return
	}
	storageRoot, err := validateLifecycleStorageRoot(text(objectAt(config, "storage")["root"]))
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "storage_root_required", "Set Settings → Container and storage → Project directory on external SSD before selecting an image.")
		return
	}
	if writable, _ := server.checkPersistentMounts(); !writable {
		server.writeErrorResponse(response, request, http.StatusServiceUnavailable, "persistent_storage_read_only", "Persistent storage is not writable; image upload was not started.")
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"ok": true, "filename": name, "size_bytes": size, "storage_root": storageRoot,
	})
}

func (server *Server) uploadLifecycleImage(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	name := request.Header.Get("X-SB-Filename")
	if !lifecycleUploadNamePattern.MatchString(name) || filepath.Base(name) != name {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_image_filename", "Choose a .tar file with a simple filename.")
		return
	}
	server.lifecycleMu.Lock()
	defer server.lifecycleMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	operation, err := server.repository.auxiliary("lifecycle-operation")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	operation = server.reconcileLifecycleOperation(request.Context(), config, operation)
	if state := text(operation["state"]); state == "preparing" || state == "scheduled" || state == "probation" {
		server.writeErrorResponse(response, request, http.StatusConflict, "image_update_already_running", "Wait for the current image update to finish.")
		return
	}
	storageRoot, err := validateLifecycleStorageRoot(text(objectAt(config, "storage")["root"]))
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusConflict, "storage_root_required", err.Error())
		return
	}
	uploadRoot := filepath.Join(server.opts.DataDir, "lifecycle-uploads")
	if err := os.MkdirAll(uploadRoot, 0o700); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	temporary, err := os.CreateTemp(uploadRoot, ".upload-*.tmp")
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		server.internalStateError(response, request, err)
		return
	}
	maximum := maxLifecycleImageUploadBytes()
	limited := http.MaxBytesReader(response, request.Body, maximum)
	version, size, digest, inspectErr := inspectDockerImageStream(limited, temporary)
	if inspectErr != nil {
		temporary.Close()
		var maxBytesError *http.MaxBytesError
		if errors.As(inspectErr, &maxBytesError) {
			server.writeErrorResponse(response, request, http.StatusRequestEntityTooLarge, "image_upload_too_large", "Container image exceeds the configured upload limit.")
		} else {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_image_archive", "The upload is not a valid Docker linux/arm64 SB Gateway image archive.")
		}
		return
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		server.internalStateError(response, request, err)
		return
	}
	if err := temporary.Close(); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	finalName := "sb-gateway-upload-" + digest[:16] + ".tar"
	finalPath := filepath.Join(uploadRoot, finalName)
	if err := replaceRegularFile(temporaryPath, finalPath); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	removed, err := pruneLifecycleUploads(uploadRoot, finalName)
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	routerOSPath := storageRoot + "/data/lifecycle-uploads/" + finalName
	verification := map[string]any{"images": map[string]any{routerOSPath: map[string]any{
		"sha256": digest, "size_bytes": size, "version": version, "verified_at": server.now().UTC().Format(time.RFC3339Nano),
	}}}
	if err := server.repository.saveAuxiliary("lifecycle-image-verifications", verification); err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "container.image_uploaded", "ok", map[string]any{
		"size_bytes": size, "sha256": digest, "superseded_uploads_removed": removed,
	})
	log.Printf("lifecycle image upload verified version=%s size_bytes=%d sha256=%s", version, size, digest)
	server.writeJSON(response, http.StatusOK, map[string]any{
		"ok": true, "filename": finalName, "size_bytes": size, "sha256": digest,
		"architecture": "arm64", "version": version, "checksum_verified": true,
		"routeros_path": routerOSPath, "superseded_uploads_removed": removed,
	})
}

func inspectDockerImageStream(source io.Reader, destination io.Writer) (string, int64, string, error) {
	digest := sha256.New()
	counter := &countingWriter{destination: io.MultiWriter(destination, digest)}
	stream := io.TeeReader(source, counter)
	archive := tar.NewReader(stream)
	jsonFiles := make(map[string][]byte)
	var metadataBytes int64
	copyBuffer := make([]byte, 64<<10)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", counter.written, "", err
		}
		if header.Size < 0 {
			return "", counter.written, "", errors.New("container image contains a negative entry size")
		}
		cleanName := filepath.ToSlash(filepath.Clean(header.Name))
		isTopJSON := !strings.Contains(strings.TrimPrefix(cleanName, "./"), "/") && strings.HasSuffix(strings.ToLower(cleanName), ".json")
		if header.FileInfo().Mode().IsRegular() && isTopJSON && header.Size <= 2<<20 && len(jsonFiles) < maxImageJSONFiles && metadataBytes+header.Size <= maxImageMetadataBytes {
			body := make([]byte, header.Size)
			if _, err := io.ReadFull(archive, body); err != nil {
				return "", counter.written, "", err
			}
			key := strings.TrimPrefix(cleanName, "./")
			if _, duplicate := jsonFiles[key]; duplicate {
				return "", counter.written, "", errors.New("container image contains duplicate JSON metadata")
			}
			jsonFiles[key] = body
			metadataBytes += header.Size
		} else if _, err := io.CopyBuffer(io.Discard, archive, copyBuffer); err != nil {
			return "", counter.written, "", err
		}
	}
	if _, err := io.CopyBuffer(io.Discard, stream, copyBuffer); err != nil {
		return "", counter.written, "", err
	}
	if counter.written < 1024 {
		return "", counter.written, "", errors.New("container image archive is truncated")
	}
	manifestBody, ok := jsonFiles["manifest.json"]
	if !ok {
		return "", counter.written, "", errors.New("container image manifest is missing")
	}
	var manifests []dockerSaveManifest
	if err := json.Unmarshal(manifestBody, &manifests); err != nil || len(manifests) != 1 || manifests[0].Config == "" {
		return "", counter.written, "", errors.New("container image manifest is invalid")
	}
	configName := strings.TrimPrefix(filepath.ToSlash(filepath.Clean(manifests[0].Config)), "./")
	if strings.Contains(configName, "/") || !strings.HasSuffix(strings.ToLower(configName), ".json") {
		return "", counter.written, "", errors.New("container image config path is invalid")
	}
	configBody, ok := jsonFiles[configName]
	if !ok {
		return "", counter.written, "", errors.New("container image config is missing")
	}
	var config dockerImageConfig
	if err := json.Unmarshal(configBody, &config); err != nil {
		return "", counter.written, "", errors.New("container image config is invalid")
	}
	version := config.Config.Labels["org.opencontainers.image.version"]
	labels := config.Config.Labels
	_, _, compatible := releasecontract.Compatible(labels, currentSchemaVersion)
	correctPlatform := config.OS == "linux" && (config.Architecture == "arm64" || config.Architecture == "aarch64")
	if !correctPlatform || !compatible || !lifecycleVersionPattern.MatchString(version) {
		return "", counter.written, "", errors.New("container image identity is invalid")
	}
	return version, counter.written, hex.EncodeToString(digest.Sum(nil)), nil
}

type countingWriter struct {
	destination io.Writer
	written     int64
}

func (writer *countingWriter) Write(body []byte) (int, error) {
	count, err := writer.destination.Write(body)
	writer.written += int64(count)
	return count, err
}

func maxLifecycleImageUploadBytes() int64 {
	value, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("SB_GATEWAY_MAX_IMAGE_UPLOAD_BYTES")), 10, 64)
	if err != nil || value < 1<<20 || value > 4<<30 {
		return defaultMaxImageUploadBytes
	}
	return value
}

func validateLifecycleStorageRoot(value string) (string, error) {
	root := strings.Trim(strings.TrimSpace(value), "/")
	lower := strings.ToLower(root)
	if !lifecycleStoragePattern.MatchString(root) || !strings.Contains(root, "/") || strings.HasPrefix(lower, "flash") || lower == "disk1" || lower == "usb1" || lower == "usb2" || lower == "sata1" || lower == "nvme1" {
		return "", errors.New("storage root must be a dedicated directory on external storage")
	}
	for _, part := range strings.Split(root, "/") {
		if part == "" || part == "." || part == ".." {
			return "", errors.New("storage root must be a dedicated directory on external storage")
		}
	}
	return root, nil
}

func replaceRegularFile(source, destination string) error {
	if info, err := os.Lstat(destination); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("verified image destination is not a regular file")
		}
		if runtime.GOOS == "windows" {
			if err := os.Remove(destination); err != nil {
				return err
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}

func pruneLifecycleUploads(root, keep string) (int, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if entry.Name() == keep || !entry.Type().IsRegular() || !lifecycleStoredNamePattern.MatchString(entry.Name()) {
			continue
		}
		path := filepath.Join(root, entry.Name())
		info, err := os.Lstat(path)
		if err != nil {
			return removed, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if err := os.Remove(path); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}
