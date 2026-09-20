package controlplane

import (
	"archive/tar"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const recoveryMaxManifestBytes = 1 << 20

var errRecoveryPending = errors.New("a recovery operation is already pending")

type recoveryManifestDocument struct {
	FormatVersion int                    `json:"format_version"`
	Files         []recoveryManifestFile `json:"files"`
}

type recoveryManifestFile struct {
	Path   string `json:"path"`
	Size   int64  `json:"size_bytes"`
	SHA256 string `json:"sha256"`
}

type recoveryChunkDecryptor struct {
	source       io.Reader
	aead         cipher.AEAD
	noncePrefix  [4]byte
	headerDigest [32]byte
	index        uint64
	total        int64
	plain        []byte
	ciphertext   []byte
	offset       int
}

func newRecoveryChunkDecryptor(source io.Reader, master, noncePrefix []byte, header map[string]any) (*recoveryChunkDecryptor, error) {
	if len(noncePrefix) != 4 {
		return nil, errors.New("recovery nonce prefix is invalid")
	}
	block, err := aes.NewCipher(master)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	headerBody, err := canonicalJSON(header)
	if err != nil {
		return nil, err
	}
	reader := &recoveryChunkDecryptor{
		source: source, aead: aead, headerDigest: sha256.Sum256(headerBody),
		ciphertext: make([]byte, recoveryChunkBytes+aead.Overhead()),
	}
	copy(reader.noncePrefix[:], noncePrefix)
	return reader, nil
}

func (reader *recoveryChunkDecryptor) Read(destination []byte) (int, error) {
	if len(destination) == 0 {
		return 0, nil
	}
	if reader.offset == len(reader.plain) {
		if err := reader.next(); err != nil {
			return 0, err
		}
	}
	count := copy(destination, reader.plain[reader.offset:])
	reader.offset += count
	return count, nil
}

func (reader *recoveryChunkDecryptor) next() error {
	var sizeBody [4]byte
	if _, err := io.ReadFull(reader.source, sizeBody[:]); err != nil {
		if errors.Is(err, io.EOF) {
			return io.EOF
		}
		return errors.New("recovery encrypted payload is truncated")
	}
	plainSize := int(binary.BigEndian.Uint32(sizeBody[:]))
	if plainSize < 1 || plainSize > recoveryChunkBytes || reader.total+int64(plainSize) > recoveryMaxPlainBytes {
		return errors.New("recovery encrypted chunk size is invalid")
	}
	ciphertext := reader.ciphertext[:plainSize+reader.aead.Overhead()]
	if _, err := io.ReadFull(reader.source, ciphertext); err != nil {
		return errors.New("recovery encrypted payload is truncated")
	}
	nonce := recoveryChunkNonce(reader.noncePrefix, reader.index)
	aad := recoveryChunkAAD(reader.headerDigest, reader.index, plainSize)
	plain, err := reader.aead.Open(reader.plain[:0], nonce[:], ciphertext, aad[:])
	if err != nil {
		return errors.New("recovery archive authentication failed")
	}
	reader.plain = plain
	reader.offset = 0
	reader.total += int64(plainSize)
	reader.index++
	return nil
}

func (server *Server) stageRecoveryArchive(path, archiveName, password string) (string, int, error) {
	server.recoveryMu.Lock()
	defer server.recoveryMu.Unlock()

	configRoot, _, stagingRoot := server.recoveryRoots()
	pendingPath := filepath.Join(configRoot, ".sb-gateway-recovery-pending.json")
	if _, err := os.Lstat(pendingPath); err == nil {
		return "", 0, errRecoveryPending
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", 0, err
	}
	prefix, err := readRecoveryArchivePrefix(path)
	if err != nil {
		return "", 0, err
	}
	master, err := unwrapRecoveryMasterKey(prefix.active.wrapper, password)
	if err != nil {
		return "", 0, err
	}
	noncePrefix, err := recoveryHeaderNonce(prefix.header)
	if err != nil {
		return "", 0, err
	}
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer file.Close()
	if _, err := file.Seek(prefix.payloadOffset, io.SeekStart); err != nil {
		return "", 0, err
	}
	decryptor, err := newRecoveryChunkDecryptor(file, master, noncePrefix, prefix.header)
	if err != nil {
		return "", 0, err
	}
	archive := tar.NewReader(decryptor)
	manifest, err := readRecoveryManifest(archive)
	if err != nil {
		return "", 0, err
	}
	if err := os.MkdirAll(stagingRoot, 0o700); err != nil {
		return "", 0, err
	}
	temporary, err := os.MkdirTemp(stagingRoot, ".restore-*")
	if err != nil {
		return "", 0, err
	}
	defer os.RemoveAll(temporary)
	if err := extractRecoveryTar(archive, temporary, manifest); err != nil {
		return "", 0, err
	}
	trailing, err := io.Copy(io.Discard, decryptor)
	if err != nil {
		return "", 0, err
	}
	if trailing != 0 {
		return "", 0, errors.New("recovery payload contains trailing data")
	}
	operationBytes := make([]byte, 8)
	if _, err := rand.Read(operationBytes); err != nil {
		return "", 0, err
	}
	operationID := hex.EncodeToString(operationBytes)
	finalStaging := filepath.Join(stagingRoot, operationID)
	if err := os.Rename(temporary, finalStaging); err != nil {
		return "", 0, err
	}
	pending := map[string]any{
		"operation_id": operationID,
		"archive_name": archiveName,
		"staging_path": finalStaging,
		"manifest":     manifest,
	}
	body, err := canonicalJSON(pending)
	if err != nil {
		_ = os.RemoveAll(finalStaging)
		return "", 0, err
	}
	if err := writeAtomic(pendingPath, append(body, '\n'), 0o600, false); err != nil {
		_ = os.RemoveAll(finalStaging)
		return "", 0, err
	}
	return operationID, len(manifest.Files), nil
}

func recoveryHeaderNonce(header map[string]any) ([]byte, error) {
	chunkSize, ok := jsonInt(header["chunk_size"])
	if !ok || chunkSize != recoveryChunkBytes || header["payload_format"] != "tar" {
		return nil, errors.New("recovery payload format is not supported")
	}
	nonce, err := base64.RawURLEncoding.DecodeString(text(header["nonce_prefix"]))
	if err != nil || len(nonce) != 4 {
		return nil, errors.New("recovery nonce prefix is invalid")
	}
	return nonce, nil
}

func readRecoveryManifest(archive *tar.Reader) (recoveryManifestDocument, error) {
	header, err := archive.Next()
	if err != nil || header.Name != "manifest.json" || !header.FileInfo().Mode().IsRegular() || header.Size < 1 || header.Size > recoveryMaxManifestBytes {
		return recoveryManifestDocument{}, errors.New("recovery manifest is missing or invalid")
	}
	decoder := json.NewDecoder(io.LimitReader(archive, recoveryMaxManifestBytes+1))
	var manifest recoveryManifestDocument
	if err := decoder.Decode(&manifest); err != nil {
		return recoveryManifestDocument{}, errors.New("recovery manifest is invalid")
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return recoveryManifestDocument{}, errors.New("recovery manifest is invalid")
	}
	if manifest.FormatVersion != recoveryFormatVersion || len(manifest.Files) < 1 || len(manifest.Files) > recoveryMaxFiles {
		return recoveryManifestDocument{}, errors.New("recovery manifest format is not supported")
	}
	seen := make(map[string]bool, len(manifest.Files))
	var total int64
	for _, entry := range manifest.Files {
		if !validRecoveryManifestEntry(entry) || seen[entry.Path] {
			return recoveryManifestDocument{}, errors.New("recovery manifest contains an invalid file")
		}
		seen[entry.Path] = true
		total += entry.Size
		if total > recoveryMaxPlainBytes {
			return recoveryManifestDocument{}, errors.New("recovery manifest exceeds the safety limit")
		}
	}
	return manifest, nil
}

func validRecoveryManifestEntry(entry recoveryManifestFile) bool {
	if entry.Size < 0 || entry.Size > recoveryMaxFileBytes || !recoveryPayloadPathPattern.MatchString(entry.Path) || hasRecoveryParentTraversal(entry.Path) {
		return false
	}
	digest, err := hex.DecodeString(entry.SHA256)
	return err == nil && len(digest) == sha256.Size && strings.ToLower(entry.SHA256) == entry.SHA256
}

func hasRecoveryParentTraversal(path string) bool {
	for _, part := range strings.Split(path, "/") {
		if part == "" || part == "." || part == ".." {
			return true
		}
	}
	return false
}

func extractRecoveryTar(archive *tar.Reader, root string, manifest recoveryManifestDocument) error {
	expected := make(map[string]recoveryManifestFile, len(manifest.Files))
	for _, entry := range manifest.Files {
		expected[entry.Path] = entry
	}
	seen := make(map[string]bool, len(expected))
	buffer := make([]byte, recoveryChunkBytes)
	for {
		header, err := archive.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return errors.New("recovery payload is invalid")
		}
		entry, ok := expected[header.Name]
		if !ok || seen[header.Name] || !header.FileInfo().Mode().IsRegular() || header.Size != entry.Size {
			return errors.New("recovery payload does not match its manifest")
		}
		destination, err := recoveryStagingPath(root, header.Name)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(destination), 0o700); err != nil {
			return err
		}
		output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		digest := sha256.New()
		written, copyErr := io.CopyBuffer(io.MultiWriter(output, digest), archive, buffer)
		syncErr := output.Sync()
		closeErr := output.Close()
		if copyErr != nil {
			return copyErr
		}
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
		if written != entry.Size || hex.EncodeToString(digest.Sum(nil)) != entry.SHA256 {
			return errors.New("recovery file failed checksum verification")
		}
		seen[header.Name] = true
	}
	if len(seen) != len(expected) {
		return errors.New("recovery payload is missing manifest files")
	}
	return nil
}

func recoveryStagingPath(root, archivePath string) (string, error) {
	if !recoveryPayloadPathPattern.MatchString(archivePath) || hasRecoveryParentTraversal(archivePath) {
		return "", errors.New("recovery path escaped its staging directory")
	}
	candidate := filepath.Clean(filepath.Join(root, filepath.FromSlash(archivePath)))
	relative, err := filepath.Rel(root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("recovery path escaped its staging directory")
	}
	return candidate, nil
}

func recoveryArchivePath(root, name string) (string, error) {
	if !recoveryArchiveName.MatchString(name) || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid recovery archive name")
	}
	return filepath.Join(root, name), nil
}
