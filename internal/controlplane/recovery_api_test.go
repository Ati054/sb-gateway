package controlplane

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	recoveryboot "github.com/sb-gateway/sb-gateway/internal/recovery"
)

func TestNativeRecoveryCreateListDownloadStageAndBootApply(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	markerPath := filepath.Join(root, "state", "marker.json")
	if err := os.WriteFile(markerPath, []byte("original\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	created := performRequest(t, server, http.MethodPost, apiPrefix+"/recovery/backups", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if created.Code != http.StatusOK {
		t.Fatalf("create failed: %d %s", created.Code, created.Body.String())
	}
	archive := decodeResponse(t, created)["archive"].(map[string]any)
	name := archive["name"].(string)
	if archive["sha256"] == nil || archive["size_bytes"].(float64) <= 0 {
		t.Fatalf("archive metadata = %#v", archive)
	}
	listed := performRequest(t, server, http.MethodGet, apiPrefix+"/recovery/backups", nil, nil, cookie)
	if listed.Code != http.StatusOK || len(decodeResponse(t, listed)["items"].([]any)) != 1 {
		t.Fatalf("list failed: %d %s", listed.Code, listed.Body.String())
	}
	listedArchive := decodeResponse(t, listed)["items"].([]any)[0].(map[string]any)
	if listedArchive["sha256"] != archive["sha256"] {
		t.Fatalf("indexed digest was lost: %#v", listedArchive)
	}
	downloaded := performRequest(t, server, http.MethodGet, apiPrefix+"/recovery/backups/"+name+"/download", nil, nil, cookie)
	if downloaded.Code != http.StatusOK || !bytes.HasPrefix(downloaded.Body.Bytes(), []byte(recoveryMagic)) {
		t.Fatalf("download failed: %d", downloaded.Code)
	}
	if err := os.WriteFile(markerPath, []byte("changed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wrong := performRequest(t, server, http.MethodPost, apiPrefix+"/recovery/restore", map[string]any{
		"name": name, "source": "auto", "password": "wrong-password-123",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if wrong.Code != http.StatusForbidden {
		t.Fatalf("wrong panel password accepted: %d %s", wrong.Code, wrong.Body.String())
	}
	staged := performRequest(t, server, http.MethodPost, apiPrefix+"/recovery/restore", map[string]any{
		"name": name, "source": "auto", "password": "panel-password-123",
	}, map[string]string{csrfHeader: csrf}, cookie)
	if staged.Code != http.StatusAccepted {
		t.Fatalf("stage failed: %d %s", staged.Code, staged.Body.String())
	}
	if string(mustReadFile(t, markerPath)) != "changed\n" {
		t.Fatal("live state changed before boot")
	}
	result, err := recoveryboot.ApplyPending(recoveryboot.Options{
		ConfigDir: filepath.Join(root, "config"), StateDir: filepath.Join(root, "state"), DataDir: filepath.Join(root, "data"),
	})
	if err != nil || !result.OK || result.Operation != "restored" {
		t.Fatalf("boot apply = %#v, %v", result, err)
	}
	if string(mustReadFile(t, markerPath)) != "original\n" {
		t.Fatal("verified state was not restored")
	}
	if !server.secrets.exists("admin-password-hash") {
		t.Fatal("fresh administrator identity was overwritten")
	}
}

func TestNativeRecoveryRejectsTamperedCiphertext(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	_, _ = bootstrapSession(t, server)
	if err := os.WriteFile(filepath.Join(root, "state", "marker.json"), []byte("protected\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata, err := server.createRecoveryArchive()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "data", "recovery-backups", metadata.Name)
	body := mustReadFile(t, path)
	body[len(body)-1] ^= 0x40
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := server.stageRecoveryArchive(path, metadata.Name, "panel-password-123"); err == nil {
		t.Fatalf("tampered archive error = %v", err)
	}
}

func TestNativeRecoveryUploadStreamsAndValidatesName(t *testing.T) {
	source, sourceRoot := newRecoveryTestServer(t)
	sourceCookie, _ := bootstrapSession(t, source)
	_ = sourceCookie
	if err := os.WriteFile(filepath.Join(sourceRoot, "state", "marker.json"), []byte("upload\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	metadata, err := source.createRecoveryArchive()
	if err != nil {
		t.Fatal(err)
	}
	archive := mustReadFile(t, filepath.Join(sourceRoot, "data", "recovery-backups", metadata.Name))

	target, _ := newRecoveryTestServer(t)
	cookie, csrf := bootstrapSession(t, target)
	request := httptest.NewRequest(http.MethodPut, apiPrefix+"/recovery/backups/upload", bytes.NewReader(archive))
	request.Header.Set(csrfHeader, csrf)
	request.Header.Set("X-SB-Recovery-Filename", metadata.Name)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	target.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("upload failed: %d %s", response.Code, response.Body.String())
	}
	bad := httptest.NewRequest(http.MethodPut, apiPrefix+"/recovery/backups/upload", bytes.NewReader(archive))
	bad.Header.Set(csrfHeader, csrf)
	bad.Header.Set("X-SB-Recovery-Filename", "foreign.sbgw")
	bad.AddCookie(cookie)
	badResponse := httptest.NewRecorder()
	target.ServeHTTP(badResponse, bad)
	if badResponse.Code != http.StatusUnprocessableEntity {
		t.Fatalf("unsafe upload name accepted: %d", badResponse.Code)
	}
}

func TestRecoveryArchiveSkipsOnlyRecognizedAtomicTemporaryFiles(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"active.json":             `{"revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`,
		".active.json.abcdef.tmp": "transient atomic state",
		".first-write.abcdef.tmp": "transient atomic state without final sibling",
		".unrelated.tmp":          "must remain in the archive",
		"normal.json":             "persistent state",
	} {
		if err := os.WriteFile(filepath.Join(stateRoot, path), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	files, err := collectRecoveryFiles(filepath.Join(root, "config"), stateRoot, filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]bool, len(files))
	for _, file := range files {
		paths[file.archivePath] = true
	}
	if paths["state/.active.json.abcdef.tmp"] || paths["state/.first-write.abcdef.tmp"] {
		t.Fatalf("recognized atomic temporary artifact was collected: %#v", paths)
	}
	if !paths["state/.unrelated.tmp"] || !paths["state/normal.json"] {
		t.Fatalf("collector skipped more than atomic artifacts: %#v", paths)
	}
	directory := filepath.Join(stateRoot, ".directory.abcdef.tmp")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(directory)
	if err != nil {
		t.Fatal(err)
	}
	if recoveryAtomicTemporaryArtifact(filepath.Base(directory), info) {
		t.Fatal("directory matching an atomic filename was treated as a temporary file")
	}
}

func TestRecoveryArchiveSkipsReconstructedRuntimeState(t *testing.T) {
	root := t.TempDir()
	stateRoot := filepath.Join(root, "state")
	if err := os.MkdirAll(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	volatile := []string{
		"audit.jsonl",
		"cdn-feeds.json",
		"client-telemetry.json",
		"rulesets-update.json",
		"runtime-status.json",
		"selector-health.json",
		"subscription-refresh-status.json",
		"subscription-runtime-operation.json",
		"subscription-runtime-status.json",
	}
	for _, name := range volatile {
		if err := os.WriteFile(filepath.Join(stateRoot, name), []byte("runtime\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stateRoot, "active.json"), []byte(`{"revision":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := collectRecoveryFiles(filepath.Join(root, "config"), stateRoot, filepath.Join(root, "data"))
	if err != nil {
		t.Fatal(err)
	}
	paths := make(map[string]bool, len(files))
	for _, file := range files {
		paths[file.archivePath] = true
	}
	if !paths["state/active.json"] {
		t.Fatalf("authoritative active state was skipped: %#v", paths)
	}
	for _, name := range volatile {
		if paths["state/"+name] {
			t.Fatalf("reconstructed runtime state %q was archived: %#v", name, paths)
		}
	}
}

func TestRecoverySnapshotClassifiesSourceRenameDeleteAndChangeAsChurn(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		mutate func(t *testing.T, path string)
	}{
		{
			name: "rename",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Rename(path, path+".moved"); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "delete",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "change",
			mutate: func(t *testing.T, path string) {
				t.Helper()
				if err := os.WriteFile(path, []byte("changed content"), 0o600); err != nil {
					t.Fatal(err)
				}
				changed := time.Now().Add(2 * time.Second)
				if err := os.Chtimes(path, changed, changed); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			root := t.TempDir()
			stateRoot := filepath.Join(root, "state")
			if err := os.MkdirAll(stateRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			marker := filepath.Join(stateRoot, "marker.json")
			if err := os.WriteFile(marker, []byte("original content"), 0o600); err != nil {
				t.Fatal(err)
			}
			files, err := collectRecoveryFiles(filepath.Join(root, "config"), stateRoot, filepath.Join(root, "data"))
			if err != nil || len(files) != 1 {
				t.Fatalf("collect files = %#v, %v", files, err)
			}
			scenario.mutate(t, marker)
			_, err = snapshotRecoverySource(filepath.Join(root, "snapshot"), files[0], make([]byte, recoveryChunkBytes))
			if recoveryArchiveFailureClass(err) != recoveryFailureSourceChurn {
				t.Fatalf("failure class = %q, err=%v", recoveryArchiveFailureClass(err), err)
			}
		})
	}
}

func TestRecoveryArchiveRetriesSourceChurnWithConsistentSnapshot(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	_, _ = bootstrapSession(t, server)
	marker := filepath.Join(root, "state", "marker.json")
	if err := os.WriteFile(marker, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	callbackCalls := 0
	server.recoveryBeforeSnapshot = func(attempt int) {
		callbackCalls++
		if attempt == 0 {
			if err := os.WriteFile(marker, []byte("after retry\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	metadata, err := server.createRecoveryArchive()
	if err != nil {
		t.Fatal(err)
	}
	if callbackCalls != recoverySnapshotAttempts {
		t.Fatalf("snapshot attempts = %d, want %d", callbackCalls, recoverySnapshotAttempts)
	}
	archive := filepath.Join(root, "data", "recovery-backups", metadata.Name)
	operationID, _, err := server.stageRecoveryArchive(archive, metadata.Name, "panel-password-123")
	if err != nil {
		t.Fatal(err)
	}
	staged := filepath.Join(root, "data", "recovery-staging", operationID, "state", "marker.json")
	if got := string(mustReadFile(t, staged)); got != "after retry\n" {
		t.Fatalf("staged snapshot = %q", got)
	}
	entries, err := os.ReadDir(server.recoveryArchiveSnapshotRoot())
	if err != nil || len(entries) != 0 {
		t.Fatalf("plaintext snapshot directories remain: %v %#v", err, entries)
	}
}

func TestRecoveryArchiveStopsAfterBoundedSourceChurn(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	marker := filepath.Join(root, "state", "marker.json")
	if err := os.WriteFile(marker, []byte("before\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	callbackCalls := 0
	server.recoveryBeforeSnapshot = func(attempt int) {
		callbackCalls++
		if err := os.WriteFile(marker, []byte("changed-"+string(rune('a'+attempt))+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := server.createRecoveryArchive()
	if recoveryArchiveFailureClass(err) != recoveryFailureSourceChurn {
		t.Fatalf("failure class = %q, err=%v", recoveryArchiveFailureClass(err), err)
	}
	if callbackCalls != recoverySnapshotAttempts {
		t.Fatalf("snapshot attempts = %d, want %d", callbackCalls, recoverySnapshotAttempts)
	}
	_, backupRoot, _ := server.recoveryRoots()
	entries, readErr := os.ReadDir(backupRoot)
	if readErr != nil && !errors.Is(readErr, os.ErrNotExist) {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("archive was retained after exhausted source churn: %#v", entries)
	}
}

func TestRecoveryArchiveCleansOnlyOwnedStaleSnapshotDirectories(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	_, _ = bootstrapSession(t, server)
	if err := os.WriteFile(filepath.Join(root, "state", "marker.json"), []byte("snapshot cleanup\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	snapshotRoot := server.recoveryArchiveSnapshotRoot()
	stale := filepath.Join(snapshotRoot, ".archive-abcdef")
	retained := filepath.Join(snapshotRoot, ".restore-unrelated")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "plain.txt"), []byte("stale snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(retained, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := server.createRecoveryArchive(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned stale snapshot remained: %v", err)
	}
	if info, err := os.Stat(retained); err != nil || !info.IsDir() {
		t.Fatalf("unrelated staging entry was removed: %#v, %v", info, err)
	}
	if runtime.GOOS != "windows" {
		if info, err := os.Stat(snapshotRoot); err != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("snapshot root permissions = %#v, %v", info, err)
		}
	}
}

func TestNewServerCleansOwnedStaleRecoveryArchiveSnapshots(t *testing.T) {
	server, _ := newRecoveryTestServer(t)
	snapshotRoot := server.recoveryArchiveSnapshotRoot()
	stale := filepath.Join(snapshotRoot, ".archive-abcdef")
	retained := filepath.Join(snapshotRoot, ".restore-unrelated")
	if err := os.MkdirAll(stale, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "plain.txt"), []byte("stale snapshot"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(retained, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := NewServer(server.opts); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned stale snapshot remained after startup: %v", err)
	}
	if info, err := os.Stat(retained); err != nil || !info.IsDir() {
		t.Fatalf("startup removed unrelated staging entry: %#v, %v", info, err)
	}
}

func TestRecoveryArchiveDoesNotRetryPersistentCollectionFailure(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	oversize := make([]byte, recoveryMaxFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "state", "too-large.json"), oversize, 0o600); err != nil {
		t.Fatal(err)
	}
	callbackCalls := 0
	server.recoveryBeforeSnapshot = func(int) { callbackCalls++ }
	_, err := server.createRecoveryArchive()
	if recoveryArchiveFailureClass(err) != recoveryFailureSourceCollection {
		t.Fatalf("failure class = %q, err=%v", recoveryArchiveFailureClass(err), err)
	}
	if callbackCalls != 0 {
		t.Fatalf("persistent collection failure retried snapshot %d times", callbackCalls)
	}
}

func TestRecoveryArchiveFailurePresentationRedactsInternalCause(t *testing.T) {
	err := recoveryArchiveFailure(recoveryFailureSourceChurn, errors.New("/config/secrets/private-key.pem"))
	classifier, action, message := recoveryArchiveFailurePresentation(err)
	if classifier != "source_churn" || action != "retry_when_idle" {
		t.Fatalf("safe failure presentation = %q %q", classifier, action)
	}
	for _, value := range []string{err.Error(), classifier, action, message} {
		if strings.Contains(value, "private-key") || strings.Contains(value, "/config/") {
			t.Fatalf("internal cause leaked through safe recovery presentation: %q", value)
		}
	}
}

func TestNativeRecoveryCreateFailureReturnsSafeClassifier(t *testing.T) {
	server, root := newRecoveryTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	oversize := make([]byte, recoveryMaxFileBytes+1)
	if err := os.WriteFile(filepath.Join(root, "state", "too-large.json"), oversize, 0o600); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/recovery/backups", map[string]any{}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("manual recovery failure status = %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	failure := objectAt(body, "error")
	if failure["code"] != "recovery_create_failed" || strings.Contains(response.Body.String(), "too-large") {
		t.Fatalf("manual recovery failure exposed the source: %#v", body)
	}
	details, _ := failure["details"].([]any)
	if len(details) != 1 || objectAt(map[string]any{"detail": details[0]}, "detail")["classifier"] != "source_collection" {
		t.Fatalf("manual recovery diagnostic = %#v", failure)
	}
}

func newRecoveryTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	root := t.TempDir()
	t.Cleanup(func() {
		for attempt := 0; attempt < 6; attempt++ {
			if err := os.RemoveAll(root); err == nil || runtime.GOOS != "windows" {
				return
			}
			time.Sleep(time.Duration(attempt+1) * 15 * time.Millisecond)
		}
	})
	server, err := NewServer(Options{
		Host: "127.0.0.1", Port: 8080, StateDir: filepath.Join(root, "state"),
		SecretsDir: filepath.Join(root, "config", "secrets"), DataDir: filepath.Join(root, "data"),
		AdminUser: "admin", SecureCookie: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := server.secrets.write("management-api-token", "management-test-token", false); err != nil {
		t.Fatal(err)
	}
	return server, root
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}
