package controlplane

import (
	"bytes"
	"crypto/sha256"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestRecoveryRewrapPreservesEncryptedPayload(t *testing.T) {
	server := newTestServer(t)
	if _, err := server.ensureRecoveryProtection("panel-password-123"); err != nil {
		t.Fatal(err)
	}
	encodedWrapper, _ := server.secrets.read(recoveryKeyWrapRef, true)
	wrapper, err := decodeRecoveryKeyWrap(encodedWrapper)
	if err != nil {
		t.Fatal(err)
	}
	header := map[string]any{
		"format_version":      recoveryFormatVersion,
		"created_at":          "2026-09-03T00:00:00Z",
		"application_version": "1.5.10",
		"architecture":        "aarch64",
		"active_revision":     nil,
		"cipher":              recoveryArchiveCipher,
		"chunk_size":          1 << 20,
	}
	prefix, err := encodeRecoveryArchivePrefix(header, wrapper)
	if err != nil {
		t.Fatal(err)
	}
	archiveRoot := filepath.Join(server.opts.DataDir, "recovery-backups")
	if err := os.MkdirAll(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "SB-GATEWAY-state-20260903T000000Z-000000000000.sbgw"
	path := filepath.Join(archiveRoot, name)
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.Write(prefix); err != nil {
		file.Close()
		t.Fatal(err)
	}
	// A sparse payload makes the test sensitive to accidental whole-file reads
	// without allocating or writing a large image itself.
	if err := file.Truncate(int64(len(prefix)) + 32<<20); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	prefixBefore, err := readRecoveryArchivePrefix(path)
	if err != nil {
		t.Fatal(err)
	}
	payloadBefore := hashRecoveryPayload(t, path, prefixBefore.payloadOffset)
	infoBefore, _ := os.Stat(path)

	rewritten, err := server.rewrapRecoveryProtection("panel-password-123", "new-panel-password-456")
	if err != nil || len(rewritten) != 1 || rewritten[0] != name {
		t.Fatalf("recovery rewrap failed: %#v, %v", rewritten, err)
	}
	prefixAfter, err := readRecoveryArchivePrefix(path)
	if err != nil {
		t.Fatal(err)
	}
	payloadAfter := hashRecoveryPayload(t, path, prefixAfter.payloadOffset)
	infoAfter, _ := os.Stat(path)
	if !bytes.Equal(payloadBefore, payloadAfter) || infoBefore.Size() != infoAfter.Size() || prefixBefore.payloadOffset != prefixAfter.payloadOffset {
		t.Fatal("rewrap touched the encrypted archive payload")
	}
	if prefixAfter.active.generation != 2 {
		t.Fatalf("unexpected wrapper generation: %d", prefixAfter.active.generation)
	}
	if _, err := unwrapRecoveryMasterKey(prefixAfter.active.wrapper, "new-panel-password-456"); err != nil {
		t.Fatalf("new password does not unlock rewritten archive: %v", err)
	}
	if _, err := unwrapRecoveryMasterKey(prefixAfter.active.wrapper, "panel-password-123"); err == nil {
		t.Fatal("old password still unlocks rewritten archive")
	}
}

func hashRecoveryPayload(t *testing.T, path string, offset int64) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	digest := sha256.New()
	if _, err := io.CopyBuffer(digest, file, make([]byte, 64<<10)); err != nil {
		t.Fatal(err)
	}
	return digest.Sum(nil)
}

func TestRecoveryRewrapRejectsCorruptArchiveBeforeRotatingSecrets(t *testing.T) {
	server := newTestServer(t)
	if _, err := server.ensureRecoveryProtection("panel-password-123"); err != nil {
		t.Fatal(err)
	}
	wrapperBefore, _ := server.secrets.read(recoveryKeyWrapRef, true)
	archiveRoot := filepath.Join(server.opts.DataDir, "recovery-backups")
	if err := os.MkdirAll(archiveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	name := "SB-GATEWAY-state-20260903T000000Z-000000000000.sbgw"
	if err := os.WriteFile(filepath.Join(archiveRoot, name), []byte("corrupt"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := server.rewrapRecoveryProtection("panel-password-123", "new-panel-password-456"); err == nil {
		t.Fatal("corrupt retained archive was accepted")
	}
	wrapperAfter, _ := server.secrets.read(recoveryKeyWrapRef, true)
	backupPassword, _ := server.secrets.read(recoveryBackupPwdRef, true)
	if wrapperAfter != wrapperBefore || backupPassword != "panel-password-123" {
		t.Fatal("failed rewrap changed recovery secrets")
	}
}

func TestPasswordChangeRewrapsRecoveryAndInvalidatesSessions(t *testing.T) {
	server := newTestServer(t)
	oldCookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/password", map[string]any{
		"current_password":      "panel-password-123",
		"new_password":          "new-panel-password-456",
		"password_confirmation": "new-panel-password-456",
	}, map[string]string{csrfHeader: csrf}, oldCookie)
	if response.Code != http.StatusOK {
		t.Fatalf("password change failed: %d %s", response.Code, response.Body.String())
	}
	newCookies := response.Result().Cookies()
	if len(newCookies) != 1 || newCookies[0].Value == "" {
		t.Fatalf("new session cookie missing: %#v", newCookies)
	}
	oldSession := performRequest(t, server, http.MethodGet, apiPrefix+"/auth/session", nil, nil, oldCookie)
	if decodeResponse(t, oldSession)["authenticated"].(bool) {
		t.Fatal("old session remained valid after password change")
	}
	newSession := performRequest(t, server, http.MethodGet, apiPrefix+"/auth/session", nil, nil, newCookies[0])
	if !decodeResponse(t, newSession)["authenticated"].(bool) {
		t.Fatal("replacement session was not accepted")
	}
	oldLogin := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
		"username": "admin", "password": "panel-password-123",
	}, nil)
	if oldLogin.Code != http.StatusUnauthorized {
		t.Fatalf("old password remained valid: %d", oldLogin.Code)
	}
	newLogin := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
		"username": "admin", "password": "new-panel-password-456",
	}, nil)
	if newLogin.Code != http.StatusOK {
		t.Fatalf("new password was rejected: %d %s", newLogin.Code, newLogin.Body.String())
	}
	backupPassword, err := server.secrets.read(recoveryBackupPwdRef, true)
	if err != nil || backupPassword != "new-panel-password-456" {
		t.Fatalf("RouterOS backup password did not rotate: %q, %v", backupPassword, err)
	}
}
