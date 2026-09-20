package controlplane

import (
	"bytes"
	"net/http"
	"testing"
)

func TestRecoveryWrapperRoundTrip(t *testing.T) {
	master := []byte("0123456789abcdef0123456789abcdef")
	wrapper, err := wrapRecoveryMasterKey(master, "panel-password-123")
	if err != nil {
		t.Fatal(err)
	}
	if wrapper.Cipher != "AES-256-GCM" || wrapper.KDF != "scrypt-16384-8-1" || wrapper.KeyID != recoveryKeyID(master) {
		t.Fatalf("recovery wrapper contract drifted: %#v", wrapper)
	}
	unwrapped, err := unwrapRecoveryMasterKey(wrapper, "panel-password-123")
	if err != nil || !bytes.Equal(unwrapped, master) {
		t.Fatalf("recovery wrapper did not round trip: %x, %v", unwrapped, err)
	}
	if _, err := unwrapRecoveryMasterKey(wrapper, "wrong-password-123"); err == nil {
		t.Fatal("recovery wrapper accepted the wrong password")
	}
}

func TestEnsureRecoveryProtectionDoesNotRewriteHealthyKey(t *testing.T) {
	server := newTestServer(t)
	initialized, err := server.ensureRecoveryProtection("panel-password-123")
	if err != nil || !initialized {
		t.Fatalf("recovery protection was not initialized: %v", err)
	}
	masterBefore, err := server.secrets.read(recoveryMasterKeyRef, true)
	if err != nil {
		t.Fatal(err)
	}
	wrapperBefore, err := server.secrets.read(recoveryKeyWrapRef, true)
	if err != nil {
		t.Fatal(err)
	}
	initialized, err = server.ensureRecoveryProtection("panel-password-123")
	if err != nil || initialized {
		t.Fatalf("healthy recovery protection was rewritten: %v", err)
	}
	masterAfter, _ := server.secrets.read(recoveryMasterKeyRef, true)
	wrapperAfter, _ := server.secrets.read(recoveryKeyWrapRef, true)
	if masterBefore != masterAfter || wrapperBefore != wrapperAfter {
		t.Fatal("repeat login rewrote recovery key material")
	}
	backupPassword, err := server.secrets.read(recoveryBackupPwdRef, true)
	if err != nil || backupPassword != "panel-password-123" {
		t.Fatalf("RouterOS backup password not synchronized: %q, %v", backupPassword, err)
	}
}

func TestEnsureRecoveryProtectionRejectsIncompleteStoredKey(t *testing.T) {
	server := newTestServer(t)
	if err := server.secrets.write(recoveryMasterKeyRef, "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY", false); err != nil {
		t.Fatal(err)
	}
	if _, err := server.ensureRecoveryProtection("panel-password-123"); err == nil {
		t.Fatal("incomplete recovery key was accepted")
	}

	hash, err := makePasswordHash("panel-password-123", []byte("0123456789abcdef"))
	if err != nil || server.secrets.write("admin-password-hash", hash, false) != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/auth/login", map[string]any{
		"username": "admin", "password": "panel-password-123",
	}, nil)
	if response.Code != http.StatusInternalServerError || decodeResponse(t, response)["error"].(map[string]any)["code"] != "recovery_protection_failed" {
		t.Fatalf("incomplete key did not fail closed: %d %s", response.Code, response.Body.String())
	}
}
