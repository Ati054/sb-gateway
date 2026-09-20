package controlplane

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestStableScryptPasswordEncoding(t *testing.T) {
	salt := []byte("0123456789abcdef")
	hash, err := makePasswordHash("panel-password-123", salt)
	if err != nil {
		t.Fatal(err)
	}
	const expected = "scrypt$16384$8$1$MDEyMzQ1Njc4OWFiY2RlZg$7JVe550sJ77OVFqeJBER32mbpE9p6H9oX_O5y-o-g1M"
	if hash != expected {
		t.Fatalf("password encoding drifted: %s", hash)
	}
	if !verifyPassword("panel-password-123", hash) || verifyPassword("wrong-password", hash) {
		t.Fatal("password verification failed")
	}
}

func TestSessionCodecRoundTrip(t *testing.T) {
	codec, err := newSessionCodec([]byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	token, csrf, err := codec.issue("admin", now)
	if err != nil {
		t.Fatal(err)
	}
	payload, ok := codec.decode(token, now.Add(time.Minute))
	if !ok || payload["sub"] != "admin" || !codec.verifyCSRF(payload, csrf) {
		t.Fatalf("invalid session round trip: %#v", payload)
	}
	if _, ok := codec.decode(token, now.Add(9*time.Hour)); ok {
		t.Fatal("expired session remained valid")
	}
}

func TestSecretStoreRejectsTraversalAndReadsSigningKey(t *testing.T) {
	root := t.TempDir()
	store, err := newSecretStore(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.path("../escape"); err == nil {
		t.Fatal("secret traversal accepted")
	}
	encoded := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	if err := store.write("session-signing-key", encoded, false); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "session-signing-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	key, err := signingKey(store)
	if err != nil || string(key) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected signing key: %q, %v", key, err)
	}
}
