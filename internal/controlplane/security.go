package controlplane

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/scrypt"
)

const (
	sessionCookie = "sb_gateway_session"
	csrfHeader    = "X-CSRF-Token"
)

type secretStore struct {
	root string
}

func newSecretStore(root string) (*secretStore, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, fmt.Errorf("resolve secrets root: %w", err)
	}
	abs = filepath.Clean(abs)
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, fmt.Errorf("create secrets root: %w", err)
	}
	info, err := os.Lstat(abs)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("secrets root must be a real directory")
	}
	return &secretStore{root: abs}, nil
}

func (store *secretStore) path(reference string) (string, error) {
	if reference == "" || strings.ContainsRune(reference, '\x00') || filepath.IsAbs(reference) {
		return "", errors.New("invalid secret reference")
	}
	candidate := filepath.Clean(filepath.Join(store.root, reference))
	relative, err := filepath.Rel(store.root, candidate)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("secret reference escapes configured directory")
	}
	current := store.root
	parts := strings.Split(relative, string(filepath.Separator))
	for index, part := range parts {
		current = filepath.Join(current, part)
		info, statErr := os.Lstat(current)
		if errors.Is(statErr, os.ErrNotExist) {
			break
		}
		if statErr != nil {
			return "", statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("secret reference cannot traverse a symbolic link")
		}
		if index < len(parts)-1 && !info.IsDir() {
			return "", errors.New("secret reference parent must be a directory")
		}
	}
	return candidate, nil
}

func (store *secretStore) read(reference string, required bool) (string, error) {
	path, err := store.path(reference)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", errors.New("secret reference must point to a regular file")
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("secret file permissions must be 0600 or stricter")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimRight(string(body), "\r\n")
	if required && value == "" {
		return "", errors.New("required secret is empty")
	}
	return value, nil
}

func (store *secretStore) exists(reference string) bool {
	_, err := store.read(reference, true)
	return err == nil
}

func (store *secretStore) write(reference, value string, overwrite bool) error {
	if value == "" || strings.ContainsRune(value, '\x00') || len([]byte(value)) > 1<<20 {
		return errors.New("secret value is invalid")
	}
	path, err := store.path(reference)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if !overwrite {
		if _, err := os.Lstat(path); err == nil {
			return errors.New("secret reference already exists")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return writeAtomic(path, []byte(value+"\n"), 0o600, false)
}

func (store *secretStore) remove(reference string) error {
	path, err := store.path(reference)
	if err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("secret reference must point to a regular file")
	}
	return os.Remove(path)
}

type sessionCodec struct {
	key    []byte
	ttl    time.Duration
	issuer string
}

func newSessionCodec(key []byte) (*sessionCodec, error) {
	if len(key) < 32 {
		return nil, errors.New("session signing key must contain at least 32 bytes")
	}
	return &sessionCodec{key: append([]byte(nil), key...), ttl: 8 * time.Hour, issuer: "sb-gateway"}, nil
}

func signingKey(store *secretStore) ([]byte, error) {
	value, err := store.read("session-signing-key", false)
	if err != nil {
		return nil, err
	}
	if value == "" {
		key := make([]byte, 32)
		_, err = rand.Read(key)
		return key, err
	}
	if decoded, decodeErr := base64.RawURLEncoding.DecodeString(value); decodeErr == nil && len(decoded) >= 32 {
		return decoded, nil
	}
	if len([]byte(value)) < 32 {
		return nil, errors.New("session signing key must contain at least 32 bytes")
	}
	return []byte(value), nil
}

func (codec *sessionCodec) issue(username string, now time.Time) (string, string, error) {
	csrfBytes := make([]byte, 32)
	nonceBytes := make([]byte, 8)
	if _, err := rand.Read(csrfBytes); err != nil {
		return "", "", err
	}
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", "", err
	}
	csrf := base64.RawURLEncoding.EncodeToString(csrfBytes)
	csrfDigest := sha256.Sum256([]byte(csrf))
	payload := map[string]any{
		"iss":        codec.issuer,
		"sub":        username,
		"iat":        now.Unix(),
		"exp":        now.Add(codec.ttl).Unix(),
		"csrf":       hex.EncodeToString(csrfDigest[:]),
		"csrf_token": csrf,
		"nonce":      hex.EncodeToString(nonceBytes),
	}
	body, err := canonicalJSON(payload)
	if err != nil {
		return "", "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(body)
	signature := hmac.New(sha256.New, codec.key)
	_, _ = signature.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(signature.Sum(nil)), csrf, nil
}

func (codec *sessionCodec) decode(token string, now time.Time) (map[string]any, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	supplied, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, codec.key)
	_, _ = mac.Write([]byte(parts[0]))
	if !hmac.Equal(supplied, mac.Sum(nil)) {
		return nil, false
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()
	payload := map[string]any{}
	if err := decoder.Decode(&payload); err != nil {
		return nil, false
	}
	issued, okIssued := jsonInt(payload["iat"])
	expires, okExpires := jsonInt(payload["exp"])
	_, okSubject := payload["sub"].(string)
	if payload["iss"] != codec.issuer || !okSubject || !okIssued || !okExpires || issued > now.Unix()+30 || expires <= now.Unix() {
		return nil, false
	}
	return payload, true
}

func (codec *sessionCodec) verifyCSRF(payload map[string]any, supplied string) bool {
	expected, ok := payload["csrf"].(string)
	if !ok || supplied == "" {
		return false
	}
	digest := sha256.Sum256([]byte(supplied))
	return subtle.ConstantTimeCompare([]byte(expected), []byte(hex.EncodeToString(digest[:]))) == 1
}

func makePasswordHash(password string, salt []byte) (string, error) {
	if len(password) < 12 {
		return "", errors.New("management password must contain at least 12 characters")
	}
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return "", err
		}
	}
	derived, err := scrypt.Key([]byte(password), salt, 1<<14, 8, 1, 32)
	if err != nil {
		return "", err
	}
	return strings.Join([]string{
		"scrypt", "16384", "8", "1",
		base64.RawURLEncoding.EncodeToString(salt),
		base64.RawURLEncoding.EncodeToString(derived),
	}, "$"), nil
}

func verifyPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "scrypt" {
		return false
	}
	n, errN := strconv.Atoi(parts[1])
	r, errR := strconv.Atoi(parts[2])
	p, errP := strconv.Atoi(parts[3])
	if errN != nil || errR != nil || errP != nil || n < 1<<13 || n > 1<<18 || r < 1 || r > 16 || p < 1 || p > 8 {
		return false
	}
	salt, errSalt := base64.RawURLEncoding.DecodeString(parts[4])
	expected, errExpected := base64.RawURLEncoding.DecodeString(parts[5])
	if errSalt != nil || errExpected != nil || len(expected) == 0 {
		return false
	}
	actual, err := scrypt.Key([]byte(password), salt, n, r, p, len(expected))
	return err == nil && hmac.Equal(actual, expected)
}

func jsonInt(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		result, err := typed.Int64()
		return result, err == nil
	case float64:
		return int64(typed), typed == float64(int64(typed))
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	default:
		return 0, false
	}
}
