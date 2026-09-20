package controlplane

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/scrypt"
)

const (
	recoveryMasterKeyRef = "recovery/master-key"
	recoveryKeyWrapRef   = "recovery/key-wrap"
	recoveryBackupPwdRef = "routeros/backup-password"
	recoveryCipher       = "AES-256-GCM"
	recoveryKDF          = "scrypt-16384-8-1"
)

type recoveryKeyWrap struct {
	Cipher     string `json:"cipher"`
	KDF        string `json:"kdf"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	WrappedKey string `json:"wrapped_key"`
	KeyID      string `json:"key_id"`
}

func (server *Server) ensureRecoveryProtection(password string) (bool, error) {
	server.recoveryMu.Lock()
	defer server.recoveryMu.Unlock()

	if err := validateRecoveryPassword(password); err != nil {
		return false, err
	}
	encodedMaster, err := server.secrets.read(recoveryMasterKeyRef, false)
	if err != nil {
		return false, err
	}
	encodedWrapper, err := server.secrets.read(recoveryKeyWrapRef, false)
	if err != nil {
		return false, err
	}

	initialized := false
	switch {
	case encodedMaster != "" && encodedWrapper != "":
		master, err := decodeRecoveryMasterKey(encodedMaster)
		if err != nil {
			return false, err
		}
		wrapper, err := decodeRecoveryKeyWrap(encodedWrapper)
		if err != nil {
			return false, err
		}
		if recoveryKeyID(master) != wrapper.KeyID {
			return false, errors.New("stored recovery key wrapper is inconsistent")
		}
	case encodedMaster != "" || encodedWrapper != "":
		return false, errors.New("stored recovery key is incomplete")
	default:
		master := make([]byte, 32)
		if _, err := rand.Read(master); err != nil {
			return false, fmt.Errorf("generate recovery master key: %w", err)
		}
		wrapper, err := wrapRecoveryMasterKey(master, password)
		if err != nil {
			return false, err
		}
		wrapperBody, err := encodeRecoveryKeyWrap(wrapper)
		if err != nil {
			return false, fmt.Errorf("encode recovery key wrapper: %w", err)
		}
		if err := server.secrets.write(recoveryMasterKeyRef, base64.RawURLEncoding.EncodeToString(master), false); err != nil {
			return false, fmt.Errorf("store recovery master key: %w", err)
		}
		if err := server.secrets.write(recoveryKeyWrapRef, string(wrapperBody), false); err != nil {
			return false, fmt.Errorf("store recovery key wrapper: %w", err)
		}
		initialized = true
	}

	if err := server.secrets.write(recoveryBackupPwdRef, password, true); err != nil {
		return false, fmt.Errorf("store RouterOS backup password: %w", err)
	}
	return initialized, nil
}

func encodeRecoveryKeyWrap(wrapper recoveryKeyWrap) ([]byte, error) {
	return canonicalJSON(recoveryWrapperObject(wrapper))
}

func validateRecoveryPassword(password string) error {
	if utf8.RuneCountInString(password) < 12 || strings.ContainsRune(password, '\x00') {
		return errors.New("recovery password must contain at least 12 characters")
	}
	return nil
}

func wrapRecoveryMasterKey(master []byte, password string) (recoveryKeyWrap, error) {
	if len(master) != 32 {
		return recoveryKeyWrap{}, errors.New("recovery master key has an invalid length")
	}
	if err := validateRecoveryPassword(password); err != nil {
		return recoveryKeyWrap{}, err
	}
	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err := rand.Read(salt); err != nil {
		return recoveryKeyWrap{}, fmt.Errorf("generate recovery salt: %w", err)
	}
	if _, err := rand.Read(nonce); err != nil {
		return recoveryKeyWrap{}, fmt.Errorf("generate recovery nonce: %w", err)
	}
	keyID := recoveryKeyID(master)
	wrapped, err := encryptRecoveryMasterKey(master, password, salt, nonce, keyID)
	if err != nil {
		return recoveryKeyWrap{}, err
	}
	return recoveryKeyWrap{
		Cipher:     recoveryCipher,
		KDF:        recoveryKDF,
		Salt:       base64.RawURLEncoding.EncodeToString(salt),
		Nonce:      base64.RawURLEncoding.EncodeToString(nonce),
		WrappedKey: base64.RawURLEncoding.EncodeToString(wrapped),
		KeyID:      keyID,
	}, nil
}

func unwrapRecoveryMasterKey(wrapper recoveryKeyWrap, password string) ([]byte, error) {
	if err := validateRecoveryPassword(password); err != nil {
		return nil, err
	}
	if wrapper.Cipher != recoveryCipher || wrapper.KDF != recoveryKDF {
		return nil, errors.New("recovery key wrapper suite is unsupported")
	}
	keyIDBytes, err := hex.DecodeString(wrapper.KeyID)
	if err != nil || len(keyIDBytes) != sha256.Size {
		return nil, errors.New("recovery key identifier is invalid")
	}
	salt, err := decodeRecoveryURL(wrapper.Salt, 16, "salt")
	if err != nil {
		return nil, err
	}
	nonce, err := decodeRecoveryURL(wrapper.Nonce, 12, "nonce")
	if err != nil {
		return nil, err
	}
	wrapped, err := decodeRecoveryURL(wrapper.WrappedKey, 48, "wrapped key")
	if err != nil {
		return nil, err
	}
	derived, err := scrypt.Key([]byte(password), salt, 1<<14, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("derive recovery key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("initialize recovery cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize recovery AEAD: %w", err)
	}
	master, err := aead.Open(nil, nonce, wrapped, recoveryWrapAAD(wrapper.KeyID))
	if err != nil {
		return nil, errors.New("administrator password does not unlock this archive")
	}
	if len(master) != 32 || recoveryKeyID(master) != wrapper.KeyID {
		return nil, errors.New("recovery master key failed verification")
	}
	return master, nil
}

func encryptRecoveryMasterKey(master []byte, password string, salt, nonce []byte, keyID string) ([]byte, error) {
	derived, err := scrypt.Key([]byte(password), salt, 1<<14, 8, 1, 32)
	if err != nil {
		return nil, fmt.Errorf("derive recovery key: %w", err)
	}
	block, err := aes.NewCipher(derived)
	if err != nil {
		return nil, fmt.Errorf("initialize recovery cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("initialize recovery AEAD: %w", err)
	}
	return aead.Seal(nil, nonce, master, recoveryWrapAAD(keyID)), nil
}

func decodeRecoveryMasterKey(encoded string) ([]byte, error) {
	return decodeRecoveryURL(encoded, 32, "master key")
}

func decodeRecoveryKeyWrap(encoded string) (recoveryKeyWrap, error) {
	var wrapper recoveryKeyWrap
	if err := json.Unmarshal([]byte(encoded), &wrapper); err != nil {
		return recoveryKeyWrap{}, errors.New("stored recovery key wrapper is invalid")
	}
	if err := validateRecoveryWrapperMetadata(wrapper); err != nil {
		return recoveryKeyWrap{}, err
	}
	return wrapper, nil
}

func validateRecoveryWrapperMetadata(wrapper recoveryKeyWrap) error {
	if wrapper.Cipher != recoveryCipher || wrapper.KDF != recoveryKDF {
		return errors.New("recovery key wrapper suite is unsupported")
	}
	keyID, err := hex.DecodeString(wrapper.KeyID)
	if err != nil || len(keyID) != sha256.Size {
		return errors.New("recovery key identifier is invalid")
	}
	if _, err := decodeRecoveryURL(wrapper.Salt, 16, "salt"); err != nil {
		return err
	}
	if _, err := decodeRecoveryURL(wrapper.Nonce, 12, "nonce"); err != nil {
		return err
	}
	if _, err := decodeRecoveryURL(wrapper.WrappedKey, 48, "wrapped key"); err != nil {
		return err
	}
	return nil
}

func decodeRecoveryURL(value string, expected int, label string) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("recovery %s encoding is invalid", label)
	}
	if len(decoded) != expected {
		return nil, fmt.Errorf("recovery %s length is invalid", label)
	}
	return decoded, nil
}

func recoveryKeyID(master []byte) string {
	digest := sha256.Sum256(master)
	return hex.EncodeToString(digest[:])
}

func recoveryWrapAAD(keyID string) []byte {
	return []byte("SBGWREC1:key-wrap:" + keyID)
}
