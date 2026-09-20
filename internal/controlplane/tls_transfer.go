package controlplane

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
	"golang.org/x/crypto/scrypt"
)

// Fixed, versioned parameters: untrusted files cannot request arbitrary KDF work.
// Only the encrypted envelope crosses the API; there is no plaintext export.
const tlsTransferMagic = "SB-TLS-1\n"
const tlsTransferLimit = 1 << 20

func tlsTransferProfileID(token string) string {
	// URL-safe random tokens may end in '-' or '_', which entity IDs reject.
	return "tls-import-" + hex.EncodeToString([]byte(token))
}

type tlsTransferACME struct {
	Settings    acmejob.Settings  `json:"settings"`
	Credentials map[string]string `json:"credentials"`
	AccountKey  string            `json:"account_key,omitempty"`
}
type tlsTransferLocalCA struct {
	ServerName  string `json:"server_name"`
	Certificate string `json:"certificate"`
	PrivateKey  string `json:"private_key"`
}
type tlsTransferPayload struct {
	Version     int                 `json:"version"`
	Name        string              `json:"name"`
	Certificate string              `json:"certificate"`
	PrivateKey  string              `json:"private_key"`
	ACME        *tlsTransferACME    `json:"acme,omitempty"`
	LocalCA     *tlsTransferLocalCA `json:"local_ca,omitempty"`
}

func tlsTransferCipher(password string, salt []byte) (cipher.AEAD, error) {
	key, err := scrypt.Key([]byte(password), salt, 32768, 8, 1, 32)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func sealTLSProfile(plain []byte, password string) ([]byte, error) {
	if len(plain) > tlsTransferLimit {
		return nil, errors.New("TLS profile too large")
	}
	header := make([]byte, len(tlsTransferMagic)+16+12)
	copy(header, tlsTransferMagic)
	if _, err := rand.Read(header[len(tlsTransferMagic):]); err != nil {
		return nil, err
	}
	aead, err := tlsTransferCipher(password, header[len(tlsTransferMagic):len(tlsTransferMagic)+16])
	if err != nil {
		return nil, err
	}
	return aead.Seal(header, header[len(header)-12:], plain, header), nil
}
func openTLSProfile(blob []byte, password string) ([]byte, error) {
	n := len(tlsTransferMagic) + 16 + 12
	if len(blob) < n+16 || len(blob) > tlsTransferLimit+n+16 || !bytes.HasPrefix(blob, []byte(tlsTransferMagic)) {
		return nil, errors.New("invalid TLS archive")
	}
	header := blob[:n]
	aead, err := tlsTransferCipher(password, header[len(tlsTransferMagic):len(tlsTransferMagic)+16])
	if err != nil {
		return nil, err
	}
	return aead.Open(nil, header[n-12:], blob[n:], header)
}

func (s *Server) tlsTransferRequest(w http.ResponseWriter, r *http.Request) (map[string]any, map[string]any, bool) {
	actor, ok := s.requireCSRF(w, r)
	if !ok {
		return nil, nil, false
	}
	body, ok := s.readObject(w, r, 2<<20)
	if !ok {
		return nil, nil, false
	}
	p, ok := body["password"].(string)
	if !ok || utf8.RuneCountInString(p) < 12 || len(p) > 256 || strings.TrimSpace(p) == "" {
		s.writeErrorResponse(w, r, 422, "archive_password", "Пароль архива: от 12 символов, до 256 байт.")
		return nil, nil, false
	}
	return body, actor, true
}
func (s *Server) exportTLSProfile(w http.ResponseWriter, r *http.Request) {
	body, actor, ok := s.tlsTransferRequest(w, r)
	if !ok {
		return
	}
	if !s.tlsTransferMu.TryLock() {
		s.writeErrorResponse(w, r, 409, "transfer_busy", "Перенос уже выполняется. Повторите позже.")
		return
	}
	defer s.tlsTransferMu.Unlock()
	id := r.PathValue("entity")
	s.configMu.Lock()
	payload, err := s.collectTLSProfile(id)
	s.configMu.Unlock()
	if err != nil {
		s.writeErrorResponse(w, r, 422, "tls_export_failed", "Не удалось собрать профиль. Проверьте наличие сертификата, ключа и данных ACME.")
		return
	}
	plain, err := json.Marshal(payload)
	if err != nil {
		s.internalStateError(w, r, err)
		return
	}
	defer clear(plain)
	blob, err := sealTLSProfile(plain, body["password"].(string))
	if err != nil {
		s.internalStateError(w, r, err)
		return
	}
	s.audit(r, subscriptionText(actor["sub"]), "tls.export", "ok", map[string]any{"id": id})
	w.Header().Set("Cache-Control", "no-store")
	s.writeJSON(w, 200, map[string]any{"archive": base64.StdEncoding.EncodeToString(blob), "filename": "TLS-profile.sbtls"})
}
func (s *Server) collectTLSProfile(id string) (tlsTransferPayload, error) {
	var out tlsTransferPayload
	if !entityIDPattern.MatchString(id) {
		return out, errors.New("invalid id")
	}
	draft, err := s.getDraft()
	if err != nil {
		return out, err
	}
	p := acmeProfile(draft, id)
	if p == nil {
		return out, errors.New("missing profile")
	}
	out.Version, out.Name = 1, subscriptionText(p["display_name"])
	out.Certificate, err = s.secrets.read(subscriptionText(p["certificate_secret_ref"]), true)
	if err != nil {
		return out, err
	}
	out.PrivateKey, err = s.secrets.read(subscriptionText(p["private_key_secret_ref"]), true)
	if err != nil {
		return out, err
	}
	if _, err := tlsCertificateMetadata(out.Certificate, out.PrivateKey); err != nil {
		return out, err
	}
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		return out, err
	}
	record := decodeACMERecord(state[id])
	// A manual replacement must not inherit an old, unrelated ACME account.
	if p["certificate_secret_ref"] == "tls-profiles/"+id+"/acme-bundle.pem" && record.CredentialsRef != "" {
		if record.State == "queued" || record.State == "running" {
			return out, errors.New("ACME busy")
		}
		a := &tlsTransferACME{Settings: record.Settings}
		secret, err := s.secrets.read(record.CredentialsRef, true)
		if err != nil {
			return out, err
		}
		if err := json.Unmarshal([]byte(secret), &a.Credentials); err != nil {
			return out, err
		}
		a.AccountKey, err = s.secrets.read("acme/"+id+"/account.pem", false)
		if err != nil {
			return out, err
		}
		out.ACME = a
	}
	if subscriptionText(p["certificate_source"]) == "local-ca" {
		local := &tlsTransferLocalCA{ServerName: subscriptionText(p["local_ca_server_name"])}
		local.Certificate, err = s.secrets.read(subscriptionText(p["local_ca_certificate_secret_ref"]), true)
		if err != nil {
			return out, err
		}
		local.PrivateKey, err = s.secrets.read(subscriptionText(p["local_ca_private_key_secret_ref"]), true)
		if err != nil {
			return out, err
		}
		if err := validateLocalCABundle(localCABundle{
			certificate: out.Certificate, privateKey: out.PrivateKey,
			rootCertificate: local.Certificate, rootPrivateKey: local.PrivateKey,
		}, local.ServerName, s.now()); err != nil {
			return out, err
		}
		out.LocalCA = local
	}
	return out, nil
}

func (s *Server) importTLSProfile(w http.ResponseWriter, r *http.Request) {
	body, actor, ok := s.tlsTransferRequest(w, r)
	if !ok {
		return
	}
	if !s.tlsTransferMu.TryLock() {
		s.writeErrorResponse(w, r, 409, "transfer_busy", "Перенос уже выполняется. Повторите позже.")
		return
	}
	defer s.tlsTransferMu.Unlock()
	invalid := func() {
		s.writeErrorResponse(w, r, 422, "invalid_tls_archive", "Неверный пароль или повреждённый архив TLS-профиля.")
	}
	blob, err := base64.StdEncoding.DecodeString(subscriptionText(body["archive"]))
	if err != nil {
		invalid()
		return
	}
	plain, err := openTLSProfile(blob, body["password"].(string))
	if err != nil {
		invalid()
		return
	}
	defer clear(plain)
	var payload tlsTransferPayload
	decoder := json.NewDecoder(bytes.NewReader(plain))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&payload) != nil || decoder.Decode(new(any)) != io.EOF || payload.Version != 1 {
		invalid()
		return
	}
	metadata, err := tlsCertificateMetadata(payload.Certificate, payload.PrivateKey)
	if err != nil {
		invalid()
		return
	}
	if a := payload.ACME; a != nil {
		if acmejob.ValidateConfiguration(a.Settings, a.Credentials) != nil {
			invalid()
			return
		}
		// Restore settings even for an expired certificate, without issuing anything.
		pairBlock, _ := pem.Decode([]byte(payload.Certificate))
		if pairBlock == nil {
			invalid()
			return
		}
		cert, e := x509.ParseCertificate(pairBlock.Bytes)
		if e != nil {
			invalid()
			return
		}
		for _, domain := range a.Settings.Domains {
			if strings.HasPrefix(domain, "*.") {
				domain = "acme-check." + strings.TrimPrefix(domain, "*.")
			}
			if cert.VerifyHostname(domain) != nil {
				invalid()
				return
			}
		}
		if a.AccountKey != "" {
			block, _ := pem.Decode([]byte(a.AccountKey))
			if block == nil || block.Type != "PRIVATE KEY" {
				invalid()
				return
			}
			key, e := x509.ParsePKCS8PrivateKey(block.Bytes)
			if e != nil {
				invalid()
				return
			}
			if _, ok := key.(crypto.Signer); !ok {
				invalid()
				return
			}
		}
	}
	if payload.ACME != nil && payload.LocalCA != nil {
		invalid()
		return
	}
	if local := payload.LocalCA; local != nil {
		if err := validateLocalCABundle(localCABundle{
			certificate: payload.Certificate, privateKey: payload.PrivateKey,
			rootCertificate: local.Certificate, rootPrivateKey: local.PrivateKey,
		}, local.ServerName, s.now()); err != nil {
			invalid()
			return
		}
	}
	name := strings.TrimSpace(subscriptionText(body["name"]))
	if name == "" {
		name = strings.TrimSpace(payload.Name)
	}
	if name == "" {
		name = "TLS-профиль"
	}
	if len(name) > 256 || strings.ContainsAny(name, "\x00\r\n") {
		invalid()
		return
	}
	s.configMu.Lock()
	defer s.configMu.Unlock()
	draft, err := s.getDraft()
	if err != nil {
		s.internalStateError(w, r, err)
		return
	}
	token, err := randomURLToken(12)
	if err != nil {
		s.internalStateError(w, r, err)
		return
	}
	id := tlsTransferProfileID(token)
	if acmeProfile(draft, id) != nil {
		s.writeErrorResponse(w, r, 409, "id_conflict", "Повторите импорт.")
		return
	}
	ref := "tls-profiles/" + id + "/certificate.pem"
	keyRef := "tls-profiles/" + id + "/private-key.pem"
	if payload.ACME != nil {
		ref = "tls-profiles/" + id + "/acme-bundle.pem"
		keyRef = ref
	}
	profile := map[string]any{"id": id, "display_name": name, "enabled": false, "certificate_source": "manual", "certificate_secret_ref": ref, "private_key_secret_ref": keyRef, "certificate_metadata": metadata}
	if payload.ACME != nil {
		profile["certificate_source"] = "acme"
	}
	if local := payload.LocalCA; local != nil {
		profile["certificate_source"] = "local-ca"
		profile["local_ca_server_name"] = local.ServerName
		profile["local_ca_certificate_secret_ref"] = "tls-profiles/" + id + "/local-ca-certificate.pem"
		profile["local_ca_private_key_secret_ref"] = "tls-profiles/" + id + "/local-ca-private-key.pem"
	}
	items, _ := draft["tls_profiles"].([]any)
	draft["tls_profiles"] = append(items, profile)
	objectAt(draft, "system")["deployment_ready"] = false
	validation := validateCurrentConfig(draft)
	if !validation.Valid {
		s.writeValidationError(w, r, validation)
		return
	}
	pending := []pendingEntitySecret{{reference: ref, value: payload.Certificate}}
	if keyRef == ref {
		pending[0].value += "\n" + payload.PrivateKey
	} else {
		pending = append(pending, pendingEntitySecret{reference: keyRef, value: payload.PrivateKey})
	}
	if local := payload.LocalCA; local != nil {
		pending = append(pending,
			pendingEntitySecret{reference: subscriptionText(profile["local_ca_certificate_secret_ref"]), value: local.Certificate},
			pendingEntitySecret{reference: subscriptionText(profile["local_ca_private_key_secret_ref"]), value: local.PrivateKey},
		)
	}
	state, err := s.repository.auxiliary("acme")
	if err != nil {
		s.internalStateError(w, r, err)
		return
	}
	if a := payload.ACME; a != nil {
		credentials, _ := json.Marshal(a.Credentials)
		credRef := "acme/" + id + "/dns.json"
		pending = append(pending, pendingEntitySecret{reference: credRef, value: string(credentials)})
		if a.AccountKey != "" {
			pending = append(pending, pendingEntitySecret{reference: "acme/" + id + "/account.pem", value: a.AccountKey})
		}
		a.Settings.Enabled = false
		state[id] = acmeRecord{Settings: a.Settings, Revision: token, CredentialsRef: credRef, State: "disabled", Message: "Импортирован. Автопродление выключено.", Metadata: metadata}
	}
	undo, err := s.writeEntitySecrets(pending)
	if err != nil {
		s.writeErrorResponse(w, r, 500, "secret_store_failed", "Не удалось сохранить профиль.")
		return
	}
	if payload.ACME != nil {
		if err := s.repository.saveAuxiliary("acme", state); err != nil {
			_ = undo()
			s.internalStateError(w, r, err)
			return
		}
	}
	revision, err := s.repository.saveDraft(draft)
	if err != nil {
		delete(state, id)
		if payload.ACME != nil {
			_ = s.repository.saveAuxiliary("acme", state)
		}
		_ = undo()
		s.internalStateError(w, r, err)
		return
	}
	s.audit(r, subscriptionText(actor["sub"]), "tls.import", "ok", map[string]any{"id": id})
	s.writeJSON(w, 200, map[string]any{"id": id, "revision": revision, "display_name": name, "acme": payload.ACME != nil})
}
