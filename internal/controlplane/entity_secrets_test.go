package controlplane

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestNativeTransportMutationGeneratesX25519RealityAndPathSecrets(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/transports", map[string]any{
		"item": map[string]any{
			"id": "native-reality", "kind": "xhttp-reality", "enabled": false,
			"listen_port": 2446, "hostname": "reverse.example.test", "server_name": "reverse.example.test",
			"generate_transport_secret": true, "vless_encryption_enabled": false,
		},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("transport create failed: %d %s", response.Code, response.Body.String())
	}
	item := decodeResponse(t, response)["item"].(map[string]any)
	if _, leaked := item["generate_transport_secret"]; leaked {
		t.Fatalf("transient generation flag persisted: %#v", item)
	}
	if item["path_secret_ref"] != "transports/native-reality/path" {
		t.Fatalf("path ref = %#v", item["path_secret_ref"])
	}
	refs := item["secret_refs"].(map[string]any)
	privateRef := refs["reality_private_key"].(string)
	privateText, err := server.secrets.read(privateRef, true)
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(privateText)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	wantedPublic := base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes())
	if item["public_key"] != wantedPublic {
		t.Fatalf("public key does not match private key")
	}
	path, err := server.secrets.read("transports/native-reality/path", true)
	if err != nil || len(path) < 25 || path[0] != '/' {
		t.Fatalf("generated path = %q, err=%v", path, err)
	}
	shortID, err := server.secrets.read("transports/native-reality/reality_short_id", true)
	if err != nil || len(shortID) != 16 {
		t.Fatalf("short ID = %q, err=%v", shortID, err)
	}
}

func TestNativeTLSProfileMutationValidatesPairAndStoresMetadata(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	certificatePEM, privateKeyPEM := testTLSKeypair(t)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/tls-profiles", map[string]any{
		"item": map[string]any{
			"id": "native-tls", "display_name": "Native TLS", "enabled": true,
			"secret_values": map[string]any{"certificate": certificatePEM, "private_key": privateKeyPEM},
		},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("TLS create failed: %d %s", response.Code, response.Body.String())
	}
	item := decodeResponse(t, response)["item"].(map[string]any)
	if _, leaked := item["secret_values"]; leaked {
		t.Fatalf("TLS values leaked: %#v", item)
	}
	metadata := item["certificate_metadata"].(map[string]any)
	if metadata["fingerprint_sha256"] == "" || metadata["not_after"] == "" {
		t.Fatalf("TLS metadata = %#v", metadata)
	}
	stored, err := server.secrets.read("tls-profiles/native-tls/certificate.pem", true)
	if err != nil || stored != certificatePEM[:len(certificatePEM)-1] {
		t.Fatalf("stored certificate mismatch: %v", err)
	}
}

func TestNativeTLSProfileGeneratesStableLocalCAAndExplicitlyRotates(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	create := performRequest(t, server, http.MethodPost, apiPrefix+"/tls-profiles", map[string]any{
		"item": map[string]any{
			"id": "private-pin", "display_name": "Private pin", "enabled": true,
			"certificate_source": "local-ca", "local_ca_server_name": "Cover.Example.Test.",
			"generate_local_ca": true,
		},
	}, map[string]string{csrfHeader: csrf}, cookie)
	if create.Code != http.StatusOK {
		t.Fatalf("local CA create failed: %d %s", create.Code, create.Body.String())
	}
	item := decodeResponse(t, create)["item"].(map[string]any)
	if item["certificate_source"] != "local-ca" || item["local_ca_server_name"] != "cover.example.test" {
		t.Fatalf("local CA profile = %#v", item)
	}
	if _, leaked := item["generate_local_ca"]; leaked {
		t.Fatalf("generation flag leaked: %#v", item)
	}
	if encoded, _ := json.Marshal(item); strings.Contains(string(encoded), "BEGIN ") {
		t.Fatalf("local CA key material leaked in API response: %s", encoded)
	}
	for _, field := range []string{"certificate_secret_ref", "private_key_secret_ref", "local_ca_certificate_secret_ref", "local_ca_private_key_secret_ref"} {
		if !server.secrets.exists(item[field].(string)) {
			t.Fatalf("missing %s secret", field)
		}
	}
	certificate, _ := server.secrets.read(item["certificate_secret_ref"].(string), true)
	privateKey, _ := server.secrets.read(item["private_key_secret_ref"].(string), true)
	rootCertificate, _ := server.secrets.read(item["local_ca_certificate_secret_ref"].(string), true)
	rootPrivateKey, _ := server.secrets.read(item["local_ca_private_key_secret_ref"].(string), true)
	if privateKey == rootPrivateKey {
		t.Fatal("root and leaf reused one private key")
	}
	if err := validateLocalCABundle(localCABundle{
		certificate: certificate, privateKey: privateKey,
		rootCertificate: rootCertificate, rootPrivateKey: rootPrivateKey,
	}, "cover.example.test", server.now()); err != nil {
		t.Fatal(err)
	}
	metadata := item["certificate_metadata"].(map[string]any)
	firstFingerprint := metadata["fingerprint_sha256"]
	notAfter, err := time.Parse(time.RFC3339, metadata["not_after"].(string))
	if err != nil || notAfter.Before(server.now().AddDate(9, 11, 0)) {
		t.Fatalf("local leaf lifetime = %v, err=%v", notAfter, err)
	}

	stable := performRequest(t, server, http.MethodPut, apiPrefix+"/tls-profiles/private-pin", item, map[string]string{csrfHeader: csrf}, cookie)
	if stable.Code != http.StatusOK {
		t.Fatalf("stable local CA update failed: %d %s", stable.Code, stable.Body.String())
	}
	stableItem := decodeResponse(t, stable)["item"].(map[string]any)
	if stableItem["certificate_metadata"].(map[string]any)["fingerprint_sha256"] != firstFingerprint {
		t.Fatal("ordinary save rotated the local leaf")
	}

	stableItem["generate_local_ca"] = true
	rotated := performRequest(t, server, http.MethodPut, apiPrefix+"/tls-profiles/private-pin", stableItem, map[string]string{csrfHeader: csrf}, cookie)
	if rotated.Code != http.StatusOK {
		t.Fatalf("local CA rotation failed: %d %s", rotated.Code, rotated.Body.String())
	}
	rotatedItem := decodeResponse(t, rotated)["item"].(map[string]any)
	if rotatedItem["certificate_metadata"].(map[string]any)["fingerprint_sha256"] == firstFingerprint {
		t.Fatal("explicit local CA rotation retained the old leaf")
	}
}

func TestNativeTLSProfileRejectsUnsafeLocalCASNIWithoutSecrets(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	for _, name := range []string{"", "192.0.2.1", "*.example.test", "localhost", "bad name.example"} {
		response := performRequest(t, server, http.MethodPost, apiPrefix+"/tls-profiles", map[string]any{
			"item": map[string]any{
				"id": "bad-private-pin", "display_name": "Bad private pin", "enabled": false,
				"certificate_source": "local-ca", "local_ca_server_name": name, "generate_local_ca": true,
			},
		}, map[string]string{csrfHeader: csrf}, cookie)
		if response.Code != http.StatusUnprocessableEntity {
			t.Fatalf("unsafe local CA SNI %q returned %d: %s", name, response.Code, response.Body.String())
		}
		if server.secrets.exists("tls-profiles/bad-private-pin/certificate.pem") {
			t.Fatalf("unsafe SNI %q left generated secrets", name)
		}
	}
}

func TestNativeTransportValidationLeavesNoGeneratedSecrets(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	response := performRequest(t, server, http.MethodPost, apiPrefix+"/transports", map[string]any{
		"id": "invalid-reality", "kind": "reality", "enabled": false,
		"generate_transport_secret": true,
	}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("invalid transport returned %d: %s", response.Code, response.Body.String())
	}
	for _, reference := range []string{
		"transports/invalid-reality/reality_private_key", "transports/invalid-reality/reality_short_id",
	} {
		if server.secrets.exists(reference) {
			t.Fatalf("validation left orphan %s", reference)
		}
	}
}

func TestTransportProvisionerDropsInapplicableTransientValues(t *testing.T) {
	server := newTestServer(t)
	item := map[string]any{
		"id": "plain-reality", "kind": "reality", "http_path": "/must-not-persist",
		"generate_vless_encryption": true,
	}
	pending, err := server.prepareTransportSecrets(item, "plain-reality", true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := item["http_path"]; exists {
		t.Fatalf("inapplicable HTTP path persisted: %#v", item)
	}
	if _, exists := item["generate_vless_encryption"]; exists || len(pending) != 0 {
		t.Fatalf("inapplicable generation request survived: %#v %#v", item, pending)
	}
}

func TestXrayOwnedKeyOutputParsersSelectExactFormats(t *testing.T) {
	seed, verify, err := parseMLDSA65Output("Seed: seed-value\nVerify: verify-value\n")
	if err != nil || seed != "seed-value" || verify != "verify-value" {
		t.Fatalf("ML-DSA parse = %q %q %v", seed, verify, err)
	}
	output := "Authentication: X25519\n{\"decryption\":\"x-dec\",\"encryption\":\"x-enc\"}\n" +
		"Authentication: ML-KEM-768\n{\"decryption\":\"m-dec\",\"encryption\":\"m-enc\"}\n"
	decryption, encryption, err := parseVLESSEncryptionOutput(output, "mlkem768")
	if err != nil || decryption != "m-dec" || encryption != "m-enc" {
		t.Fatalf("VLESS parse = %q %q %v", decryption, encryption, err)
	}
	if _, _, err := parseVLESSEncryptionOutput(output, "unsupported"); err == nil {
		t.Fatal("unsupported VLESS authentication was accepted")
	}
}

func testTLSKeypair(t *testing.T) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "gateway.example.test"},
		DNSNames: []string{"gateway.example.test"}, NotBefore: time.Unix(1_700_000_000, 0),
		NotAfter: time.Unix(1_800_000_000, 0), KeyUsage: x509.KeyUsageDigitalSignature,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	privateKey := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})
	return string(certificate), string(privateKey)
}
