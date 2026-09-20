package controlplane

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

var (
	httpTransportPathPattern = regexp.MustCompile(`^/[A-Za-z0-9._~!$&'()*+,;=:@/-]{1,127}$`)
	grpcServiceNamePattern   = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9._/-]{0,126}[A-Za-z0-9])?$`)
	mldsaSeedPattern         = regexp.MustCompile(`(?m)^Seed:\s*(\S+)`)
	mldsaVerifyPattern       = regexp.MustCompile(`(?m)^Verify:\s*(\S+)`)
	vlessEncPairPattern      = regexp.MustCompile(`(?s)Authentication:\s*([^\r\n]+).*?"decryption"\s*:\s*"([^"]+)".*?"encryption"\s*:\s*"([^"]+)"`)
	ansiEscapePattern        = regexp.MustCompile(`\x1b\[[0-9;]*m`)
)

func (server *Server) prepareTLSProfileSecrets(item map[string]any, entityID string, create bool, pending []pendingEntitySecret) ([]pendingEntitySecret, error) {
	source := stringDefault(item["certificate_source"], "manual")
	if source != "manual" && source != "acme" && source != "local-ca" {
		return nil, errors.New("unsupported TLS certificate source")
	}
	item["certificate_source"] = source
	generateLocalCA := popBool(item, "generate_local_ca")
	raw, supplied := item["secret_values"]
	delete(item, "secret_values")
	if source == "local-ca" {
		if supplied {
			return nil, errors.New("local CA profile cannot accept an uploaded TLS pair")
		}
		serverName, err := normalizeLocalCAServerName(stringDefault(item["local_ca_server_name"], ""))
		if err != nil {
			return nil, err
		}
		item["local_ca_server_name"] = serverName
		certificateRef := "tls-profiles/" + entityID + "/certificate.pem"
		privateKeyRef := "tls-profiles/" + entityID + "/private-key.pem"
		rootCertificateRef := "tls-profiles/" + entityID + "/local-ca-certificate.pem"
		rootPrivateKeyRef := "tls-profiles/" + entityID + "/local-ca-private-key.pem"
		if generateLocalCA {
			bundle, err := generateLocalCABundle(serverName, server.now())
			if err != nil {
				return nil, err
			}
			metadata, err := tlsCertificateMetadata(bundle.certificate, bundle.privateKey)
			if err != nil {
				return nil, err
			}
			pending = append(pending,
				pendingEntitySecret{reference: certificateRef, value: bundle.certificate, overwrite: !create || server.secrets.exists(certificateRef)},
				pendingEntitySecret{reference: privateKeyRef, value: bundle.privateKey, overwrite: !create || server.secrets.exists(privateKeyRef)},
				pendingEntitySecret{reference: rootCertificateRef, value: bundle.rootCertificate, overwrite: !create || server.secrets.exists(rootCertificateRef)},
				pendingEntitySecret{reference: rootPrivateKeyRef, value: bundle.rootPrivateKey, overwrite: !create || server.secrets.exists(rootPrivateKeyRef)},
			)
			item["certificate_metadata"] = metadata
		}
		for field, reference := range map[string]string{
			"certificate_secret_ref": certificateRef, "private_key_secret_ref": privateKeyRef,
			"local_ca_certificate_secret_ref": rootCertificateRef, "local_ca_private_key_secret_ref": rootPrivateKeyRef,
		} {
			item[field] = reference
		}
		if !generateLocalCA && (!server.secrets.exists(certificateRef) || !server.secrets.exists(privateKeyRef) ||
			!server.secrets.exists(rootCertificateRef) || !server.secrets.exists(rootPrivateKeyRef)) {
			return nil, errors.New("create the local CA certificate before saving the profile")
		}
		return pending, nil
	}
	delete(item, "local_ca_server_name")
	delete(item, "local_ca_certificate_secret_ref")
	delete(item, "local_ca_private_key_secret_ref")
	if !supplied {
		if _, ok := item["certificate_metadata"].(map[string]any); !ok {
			item["certificate_metadata"] = map[string]any{}
		}
		return pending, nil
	}
	values, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("secret_values must be an object")
	}
	certificate, certificateOK := values["certificate"].(string)
	privateKey, privateKeyOK := values["private_key"].(string)
	if !certificateOK || !privateKeyOK {
		return nil, errors.New("upload the TLS certificate and private key together")
	}
	metadata, err := tlsCertificateMetadata(certificate, privateKey)
	if err != nil {
		return nil, err
	}
	certificateRef := "tls-profiles/" + entityID + "/certificate.pem"
	privateKeyRef := "tls-profiles/" + entityID + "/private-key.pem"
	pending = append(pending,
		pendingEntitySecret{reference: certificateRef, value: certificate, overwrite: !create},
		pendingEntitySecret{reference: privateKeyRef, value: privateKey, overwrite: !create},
	)
	item["certificate_secret_ref"] = certificateRef
	item["private_key_secret_ref"] = privateKeyRef
	item["certificate_metadata"] = metadata
	return pending, nil
}

func tlsCertificateMetadata(certificatePEM, privateKeyPEM string) (map[string]any, error) {
	pair, err := tls.X509KeyPair([]byte(certificatePEM), []byte(privateKeyPEM))
	if err != nil || len(pair.Certificate) == 0 {
		return nil, errors.New("TLS certificate and private key do not form a valid pair")
	}
	certificate, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, errors.New("TLS certificate is invalid")
	}
	digest := sha256.Sum256(pair.Certificate[0])
	return map[string]any{
		"subject": certificate.Subject.String(), "issuer": certificate.Issuer.String(),
		"dns_names":          append([]string(nil), certificate.DNSNames...),
		"not_before":         certificate.NotBefore.UTC().Format(time.RFC3339),
		"not_after":          certificate.NotAfter.UTC().Format(time.RFC3339),
		"serial_number":      certificate.SerialNumber.String(),
		"fingerprint_sha256": hex.EncodeToString(digest[:]),
	}, nil
}

func (server *Server) prepareTransportSecrets(item map[string]any, entityID string, create bool, pending []pendingEntitySecret) ([]pendingEntitySecret, error) {
	kind := stringDefault(item["kind"], "")
	realityKind := kind == "reality" || kind == "reality-grpc" || kind == "xhttp-reality"
	xhttpKind := kind == "xhttp" || kind == "xhttp-reality"
	rawHTTPPath, httpPathSupplied := item["http_path"]
	rawGRPCService, grpcServiceSupplied := item["grpc_service_name"]
	delete(item, "http_path")
	delete(item, "grpc_service_name")
	generateAll := popBool(item, "generate_transport_secret")
	requestedReality := popBool(item, "generate_reality_keys")
	requestedVLESS := popBool(item, "generate_vless_encryption")
	requestedMLDSA := popBool(item, "generate_reality_mldsa65")
	generatePath := popBool(item, "generate_http_path") || generateAll && (kind == "ws" || kind == "httpupgrade" || kind == "xhttp" || kind == "xhttp-reality")
	generateService := popBool(item, "generate_grpc_service_name") || generateAll && (kind == "grpc" || kind == "reality-grpc" || kind == "grpc-tls")
	generateReality := realityKind && (requestedReality || generateAll)
	generateVLESS := xhttpKind && (requestedVLESS || generateAll) && item["vless_encryption_enabled"] == true
	generateMLDSA := realityKind && (requestedMLDSA || generateAll) && item["reality_mldsa65_enabled"] == true
	generateHysteria := popBool(item, "generate_hysteria2_obfs") || generateAll && kind == "hysteria2"

	var err error
	pending, err = server.prepareCDNOriginSecrets(item, entityID, pending)
	if err != nil {
		return nil, err
	}
	if kind == "ws" || kind == "httpupgrade" || kind == "xhttp" || kind == "xhttp-reality" {
		reference := stringDefault(item["path_secret_ref"], "transports/"+entityID+"/path")
		if !validSecretReference(reference) {
			return nil, errors.New("HTTP path secret reference is invalid")
		}
		if httpPathSupplied {
			value, ok := rawHTTPPath.(string)
			if !ok || !httpTransportPathPattern.MatchString(value) || strings.Contains(value, "//") || strings.Contains(value, "..") {
				return nil, errors.New("HTTP transport path is invalid")
			}
			pending = append(pending, pendingEntitySecret{reference: reference, value: value, overwrite: !create})
			item["path_secret_ref"] = reference
		} else if generatePath {
			value, randomErr := randomURLToken(24)
			if randomErr != nil {
				return nil, randomErr
			}
			pending = append(pending, pendingEntitySecret{reference: reference, value: "/" + value, overwrite: !create})
			item["path_secret_ref"] = reference
		}
	}
	if kind == "grpc" || kind == "reality-grpc" || kind == "grpc-tls" {
		reference := stringDefault(item["service_name_secret_ref"], "transports/"+entityID+"/service-name")
		if !validSecretReference(reference) {
			return nil, errors.New("gRPC service secret reference is invalid")
		}
		if grpcServiceSupplied {
			value, ok := rawGRPCService.(string)
			if !ok || !grpcServiceNamePattern.MatchString(value) || strings.Contains(value, "//") || strings.Contains(value, "..") {
				return nil, errors.New("gRPC service name is invalid")
			}
			pending = append(pending, pendingEntitySecret{reference: reference, value: value, overwrite: !create})
			item["service_name_secret_ref"] = reference
		} else if generateService {
			value, randomErr := randomURLToken(18)
			if randomErr != nil {
				return nil, randomErr
			}
			value = "grpc-" + strings.ReplaceAll(value, "-", "x")
			pending = append(pending, pendingEntitySecret{reference: reference, value: value, overwrite: !create})
			item["service_name_secret_ref"] = reference
		}
	}
	refs, _ := item["secret_refs"].(map[string]any)
	if refs == nil {
		refs = map[string]any{}
	}
	if generateReality {
		privateValue, publicValue, keyErr := generateRealityKeypair()
		if keyErr != nil {
			return nil, keyErr
		}
		shortID, keyErr := randomHex(8)
		if keyErr != nil {
			return nil, keyErr
		}
		privateRef, shortIDRef := "transports/"+entityID+"/reality_private_key", "transports/"+entityID+"/reality_short_id"
		pending = append(pending,
			pendingEntitySecret{reference: privateRef, value: privateValue, overwrite: !create},
			pendingEntitySecret{reference: shortIDRef, value: shortID, overwrite: !create},
		)
		refs["reality_private_key"], refs["reality_short_id"] = privateRef, shortIDRef
		item["public_key"] = publicValue
	}
	if item["reality_mldsa65_enabled"] == true && (generateMLDSA || generateReality) {
		seed, verify, keyErr := generateMLDSA65()
		if keyErr != nil {
			return nil, keyErr
		}
		reference := "transports/" + entityID + "/reality_mldsa65_seed"
		pending = append(pending, pendingEntitySecret{reference: reference, value: seed, overwrite: !create})
		refs["reality_mldsa65_seed"] = reference
		item["mldsa65_verify"] = verify
	}
	if generateVLESS && item["vless_encryption_enabled"] == true {
		decryption, encryption, keyErr := generateVLESSEncryption(stringDefault(item["vless_encryption_authentication"], "mlkem768"))
		if keyErr != nil {
			return nil, keyErr
		}
		decryptionRef, encryptionRef := "transports/"+entityID+"/vless_decryption", "transports/"+entityID+"/vless_encryption"
		pending = append(pending,
			pendingEntitySecret{reference: decryptionRef, value: decryption, overwrite: !create},
			pendingEntitySecret{reference: encryptionRef, value: encryption, overwrite: !create},
		)
		refs["vless_decryption"], refs["vless_encryption"] = decryptionRef, encryptionRef
	}
	if generateHysteria && kind == "hysteria2" {
		value, randomErr := randomURLToken(32)
		if randomErr != nil {
			return nil, randomErr
		}
		reference := "transports/" + entityID + "/hysteria2_obfs_password"
		pending = append(pending, pendingEntitySecret{reference: reference, value: value, overwrite: !create})
		refs["hysteria2_obfs_password"] = reference
		item["obfs_enabled"] = true
	}
	rawValues, valuesSupplied := item["secret_values"]
	delete(item, "secret_values")
	if valuesSupplied {
		values, ok := rawValues.(map[string]any)
		if !ok {
			return nil, errors.New("secret_values must be an object")
		}
		allowed := map[string]bool{
			"tls_certificate": true, "tls_private_key": true, "reality_private_key": true, "reality_short_id": true,
			"vless_decryption": true, "vless_encryption": true, "reality_mldsa65_seed": true,
			"hysteria2_tls_certificate": true, "hysteria2_tls_private_key": true, "hysteria2_obfs_password": true,
		}
		for name, rawValue := range values {
			value, ok := rawValue.(string)
			if !allowed[name] || !ok || value == "" {
				return nil, errors.New("unsupported transport secret field")
			}
			reference := "transports/" + entityID + "/" + name
			pending = append(pending, pendingEntitySecret{reference: reference, value: value, overwrite: !create})
			refs[name] = reference
		}
	}
	if len(refs) > 0 {
		item["secret_refs"] = refs
	}
	return pending, nil
}

func (server *Server) prepareCDNOriginSecrets(item map[string]any, entityID string, pending []pendingEntitySecret) ([]pendingEntitySecret, error) {
	kind := stringDefault(item["kind"], "")
	if kind != "ws" && kind != "grpc" && kind != "httpupgrade" && kind != "xhttp" {
		return pending, nil
	}
	deployments, ok := item["cdn_deployments"].([]any)
	if !ok {
		return pending, nil
	}
	prepared := make([]any, 0, len(deployments))
	for index, raw := range deployments {
		deployment, ok := raw.(map[string]any)
		if !ok {
			prepared = append(prepared, raw)
			continue
		}
		deployment = cloneJSONObject(deployment)
		deploymentID := strings.ToLower(strings.TrimSpace(stringDefault(deployment["id"], fmt.Sprintf("cdn-%d", index+1))))
		mode := stringDefault(deployment["origin_protection_mode"], "")
		if mode == "" {
			if deployment["cdn_provider"] == "cloudflare" {
				mode = "auto-cidr"
			} else {
				mode = "secret-header"
			}
		}
		rawHeader, supplied := deployment["origin_header_value"]
		delete(deployment, "origin_header_value")
		reference := stringDefault(deployment["origin_header_secret_ref"], "transports/"+entityID+"/cdn/"+deploymentID+".origin-header")
		if mode == "secret-header" && !validSecretReference(reference) {
			return nil, errors.New("origin header secret reference is invalid")
		}
		if supplied {
			value, valid := rawHeader.(string)
			if !valid || !visibleSecret(value, 24, 256) {
				return nil, errors.New("origin header secret must contain 24 to 256 visible characters without spaces")
			}
			pending = append(pending, pendingEntitySecret{reference: reference, value: value, overwrite: server.secrets.exists(reference)})
		} else if mode == "secret-header" && !server.secrets.exists(reference) {
			value, err := randomURLToken(32)
			if err != nil {
				return nil, err
			}
			pending = append(pending, pendingEntitySecret{reference: reference, value: value})
		}
		if mode == "secret-header" {
			deployment["origin_header_secret_ref"] = reference
			if _, exists := deployment["origin_header_name"]; !exists {
				deployment["origin_header_name"] = "X-SB-Origin"
			}
		}
		prepared = append(prepared, deployment)
	}
	item["cdn_deployments"] = prepared
	return pending, nil
}

func generateRealityKeypair() (string, string, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	encode := base64.RawURLEncoding.EncodeToString
	return encode(privateKey.Bytes()), encode(privateKey.PublicKey().Bytes()), nil
}

func generateMLDSA65() (string, string, error) {
	output, err := runXrayKeyCommand("mldsa65")
	if err != nil {
		return "", "", err
	}
	return parseMLDSA65Output(output)
}

func parseMLDSA65Output(output string) (string, string, error) {
	seed, verify := mldsaSeedPattern.FindStringSubmatch(output), mldsaVerifyPattern.FindStringSubmatch(output)
	if len(seed) != 2 || len(verify) != 2 {
		return "", "", errors.New("Xray mldsa65 returned an unsupported output format")
	}
	return seed[1], verify[1], nil
}

func generateVLESSEncryption(authentication string) (string, string, error) {
	if authentication != "mlkem768" && authentication != "x25519" {
		return "", "", errors.New("unsupported VLESS Encryption authentication")
	}
	output, err := runXrayKeyCommand("vlessenc")
	if err != nil {
		return "", "", err
	}
	return parseVLESSEncryptionOutput(output, authentication)
}

func parseVLESSEncryptionOutput(output, authentication string) (string, string, error) {
	if authentication != "mlkem768" && authentication != "x25519" {
		return "", "", errors.New("unsupported VLESS Encryption authentication")
	}
	wanted := "ML-KEM"
	if authentication == "x25519" {
		wanted = "X25519"
	}
	for _, pair := range vlessEncPairPattern.FindAllStringSubmatch(output, -1) {
		if len(pair) == 4 && strings.Contains(strings.ToLower(pair[1]), strings.ToLower(wanted)) {
			return pair[2], pair[3], nil
		}
	}
	return "", "", errors.New("Xray vlessenc returned an unsupported output format")
}

func runXrayKeyCommand(argument string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	binary := strings.TrimSpace(os.Getenv("SB_XRAY_BIN"))
	if binary == "" {
		binary = "xray"
	}
	command := exec.CommandContext(ctx, binary, argument)
	command.Stdin = nil
	output := &limitedWriter{remaining: 64 << 10}
	command.Stdout, command.Stderr = output, output
	if err := command.Run(); err != nil {
		return "", fmt.Errorf("Xray %s failed: %w", argument, err)
	}
	return stripANSI(output.String()), nil
}

func stripANSI(value string) string {
	return ansiEscapePattern.ReplaceAllString(value, "")
}

func randomHex(size int) (string, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func popBool(item map[string]any, key string) bool {
	value, _ := item[key].(bool)
	delete(item, key)
	return value
}

func visibleSecret(value string, minimum, maximum int) bool {
	if len(value) < minimum || len(value) > maximum {
		return false
	}
	return strings.IndexFunc(value, func(character rune) bool { return character < 33 }) < 0
}
