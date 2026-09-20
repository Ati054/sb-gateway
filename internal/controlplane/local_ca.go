package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"strings"
	"time"
)

const (
	localCARootValidityYears = 20
	localCALeafValidityYears = 10
)

type localCABundle struct {
	certificate     string
	privateKey      string
	rootCertificate string
	rootPrivateKey  string
}

func normalizeLocalCAServerName(value string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(value))
	name = strings.TrimSuffix(name, ".")
	if name == "" || net.ParseIP(name) != nil || strings.Contains(name, "*") ||
		!strings.Contains(name, ".") || !validReverseExportHostname(name) {
		return "", errors.New("local CA requires a concrete DNS SNI")
	}
	return name, nil
}

func generateLocalCABundle(serverName string, now time.Time) (localCABundle, error) {
	var result localCABundle
	name, err := normalizeLocalCAServerName(serverName)
	if err != nil {
		return result, err
	}
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return result, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return result, err
	}
	rootSerial, err := localCASerial()
	if err != nil {
		return result, err
	}
	leafSerial, err := localCASerial()
	if err != nil {
		return result, err
	}
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		return result, err
	}
	rootSubjectKeyID, err := localCASubjectKeyID(&rootKey.PublicKey)
	if err != nil {
		return result, err
	}
	leafSubjectKeyID, err := localCASubjectKeyID(&leafKey.PublicKey)
	if err != nil {
		return result, err
	}
	notBefore := now.UTC().Add(-24 * time.Hour)
	root := &x509.Certificate{
		SerialNumber:          rootSerial,
		Subject:               pkix.Name{CommonName: "MyRootCA-" + hex.EncodeToString(suffix)},
		NotBefore:             notBefore,
		NotAfter:              now.UTC().AddDate(localCARootValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          rootSubjectKeyID,
	}
	leaf := &x509.Certificate{
		SerialNumber:          leafSerial,
		Subject:               pkix.Name{CommonName: name},
		DNSNames:              []string{name},
		NotBefore:             notBefore,
		NotAfter:              now.UTC().AddDate(localCALeafValidityYears, 0, 0),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		SubjectKeyId:          leafSubjectKeyID,
		AuthorityKeyId:        rootSubjectKeyID,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, &rootKey.PublicKey, rootKey)
	if err != nil {
		return result, err
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		return result, err
	}
	rootKeyDER, err := x509.MarshalPKCS8PrivateKey(rootKey)
	if err != nil {
		return result, err
	}
	leafKeyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		return result, err
	}
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	result.rootCertificate = string(rootPEM)
	result.rootPrivateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: rootKeyDER}))
	result.certificate = strings.TrimSpace(string(leafPEM)) + "\n" + strings.TrimSpace(string(rootPEM))
	result.privateKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: leafKeyDER}))
	return result, nil
}

func validateLocalCABundle(bundle localCABundle, serverName string, now time.Time) error {
	name, err := normalizeLocalCAServerName(serverName)
	if err != nil {
		return err
	}
	rootBlock, _ := pem.Decode([]byte(bundle.rootCertificate))
	if rootBlock == nil || rootBlock.Type != "CERTIFICATE" {
		return errors.New("local CA certificate is invalid")
	}
	root, err := x509.ParseCertificate(rootBlock.Bytes)
	if err != nil || !root.IsCA || !root.BasicConstraintsValid {
		return errors.New("local CA certificate is invalid")
	}
	if _, err := x509.ParsePKCS8PrivateKey(pemBlockBytes(bundle.rootPrivateKey, "PRIVATE KEY")); err != nil {
		return errors.New("local CA private key is invalid")
	}
	if _, err := tlsCertificateMetadata(bundle.rootCertificate, bundle.rootPrivateKey); err != nil {
		return errors.New("local CA certificate and private key do not match")
	}
	pair, err := x509LeafPair(bundle.certificate, bundle.privateKey)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := pair.Verify(x509.VerifyOptions{DNSName: name, CurrentTime: now, Roots: roots}); err != nil {
		return errors.New("local CA does not validate the leaf certificate")
	}
	return nil
}

func x509LeafPair(certificatePEM, privateKeyPEM string) (*x509.Certificate, error) {
	metadata, err := tlsCertificateMetadata(certificatePEM, privateKeyPEM)
	if err != nil || metadata == nil {
		return nil, errors.New("TLS certificate and private key do not form a valid pair")
	}
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("TLS certificate is invalid")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, errors.New("TLS certificate is invalid")
	}
	return certificate, nil
}

func pemBlockBytes(value, expectedType string) []byte {
	block, _ := pem.Decode([]byte(value))
	if block == nil || block.Type != expectedType {
		return nil
	}
	return block.Bytes
}

func localCASerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, limit)
	if err == nil && serial.Sign() == 0 {
		serial.SetInt64(1)
	}
	return serial, err
}

func localCASubjectKeyID(publicKey any) ([]byte, error) {
	encoded, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return append([]byte(nil), digest[:20]...), nil
}
