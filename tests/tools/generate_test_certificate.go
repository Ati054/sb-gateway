// Command generate_test_certificate creates a short-lived localhost
// certificate used only by the reproducible Nginx configuration check.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"math/big"
	"net"
	"os"
	"time"
)

func main() {
	certificatePath := flag.String("cert", "", "PEM certificate output path")
	keyPath := flag.String("key", "", "PEM private-key output path")
	flag.Parse()
	if *certificatePath == "" || *keyPath == "" {
		panic("-cert and -key are required")
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	writePEM(*certificatePath, "CERTIFICATE", der, 0o600)
	writePEM(*keyPath, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), 0o600)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		panic(err)
	}
	if err := pem.Encode(file, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = file.Close()
		panic(err)
	}
	if err := file.Close(); err != nil {
		panic(err)
	}
}
