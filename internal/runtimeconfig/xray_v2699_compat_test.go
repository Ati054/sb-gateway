package runtimeconfig

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestXrayV2699RendererCompatibility runs only when XRAY_TEST_BINARY names an
// official Xray 26.9.9 executable. It verifies syntax of complete renderer
// output; it deliberately does not claim a Hysteria or Reverse data-plane
// handshake.
func TestXrayV2699RendererCompatibility(t *testing.T) {
	binary := strings.TrimSpace(os.Getenv("XRAY_TEST_BINARY"))
	if binary == "" {
		t.Skip("set XRAY_TEST_BINARY to an official Xray 26.9.9 binary")
	}
	contextWithDeadline, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	version, err := exec.CommandContext(contextWithDeadline, binary, "version").CombinedOutput()
	if err != nil || !strings.Contains(string(version), "Xray 26.9.9") {
		t.Fatalf("XRAY_TEST_BINARY must be Xray 26.9.9: %v: %s", err, version)
	}

	certificatePath, keyPath := writeXrayCompatCertificate(t)
	for _, scenario := range []struct {
		name        string
		quic        map[string]any
		masquerade  map[string]any
		wantQUICKey []string
		noForwarded bool
	}{
		{
			name: "new fields omitted by default",
			quic: map[string]any{
				"congestion": "brutal", "brutal_up_mbps": 100, "brutal_down_mbps": 100,
			},
			masquerade:  map[string]any{"type": "proxy", "url": "http://127.0.0.1:8080/"},
			noForwarded: true,
		},
		{
			name: "explicit local proxy controls",
			quic: map[string]any{
				"congestion": "brutal", "brutal_up_mbps": 100, "brutal_down_mbps": 100,
				"brutal_disable_loss_compensation": true, "disable_gso": true, "disable_stateless_reset": true,
			},
			masquerade:  map[string]any{"type": "proxy", "url": "http://127.0.0.1:8080/", "x_forwarded": true},
			wantQUICKey: []string{"brutalDisableLossCompensation", "disableGSO", "disableStatelessReset"},
		},
		{
			name: "website stays isolated from local proxy forwarding",
			quic: map[string]any{
				"congestion": "brutal", "brutal_up_mbps": 100, "brutal_down_mbps": 100,
				"brutal_disable_loss_compensation": true, "disable_gso": true, "disable_stateless_reset": true,
			},
			masquerade:  map[string]any{"type": "website", "url": "https://example.test/"},
			wantQUICKey: []string{"brutalDisableLossCompensation", "disableGSO", "disableStatelessReset"},
			noForwarded: true,
		},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			candidate := xrayV2699RendererCandidate(t, certificatePath, keyPath, scenario.quic, scenario.masquerade)
			hysteria := findXraySourceRule(objectSlice(candidate.Config["inbounds"]), func(inbound map[string]any) bool {
				return inbound["tag"] == "hysteria2-direct"
			})
			if hysteria == nil {
				t.Fatal("renderer omitted Hysteria inbound")
			}
			quic := objectValue(objectValue(objectValue(hysteria["streamSettings"])["finalmask"])["quicParams"])
			for _, key := range scenario.wantQUICKey {
				if quic[key] != true {
					t.Fatalf("renderer omitted %s: %#v", key, quic)
				}
			}
			masquerade := objectValue(objectValue(objectValue(hysteria["streamSettings"])["hysteriaSettings"])["masquerade"])
			if scenario.noForwarded {
				if _, exists := masquerade["xForwarded"]; exists {
					t.Fatalf("unexpected xForwarded in %s: %#v", scenario.name, masquerade)
				}
			}
			body, marshalErr := MarshalXrayCandidate(candidate.Config)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			configPath := filepath.Join(t.TempDir(), "xray.json")
			if writeErr := os.WriteFile(configPath, body, 0o600); writeErr != nil {
				t.Fatal(writeErr)
			}
			output, runErr := exec.CommandContext(contextWithDeadline, binary, "run", "-test", "-config", configPath).CombinedOutput()
			if runErr != nil {
				t.Fatalf("Xray 26.9.9 rejected renderer output: %v: %s", runErr, output)
			}
		})
	}

	clientConfig := map[string]any{
		"log": map[string]any{"loglevel": "warning"},
		"outbounds": []any{map[string]any{
			"tag": "hysteria-hop", "protocol": "hysteria",
			"settings": map[string]any{"version": 2, "address": "hy2.example.test", "port": 20443},
			"streamSettings": map[string]any{
				"network": "hysteria", "security": "tls",
				"hysteriaSettings": map[string]any{"version": 2, "auth": "test-password"},
				"tlsSettings":      map[string]any{"serverName": "hy2.example.test"},
				"finalmask": map[string]any{"udp": []any{
					map[string]any{"type": "udphop", "settings": map[string]any{
						"mode": "intervalRemote", "interval": "15-45", "remotePorts": "20000-20100",
					}},
					map[string]any{"type": "salamander", "settings": map[string]any{"password": "obfs-password"}},
				}},
			},
		}},
	}
	body, err := json.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "xray-client-udphop.json")
	if err := os.WriteFile(configPath, body, 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := exec.CommandContext(contextWithDeadline, binary, "run", "-test", "-config", configPath).CombinedOutput()
	if err != nil {
		t.Fatalf("Xray 26.9.9 rejected UDP hopping client profile: %v: %s", err, output)
	}
}

func xrayV2699RendererCandidate(t *testing.T, certificatePath, keyPath string, quic, masquerade map[string]any) (result XrayCandidateArtifacts) {
	t.Helper()
	config := map[string]any{
		"system": map[string]any{"networking": map[string]any{
			"tun_address": "198.18.0.1/30", "container_address": "198.18.0.2/29", "tun_mtu": 1400,
			"tun_stack": "system", "remote_ipv6_mode": "proxy_only",
		}},
		"dns": map[string]any{
			"internal_server": "192.168.3.1",
			"direct_resolver": map[string]any{"provider": "cloudflare", "protocol": "doh"},
			"vpn_resolver":    map[string]any{"provider": "cloudflare", "protocol": "doh"},
		},
		"tls_profiles": []any{map[string]any{
			"id": "tls-main", "enabled": true, "certificate_secret_ref": "tls/cert", "private_key_secret_ref": "tls/key",
		}},
		"transports": []any{
			map[string]any{"id": "ws-public", "enabled": true, "kind": "ws", "path_secret_ref": "transport/ws-path"},
			map[string]any{"id": "xhttp-public", "enabled": true, "kind": "xhttp", "path_secret_ref": "transport/xhttp-path", "mode": "auto"},
			map[string]any{
				"id": "hysteria-public", "enabled": true, "kind": "hysteria2", "listen_port": 8443,
				"tls_profile_id": "tls-main", "xray_hysteria": map[string]any{
					"udp_idle_timeout": 60, "quic_params": quic, "masquerade": masquerade,
				},
			},
		},
		"remote_users": []any{map[string]any{
			"id": "phone", "enabled": true, "uuid_secret_ref": "user/phone", "hysteria2_password_secret_ref": "user/phone-hysteria", "policy_id": "europe",
		}},
		"reverse_vless_exits": []any{map[string]any{
			"id": "home", "enabled": true, "uuid_secret_ref": "reverse/home", "transport_ids": []any{"ws-public", "xhttp-public"},
		}},
		"policies": []any{map[string]any{
			"id": "europe", "enabled": true, "mode": "priority", "selection_order": []any{"reverse:home"},
		}},
	}
	secrets := inboundSecretReader(map[string]string{
		"transport/ws-path": "/ws", "transport/xhttp-path": "/xhttp",
		"user/phone": "018f7b76-7cdb-4a08-9f0a-7514a1d90a11", "user/phone-hysteria": "hysteria-password",
		"reverse/home": "123e4567-e89b-42d3-a456-426614174000",
	})
	paths := func(reference string) (string, error) {
		switch reference {
		case "tls/cert":
			return certificatePath, nil
		case "tls/key":
			return keyPath, nil
		default:
			return "", fmt.Errorf("unexpected secret path %q", reference)
		}
	}
	result, err := BuildXrayCandidateFromSchema(config, nil, secrets, paths, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func writeXrayCompatCertificate(t *testing.T) (string, string) {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "compat.example.test"},
		DNSNames: []string{"compat.example.test"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	certificate, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	privateKeyBody, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	certificatePath, keyPath := filepath.Join(directory, "cert.pem"), filepath.Join(directory, "key.pem")
	if err := os.WriteFile(certificatePath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBody}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certificatePath, keyPath
}
