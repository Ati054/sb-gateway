package controlplane

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestSubscriptionIDsDoNotDependOnFeedOrder(t *testing.T) {
	links := []string{"vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@one.example.test:443?security=tls&type=ws#Warsaw", "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@one.example.test:443?security=reality&type=tcp&sni=one.example.test&pbk=public#Warsaw", "hy2://password@two.example.test:443", "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@three.example.test:443?security=tls"}
	a, err := parseProxySubscription([]byte(strings.Join(links, "\n")), 10)
	if err != nil {
		t.Fatal(err)
	}
	for i, j := 0, len(links)-1; i < j; i, j = i+1, j-1 {
		links[i], links[j] = links[j], links[i]
	}
	b, err := parseProxySubscription([]byte(strings.Join(links, "\n")), 10)
	if err != nil {
		t.Fatal(err)
	}
	for i, n := range a {
		if n["id"] != b[len(b)-1-i]["id"] {
			t.Fatal("feed order changed node identity")
		}
	}
	if a[0]["id"] == a[1]["id"] {
		t.Fatal("different protocols merged")
	}
}

func TestDuplicateEndpointAccountsRemainDistinctAcrossReordering(t *testing.T) {
	a := "hy2://password-a@same.example.test:443#Same"
	b := "hy2://password-b@same.example.test:443#Same"
	first, err := parseProxySubscription([]byte(a+"\n"+b), 10)
	if err != nil {
		t.Fatal(err)
	}
	second, err := parseProxySubscription([]byte(b+"\n"+a), 10)
	if err != nil {
		t.Fatal(err)
	}
	if first[0]["id"] == first[1]["id"] || first[0]["id"] != second[1]["id"] || first[1]["id"] != second[0]["id"] {
		t.Fatal("duplicate endpoint identities depend on ordering")
	}
}

func TestParseProxySubscriptionNormalizesBase64VLESSAndHysteria(t *testing.T) {
	const uuid = "2f1c08fc-3f43-4e95-8f57-f8bded750a1a"
	plain := "vless://" + uuid + "@de.example.test:443?security=tls&type=grpc&serviceName=edge#%F0%9F%87%A9%F0%9F%87%AA%20Berlin\n" +
		"hy2://strong-password@fi.example.test:8443?sni=fi.example.test&obfs=salamander&obfs-password=cover&upmbps=20#Helsinki"
	body := []byte(base64.RawStdEncoding.EncodeToString([]byte(plain)))
	nodes, err := parseProxySubscription(body, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	if nodes[0]["protocol"] != "vless" || nodes[0]["country"] != "DE" || nodes[0]["city"] != "🇩🇪 Berlin" || nodes[0]["_uuid"] != uuid {
		t.Fatalf("VLESS node = %#v", nodes[0])
	}
	if nodes[1]["protocol"] != "hysteria2" || nodes[1]["_password"] != "strong-password" || nodes[1]["_obfs_password"] != "cover" || nodes[1]["up_mbps"] != 20 {
		t.Fatalf("Hysteria node = %#v", nodes[1])
	}
}

func TestParseProxySubscriptionKeepsValidNodesAndHonorsProviderTLSPins(t *testing.T) {
	const valid = "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@safe.example.test:443?security=tls#Safe"
	const pin = "ea1f9d54f3955fa404e7fd3135319e93b4b7d2c719bdfd249aed20f470de131c"
	nodes, err := parseProxySubscription([]byte("vless://bad@invalid:443\n"+valid), 10)
	if err != nil || len(nodes) != 1 {
		t.Fatalf("mixed nodes = %#v, err=%v", nodes, err)
	}
	providerNodes, err := parseProxySubscription([]byte(
		"vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@provider.example.test:443?security=tls&type=grpc&serviceName=edge&fp=edge&pcs=EA:1F:9D:54:F3:95:5F:A4:04:E7:FD:31:35:31:9E:93:B4:B7:D2:C7:19:BD:FD:24:9A:ED:20:F4:70:DE:13:1C&vcn=provider.example.test#Provider-gRPC\n"+
			"hy2://secret@unsafe.example.test:443?allowInsecure=1&pinSHA256="+pin+"&vcn=unsafe.example.test&fp=chrome&alpn=h3#Provider-Hysteria",
	), 10)
	if err != nil || len(providerNodes) != 2 {
		t.Fatalf("provider TLS nodes = %#v, err=%v", providerNodes, err)
	}
	for _, node := range providerNodes {
		tls, _ := node["tls"].(map[string]any)
		if tls["pinned_peer_cert_sha256"] != pin || tls["insecure"] == true || node["_provider_tls_insecure"] == true {
			t.Fatalf("provider TLS pin was not retained safely: %#v", node)
		}
	}
	grpcTLS := providerNodes[0]["tls"].(map[string]any)
	if grpcTLS["verify_peer_cert_by_name"] != "provider.example.test" || grpcTLS["utls"].(map[string]any)["fingerprint"] != "edge" {
		t.Fatalf("VLESS TLS client settings were not retained: %#v", grpcTLS)
	}
	hysteriaTLS := providerNodes[1]["tls"].(map[string]any)
	if hysteriaTLS["verify_peer_cert_by_name"] != "unsafe.example.test" || hysteriaTLS["utls"].(map[string]any)["fingerprint"] != "chrome" || len(hysteriaTLS["alpn"].([]any)) != 1 {
		t.Fatalf("Hysteria TLS client settings were not retained: %#v", hysteriaTLS)
	}
	if _, err = parseProxySubscription([]byte("hy2://secret@unsafe.example.test:443?insecure=1"), 10); err == nil {
		t.Fatal("legacy insecure Hysteria node without a pin was accepted")
	}
}

func TestParseProxySubscriptionEnforcesNodeLimit(t *testing.T) {
	const link = "vless://2f1c08fc-3f43-4e95-8f57-f8bded750a1a@safe.example.test:443?security=tls#Safe"
	if _, err := parseProxySubscription([]byte(link+"\n"+link), 1); err == nil {
		t.Fatal("node limit was not enforced")
	}
}
