package controlplane

import (
	"net/http"
	"net/netip"
	"testing"
)

func TestClientDirectPrivateCIDRsExcludeRemoteLANWithoutLosingLocalLAN(t *testing.T) {
	direct := clientDirectPrivateCIDRs([]string{
		"192.168.90.0/24",
		"192.168.50.0/24",
		"10.77.0.0/16",
		"fd42:99::/48",
	})

	for _, test := range []struct {
		address string
		want    bool
	}{
		{address: "192.168.90.1", want: false},
		{address: "192.168.50.250", want: false},
		{address: "10.77.10.1", want: false},
		{address: "fd42:99::1", want: false},
		{address: "192.168.1.1", want: true},
		{address: "10.78.0.1", want: true},
		{address: "fd42:100::1", want: true},
		{address: "127.0.0.1", want: true},
	} {
		address := netip.MustParseAddr(test.address)
		got := false
		for _, value := range direct {
			if netip.MustParsePrefix(value).Contains(address) {
				got = true
				break
			}
		}
		if got != test.want {
			t.Fatalf("direct private membership for %s = %v, want %v; ranges=%v", test.address, got, test.want, direct)
		}
	}
}

func TestHappManagedTunnelHeadersCaptureRemotePrivateNetworks(t *testing.T) {
	header := make(http.Header)
	document := &clientProfileDocument{
		format: "array", capturesRemoteNetworks: true, happProviderID: "provider-123",
		happIncludeAllNetworks: true, happExcludeLocal: true, happExcludeAPNs: true,
	}
	setHappManagedTunnelHeaders(header, "Happ/4.12.0 iOS", document)

	if header.Get("include-all-networks-enable") != "true" ||
		header.Get("exclude-local-networks-enable") != "true" ||
		header.Get("exclude-apns-enable") != "true" ||
		header.Get("xray-tun-enable") != "true" {
		t.Fatalf("Happ tunnel headers = %#v", header)
	}
	if got := header.Get("providerid"); got != "provider-123" {
		t.Fatalf("Happ provider ID = %q", got)
	}
	if got := header.Get("exclude-routes-set"); got != "127.0.0.0/8, ::1/128" {
		t.Fatalf("Happ excluded routes = %q", got)
	}
	portable := make(http.Header)
	setHappManagedTunnelHeaders(portable, "Happ/4.12.0 iOS", &clientProfileDocument{
		format: "links", capturesRemoteNetworks: true, happProviderID: "provider-123",
		happIncludeAllNetworks: false, happExcludeLocal: false, happExcludeAPNs: false,
	})
	if portable.Get("providerid") != "provider-123" ||
		portable.Get("include-all-networks-enable") != "false" ||
		portable.Get("exclude-local-networks-enable") != "false" ||
		portable.Get("exclude-apns-enable") != "false" ||
		portable.Get("xray-tun-enable") != "" ||
		portable.Get("exclude-routes-set") != "" {
		t.Fatalf("Happ portable subscription headers = %#v", portable)
	}

	for _, test := range []struct {
		name      string
		userAgent string
		document  *clientProfileDocument
	}{
		{name: "other client", userAgent: "V2Box/1.5.7 iOS", document: document},
		{name: "provider ID missing", userAgent: "Happ/4.12.0 iOS", document: &clientProfileDocument{format: "array", capturesRemoteNetworks: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			header := make(http.Header)
			setHappManagedTunnelHeaders(header, test.userAgent, test.document)
			if len(header) != 0 {
				t.Fatalf("unexpected managed tunnel headers = %#v", header)
			}
		})
	}
}
