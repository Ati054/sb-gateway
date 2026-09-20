package cdnfeed

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestProviderParsers(t *testing.T) {
	for _, tc := range []struct{ provider, body string }{
		{"cloudflare", "8.8.8.0/24\n"},
		{"gcore", `{"addresses":["8.8.8.1/24","8.8.8.0/24"],"addresses_v6":["2606:4700::/32"]}`},
		{"edgecenter", `{"addresses":["8.8.8.0/24"]}`},
		{"yandex", `{"prefixes":["8.8.8.0/24","2606:4700::/32"]}`},
		{"timeweb", `{"status":"OK","data":[{"IPv4_subnet":"8.8.8.0/24"},{"IPv6_subnet":"2606:4700::/32"}]}`},
		{"beeline", `{"status":"Completed","data":[{"IPv4_subnet":"8.8.8.0/24"}]}`},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			p, _ := Lookup(tc.provider)
			got, err := Parse(p, []byte(tc.body))
			if err != nil || !reflect.DeepEqual(got, []string{"8.8.8.0/24"}) {
				t.Fatalf("got %v, %v", got, err)
			}
		})
	}
}

func TestRejectEntireUntrustedFeed(t *testing.T) {
	p, _ := Lookup("gcore")
	for _, body := range []string{
		`{}`, `null`, `<html>error</html>`, `{"addresses":[]}`, `{"addresses":["8.8.8.0/24"]} trailing`,
		`{"addresses":["8.8.8.0/24","broken"]}`, `{"addresses":["8.8.8.0/24"],"addresses_v6":["broken"]}`,
		`{"addresses":["0.0.0.0/0"]}`, `{"addresses":["10.0.0.0/8"]}`, `{"addresses":["100.64.0.0/10"]}`,
		`{"addresses":["192.0.0.0/8"]}`, `{"addresses":["127.0.0.1/32"]}`, `{"addresses":["198.18.0.0/15"]}`,
		`{"addresses":["8.8.8.8"]}`, `{"addresses":["::ffff:8.8.8.8/128"]}`, strings.Repeat(" ", MaxBytes+1),
	} {
		if got, err := Parse(p, []byte(body)); err == nil || got != nil {
			t.Fatalf("unsafe feed accepted: %s", body[:min(len(body), 100)])
		}
	}
	for _, body := range []string{`{"status":"Error","data":[{"IPv4_subnet":"8.8.8.0/24"}]}`, `{"status":"OK","data":[{"IPv4_subnet":"8.8.8.0/24"},{}]}`} {
		p, _ := Lookup("timeweb")
		if _, err := Parse(p, []byte(body)); err == nil {
			t.Fatal("incomplete feed accepted")
		}
	}
}

func TestCapabilityBoundaries(t *testing.T) {
	for _, id := range []string{"cloudflare", "gcore", "edgecenter", "yandex", "beeline", "timeweb"} {
		if !Supports(id) || ListName(id) == "" {
			t.Fatal(id)
		}
	}
	for _, id := range []string{"vk", "cdnetworks", "custom", "https://127.0.0.1", `gcore"; /system/reboot`} {
		if Supports(id) || ListName(id) != "" {
			t.Fatal("unverified provider accepted:", id)
		}
	}
}

// Explicit opt-in; ordinary unit tests never depend on a provider or network.
func TestLiveOfficialFeeds(t *testing.T) {
	if os.Getenv("SB_TEST_LIVE_CDN_FEEDS") != "1" {
		t.Skip("live network check disabled")
	}
	fetch := NewFetcher()
	for _, p := range providers {
		t.Run(p.ID, func(t *testing.T) {
			values, err := fetch(context.Background(), p.ID)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("validated %d IPv4 networks", len(values))
		})
	}
}
