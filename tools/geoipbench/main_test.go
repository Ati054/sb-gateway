package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
)

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "core")
	for _, body := range [][]byte{nil, []byte("core"), bytes.Repeat([]byte("bounded hash input"), 100000)} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
		got, err := fileSHA256(path)
		want := sha256.Sum256(body)
		if err != nil || got != hex.EncodeToString(want[:]) {
			t.Fatalf("digest=%q err=%v", got, err)
		}
	}
	if _, err := fileSHA256(path + "-missing"); err == nil {
		t.Fatal("missing input was accepted")
	}
}

func TestEncodeGeoIPWireFormat(t *testing.T) {
	got, err := encodeGeoIP([]string{"192.0.2.7/24", "2001:db8::1/128"})
	if err != nil {
		t.Fatal(err)
	}
	// GeoIPList.entry -> GeoIP(code=RU, CIDR(ip,prefix)); host bits are masked.
	want, err := hex.DecodeString("0a250a02525512080a04c0000200101812150a1020010db8000000000000000000000001108001")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("unexpected GeoIP protobuf: %x, want %x", got, want)
	}
}

func TestEncodeGeoIPRejectsInvalidPrefix(t *testing.T) {
	for _, s := range []string{"", "not-an-ip", "192.0.2.1/33", "2001:db8::/129"} {
		if _, err := encodeGeoIP([]string{s}); err == nil {
			t.Fatalf("accepted %q", s)
		}
	}
}

func TestLoopbackMarkerChecksRoute(t *testing.T) {
	l, err := echoMarker('M')
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := marker(c, 'M'); err != nil {
		t.Fatal(err)
	}
	if err := marker(c, 'N'); err == nil {
		t.Fatal("wrong route marker accepted")
	}
}

func TestManagedCleanupAllowsAlreadyPrunedGeneration(t *testing.T) {
	for _, earlierCleanup := range []bool{false, true} {
		t.Run(map[bool]string{false: "old-generation-present", true: "old-generation-already-pruned"}[earlierCleanup], func(t *testing.T) {
			root := t.TempDir()
			publish := func(prefix string) string {
				ref, err := geoipasset.Publish(root, "geoip-ru", []byte(`{"rules":[{"ip_cidr":["`+prefix+`"]}]}`))
				if err != nil {
					t.Fatal(err)
				}
				return ref
			}
			active := publish("198.18.0.1/32")
			if !earlierCleanup {
				publish("198.18.0.2/32")
			}
			publish("198.18.0.3/32")
			entries, err := os.ReadDir(root)
			if err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			for _, entry := range entries {
				if err := os.Chtimes(filepath.Join(root, entry.Name()), now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
					t.Fatal(err)
				}
			}
			live := []byte(`{"ip":["` + active + `"]}`)
			removed, err := geoipasset.Prune(root, nil, nil, live, now)
			want := 2
			if earlierCleanup {
				want = 1
			}
			if err != nil || removed != want {
				t.Fatalf("removed=%d want=%d err=%v", removed, want, err)
			}
			if err := verifyManagedAssets(root, active); err != nil {
				t.Fatal(err)
			}
			extra := publish("198.18.0.4/32")
			if err := verifyManagedAssets(root, active); err == nil {
				t.Fatal("unexpected leftover accepted")
			}
			extra2 := publish("198.18.0.5/32")
			if err := verifyManagedAssets(root, active, extra2); err == nil {
				t.Fatal("unexpected leftover accepted alongside a retained asset")
			}
			if err := verifyManagedAssets(root, active, extra, extra2); err != nil {
				t.Fatal(err)
			}
			for _, ref := range []string{extra, extra2} {
				name, _ := geoipasset.ReferenceName(ref)
				if err := os.Remove(filepath.Join(root, name)); err != nil {
					t.Fatal(err)
				}
			}
			name, _ := geoipasset.ReferenceName(active)
			if err := os.Remove(filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
			if err := verifyManagedAssets(root, active); err == nil {
				t.Fatal("missing active asset accepted")
			}
		})
	}
}
