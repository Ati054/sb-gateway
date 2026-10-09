package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"testing"
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
