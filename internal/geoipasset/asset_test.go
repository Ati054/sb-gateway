package geoipasset

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/encoding/protowire"
)

func pack(prefix string) []byte {
	return []byte(`{"version":3,"rules":[{"ip_cidr":["` + prefix + `"]}]}`)
}

func TestEncodeWireFormatAndEveryPrefix(t *testing.T) {
	body := []byte(`{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24","2001:db8::1/128"]}]}`)
	got, err := Encode("geoip-ru", body)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("0a250a02525512080a04c0000200101812150a1020010db8000000000000000000000001108001")
	if !bytes.Equal(got, want) {
		t.Fatalf("protobuf changed: %x", got)
	}
	var prefixes []string
	for i := 0; i < 25094; i++ {
		prefixes = append(prefixes, fmt.Sprintf(`"10.%d.%d.0/24"`, i/256, i%256))
	}
	got, err = Encode("geoip-ru", []byte(`{"rules":[{"ip_cidr":[`+strings.Join(prefixes, ",")+`]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	_, _, n := protowire.ConsumeTag(got)
	entry, n := protowire.ConsumeBytes(got[n:])
	if n < 0 {
		t.Fatal("invalid wire entry")
	}
	count := 0
	for len(entry) > 0 {
		field, typ, n := protowire.ConsumeTag(entry)
		entry = entry[n:]
		if typ != protowire.BytesType {
			t.Fatal("invalid field type")
		}
		_, n = protowire.ConsumeBytes(entry)
		if n < 0 {
			t.Fatal("truncated entry")
		}
		entry = entry[n:]
		if field == 2 {
			count++
		}
	}
	if count != len(prefixes) {
		t.Fatalf("lost CIDRs: %d", count)
	}
}

func TestPublishImmutableConcurrentAndCorruption(t *testing.T) {
	root := t.TempDir()
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := Publish(root, "geoip-ru", pack("192.0.2.0/24")); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	files, err := os.ReadDir(root)
	if err != nil || len(files) != 1 {
		t.Fatalf("publication left temporary assets: %v %v", files, err)
	}
	ref, err := Publish(root, "geoip-ru", pack("192.0.2.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	name, valid := ReferenceName(ref)
	if !valid {
		t.Fatal(ref)
	}
	if err := Verify(root, ref); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, name), []byte("damaged"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Publish(root, "geoip-ru", pack("192.0.2.0/24")); err == nil {
		t.Fatal("overwrote corrupt immutable asset")
	}
	if err := Verify(root, ref); err == nil {
		t.Fatal("corrupt asset checksum was accepted")
	}
	got, _ := os.ReadFile(filepath.Join(root, name))
	if string(got) != "damaged" {
		t.Fatal("corrupt asset silently overwritten")
	}
}

func TestRejectInvalidPacksAndUnsafeReferences(t *testing.T) {
	for _, body := range []string{`null`, `{"rules":[]}`, `{"rules":[{"ip_cidr":["192.0.2.7/24"]}]}`, `{"rules":[{"ip_cidr":["::/129"]}]}`, `{"rules":[{"ip_cidr":["::/0"],"domain":["example.com"]}]}`, `{"rules":[{"ip_cidr":["::/0"]}]} {}`} {
		if _, err := Encode("geoip-ru", []byte(body)); err == nil {
			t.Fatalf("accepted %s", body)
		}
	}
	for _, ref := range []string{"ext:../../file:ru", "ext:sb-geoip-ru-" + strings.Repeat("a", 64) + ".dat:cn", "ext:/config/rulesets/file.dat:ru"} {
		if _, ok := ReferenceName(ref); ok {
			t.Fatal(ref)
		}
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "source"), pack("::/0"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "source"), filepath.Join(root, "geoip-ru.json")); err != nil {
		t.Skip(err)
	}
	if _, err := Ensure(root, "geoip-ru"); err == nil {
		t.Fatal("symlink accepted")
	}
}

func TestPruneRetainsLiveLKGApplyRollbackAndLease(t *testing.T) {
	root := t.TempDir()
	now := time.Now()
	var refs []string
	for i := 0; i < 6; i++ {
		ref, err := Publish(root, "geoip-ru", pack(fmt.Sprintf("192.0.2.%d/32", i)))
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
		if i != 5 {
			name, _ := ReferenceName(ref)
			if err := os.Chtimes(filepath.Join(root, name), now.Add(-time.Hour), now.Add(-time.Hour)); err != nil {
				t.Fatal(err)
			}
		}
	}
	config := func(ref string) []byte { return []byte(`{"routing":{"rules":[{"ip":["` + ref + `"]}]}}`) }
	active := filepath.Join(root, "active.json")
	lkg := filepath.Join(root, "lkg.json")
	candidates := filepath.Join(root, "candidates", "revision", ".previous-runtime")
	if err := os.MkdirAll(candidates, 0700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string][]byte{active: config(refs[0]), lkg: config(refs[1]), filepath.Join(candidates, "xray.json"): config(refs[3])} {
		if err := os.WriteFile(path, body, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "user.dat"), []byte("user"), 0600); err != nil {
		t.Fatal(err)
	}
	removed, err := Prune(root, []string{active, lkg}, []string{filepath.Join(root, "candidates")}, config(refs[2]), now)
	if err != nil || removed != 1 {
		t.Fatalf("cleanup=%d %v", removed, err)
	}
	for i, ref := range refs {
		name, _ := ReferenceName(ref)
		_, err := os.Stat(filepath.Join(root, name))
		if (err == nil) != (i != 4) {
			t.Fatalf("retention changed for %d: %v", i, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "user.dat")); err != nil {
		t.Fatal("deleted user file")
	}
	if removed, err := Prune(root, []string{active, lkg}, []string{filepath.Join(root, "candidates")}, config(refs[2]), now.Add(11*time.Minute)); err != nil || removed != 1 {
		t.Fatalf("expired lease=%d %v", removed, err)
	}
	for _, body := range []string{"broken", "", `{"routing":`, `{"routing":{}`, `{} {}`} {
		if err := os.WriteFile(active, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if removed, err := Prune(root, []string{active}, nil, nil, now.Add(time.Hour)); err == nil || removed != 0 {
			t.Fatalf("cleaned assets with incomplete retention roots %q: removed=%d err=%v", body, removed, err)
		}
	}
}
