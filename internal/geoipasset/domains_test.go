package geoipasset

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGeoSitePublicationVerificationAndRetention(t *testing.T) {
	root := t.TempDir()
	ref, err := PublishDomains(root, map[string][]string{"domain_suffix": {"example.test"}, "domain": {"exact.test"}, "domain_regex": {"^img[0-9]+\\.test$"}, "domain_keyword": {"video"}})
	if err != nil {
		t.Fatal(err)
	}
	name, ok := ReferenceName(ref)
	if !ok || !IsManagedName(name) {
		t.Fatal("asset cannot be retained or restored")
	}
	if err := Verify(root, ref); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(root, name), old, old); err != nil {
		t.Fatal(err)
	}
	if count, err := Prune(root, nil, nil, []byte(`{"routing":{"rules":[{"domain":["`+ref+`"]}]}}`), time.Now()); err != nil || count != 0 {
		t.Fatal("active site pruned", count, err)
	}
	if count, err := Prune(root, nil, nil, []byte(`{}`), time.Now()); err != nil || count != 1 {
		t.Fatal("obsolete site not pruned", count, err)
	}
	if _, err := PublishDomains(root, map[string][]string{"domain_regex": {"["}}); err == nil {
		t.Fatal("invalid regex accepted")
	}
}

func TestGeoSiteConfigRejectsDamagedAsset(t *testing.T) {
	root := t.TempDir()
	ref, err := PublishDomains(root, map[string][]string{"domain": {"example.test"}})
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(root, "xray.json")
	if err := os.WriteFile(config, []byte(`{"routing":{"rules":[{"domain":["`+ref+`"]}]}}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyConfig(root, config); err != nil {
		t.Fatal(err)
	}
	name, _ := ReferenceName(ref)
	if err := os.WriteFile(filepath.Join(root, name), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyConfig(root, config); err == nil {
		t.Fatal("damaged domain asset passed startup validation")
	}
}
