package geoipasset

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
)

var siteNamePattern = regexp.MustCompile(`^sb-geosite-([a-f0-9]{64})\.dat$`)

// PublishDomains uses the native GeoSite protobuf schema, without depending on
// Xray in the portable renderer. Immutable filenames also key its matcher cache.
func PublishDomains(root string, fields map[string][]string) (string, error) {
	site := protowire.AppendString(protowire.AppendTag(nil, 1, protowire.BytesType), "DOMAINS")
	count := 0
	for _, field := range []struct {
		name string
		kind uint64
	}{{"domain_keyword", 0}, {"domain_regex", 1}, {"domain_suffix", 2}, {"domain", 3}} {
		for _, value := range fields[field.name] {
			if value == "" || len(value) > 1024 {
				return "", errors.New("invalid GeoSite domain")
			}
			if field.kind == 1 {
				if _, err := regexp.Compile(value); err != nil {
					return "", errors.New("invalid GeoSite regular expression")
				}
			}
			if field.kind != 1 {
				value = strings.ToLower(value)
			}
			domain := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), field.kind)
			domain = protowire.AppendString(protowire.AppendTag(domain, 2, protowire.BytesType), value)
			site = protowire.AppendBytes(protowire.AppendTag(site, 2, protowire.BytesType), domain)
			count++
			if count > 250_000 || len(site) > 8<<20 {
				return "", errors.New("GeoSite set exceeds the limit")
			}
		}
	}
	if count == 0 {
		return "", errors.New("empty GeoSite set")
	}
	data := protowire.AppendBytes(protowire.AppendTag(nil, 1, protowire.BytesType), site)
	if len(data) > 8<<20 {
		return "", errors.New("GeoSite set exceeds the limit")
	}
	sum := sha256.Sum256(data)
	return publishEncoded(root, "sb-geosite-"+hex.EncodeToString(sum[:])+".dat", "domains", data)
}
