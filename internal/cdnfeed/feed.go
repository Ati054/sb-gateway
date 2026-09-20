// Package cdnfeed contains only provider-published origin address feeds. It
// never derives an allowlist from DNS, ASN ownership, or edge delivery IPs.
package cdnfeed

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const MaxBytes = 1 << 20
const Interval = 15 * time.Minute

type Provider struct{ ID, URL, Format string }

var providers = []Provider{
	{"cloudflare", "https://www.cloudflare.com/ips-v4", "plain"},
	{"gcore", "https://api.gcore.com/cdn/public-net-list", "addresses"},
	{"edgecenter", "https://api.edgecenter.ru/cdn/public_net_list", "addresses"},
	{"yandex", "https://tech.cdn.yandex.net/prefixes/yc.json", "prefixes"},
	{"beeline", "https://api-cdn.beelinecloud.ru/app/nodes/v2/ip2origin/?with_extra_zones=true", "origin-nodes"},
	{"timeweb", "https://cdn-api.timeweb.cloud/app/nodes/v2/ip2origin/?with_extra_zones=true", "origin-nodes"},
}

func Lookup(id string) (Provider, bool) {
	for _, p := range providers {
		if p.ID == strings.ToLower(strings.TrimSpace(id)) {
			return p, true
		}
	}
	return Provider{}, false
}

// Cloudflare retains its standalone RouterOS updater for compatibility with
// installations where the container is temporarily unavailable.
func Supports(id string) bool {
	_, ok := Lookup(id)
	return ok || strings.EqualFold(strings.TrimSpace(id), "cloudflare")
}

func ListName(id string) string {
	if strings.EqualFold(strings.TrimSpace(id), "cloudflare") {
		return "SB_CLOUDFLARE_V4"
	}
	if p, ok := Lookup(id); ok {
		return "SB_CDN_" + strings.ToUpper(p.ID) + "_V4"
	}
	return ""
}

type Fetcher func(context.Context, string) ([]string, error)

func NewFetcher() Fetcher {
	// Direct HTTPS, verified certificates, no environment proxy, redirects,
	// credentials, or user-controlled URLs.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("CDN feed redirect rejected") },
	}
	return func(ctx context.Context, id string) ([]string, error) {
		p, ok := Lookup(id)
		if !ok {
			return nil, errors.New("no official CDN origin feed adapter")
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, p.URL, nil)
		if err != nil {
			return nil, err
		}
		response, err := client.Do(request)
		if err != nil {
			return nil, fmt.Errorf("CDN feed %s HTTPS request failed: %w", id, err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("CDN feed %s HTTP %d", id, response.StatusCode)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
		if err != nil {
			return nil, err
		}
		return Parse(p, body)
	}
}

func Parse(p Provider, body []byte) ([]string, error) {
	if len(body) == 0 || len(body) > MaxBytes {
		return nil, errors.New("CDN feed size is invalid")
	}
	var values []string
	switch p.Format {
	case "plain":
		values = strings.Fields(string(body))
	case "addresses":
		var data struct {
			Addresses []string `json:"addresses"`
			IPv6      []string `json:"addresses_v6"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, err
		}
		if len(data.Addresses) == 0 {
			return nil, errors.New("CDN feed has no IPv4 addresses")
		}
		values = append(data.Addresses, data.IPv6...)
	case "prefixes":
		var data struct {
			Prefixes []string `json:"prefixes"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, err
		}
		values = data.Prefixes
	case "origin-nodes":
		var data struct {
			Status string              `json:"status"`
			Data   []map[string]string `json:"data"`
		}
		if err := json.Unmarshal(body, &data); err != nil {
			return nil, err
		}
		// The published OpenAPI says Completed; both live APIs return OK.
		if data.Status != "Completed" && data.Status != "OK" {
			return nil, errors.New("CDN origin feed did not complete")
		}
		for _, row := range data.Data {
			found := false
			for _, key := range []string{"IPv4_subnet", "IPv6_subnet"} {
				if value, ok := row[key]; ok {
					values = append(values, value)
					found = true
				}
			}
			if !found {
				return nil, errors.New("CDN origin feed row has no subnet")
			}
		}
	default:
		return nil, errors.New("unsupported CDN feed format")
	}
	return Validate(values)
}

// Validate rejects the entire feed on a malformed/private/overbroad entry.
// IPv6 is validated too, but current public RouterOS ingress is IPv4-only.
func Validate(values []string) ([]string, error) {
	if len(values) == 0 || len(values) > 8192 {
		return nil, errors.New("CDN feed entry count is invalid")
	}
	unique := map[string]bool{}
	for _, value := range values {
		p, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, errors.New("CDN feed contains an invalid CIDR")
		}
		a := p.Addr()
		if a.Is4In6() || !a.IsGlobalUnicast() || a.IsPrivate() || p.Bits() < 8 || (!a.Is4() && p.Bits() < 16) {
			return nil, errors.New("CDN feed contains a non-public or overbroad CIDR")
		}
		for _, reserved := range []string{"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/3", "2001:db8::/32", "fc00::/7", "fe80::/10"} {
			if p.Overlaps(netip.MustParsePrefix(reserved)) {
				return nil, errors.New("CDN feed overlaps a reserved network")
			}
		}
		if a.Is4() {
			unique[p.Masked().String()] = true
		}
	}
	if len(unique) == 0 || len(unique) > 4096 {
		return nil, errors.New("CDN feed IPv4 count is invalid")
	}
	result := make([]string, 0, len(unique))
	for value := range unique {
		result = append(result, value)
	}
	sort.Strings(result)
	return result, nil
}
