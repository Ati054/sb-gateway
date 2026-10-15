package rulesets

import (
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type StreamFetch func(name string) (io.ReadCloser, error)

func stringFetcher(fetch Fetch) StreamFetch {
	return func(name string) (io.ReadCloser, error) {
		body, err := fetch(name)
		if err != nil {
			return nil, err
		}
		return io.NopCloser(strings.NewReader(body)), nil
	}
}

func HTTPStreamFetch(timeout time.Duration) StreamFetch {
	client := &http.Client{Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("rule-set download redirects are not allowed")
	}}
	return func(name string) (io.ReadCloser, error) {
		if !upstreamNamePattern.MatchString(name) {
			return nil, errors.New("invalid upstream rule-set name")
		}
		target := upstreamBase + url.PathEscape(name)
		if geoIPNamePattern.MatchString(name) {
			target = "https://raw.githubusercontent.com/Loyalsoldier/geoip/release/text/" + url.PathEscape(strings.TrimPrefix(name, "geoip-")) + ".txt"
		}
		parsed, err := url.Parse(target)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "raw.githubusercontent.com" {
			return nil, errors.New("rule-set source is outside the trusted host")
		}
		request, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			return nil, err
		}
		request.Header.Set("Accept", "text/plain")
		request.Header.Set("User-Agent", "sb-gateway-ruleset-updater/1.0")
		response, err := client.Do(request)
		if err != nil {
			return nil, errors.New("rule-set source is unavailable")
		}
		if response.StatusCode != http.StatusOK || response.ContentLength > maxSourceBytes {
			response.Body.Close()
			return nil, errors.New("rule-set source is unavailable or exceeds the size limit")
		}
		return response.Body, nil
	}
}
