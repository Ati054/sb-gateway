package controlplane

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

func registryCatalogRedirectStatus(status int) bool {
	return status == http.StatusMovedPermanently || status == http.StatusFound || status == http.StatusSeeOther || status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect
}

func validRegistryCatalogBlobURL(target *url.URL) bool {
	if target == nil || target.Scheme != "https" || target.User != nil || target.Opaque != "" || target.Fragment != "" || target.Hostname() == "" || len(target.String()) > 16<<10 || strings.HasSuffix(target.Host, ":") {
		return false
	}
	if literal, err := netip.ParseAddr(target.Hostname()); err == nil {
		return publicSubscriptionIP(literal) && literal.Zone() == ""
	}
	return true
}

// No registry bearer token, cookie, referer or client certificate crosses this
// boundary. Signed object URL query parameters are needed by CDNs, but are never
// included in returned errors or persisted metadata.
func (fetcher *registryCatalogFetcher) redirectedBlob(ctx context.Context, target *url.URL) (*http.Response, error) {
	client := fetcher.blobClient
	if client == nil {
		var err error
		client, err = newRegistryCatalogBlobClient(fetcher.client)
		if err != nil {
			return nil, err
		}
		fetcher.blobClient = client
	}
	copyClient := *client
	copyClient.Jar = nil
	copyClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	for hop := 0; hop < 2; hop++ {
		if !validRegistryCatalogBlobURL(target) {
			return nil, errRegistryCatalogCapability
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
		if err != nil {
			return nil, errRegistryCatalogCapability
		}
		request.Header.Set("Accept", "application/octet-stream, "+registryOCIConfig+", "+registryDockerConfig)
		request.Header.Set("Accept-Encoding", "identity")
		response, err := copyClient.Do(request)
		if err != nil {
			return nil, errRegistryCatalogCapability
		}
		if !registryCatalogRedirectStatus(response.StatusCode) {
			return response, nil
		}
		locationHeader := response.Header.Get("Location")
		next, parseErr := target.Parse(locationHeader)
		_ = response.Body.Close()
		if parseErr != nil || locationHeader == "" {
			return nil, errRegistryCatalogCapability
		}
		target = next
	}
	return nil, errRegistryCatalogCapability
}

func newRegistryCatalogBlobClient(original *http.Client) (*http.Client, error) {
	base, ok := original.Transport.(*http.Transport)
	if !ok {
		return nil, errRegistryCatalogCapability
	}
	transport := base.Clone()
	transport.Proxy = nil
	transport.ProxyConnectHeader = nil
	transport.GetProxyConnectHeader = nil
	//lint:ignore SA1019 Clear inherited legacy TLS dialing so it cannot bypass target pinning.
	transport.DialTLS = nil
	transport.DialTLSContext = nil
	transport.TLSNextProto = nil
	transport.DisableCompression = true
	transport.ResponseHeaderTimeout = 8 * time.Second
	transport.MaxResponseHeaderBytes = 32 << 10
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if transport.TLSClientConfig != nil {
		config = transport.TLSClientConfig.Clone()
	}
	if config.MinVersion < tls.VersionTLS12 {
		config.MinVersion = tls.VersionTLS12
	}
	config.ServerName = ""
	config.InsecureSkipVerify = false
	config.Certificates = nil
	config.GetClientCertificate = nil
	config.ClientSessionCache = nil
	config.VerifyConnection = nil
	config.VerifyPeerCertificate = nil
	config.KeyLogWriter = nil
	transport.TLSClientConfig = config
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 10 * time.Second}
	transport.DialContext = registryCatalogPublicDialer(net.DefaultResolver.LookupNetIP, dialer.DialContext)
	return &http.Client{Transport: transport}, nil
}

// Resolve once and dial approved IP literals. Checking DNS and then passing the
// hostname to a second resolver would leave a DNS-rebinding gap. Mixed public
// and private answers are rejected rather than used as a fallback list.
func registryCatalogPublicDialer(lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, errRegistryCatalogCapability
		}
		addresses, err := lookup(ctx, "ip", host)
		if err != nil || len(addresses) == 0 {
			return nil, errRegistryCatalogCapability
		}
		for _, candidate := range addresses {
			if !publicSubscriptionIP(candidate) || candidate.Zone() != "" {
				return nil, errRegistryCatalogCapability
			}
		}
		for _, candidate := range addresses {
			connection, err := dial(ctx, network, net.JoinHostPort(candidate.Unmap().String(), port))
			if err == nil {
				return connection, nil
			}
			if ctx.Err() != nil {
				break
			}
		}
		return nil, errRegistryCatalogCapability
	}
}
