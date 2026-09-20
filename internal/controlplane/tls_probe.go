package controlplane

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	maxTLSProbeAddresses = 16
	tlsProbeTimeout      = 7 * time.Second
)

type tlsProbeRequest struct {
	Hostname        string
	Port            int
	ServerName      string
	RouterAddresses []string
	RootCAs         *x509.CertPool
}

type tlsProbeFunc func(context.Context, tlsProbeRequest) (map[string]any, *tlsProbeError)

type tlsProbeError struct {
	Code    string
	Message string
}

func (server *Server) probeTLSEndpoint(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireCSRF(response, request); !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	host := strings.TrimSuffix(strings.TrimSpace(text(body["hostname"])), ".")
	serverName := strings.TrimSuffix(strings.TrimSpace(text(body["server_name"])), ".")
	if serverName == "" {
		serverName = host
	}
	port64, validPort := jsonInteger(body["port"])
	if host == "" || strings.Contains(host, "/") || strings.Contains(host, "://") {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "tls_probe_hostname_invalid", "Enter a hostname or IP address without a URL path.")
		return
	}
	if !validPort || port64 < 1 || port64 > 65535 {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "tls_probe_port_invalid", "TLS probe port must be from 1 to 65535.")
		return
	}
	probe := tlsProbeRequest{Hostname: host, Port: int(port64), ServerName: serverName}
	if body["reject_router_addresses"] == true {
		config, err := server.getDraft()
		if err != nil {
			server.internalStateError(response, request, err)
			return
		}
		probe.RouterAddresses = stringsOf(objectAt(config, "routeros")["router_addresses"])
	}
	result, probeErr := server.probeTLS(request.Context(), probe)
	if probeErr != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, probeErr.Code, probeErr.Message)
		return
	}
	server.writeJSON(response, http.StatusOK, result)
}

func probeTLSEndpoint(ctx context.Context, request tlsProbeRequest) (map[string]any, *tlsProbeError) {
	addresses, err := net.DefaultResolver.LookupIPAddr(ctx, request.Hostname)
	if err != nil || len(addresses) == 0 {
		return nil, &tlsProbeError{Code: "tls_probe_dns_failed", Message: "Public DNS did not resolve the endpoint."}
	}
	unique := make(map[netip.Addr]struct{}, len(addresses))
	for _, resolved := range addresses {
		if address, ok := netip.AddrFromSlice(resolved.IP); ok {
			unique[address.Unmap()] = struct{}{}
		}
	}
	ordered := make([]netip.Addr, 0, len(unique))
	for address := range unique {
		ordered = append(ordered, address)
	}
	sort.Slice(ordered, func(left, right int) bool { return ordered[left].Compare(ordered[right]) < 0 })
	if len(ordered) == 0 {
		return nil, &tlsProbeError{Code: "tls_probe_dns_failed", Message: "Public DNS returned no usable addresses."}
	}
	if len(ordered) > maxTLSProbeAddresses {
		return nil, &tlsProbeError{Code: "tls_probe_dns_failed", Message: "Public DNS returned too many addresses to probe safely."}
	}
	routerAddresses := make(map[netip.Addr]bool, len(request.RouterAddresses))
	for _, raw := range request.RouterAddresses {
		value := strings.TrimSpace(raw)
		if prefix, parseErr := netip.ParsePrefix(value); parseErr == nil {
			routerAddresses[prefix.Addr().Unmap()] = true
			continue
		}
		if address, parseErr := netip.ParseAddr(value); parseErr == nil {
			routerAddresses[address.Unmap()] = true
		}
	}
	loops := make([]string, 0)
	for _, address := range ordered {
		if routerAddresses[address] {
			loops = append(loops, address.String())
		}
	}
	if len(loops) != 0 {
		return nil, &tlsProbeError{Code: "tls_probe_target_loop", Message: "The REALITY target resolves to this MikroTik WAN address: " + strings.Join(loops, ", ")}
	}

	results := make([]any, 0, len(ordered))
	versions := make(map[string]bool)
	alpns := make(map[string]bool)
	ciphers := make(map[string]bool)
	dnsNames := make(map[string]bool)
	expiries := make(map[string]bool)
	var firstFailure *tlsProbeError
	successes := 0
	for _, address := range ordered {
		result, probeErr := probeTLSAddress(ctx, address, request)
		results = append(results, result)
		if probeErr != nil {
			if firstFailure == nil {
				firstFailure = probeErr
			}
			continue
		}
		successes++
		addNonempty(versions, text(result["tls_version"]))
		addNonempty(alpns, text(result["alpn"]))
		addNonempty(ciphers, text(result["cipher"]))
		addNonempty(expiries, text(result["certificate_expires_at"]))
		for _, name := range stringsOf(result["certificate_dns_names"]) {
			addNonempty(dnsNames, name)
		}
	}
	if successes == 0 {
		if firstFailure == nil {
			firstFailure = &tlsProbeError{Code: "tls_probe_handshake_failed", Message: fmt.Sprintf("TLS handshake failed for %s:%d with SNI %s.", request.Hostname, request.Port, request.ServerName)}
		}
		return nil, firstFailure
	}
	versionList, alpnList, cipherList := sortedKeys(versions), sortedKeys(alpns), sortedKeys(ciphers)
	expiryList := sortedKeys(expiries)
	return map[string]any{
		"hostname": request.Hostname, "port": request.Port, "server_name": request.ServerName,
		"addresses": addressStrings(ordered), "all_addresses_ok": successes == len(results),
		"endpoint_results": results, "tls_versions": versionList, "alpn_protocols": alpnList,
		"tls_version": singleOrMixed(versionList), "alpn": singleOrMixed(alpnList), "cipher": singleOrMixed(cipherList),
		"certificate_dns_names": sortedKeys(dnsNames), "certificate_expires_at": firstOrEmpty(expiryList),
		"provider_settings": "not_checked",
	}, nil
}

func probeTLSAddress(ctx context.Context, address netip.Addr, request tlsProbeRequest) (map[string]any, *tlsProbeError) {
	dialer := &net.Dialer{Timeout: tlsProbeTimeout}
	config := &tls.Config{ServerName: request.ServerName, MinVersion: tls.VersionTLS12, RootCAs: request.RootCAs, NextProtos: []string{"h2", "http/1.1"}}
	connection, err := (&tls.Dialer{NetDialer: dialer, Config: config}).DialContext(ctx, "tcp", net.JoinHostPort(address.String(), fmt.Sprint(request.Port)))
	if err != nil {
		probeErr := classifyTLSProbeError(err, address, request)
		return map[string]any{"address": address.String(), "ok": false, "error_code": probeErr.Code, "error_message": probeErr.Message}, probeErr
	}
	tlsConnection := connection.(*tls.Conn)
	state := tlsConnection.ConnectionState()
	_ = connection.Close()
	names := make(map[string]bool)
	expires := ""
	if len(state.PeerCertificates) != 0 {
		for _, name := range state.PeerCertificates[0].DNSNames {
			addNonempty(names, name)
		}
		expires = state.PeerCertificates[0].NotAfter.UTC().Format(time.RFC3339)
	}
	return map[string]any{
		"address": address.String(), "ok": true, "tls_version": tlsVersionName(state.Version),
		"alpn": state.NegotiatedProtocol, "cipher": tls.CipherSuiteName(state.CipherSuite),
		"certificate_dns_names": stringAnySlice(sortedKeys(names)), "certificate_expires_at": expires,
		"error_code": "", "error_message": "",
	}, nil
}

func classifyTLSProbeError(err error, address netip.Addr, request tlsProbeRequest) *tlsProbeError {
	var verification *tls.CertificateVerificationError
	if errors.As(err, &verification) {
		return &tlsProbeError{Code: "tls_probe_certificate_mismatch", Message: fmt.Sprintf("The target certificate is not valid for SNI %s.", request.ServerName)}
	}
	var recordHeader tls.RecordHeaderError
	if errors.As(err, &recordHeader) || strings.Contains(strings.ToLower(err.Error()), "tls") {
		return &tlsProbeError{Code: "tls_probe_sni_rejected", Message: fmt.Sprintf("The target rejected the TLS handshake for SNI %s.", request.ServerName)}
	}
	return &tlsProbeError{Code: "tls_probe_handshake_failed", Message: fmt.Sprintf("TLS handshake failed for %s:%d with SNI %s.", address, request.Port, request.ServerName)}
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLSv1.3"
	case tls.VersionTLS12:
		return "TLSv1.2"
	default:
		return fmt.Sprintf("0x%04x", version)
	}
}

func addNonempty(values map[string]bool, value string) {
	if value = strings.TrimSpace(value); value != "" {
		values[value] = true
	}
}

func sortedKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func addressStrings(addresses []netip.Addr) []string {
	result := make([]string, len(addresses))
	for index, address := range addresses {
		result[index] = address.String()
	}
	return result
}

func stringAnySlice(values []string) []any {
	result := make([]any, len(values))
	for index, value := range values {
		result[index] = value
	}
	return result
}

func singleOrMixed(values []string) string {
	if len(values) == 1 {
		return values[0]
	}
	return "mixed"
}

func firstOrEmpty(values []string) string {
	if len(values) == 0 {
		return ""
	}
	return values[0]
}
