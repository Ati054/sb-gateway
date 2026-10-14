package runtimeconfig

import "strings"

// WithLegacyProtocolCleanup prevents newly introduced exceptions surviving a
// failed first upgrade to an older candidate that cannot reconcile them.
func WithLegacyProtocolCleanup(previous, desired string) string {
	marker := routerOSSectionPrefix + "protocol-policy"
	if strings.Contains(previous, marker) || !strings.Contains(desired, marker) {
		return previous
	}
	header := routerOSCandidateHeader + "\n"
	if !strings.HasPrefix(previous, header) {
		return previous
	}
	var cleanup []string
	for _, table := range []string{"/ip/firewall/mangle", "/ip/firewall/filter", "/ipv6/firewall/filter"} {
		cleanup = append(cleanup, table+`/remove [`+table+`/find where comment~"^SB-GATEWAY protocol "]`)
	}
	return header + strings.Join(cleanup, "\n") + "\n" + strings.TrimPrefix(previous, header)
}
