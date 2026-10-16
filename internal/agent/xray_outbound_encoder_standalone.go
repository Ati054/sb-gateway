//go:build !xray_multicall

package agent

// Standalone developer binaries retain the existing external Xray CLI path.
func newXrayOutboundEncoder() xrayOutboundEncoder { return nil }
