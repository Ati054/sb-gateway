//go:build !linux

package watchdog

import "context"

func probeTransparentNFT(ctx context.Context, port string) (bool, error) {
	return inspectDeepCommand(ctx, "transparent_nft", func(output []byte) bool {
		return hasTransparentRules(string(output), port)
	}, "nft", "-j", "list", "table", "inet", "sb_gateway_transparent")
}
