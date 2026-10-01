package appliance

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

// An open API port precedes selector restoration and transparent routing.
// Keep Apply guarded until startup has finished for this exact core/config.
func xrayStartupProbe(options Options, procRoot string) func(context.Context) error {
	tcp := TCPProbe(options.XrayReady, time.Second)
	return func(ctx context.Context) error {
		if _, err := os.Stat(options.XrayReadyFile); err != nil {
			return errors.New("Xray startup readiness marker is missing")
		}
		body, err := os.ReadFile(options.XrayConfig)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(body)
		if !runtimeproof.XrayValidated(options.XrayValidatedFile, options.XrayReadyFile, options.XrayConfig, procRoot, hex.EncodeToString(sum[:])) {
			return errors.New("Xray startup readiness is not confirmed for the current core/config")
		}
		return tcp(ctx)
	}
}
