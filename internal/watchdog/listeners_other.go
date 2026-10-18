//go:build !linux

package watchdog

import (
	"context"
	"errors"
)

func probeListeningPort(ctx context.Context, _ string, _ int) (bool, error) {
	return false, errors.Join(errors.New("targeted listener inventory requires Linux"), ctx.Err())
}
