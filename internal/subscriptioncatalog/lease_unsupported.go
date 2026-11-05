//go:build !linux && !darwin && !dragonfly && !freebsd && !netbsd && !openbsd && !windows

package subscriptioncatalog

import "os"

func lockManifest(*os.File, bool) error { return ErrLeaseUnsupported }
func unlockManifest(*os.File) error     { return ErrLeaseUnsupported }
