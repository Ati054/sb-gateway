//go:build !linux

package subscriptioncatalog

import "os"

// Non-Linux platforms retain sync/error handling but have no portable advisory
// drop-behind primitive. This fallback makes no bounded-page-cache guarantee.
func adviseCatalogCache(*os.File, int64, int64) {}
