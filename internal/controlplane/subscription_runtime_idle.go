package controlplane

import (
	"errors"
	"os"
	"path/filepath"
	"time"
)

type subscriptionRuntimeSource struct {
	path string
	info os.FileInfo
}

// Protected by mutationMu, subscriptionMu and configMu, like the activation scan.
// Retain file identities, not another copy of the parsed subscription catalog.
type subscriptionRuntimeIdle struct {
	sources []subscriptionRuntimeSource
	checked time.Time
	retryAt time.Time
}

func subscriptionRuntimeSources(paths ...string) ([]subscriptionRuntimeSource, bool) {
	result := make([]subscriptionRuntimeSource, 0, len(paths))
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, false
		}
		if info != nil && !info.Mode().IsRegular() {
			return nil, false
		}
		result = append(result, subscriptionRuntimeSource{path: path, info: info})
	}
	return result, true
}

func subscriptionRuntimeSourcesUnchanged(sources []subscriptionRuntimeSource) bool {
	if len(sources) == 0 {
		return false
	}
	for _, source := range sources {
		current, ok := subscriptionRuntimeSources(source.path)
		if !ok {
			return false
		}
		info := current[0].info
		if source.info == nil || info == nil {
			if source.info != nil || info != nil {
				return false
			}
			continue
		}
		if !os.SameFile(source.info, info) || source.info.Size() != info.Size() || !source.info.ModTime().Equal(info.ModTime()) {
			return false
		}
	}
	return true
}

func (idle subscriptionRuntimeIdle) unchanged(now time.Time) bool {
	return !now.Before(idle.checked) && (idle.retryAt.IsZero() || now.Before(idle.retryAt)) && subscriptionRuntimeSourcesUnchanged(idle.sources)
}

func (repository *stateRepository) subscriptionRuntimePointers() ([]subscriptionRuntimeSource, bool) {
	names := []string{"active.json", "last-known-good.json", "apply-metadata.json", "subscription-nodes.json", "subscription-runtime-status.json", "subscription-runtime-operation.json"}
	paths := make([]string, len(names))
	for index, name := range names {
		paths[index] = filepath.Join(repository.root, name)
	}
	return subscriptionRuntimeSources(paths...)
}
