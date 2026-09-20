package controlplane

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
)

const (
	sbGatewayBeforeBackupPattern = `^sb-gateway\.before-[0-9]{8}T[0-9]{6}Z$`
	sbGatewayFailedBackupPattern = `^sb-gateway\.failed-[0-9]{8}T[0-9]{6}Z$`
)

func keepPreviousImage(config map[string]any) bool {
	value, ok := numberToInt64(objectAt(config, "updates")["retain_previous_images"])
	return ok && value == 1
}

// PruneLocalUpdateBackups is called only by the updater after the new binary,
// runner and (when replaced) UI have passed their health checks. It never touches
// active/LKG configuration, user backups or an in-flight rollback transaction.
func PruneLocalUpdateBackups(opts Options) (int, error) {
	keep, err := localUpdateBackupRetention(opts.StateDir)
	if err != nil {
		return 0, err
	}
	total := 0
	for _, group := range []struct {
		root, pattern string
		keep          int
	}{
		{"/usr/local/bin", sbGatewayBeforeBackupPattern, keep},
		{"/usr/local/bin", sbGatewayFailedBackupPattern, 0},
		{"/opt/sb-gateway/scripts", `^run-xray\.sh\.before-[0-9]{8}T[0-9]{6}Z$`, keep},
		{"/opt/sb-gateway/web", `^\.ui-backup-[0-9]{8}T[0-9]{6}Z-[0-9]+$`, keep},
	} {
		removed, err := pruneUpdateBackupGroup(group.root, regexp.MustCompile(group.pattern), group.keep)
		total += removed
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func localUpdateBackupRetention(stateDir string) (int, error) {
	root, err := filepath.Abs(stateDir)
	if err != nil {
		return 0, err
	}
	// Read-only repository: do not create state directories during cleanup.
	repository := &stateRepository{root: root, generations: filepath.Join(root, "generations"), cache: make(map[string]cachedDocument)}
	config, err := repository.loadDraft()
	if errors.Is(err, os.ErrNotExist) {
		config, err = repository.loadActive()
	}
	if err != nil {
		return 0, err // no guessed policy when persistent settings cannot be read
	}
	keep := 0
	if raw, exists := objectAt(config, "updates")["retain_previous_images"]; exists {
		value, valid := numberToInt64(raw)
		if !valid || (value != 0 && value != 1) {
			return 0, errors.New("update retention must be zero or one")
		}
	}
	if keepPreviousImage(config) {
		keep = 1
	}
	return keep, nil
}

func pruneUpdateBackupGroup(directory string, pattern *regexp.Regexp, keep int) (int, error) {
	if keep != 0 && keep != 1 {
		return 0, errors.New("update retention must be zero or one")
	}
	if !filepath.IsAbs(directory) {
		return 0, errors.New("update backup directory is not a canonical absolute directory")
	}
	resolved := filepath.Clean(directory)
	if runtime.GOOS != "windows" {
		var err error
		resolved, err = filepath.EvalSymlinks(directory)
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		if err != nil {
			return 0, fmt.Errorf("resolve update backup directory: %w", err)
		}
		if resolved != filepath.Clean(directory) {
			return 0, errors.New("update backup directory is not a canonical absolute directory")
		}
	}
	info, err := os.Lstat(directory)
	if err != nil {
		return 0, fmt.Errorf("inspect update backup directory: %w", err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return 0, errors.New("update backup directory is not a canonical absolute directory")
	}
	directory = resolved
	entries, err := os.ReadDir(directory)
	if err != nil {
		return 0, err
	}
	names := []string{}
	for _, entry := range entries {
		if pattern.MatchString(entry.Name()) && entry.Type()&os.ModeSymlink == 0 {
			names = append(names, entry.Name())
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))
	if len(names) <= keep {
		return 0, nil
	}
	removed := 0
	for _, name := range names[keep:] {
		// Names come from ReadDir and the strict owned-name pattern; RemoveAll
		// unlinks symlinks inside a backup without following their targets.
		if err := os.RemoveAll(filepath.Join(directory, name)); err != nil {
			return removed, fmt.Errorf("remove previous update backup: %w", err)
		}
		removed++
	}
	return removed, nil
}
