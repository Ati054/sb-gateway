package controlplane

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var errReservedSecretsNamespace = errors.New("configured secrets namespace collides with reserved product storage")

func configuredSecretsNamespace(configRoot, secretsRoot string) (string, error) {
	invalid := errors.New("configured secrets namespace is not inside the captured configuration root")
	root, err := filepath.Abs(configRoot)
	if err != nil {
		return "", invalid
	}
	secret, err := filepath.Abs(secretsRoot)
	if err != nil {
		return "", invalid
	}
	relative, err := filepath.Rel(root, secret)
	if err != nil || relative == "." || filepath.IsAbs(relative) || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", invalid
	}
	switch strings.Split(filepath.ToSlash(relative), "/")[0] {
	case "generated", "rulesets", catalogCompatDirectory:
		return "", errReservedSecretsNamespace
	}
	// Missing default trees are supported by the read-only inventory helpers,
	// but an existing configured component must never redirect outside the root.
	current := root
	for _, part := range append([]string{""}, strings.Split(relative, string(filepath.Separator))...) {
		if part != "" {
			current = filepath.Join(current, part)
		}
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", invalid
		}
	}
	return filepath.ToSlash(relative), nil
}

func inConfiguredNamespace(relative, namespace string) bool {
	value := filepath.ToSlash(relative)
	return value == namespace || strings.HasPrefix(value, namespace+"/")
}

// A scratch-looking basename is not enough outside the managed state tree:
// secret references and runtime/LKG paths may legitimately use that spelling.
func managedControlPlaneAtomicScratch(relative string) bool {
	name := filepath.Base(relative)
	if !recoveryAtomicTemporaryBasename(name) {
		return false
	}
	stem := strings.TrimSuffix(name, ".tmp")
	separator := strings.LastIndexByte(stem, '.')
	if separator <= 1 {
		return false
	}
	target := stem[1:separator]
	directory := filepath.ToSlash(filepath.Dir(relative))
	if directory == "." {
		// The compact agent cache uses this shorter producer prefix.
		if target == "selector-status" {
			return true
		}
		return strings.HasSuffix(target, ".json") && safeAuxiliaryName(strings.TrimSuffix(target, ".json"))
	}
	return directory == "generations" && strings.HasSuffix(target, ".json") && safeRevision(strings.TrimSuffix(target, ".json"))
}

// Reconstructible worker state is not an authoritative configuration input.
// Recovery can omit it; a local legacy-image handoff may preserve a stable
// point-in-time copy without requiring the live worker to stop updating it.
func volatileControlPlaneStateFile(name string) bool {
	switch name {
	case "audit.jsonl", "cdn-feeds.json", "client-telemetry.json", "rulesets-update.json",
		"runtime-status.json", "selector-health.json", "selector-runtime.json", "selector-status.json",
		"subscription-refresh-status.json", "subscription-runtime-operation.json", "subscription-runtime-status.json",
		"routeros-live-networks.json":
		return true
	}
	return false
}
