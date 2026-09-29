package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/rulesets"
)

const maxRuntimeMigrationArtifactBytes = 32 << 20

// MigrateLegacyDynamicRuntime rewrites legacy dynamic outbounds or an active
// GeoIP route missing managed rule tags. It runs before Xray starts, so an
// image update can enable hot GeoIP refresh without another data-plane restart.
func MigrateLegacyDynamicRuntime(ctx context.Context, opts Options) (bool, error) {
	legacy, err := legacyDynamicRuntime(opts.Runtime.XrayConfig, opts.Runtime.XrayHealthPool)
	if err != nil {
		return false, err
	}
	if !legacy {
		legacy, err = legacyGeoIPRouting(opts.StateDir, opts.Runtime.XrayConfig)
		if err != nil || !legacy {
			return false, err
		}
	}
	repository, err := newStateRepository(opts.StateDir)
	if err != nil {
		return false, err
	}
	if err := repository.reconcileCommitPointers(); err != nil {
		return false, err
	}
	metadata, err := repository.metadata()
	if err != nil {
		return false, err
	}
	revision := subscriptionText(metadata["revision"])
	if !safeRevision(revision) {
		return false, errors.New("legacy runtime migration has no committed configuration")
	}
	config, err := repository.loadGeneration(revision)
	if err != nil {
		return false, err
	}
	snapshotRevision := stringDefault(metadata["node_snapshot_revision"], revision)
	snapshot, err := repository.auxiliary("subscription-nodes-" + snapshotRevision)
	if err != nil {
		return false, err
	}
	if snapshot["revision"] != snapshotRevision {
		return false, errors.New("legacy runtime migration has no committed node snapshot")
	}
	nodes := objectNodes(snapshot["nodes"])
	if snapshotRevision != revision {
		checksum, checksumErr := revisionFor(nodes)
		if checksumErr != nil || checksum != snapshotRevision {
			return false, errors.New("legacy runtime migration node snapshot checksum mismatch")
		}
	}
	secrets, err := newSecretStore(opts.SecretsDir)
	if err != nil {
		return false, err
	}
	runtime, err := newNativeRuntimeStore(opts.Runtime, secrets)
	if err != nil {
		return false, err
	}
	candidate, err := runtime.prepare(config, nodes)
	if err != nil {
		return false, err
	}
	receipt, err := runtime.store.ActivateAfter(candidate, func(changed []string) error {
		return runtime.validate(ctx, candidate, changed)
	})
	if err != nil {
		return false, err
	}
	if !containsRuntimeArtifact(receipt.Changed(), "xray.json") {
		if err := runtime.store.Rollback(receipt); err != nil {
			return false, err
		}
		return false, errors.New("legacy runtime migration produced no Xray change")
	}
	if err := runtime.commit(candidate); err != nil {
		_ = runtime.store.Rollback(receipt)
		return false, err
	}
	if err := repository.updateRuntimeRevision(candidate.Revision); err != nil {
		return false, fmt.Errorf("record migrated runtime revision: %w", err)
	}
	return true, nil
}

func legacyGeoIPRouting(stateDir, xrayPath string) (bool, error) {
	catalog, err := rulesets.Catalog()
	if err != nil {
		return false, err
	}
	packs, err := rulesets.ActivePacks(stateDir, catalog)
	if err != nil {
		return false, err
	}
	selected := false
	for _, pack := range packs {
		selected = selected || pack.UpdateMode == "geoip"
	}
	if !selected {
		return false, nil
	}
	file, err := os.Open(xrayPath)
	if err != nil {
		return false, err
	}
	defer file.Close()
	body, err := io.ReadAll(io.LimitReader(file, maxRuntimeMigrationArtifactBytes+1))
	if err != nil || len(body) > maxRuntimeMigrationArtifactBytes {
		return false, errors.New("read bounded Xray GeoIP migration input")
	}
	var xray struct {
		Routing struct {
			Rules []struct {
				RuleTag string `json:"ruleTag"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(body, &xray); err != nil {
		return false, err
	}
	for _, rule := range xray.Routing.Rules {
		if strings.HasPrefix(rule.RuleTag, "sb-geoip-") {
			return false, nil
		}
	}
	return true, nil
}

func legacyDynamicRuntime(xrayPath, healthPoolPath string) (bool, error) {
	read := func(path string) ([]byte, error) {
		file, err := os.Open(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, err
		}
		defer file.Close()
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() || info.Size() > maxRuntimeMigrationArtifactBytes {
			return nil, errors.New("runtime migration input is not a bounded regular file")
		}
		body, err := io.ReadAll(io.LimitReader(file, maxRuntimeMigrationArtifactBytes+1))
		if err != nil || len(body) > maxRuntimeMigrationArtifactBytes {
			return nil, errors.New("read bounded runtime migration input")
		}
		return body, nil
	}
	xrayBody, err := read(strings.TrimSpace(xrayPath))
	if err != nil || len(xrayBody) == 0 {
		return false, err
	}
	poolBody, err := read(strings.TrimSpace(healthPoolPath))
	if err != nil || len(poolBody) == 0 {
		return false, err
	}
	var xray struct {
		Outbounds []struct {
			Tag string `json:"tag"`
		} `json:"outbounds"`
	}
	var pool struct {
		Outbounds map[string]json.RawMessage `json:"outbounds"`
	}
	if json.Unmarshal(xrayBody, &xray) != nil || json.Unmarshal(poolBody, &pool) != nil {
		return false, errors.New("decode runtime migration contract")
	}
	for _, outbound := range xray.Outbounds {
		if _, duplicated := pool.Outbounds[outbound.Tag]; duplicated {
			return true, nil
		}
	}
	return false, nil
}
