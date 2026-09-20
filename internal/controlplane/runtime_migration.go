package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxRuntimeMigrationArtifactBytes = 32 << 20

// MigrateLegacyDynamicRuntime rewrites only the legacy startup graph that
// duplicated subscription-backed outbounds already present in the health-pool
// contract. It runs before the appliance starts Xray, so an image update gets
// the smaller graph without an additional data-plane restart or RouterOS edit.
func MigrateLegacyDynamicRuntime(ctx context.Context, opts Options) (bool, error) {
	legacy, err := legacyDynamicRuntime(opts.Runtime.XrayConfig, opts.Runtime.XrayHealthPool)
	if err != nil || !legacy {
		return false, err
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
