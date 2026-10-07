package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
	"github.com/sb-gateway/sb-gateway/internal/rulesets"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const maxRuntimeMigrationArtifactBytes = 32 << 20

// ErrProbeContractMigration prevents starting workers against incompatible
// persisted probe listeners after an image upgrade.
var ErrProbeContractMigration = errors.New("startup probe contract reconciliation failed")

// MigrateLegacyDynamicRuntime reconciles legacy outbounds, probe contracts and
// active GeoIP rules from the committed generation before Xray starts.
func MigrateLegacyDynamicRuntime(ctx context.Context, opts Options) (migrated bool, result error) {
	probeMigration := false
	defer func() {
		if probeMigration && result != nil {
			result = fmt.Errorf("%w: %w", ErrProbeContractMigration, result)
		}
	}()
	repository, err := newStateRepository(opts.StateDir)
	if err != nil {
		return false, err
	}
	if err := repository.reconcileCommitPointers(); err != nil {
		return false, err
	}
	// Interrupted transactions own their generated artifacts until their
	// existing recovery worker has reconciled the committed generation.
	for _, name := range []string{"apply-operation", "subscription-runtime-operation"} {
		operation, err := repository.auxiliary(name)
		if err != nil || operation["pending"] == true {
			return false, err
		}
	}
	metadata, err := repository.metadata()
	if err != nil {
		return false, err
	}
	revision := subscriptionText(metadata["revision"])
	var config map[string]any
	var nodes []map[string]any
	nodesLoaded := false
	if safeRevision(revision) {
		config, err = repository.loadGeneration(revision)
		if err != nil {
			return false, err
		}
		if hasStartupProbePolicies(config) {
			present, err := runtimeMigrationInputsPresent(opts.Runtime.XrayConfig, opts.Runtime.XrayHealthPool)
			if err != nil {
				probeMigration = true
				return false, err
			}
			if present {
				nodes, err = committedRuntimeMigrationNodes(repository, metadata, revision)
				if err != nil {
					probeMigration = true
					return false, err
				}
				nodesLoaded = true
				probeMigration, err = legacyProbeRuntime(opts.Runtime.XrayConfig, opts.Runtime.XrayHealthPool, config, nodes)
				if err != nil {
					probeMigration = true
					return false, err
				}
			}
		}
	}
	legacy, err := legacyDynamicRuntime(opts.Runtime.XrayConfig, opts.Runtime.XrayHealthPool)
	if err != nil {
		return false, err
	}
	if !legacy {
		legacy, err = legacyGeoIPRouting(opts.StateDir, opts.Runtime.XrayConfig, opts.Runtime.RuleSetDir)
		if err != nil {
			return false, err
		}
	}
	if !legacy && !probeMigration {
		return false, nil
	}
	if !safeRevision(revision) {
		return false, errors.New("legacy runtime migration has no committed configuration")
	}
	if !nodesLoaded {
		nodes, err = committedRuntimeMigrationNodes(repository, metadata, revision)
		if err != nil {
			return false, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, xrayRuntimeReadinessTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return false, err
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
	if probeMigration {
		invalid, err := legacyProbeRuntime(candidate.Files["xray.json"], candidate.Files["urltest-pool.json"], config, nodes)
		if err != nil {
			return false, err
		}
		if invalid {
			return false, errors.New("rendered runtime has an inconsistent probe contract")
		}
	}
	receipt, err := runtime.store.ActivateAfter(candidate, func(changed []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runtime.validate(ctx, candidate, changed); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return false, err
	}
	if !containsRuntimeArtifact(receipt.Changed(), "xray.json") &&
		!(probeMigration && containsRuntimeArtifact(receipt.Changed(), "urltest-pool.json")) {
		if err := runtime.store.Rollback(receipt); err != nil {
			return false, err
		}
		return false, errors.New("legacy runtime migration produced no matching runtime change")
	}
	if err := runtime.commit(candidate); err != nil {
		return false, errors.Join(err, runtime.store.Rollback(receipt))
	}
	if err := repository.updateRuntimeRevision(candidate.Revision); err != nil {
		return false, fmt.Errorf("record migrated runtime revision: %w", err)
	}
	return true, nil
}

func committedRuntimeMigrationNodes(repository *stateRepository, metadata map[string]any, revision string) ([]map[string]any, error) {
	snapshotRevision := stringDefault(metadata["node_snapshot_revision"], revision)
	snapshot, err := repository.auxiliary("subscription-nodes-" + snapshotRevision)
	if err != nil {
		return nil, err
	}
	if snapshot["revision"] != snapshotRevision {
		return nil, errors.New("legacy runtime migration has no committed node snapshot")
	}
	nodes := objectNodes(snapshot["nodes"])
	if snapshotRevision != revision {
		checksum, checksumErr := revisionFor(nodes)
		if checksumErr != nil || checksum != snapshotRevision {
			return nil, errors.New("legacy runtime migration node snapshot checksum mismatch")
		}
	}
	return nodes, nil
}

func runtimeMigrationInputsPresent(paths ...string) (bool, error) {
	for _, path := range paths {
		if strings.TrimSpace(path) == "" {
			return false, nil
		}
		info, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		if !info.Mode().IsRegular() || info.Size() > maxRuntimeMigrationArtifactBytes {
			return false, errors.New("runtime migration input is not a bounded regular file")
		}
		if info.Size() == 0 {
			return false, nil
		}
	}
	return true, nil
}

func legacyGeoIPRouting(stateDir, xrayPath, rulesetDir string) (bool, error) {
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
				RuleTag string   `json:"ruleTag"`
				IP      []string `json:"ip"`
			} `json:"rules"`
		} `json:"routing"`
	}
	if err := json.Unmarshal(body, &xray); err != nil {
		return false, err
	}
	found := false
	for _, rule := range xray.Routing.Rules {
		if strings.HasPrefix(rule.RuleTag, "sb-geoip-") {
			found = true
			if len(rule.IP) != 1 {
				return true, nil
			}
			if err := geoipasset.Verify(rulesetDir, rule.IP[0]); err != nil {
				return true, nil
			}
		}
	}
	return !found, nil
}

func hasStartupProbePolicies(config map[string]any) bool {
	for _, policy := range objects(config["policies"]) {
		mode := stringDefault(policy["mode"], "best")
		if policy["enabled"] != false && (mode == "best" || mode == "priority" || mode == "urltest") {
			return true
		}
	}
	return false
}

// The fast path renders only the in-memory health contract, without secret
// reads or validators. Full runtime preparation runs only for an old contract.
func legacyProbeRuntime(xrayPath, healthPoolPath string, config map[string]any, nodes []map[string]any) (bool, error) {
	if !hasStartupProbePolicies(config) {
		return false, nil
	}
	poolBody, err := readRuntimeMigrationArtifact(healthPoolPath)
	if err != nil || len(poolBody) == 0 {
		return false, err
	}
	xrayBody, err := readRuntimeMigrationArtifact(xrayPath)
	if err != nil || len(xrayBody) == 0 {
		return false, err
	}
	var pool struct {
		ProbeBudget int `json:"probe_budget"`
		ProbeLanes  int `json:"probe_lanes"`
		Policies    map[string]struct {
			Policy map[string]json.RawMessage `json:"policy"`
		} `json:"health_policies"`
	}
	var xray struct {
		Inbounds []struct {
			Tag      string `json:"tag"`
			Protocol string `json:"protocol"`
			Listen   string `json:"listen"`
			Port     int    `json:"port"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(poolBody, &pool) != nil || json.Unmarshal(xrayBody, &xray) != nil {
		return false, errors.New("decode startup probe contract")
	}
	if len(pool.Policies) == 0 {
		return false, nil
	}
	expectedBody, err := runtimeconfig.BuildXrayHealthPool(config, nodes, map[string]any{})
	if err != nil {
		return false, err
	}
	var expected struct {
		ProbeBudget int `json:"probe_budget"`
		ProbeLanes  int `json:"probe_lanes"`
	}
	if err := json.Unmarshal(expectedBody, &expected); err != nil {
		return false, err
	}
	if pool.ProbeBudget != expected.ProbeBudget || pool.ProbeLanes != expected.ProbeLanes {
		return true, nil
	}
	for _, policy := range pool.Policies {
		var batch int
		if json.Unmarshal(policy.Policy["probe_batch_size"], &batch) != nil || batch != expected.ProbeBudget {
			return true, nil
		}
		for _, field := range []string{"speed_check_enabled", "speed_improvement_percent", "speed_degradation_percent", "speed_check_interval_seconds", "speed_probe_bytes", "speed_candidate_count"} {
			if _, exists := policy.Policy[field]; exists {
				return true, nil
			}
		}
	}
	ports := map[string]int{"outbound-health-probe": 19082}
	for index := 1; index <= pool.ProbeLanes; index++ {
		tag := "outbound-health-background"
		if index > 1 {
			tag = fmt.Sprintf("%s-%d", tag, index)
		}
		ports[tag] = 19082 + index
	}
	for _, inbound := range xray.Inbounds {
		if inbound.Tag != "outbound-health-probe" && !strings.HasPrefix(inbound.Tag, "outbound-health-background") {
			continue
		}
		port, exists := ports[inbound.Tag]
		if !exists || inbound.Port != port || inbound.Listen != "127.0.0.1" || inbound.Protocol != "http" {
			return true, nil
		}
		delete(ports, inbound.Tag)
	}
	return len(ports) != 0, nil
}

func readRuntimeMigrationArtifact(path string) ([]byte, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Size() > maxRuntimeMigrationArtifactBytes {
		return nil, errors.New("runtime migration input is not a bounded regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxRuntimeMigrationArtifactBytes {
		return nil, errors.New("runtime migration input is not a bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, maxRuntimeMigrationArtifactBytes+1))
	if err != nil || len(body) > maxRuntimeMigrationArtifactBytes {
		return nil, errors.New("read bounded runtime migration input")
	}
	return body, nil
}

func legacyDynamicRuntime(xrayPath, healthPoolPath string) (bool, error) {
	xrayBody, err := readRuntimeMigrationArtifact(xrayPath)
	if err != nil || len(xrayBody) == 0 {
		return false, err
	}
	poolBody, err := readRuntimeMigrationArtifact(healthPoolPath)
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
