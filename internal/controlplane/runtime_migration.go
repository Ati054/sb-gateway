package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
// active GeoIP rules and DNS idle policies from the committed generation before
// Xray starts.
func MigrateLegacyDynamicRuntime(ctx context.Context, opts Options) (migrated bool, result error) {
	probeMigration := false
	catalogRuntimeVerified := false
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
	// Coherent interrupted transactions retain their artifacts for ordinary
	// recovery. A mixed DNS listener pair alone needs local reconstruction
	// before the independent DNS/Xray workers may start.
	operations := make(map[string]map[string]any, 2)
	pending := false
	for _, name := range []string{"apply-operation", "subscription-runtime-operation"} {
		operation, err := repository.auxiliary(name)
		if err != nil {
			return false, err
		}
		operations[name] = operation
		pending = pending || operation["pending"] == true
	}
	if pending {
		return reconcileStartupManagedDNSPending(ctx, opts, repository, operations)
	}
	metadata, err := repository.metadata()
	if err != nil {
		return false, err
	}
	revision := subscriptionText(metadata["revision"])
	var config map[string]any
	var nodes []map[string]any
	var probeNodes []map[string]any
	var probeCatalog runtimeconfig.RuntimeNodeCatalog
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
				version, versionErr := startupProbePoolVersion(opts.Runtime.XrayHealthPool)
				if versionErr != nil {
					probeMigration = true
					return false, versionErr
				}
				if version > 5 {
					probeMigration = true
					return false, errCatalogCompatibility
				}
				if version == 5 || hasSubscriptionCatalogNodes(nodes) {
					// Prove the physical image before opening any committed
					// catalogue metadata. Pool version alone is not authority.
					if err := ValidateSubscriptionCatalogRuntimeCompatibility(ctx, opts, config); err != nil {
						probeMigration = true
						return false, err
					}
					catalogRuntimeVerified = true
				}
				probeNodes = nodes
				if hasSubscriptionCatalogNodes(nodes) {
					var closeCatalog func()
					probeNodes, probeCatalog, closeCatalog, err = startupProbeCatalog(opts, nodes)
					if err != nil {
						probeMigration = true
						return false, err
					}
					defer closeCatalog()
				}
				probeMigration, err = legacyProbeRuntimeWithCatalog(opts.Runtime.XrayConfig, opts.Runtime.XrayHealthPool, config, probeNodes, probeCatalog)
				if err != nil {
					probeMigration = true
					return false, err
				}
			}
		}
	}
	if version, versionErr := catalogCompatibilityPoolVersion(opts.Runtime.XrayHealthPool); versionErr == nil && version == 5 && !catalogRuntimeVerified {
		if !safeRevision(revision) {
			probeMigration = true
			return false, errCatalogCompatibility
		}
		if err := ValidateSubscriptionCatalogRuntimeCompatibility(ctx, opts, config); err != nil {
			probeMigration = true
			return false, err
		}
		catalogRuntimeVerified = true
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
	domainMigration, err := legacyDomainRuntime(opts.Runtime.PolicyDNSConfig)
	if err != nil {
		return false, err
	}
	dnsIdleMigration, err := legacyDNSIdleRuntime(opts.Runtime.XrayConfig)
	if err != nil {
		return false, err
	}
	if !legacy && !probeMigration && !domainMigration && !dnsIdleMigration {
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
	if hasSubscriptionCatalogNodes(nodes) && !catalogRuntimeVerified {
		if err := ValidateSubscriptionCatalogRuntimeCompatibility(ctx, opts, config); err != nil {
			probeMigration = true
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
		invalid, err := legacyProbeRuntimeWithCatalog(candidate.Files["xray.json"], candidate.Files["urltest-pool.json"], config, probeNodes, probeCatalog)
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
		!(probeMigration && containsRuntimeArtifact(receipt.Changed(), "urltest-pool.json")) &&
		!(domainMigration && containsRuntimeArtifact(receipt.Changed(), "policy-dns.json")) {
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

func legacyDNSIdleRuntime(path string) (bool, error) {
	body, err := readRuntimeMigrationArtifact(path)
	if err != nil || len(body) == 0 {
		return false, err
	}
	return runtimeconfig.LegacyPolicyDNSIdle(body)
}

func legacyDomainRuntime(path string) (bool, error) {
	if path == "" {
		return false, nil
	}
	present, err := runtimeMigrationInputsPresent(path)
	if err != nil || !present {
		return false, err
	}
	file, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	var header struct {
		Version            int `json:"version"`
		DomainIndexVersion int `json:"domain_index_version"`
		LaneLayoutVersion  int `json:"lane_layout_version"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, maxRuntimeMigrationArtifactBytes+1))
	if err := decoder.Decode(&header); err != nil {
		return false, err
	}
	return header.Version == 2 || (header.Version == 1 && (header.DomainIndexVersion != 1 || header.LaneLayoutVersion != 2)), nil
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
	values, ok := snapshot["nodes"].([]any)
	if !ok {
		return nil, errors.New("legacy runtime migration node snapshot is malformed")
	}
	for _, value := range values {
		if _, ok := value.(map[string]any); !ok {
			return nil, errors.New("legacy runtime migration node snapshot contains an invalid entry")
		}
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

func startupProbePoolVersion(path string) (int, error) {
	body, err := readRuntimeMigrationArtifact(path)
	if err != nil {
		return 0, err
	}
	var header struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(body, &header) != nil {
		return 0, errors.New("decode startup probe contract")
	}
	// Older probe contracts may predate the catalogue-version range. They
	// still use the existing legacy listener reconciliation, not a v5 proof.
	return header.Version, nil
}

// Startup owns this private reader cache. Do not leave its generation leases
// open after the metadata checks, including a failed reconciliation.
func startupProbeCatalog(opts Options, nodes []map[string]any) ([]map[string]any, runtimeconfig.RuntimeNodeCatalog, func(), error) {
	root, err := filepath.Abs(opts.SecretsDir)
	if err != nil {
		return nil, nil, nil, err
	}
	store := &secretStore{root: root}
	legacy, catalog, err := splitSubscriptionCatalogNodes(store, nodes)
	if err != nil {
		return nil, nil, nil, err
	}
	closeCatalog := func() {
		store.catalogReaders.mu.Lock()
		defer store.catalogReaders.mu.Unlock()
		for generation, entry := range store.catalogReaders.entries {
			_ = entry.reader.Close()
			delete(store.catalogReaders.entries, generation)
		}
	}
	return legacy, catalog, closeCatalog, nil
}

// The fast path checks the matching inventory without provider-definition
// lookups or external validators. Full preparation is only for an old contract.
func legacyProbeRuntime(xrayPath, healthPoolPath string, config map[string]any, nodes []map[string]any) (bool, error) {
	return legacyProbeRuntimeWithCatalog(xrayPath, healthPoolPath, config, nodes, nil)
}

func legacyProbeRuntimeWithCatalog(xrayPath, healthPoolPath string, config map[string]any, nodes []map[string]any, catalog runtimeconfig.RuntimeNodeCatalog) (bool, error) {
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
		Version     int `json:"version"`
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
	if len(pool.Policies) == 0 && catalog == nil {
		return false, nil
	}
	expected, err := runtimeconfig.BuildXrayProbeContract(config, nodes, catalog)
	if err != nil {
		return false, err
	}
	if catalog != nil && pool.Version != 5 {
		return true, nil
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
