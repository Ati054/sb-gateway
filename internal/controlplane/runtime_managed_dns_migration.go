package controlplane

import (
	"context"
	"errors"
	"fmt"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

var ErrManagedDNSStartupContract = errors.New("startup managed DNS ownership is inconsistent")

func (server *Server) updateRecoveredRuntimeRevision(revision string) error {
	metadata, err := server.repository.metadata()
	if err != nil {
		return err
	}
	if metadata["runtime_revision"] == revision {
		return nil
	}
	return server.repository.updateRuntimeRevision(revision)
}

func managedDNSOwnerFromFiles(options RuntimeOptions) (runtimeconfig.ManagedDNSOwner, bool, error) {
	core, err := readRuntimeMigrationArtifact(options.XrayConfig)
	if err != nil {
		return runtimeconfig.ManagedDNSOwnerNone, false, err
	}
	dns, err := readRuntimeMigrationArtifact(options.PolicyDNSConfig)
	if err != nil {
		return runtimeconfig.ManagedDNSOwnerNone, false, err
	}
	owner, err := runtimeconfig.ValidateManagedDNSOwnership(core, dns)
	return owner, len(core) != 0 || len(dns) != 0, err
}

// Changed paths override the live bundle, including an explicitly empty path
// for an artifact that did not exist before a first activation. This function
// only reads; RollbackAfter calls it while owning the candidate store lock.
func (runtime *nativeRuntime) validateManagedDNSRestoring(paths map[string]string) error {
	_, coreChanged := paths["xray.json"]
	_, dnsChanged := paths["policy-dns.json"]
	if !coreChanged && !dnsChanged {
		return nil
	}
	// In-memory test/embedded stores may manage only unrelated artifacts. A
	// production native store always declares both destination paths.
	if runtime.options.XrayConfig == "" && runtime.options.PolicyDNSConfig == "" {
		return nil
	}
	options := runtime.options
	if path, changed := paths["xray.json"]; changed {
		options.XrayConfig = path
	}
	if path, changed := paths["policy-dns.json"]; changed {
		options.PolicyDNSConfig = path
	}
	if _, _, err := managedDNSOwnerFromFiles(options); err != nil {
		return fmt.Errorf("managed DNS target bundle is inconsistent: %w", err)
	}
	return nil
}

func managedDNSOwnerMatchesConfig(owner runtimeconfig.ManagedDNSOwner, config map[string]any) bool {
	if boolDefault(objectAt(config, "dns"), "hijack_managed_clients", true) {
		return owner == runtimeconfig.ManagedDNSOwnerXray || owner == runtimeconfig.ManagedDNSOwnerGo
	}
	return owner == runtimeconfig.ManagedDNSOwnerNone
}

// Select the same commit decision as normal interrupted-operation recovery.
// Runtime receipts are process-local; neither the draft nor the latest fetched
// subscription inventory is an authority after a power loss.
func startupManagedDNSModel(repository *stateRepository, operations map[string]map[string]any) (map[string]any, []map[string]any, error) {
	active, err := repository.activeRevision()
	if err != nil {
		return nil, nil, err
	}
	if active != "" {
		config, err := repository.loadGeneration(active)
		if err != nil {
			return nil, nil, err
		}
		metadata, err := repository.metadata()
		if err != nil || metadata["revision"] != active {
			return nil, nil, errors.New("startup committed metadata is inconsistent")
		}
		nodes, err := committedRuntimeMigrationNodes(repository, metadata, active)
		return config, nodes, err
	}
	apply := operations["apply-operation"]
	if apply["pending"] != true || text(apply["previous_revision"]) != "" || operations["subscription-runtime-operation"]["pending"] == true {
		return nil, nil, errors.New("startup recovery has no committed configuration")
	}
	recovery := text(apply["recovery_revision"])
	if !safeRevision(recovery) {
		return nil, nil, errors.New("startup first Apply recovery generation is missing")
	}
	config, err := repository.loadGeneration(recovery)
	return config, nil, err
}

func reconcileStartupManagedDNSPending(ctx context.Context, opts Options, repository *stateRepository, operations map[string]map[string]any) (bool, error) {
	owner, present, ownershipErr := managedDNSOwnerFromFiles(opts.Runtime)
	config, nodes, err := startupManagedDNSModel(repository, operations)
	if err != nil {
		// A coherent bundle can keep serving while the ordinary recovery worker
		// reports an old or incomplete journal; do not invent missing authority.
		if ownershipErr == nil && present && owner != runtimeconfig.ManagedDNSOwnerNone {
			return false, nil
		}
		return false, fmt.Errorf("%w: %w", ErrManagedDNSStartupContract, err)
	}
	if ownershipErr == nil && present && managedDNSOwnerMatchesConfig(owner, config) {
		return false, nil
	}
	if operations["apply-operation"]["pending"] == true && operations["subscription-runtime-operation"]["pending"] == true {
		return false, fmt.Errorf("%w: competing runtime recovery journals", ErrManagedDNSStartupContract)
	}
	ctx, cancel := context.WithTimeout(ctx, xrayRuntimeReadinessTimeout)
	defer cancel()
	if hasSubscriptionCatalogNodes(nodes) {
		if err := ValidateSubscriptionCatalogRuntimeCompatibility(ctx, opts, config); err != nil {
			return false, fmt.Errorf("%w: %w", ErrManagedDNSStartupContract, err)
		}
	}
	secrets, err := newSecretStore(opts.SecretsDir)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrManagedDNSStartupContract, err)
	}
	runtime, err := newNativeRuntimeStore(opts.Runtime, secrets)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrManagedDNSStartupContract, err)
	}
	candidate, err := runtime.prepare(config, nodes)
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrManagedDNSStartupContract, err)
	}
	owner, _, err = managedDNSOwnerFromFiles(RuntimeOptions{XrayConfig: candidate.Files["xray.json"], PolicyDNSConfig: candidate.Files["policy-dns.json"]})
	if err != nil || !managedDNSOwnerMatchesConfig(owner, config) {
		return false, fmt.Errorf("%w: prepared bundle failed ownership verification", ErrManagedDNSStartupContract)
	}
	_, err = runtime.store.ActivateAfter(candidate, func(changed []string) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := runtime.validate(ctx, candidate, changed); err != nil {
			return err
		}
		return ctx.Err()
	})
	if err != nil {
		return false, fmt.Errorf("%w: %w", ErrManagedDNSStartupContract, err)
	}
	owner, _, err = managedDNSOwnerFromFiles(opts.Runtime)
	if err != nil || !managedDNSOwnerMatchesConfig(owner, config) {
		return false, fmt.Errorf("%w: reconstructed bundle failed ownership verification", ErrManagedDNSStartupContract)
	}
	// No LKG/active-pointer/journal commit here. RouterOS and the full durable
	// transaction remain the responsibility of the normal recovery scheduler.
	return true, nil
}

// A failed optional migration may retain a coherent legacy owner. A mixed pair
// must never start two competing port1053 listeners (or silently lose both).
func ValidateStartupManagedDNSRuntime(opts Options) error {
	owner, present, err := managedDNSOwnerFromFiles(opts.Runtime)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrManagedDNSStartupContract, err)
	}
	if !present {
		return nil
	}
	repository, err := newStateRepository(opts.StateDir)
	if err != nil {
		return err
	}
	active, err := repository.activeRevision()
	if err != nil {
		return err
	}
	if active == "" {
		return nil
	}
	config, err := repository.loadGeneration(active)
	if err != nil {
		return err
	}
	if !managedDNSOwnerMatchesConfig(owner, config) {
		return ErrManagedDNSStartupContract
	}
	return nil
}
