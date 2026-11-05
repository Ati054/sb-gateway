package controlplane

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
)

func hasSubscriptionCatalogNodes(nodes []map[string]any) bool {
	for _, node := range nodes {
		if _, exists := node[subscriptionCatalogSentinel]; exists {
			return true
		}
	}
	return false
}

func (server *Server) subscriptionCatalogCompatibilityAdmission(id string, base subscriptionCatalogBase) error {
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		return err
	}
	entry, _ := state[id].(map[string]any)
	revision, err := revisionFor(entry)
	if err != nil || revision != base.entryRevision {
		return errSubscriptionCommitBusy
	}
	active, err := server.repository.activeRevision()
	if err != nil || active != base.activeRevision {
		return errSubscriptionCommitBusy
	}
	metadata, err := server.repository.metadata()
	if err != nil {
		return err
	}
	revision, err = revisionFor(metadata)
	if err != nil || revision != base.metadataRevision {
		return errSubscriptionCommitBusy
	}
	if base.snapshotName != "" {
		snapshot, err := server.repository.auxiliary(base.snapshotName)
		if err != nil {
			return err
		}
		revision, err = revisionFor(snapshot)
		if err != nil || revision != base.snapshotRevision {
			return errSubscriptionCommitBusy
		}
	}
	return nil
}

// prepareSubscriptionCatalogRuntimeCompatibility is mutation-capable and only
// for a real Apply before its pending journal/RouterOS jobs/runtime preparation.
// Preview and plan callers must not invoke it. In particular it upgrades the
// draft-only bootstrap receipt to a physical producer proof before first commit.
func (server *Server) prepareSubscriptionCatalogRuntimeCompatibility(ctx context.Context, config map[string]any) error {
	return server.ensureSubscriptionCatalogCompatibility(context.WithValue(ctx, catalogCompatibilityPhysicalKey{}, true), config)
}

// Unlike the publication hook this validator is read-only and can run while a
// verified catalog-aware successor is in probation. It cannot prepare a legacy
// baseline or authorize a new catalog pointer by itself.
func (server *Server) validateSubscriptionCatalogRuntimeCompatibility(ctx context.Context, config map[string]any) error {
	value, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	if err != nil || len(value) == 0 {
		return errCatalogCompatibility
	}
	var descriptor catalogCompatibilityDescriptor
	body, _ := json.Marshal(value)
	if json.Unmarshal(body, &descriptor) != nil || descriptor.FormatVersion != 1 || descriptor.State != "prepared" || descriptor.ProducerCatalogSchema != 1 {
		return errCatalogCompatibility
	}
	active, err := server.repository.activeRevision()
	if err != nil {
		return errCatalogCompatibility
	}
	if active == "" && descriptor.Kind == "no-active-revision" {
		for _, path := range []string{server.opts.Runtime.XrayConfig, server.opts.Runtime.XrayHealthPool} {
			if path != "" {
				if _, err := os.Lstat(path); err == nil || !os.IsNotExist(err) {
					return errCatalogCompatibility
				}
			}
		}
		return ctx.Err()
	}
	if descriptor.Producer.Root == "" || descriptor.CurrentFingerprint == "" {
		return errCatalogCompatibility
	}
	client, _, err := server.newRouterOSRESTClient(config)
	if err != nil {
		return errCatalogCompatibility
	}
	defer client.CloseIdleConnections()
	if err := client.ValidateCatalogRuntimeImageProof(ctx, descriptor.Producer, descriptor.CurrentFingerprint); err != nil {
		return errCatalogCompatibility
	}
	return nil
}

// ValidateSubscriptionCatalogRuntimeCompatibility is the startup equivalent for
// callers that reconcile the committed runtime before starting the API worker.
// Existing repositories/stores are required; this does not initialize new data.
func ValidateSubscriptionCatalogRuntimeCompatibility(ctx context.Context, opts Options, config map[string]any) error {
	state, err := filepath.Abs(opts.StateDir)
	if err != nil {
		return errCatalogCompatibility
	}
	secretRoot, err := filepath.Abs(opts.SecretsDir)
	if err != nil {
		return errCatalogCompatibility
	}
	for _, path := range []string{state, secretRoot, filepath.Join(state, "generations")} {
		root, err := compatOpenRoot(path)
		if err != nil {
			return errCatalogCompatibility
		}
		root.Close()
	}
	// Ordinary constructors initialize directories. Startup proof deliberately
	// builds read-only views only after every required existing root is checked.
	repository := &stateRepository{root: state, generations: filepath.Join(state, "generations"), cache: make(map[string]cachedDocument)}
	secrets := &secretStore{root: secretRoot}
	server := &Server{opts: opts, repository: repository, secrets: secrets}
	return server.validateSubscriptionCatalogRuntimeCompatibility(ctx, config)
}
