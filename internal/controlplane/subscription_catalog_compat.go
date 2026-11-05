package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

const catalogCompatibilityAuxiliary = "subscription-catalog-compatibility"

type catalogCompatibilityPhysicalKey struct{}

type catalogCompatibilityDescriptor struct {
	FormatVersion         int                             `json:"format_version"`
	State                 string                          `json:"state"`
	Kind                  string                          `json:"kind"`
	Identifier            string                          `json:"identifier,omitempty"`
	SourceEpoch           string                          `json:"source_epoch"`
	Producer              routeros.CatalogImageContainer  `json:"producer"`
	ProducerCatalogSchema int                             `json:"producer_catalog_schema"`
	CurrentFingerprint    string                          `json:"current_fingerprint,omitempty"`
	Previous              *routeros.CatalogImageContainer `json:"previous,omitempty"`
	Mountlist             string                          `json:"mountlist,omitempty"`
	Files                 []catalogCompatFile             `json:"files,omitempty"`
	CatalogRefs           []subscriptioncatalog.Ref       `json:"catalog_refs"`
}

func (server *Server) catalogCompatibilityEpoch() (string, error) {
	metadata, err := server.repository.metadata()
	if err != nil {
		return "", errCatalogCompatibility
	}
	sources, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		return "", errCatalogCompatibility
	}
	body, err := canonicalJSON(map[string]any{"metadata": metadata, "subscription_nodes": sources})
	if err != nil {
		return "", errCatalogCompatibility
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}

func (server *Server) catalogCompatibilityRoots() catalogCompatRoots {
	state := server.opts.StateDir
	if filepath.Base(state) == "control-plane" {
		state = filepath.Dir(state)
	}
	relative, _ := filepath.Rel(state, server.opts.StateDir)
	config := filepath.Dir(server.opts.SecretsDir)
	secrets, _ := filepath.Rel(config, server.opts.SecretsDir)
	return catalogCompatRoots{Config: config, State: state, Data: server.opts.DataDir, ControlPlaneRelative: filepath.ToSlash(relative), SecretsRelative: filepath.ToSlash(secrets)}
}

func catalogCompatibilityPoolVersion(path string) (int, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 32<<20 {
		return 0, errCatalogCompatibility
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, errCatalogCompatibility
	}
	defer file.Close()
	var value struct {
		Version int `json:"version"`
	}
	decoder := json.NewDecoder(io.LimitReader(file, 32<<20+1))
	if decoder.Decode(&value) != nil || decoder.Decode(new(any)) != io.EOF || value.Version < 3 || value.Version > 5 {
		return 0, errCatalogCompatibility
	}
	return value.Version, nil
}

// Caller holds its existing mutation/source locks and rechecks the source epoch
// immediately before publication. This hook must run before the first Ref,
// sentinel snapshot or v5 runtime is made authoritative; it never applies it.
func (server *Server) ensureSubscriptionCatalogCompatibility(ctx context.Context, config map[string]any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	epoch, err := server.catalogCompatibilityEpoch()
	if err != nil {
		return err
	}
	active, err := server.repository.activeRevision()
	if err != nil {
		return errCatalogCompatibility
	}
	value, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	if err != nil {
		return errCatalogCompatibility
	}
	var old catalogCompatibilityDescriptor
	if len(value) != 0 {
		body, _ := json.Marshal(value)
		if json.Unmarshal(body, &old) != nil || old.FormatVersion != 1 || old.ProducerCatalogSchema != 1 || (old.State != "prepared" && old.State != "preparing") {
			return errCatalogCompatibility
		}
	}
	if active == "" {
		// An absent state pointer is not enough if a prior runtime still exists.
		for _, path := range []string{server.opts.Runtime.XrayConfig, server.opts.Runtime.XrayHealthPool} {
			if path == "" {
				continue
			}
			if _, err := os.Lstat(path); err == nil || !errors.Is(err, os.ErrNotExist) {
				return errCatalogCompatibility
			}
		}
		if physical, _ := ctx.Value(catalogCompatibilityPhysicalKey{}).(bool); !physical {
			descriptor := catalogCompatibilityDescriptor{FormatVersion: 1, State: "prepared", Kind: "no-active-revision", SourceEpoch: epoch, ProducerCatalogSchema: 1, CatalogRefs: []subscriptioncatalog.Ref{}}
			return server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(descriptor))
		}
	}
	operation, err := server.repository.auxiliary("lifecycle-operation")
	if err != nil || lifecycleOperationActive(operation) {
		return errCatalogCompatibility
	}
	for _, name := range []string{"apply-operation", "subscription-runtime-operation"} {
		state, err := server.repository.auxiliary(name)
		if err != nil || state["pending"] == true {
			return errCatalogCompatibility
		}
	}
	client, _, err := server.newRouterOSRESTClient(config)
	if err != nil {
		return errCatalogCompatibility
	}
	defer client.CloseIdleConnections()
	inventory, err := client.InspectCatalogImageCompatibility(ctx)
	if err != nil {
		return errCatalogCompatibility
	}
	// A bootstrap draft has no prior runtime baseline to bind to an unexpected
	// retained image. Do not invent one from newly accepted catalog pointers.
	if active == "" && inventory.Previous != nil {
		return errCatalogCompatibility
	}
	storageRoot, err := validateLifecycleStorageRoot(text(objectAt(config, "storage")["root"]))
	if err != nil || !(inventory.Current.Root == storageRoot+"/root" || strings.HasPrefix(inventory.Current.Root, storageRoot+"/root-") && !strings.Contains(strings.TrimPrefix(inventory.Current.Root, storageRoot+"/root-"), "/")) {
		return errCatalogCompatibility
	}
	for _, mount := range inventory.Mounts {
		if !strings.HasPrefix(strings.Trim(mount.Source, "/"), storageRoot+"/") {
			return errCatalogCompatibility
		}
	}
	if inventory.Previous != nil && !(inventory.Previous.Root == storageRoot+"/root" || strings.HasPrefix(inventory.Previous.Root, storageRoot+"/root-") && !strings.Contains(strings.TrimPrefix(inventory.Previous.Root, storageRoot+"/root-"), "/")) {
		return errCatalogCompatibility
	}
	contract, err := client.ReadCatalogImageContract(ctx)
	if err != nil {
		return errCatalogCompatibility
	}
	if old.State == "prepared" && old.Producer.Root == inventory.Current.Root && old.CurrentFingerprint == inventory.Fingerprint && contract != nil && contract.ProducerRoot == inventory.Current.Root && contract.CatalogSchema == 1 {
		if old.Kind == "no-previous" && old.Previous == nil && inventory.Previous == nil {
			return nil
		}
		if old.Kind == "catalog-capable" && old.Previous != nil && inventory.Previous != nil && catalogCompatSamePrevious(*old.Previous, *inventory.Previous) && contract.PreviousRoot == inventory.Previous.Root && contract.PreviousCatalogSchema == 1 {
			return nil
		}
	}
	if old.State == "prepared" && old.Kind == "legacy-snapshot" && old.Producer.Root == inventory.Current.Root && old.Previous != nil && inventory.Previous != nil && old.Previous.ID == inventory.Previous.ID && old.Previous.Root == inventory.Previous.Root {
		if old.CurrentFingerprint != inventory.Fingerprint || !catalogCompatSamePrevious(*old.Previous, *inventory.Previous) {
			return errCatalogCompatibility
		}
		if !inventory.Previous.Stopped || len(inventory.Previous.Mountlists) != 1 || inventory.Previous.Mountlists[0] != old.Mountlist || contract == nil || contract.Handoff != old.Identifier || contract.PreviousRoot != old.Previous.Root {
			return errCatalogCompatibility
		}
		mounts := catalogCompatibilityMounts(inventory, old.Identifier)
		if _, err := client.AttachCatalogImageHandoff(ctx, inventory, old.Identifier, mounts); err != nil {
			return errCatalogCompatibility
		}
		return validateCatalogCompatSnapshot(ctx, server.catalogCompatibilityRoots(), old.Identifier, old.Files, false)
	}
	// An unchanged prepared physical descriptor is already authoritative above.
	// Only an actual successor transition needs the completed-arrival readbacks.
	arrivalCapable, err := client.ValidateCompletedCatalogImageArrival(ctx, inventory)
	if err != nil {
		return errCatalogCompatibility
	}
	positiveClaim := contract != nil && inventory.Previous != nil && (contract.ProducerRoot == inventory.Previous.Root || contract.ProducerRoot == inventory.Current.Root && contract.PreviousRoot == inventory.Previous.Root && contract.PreviousCatalogSchema == 1)
	if positiveClaim && !arrivalCapable {
		return errCatalogCompatibility
	}
	poolVersion := 0
	if inventory.Previous != nil {
		poolVersion, err = catalogCompatibilityPoolVersion(server.opts.Runtime.XrayHealthPool)
		if err != nil {
			return err
		}
		if poolVersion >= 5 && !arrivalCapable {
			return errCatalogCompatibility
		}
	}
	if !arrivalCapable && (inventory.Previous != nil || old.State == "preparing" && old.Kind == "legacy-snapshot") {
		// A legacy data pool can coexist with authoritative catalogue sources
		// before Apply. A baseline that omits their private generations would
		// be incomplete; prove the whole graph empty before any new copy,
		// journal write or incomplete-stage retirement.
		if err := server.validateCatalogLegacyReferenceAbsence(ctx, value, old); err != nil {
			return err
		}
	}
	var arrivalRefs map[string]subscriptioncatalog.Ref
	if arrivalCapable {
		arrivalRefs, err = server.catalogArrivalReferences(ctx, client, inventory, epoch, value, old)
		if err != nil {
			return err
		}
		if old.State == "preparing" {
			old = catalogCompatibilityDescriptor{}
		}
	}
	if old.State == "preparing" && len(old.Files) == 0 {
		switch old.Kind {
		case "legacy-snapshot":
			if err := server.retireIncompleteCatalogCompatSnapshot(ctx, client, inventory, epoch, old); err != nil {
				return catalogCompatSnapshotError(ctx, "snapshot-retire", err)
			}
		case "no-previous":
			// No copy exists to retire. Fresh physical absence of a predecessor
			// permits completing this marker-only preparation after a restart.
			if inventory.Previous != nil || old.Previous != nil || old.Identifier != "" || old.Mountlist != "" || len(old.CatalogRefs) != 0 {
				return errCatalogCompatibility
			}
		default:
			return errCatalogCompatibility
		}
		// The old journal remains durable until a fresh descriptor is written.
		// A crash in between repeats only the checked unused-stage retirement.
		old = catalogCompatibilityDescriptor{}
	}
	descriptor := catalogCompatibilityDescriptor{FormatVersion: 1, State: "preparing", SourceEpoch: epoch, Producer: inventory.Current, ProducerCatalogSchema: 1, CurrentFingerprint: inventory.Fingerprint, Previous: inventory.Previous, CatalogRefs: []subscriptioncatalog.Ref{}}
	marker := routeros.CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: inventory.Current.Root, CatalogSchema: 1}
	if inventory.Previous == nil {
		descriptor.Kind = "no-previous"
	} else {
		if arrivalCapable {
			// Capability comes from the checked arrival/contract, independently
			// of runtime data version. Unknown v5 was rejected above.
			descriptor.Kind = "catalog-capable"
			marker.PreviousRoot = inventory.Previous.Root
			marker.PreviousCatalogSchema = 1
			refs := arrivalRefs
			keys := make([]string, 0, len(refs))
			for key := range refs {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			for _, key := range keys {
				descriptor.CatalogRefs = append(descriptor.CatalogRefs, refs[key])
			}
		} else {
			descriptor.Kind = "legacy-snapshot"
			descriptor.Identifier = catalogCompatibilitySnapshotIdentifier(epoch, inventory.Current, *inventory.Previous)
			if old.State == "preparing" {
				if old.SourceEpoch != epoch || old.Identifier != descriptor.Identifier || old.CurrentFingerprint != inventory.Fingerprint || old.Previous == nil || !catalogCompatSamePrevious(*old.Previous, *inventory.Previous) {
					return errCatalogCompatibility
				}
				if len(old.Files) == 0 {
					if err := client.AssertCatalogImageHandoffUnused(ctx, inventory, descriptor.Identifier); err != nil {
						return errCatalogCompatibility
					}
					if next, err := server.catalogCompatibilityEpoch(); err != nil || next != epoch {
						return errCatalogCompatibility
					}
					if err := removeIncompleteCatalogCompatSnapshot(ctx, server.catalogCompatibilityRoots(), descriptor.Identifier); err != nil {
						return err
					}
					files, err := buildCatalogCompatSnapshot(ctx, server.catalogCompatibilityRoots(), descriptor.Identifier)
					if err != nil {
						return err
					}
					descriptor.Files = files
					if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(descriptor)); err != nil {
						return errCatalogCompatibility
					}
				} else {
					descriptor.Files = old.Files
					if err := validateCatalogCompatSnapshot(ctx, server.catalogCompatibilityRoots(), descriptor.Identifier, descriptor.Files, true); err != nil {
						return err
					}
				}
			} else {
				if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(descriptor)); err != nil {
					return errCatalogCompatibility
				}
				files, err := buildCatalogCompatSnapshot(ctx, server.catalogCompatibilityRoots(), descriptor.Identifier)
				if err != nil {
					return err
				}
				descriptor.Files = files
				if err := server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(descriptor)); err != nil {
					return errCatalogCompatibility
				}
			}
			mounts := catalogCompatibilityMounts(inventory, descriptor.Identifier)
			if next, err := server.catalogCompatibilityEpoch(); err != nil || next != epoch {
				return errCatalogCompatibility
			}
			list, err := client.AttachCatalogImageHandoff(ctx, inventory, descriptor.Identifier, mounts)
			if err != nil {
				return errCatalogCompatibility
			}
			descriptor.Mountlist = list
			marker.PreviousRoot = inventory.Previous.Root
			marker.Mountlist = list
			marker.Handoff = descriptor.Identifier
			for i, mount := range mounts {
				marker.MountSources[i] = mount.Source
			}
		}
	}
	if next, err := server.catalogCompatibilityEpoch(); err != nil || next != epoch {
		return errCatalogCompatibility
	}
	if arrivalCapable {
		if capable, err := client.ValidateCompletedCatalogImageArrival(ctx, inventory); err != nil || !capable {
			return errCatalogCompatibility
		}
	}
	if err := client.PublishCatalogImageContract(ctx, marker); err != nil {
		return errCatalogCompatibility
	}
	if arrivalCapable {
		if capable, err := client.ValidateCompletedCatalogImageArrival(ctx, inventory); err != nil || !capable {
			return errCatalogCompatibility
		}
	}
	descriptor.State = "prepared"
	return server.repository.saveAuxiliary(catalogCompatibilityAuxiliary, catalogCompatJSON(descriptor))
}

func catalogCompatibilityMounts(inventory routeros.CatalogImageInventory, id string) []routeros.CatalogImageMount {
	mounts := make([]routeros.CatalogImageMount, 0, 4)
	for _, mount := range inventory.Mounts {
		if mount.Destination != "/logs" {
			mount.Source = strings.Trim(mount.Source, "/") + "/" + catalogCompatDirectory + "/" + id + mount.Destination
		}
		mounts = append(mounts, mount)
	}
	return mounts
}

func catalogCompatSamePrevious(left, right routeros.CatalogImageContainer) bool {
	left.Mountlists = nil
	right.Mountlists = nil
	l, _ := json.Marshal(left)
	r, _ := json.Marshal(right)
	return string(l) == string(r)
}

func catalogCompatibilitySnapshotIdentifier(epoch string, current, previous routeros.CatalogImageContainer) string {
	previous.Mountlists = nil
	seed, _ := canonicalJSON(map[string]any{"epoch": epoch, "current": current, "previous": previous})
	sum := sha256.Sum256(seed)
	return hex.EncodeToString(sum[:])
}
