package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"reflect"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

// A completed, authenticated physical arrival can replace an unrecorded failed
// preparation. It cannot turn that preparation into a prepared reference graph,
// retire recorded files, or waive a real reference. Normal export/pruning and
// all callers outside this transition keep the strict collector unchanged.
func (server *Server) catalogArrivalReferences(ctx context.Context, client *routeros.Client, inventory routeros.CatalogImageInventory, epoch string, value map[string]any, old catalogCompatibilityDescriptor) (map[string]subscriptioncatalog.Ref, error) {
	if old.State != "preparing" {
		if old.State != "" && old.Kind != "legacy-snapshot" && old.Kind != "catalog-capable" && old.Kind != "no-previous" && old.Kind != "no-active-revision" {
			return nil, errCatalogCompatibility
		}
		return server.subscriptionCatalogReferences(ctx)
	}
	body, err := canonicalJSON(value)
	if err != nil {
		return nil, errCatalogCompatibility
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var checked catalogCompatibilityDescriptor
	if decoder.Decode(&checked) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errCatalogCompatibility
	}
	old = checked
	refs, hasRefs := value["catalog_refs"].([]any)
	_, recordedFiles := value["files"]
	if !hasRefs || len(refs) != 0 || recordedFiles || old.Kind != "legacy-snapshot" || len(old.Files) != 0 || old.Mountlist != "" || len(old.CatalogRefs) != 0 || old.Previous == nil || inventory.Previous == nil || old.SourceEpoch != epoch || old.CurrentFingerprint != inventory.Fingerprint || !reflect.DeepEqual(old.Producer, inventory.Current) || !reflect.DeepEqual(*old.Previous, *inventory.Previous) {
		return nil, errCatalogCompatibility
	}
	if old.Identifier != catalogCompatibilitySnapshotIdentifier(epoch, inventory.Current, *inventory.Previous) {
		return nil, errCatalogCompatibility
	}
	revision, err := revisionFor(value)
	if err != nil {
		return nil, errCatalogCompatibility
	}
	graph, err := server.scanSubscriptionCatalogReferenceGraph(ctx, revision)
	if err != nil || graph.compatibilityPrepared || len(graph.refs) != 0 {
		return nil, errCatalogCompatibility
	}
	if err := server.retireIncompleteCatalogCompatSnapshot(ctx, client, inventory, epoch, old); err != nil {
		return nil, err
	}
	// Retirement never rewrites the old journal. Recheck exactly that durable
	// journal and epoch before publishing a truthful marker and new descriptor.
	fresh, err := server.repository.auxiliary(catalogCompatibilityAuxiliary)
	if err != nil {
		return nil, errCatalogCompatibility
	}
	freshRevision, err := revisionFor(fresh)
	if err != nil || freshRevision != revision {
		return nil, errCatalogCompatibility
	}
	if next, err := server.catalogCompatibilityEpoch(); err != nil || next != epoch {
		return nil, errCatalogCompatibility
	}
	return graph.refs, nil
}
