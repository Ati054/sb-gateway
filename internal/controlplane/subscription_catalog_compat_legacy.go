package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
)

// A newly made legacy baseline intentionally excludes private catalogue files.
// Its complete authoritative graph must therefore contain no catalogue Ref,
// irrespective of pool version or the availability of an image contract.
func (server *Server) validateCatalogLegacyReferenceAbsence(ctx context.Context, value map[string]any, old catalogCompatibilityDescriptor) error {
	if old.State != "preparing" {
		refs, err := server.subscriptionCatalogReferences(ctx)
		if err != nil || len(refs) != 0 {
			return errCatalogCompatibility
		}
		return nil
	}
	body, err := canonicalJSON(value)
	if err != nil {
		return errCatalogCompatibility
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var checked catalogCompatibilityDescriptor
	if decoder.Decode(&checked) != nil || decoder.Decode(new(any)) != io.EOF {
		return errCatalogCompatibility
	}
	refs, hasRefs := value["catalog_refs"].([]any)
	files, hasFiles := value["files"]
	if checked.FormatVersion != 1 || checked.ProducerCatalogSchema != 1 || checked.State != "preparing" || !hasRefs || len(refs) != 0 || len(checked.CatalogRefs) != 0 {
		return errCatalogCompatibility
	}
	if hasFiles {
		rows, ok := files.([]any)
		if !ok || len(rows) == 0 || len(rows) != len(checked.Files) {
			return errCatalogCompatibility
		}
	} else if checked.Files != nil {
		return errCatalogCompatibility
	}
	switch checked.Kind {
	case "legacy-snapshot":
		if !safeRevision(checked.Identifier) || !safeRevision(checked.SourceEpoch) || !safeRevision(checked.CurrentFingerprint) || checked.Previous == nil {
			return errCatalogCompatibility
		}
	case "no-previous":
		if hasFiles || checked.Identifier != "" || checked.Mountlist != "" || checked.Previous != nil {
			return errCatalogCompatibility
		}
	default:
		return errCatalogCompatibility
	}
	revision, err := revisionFor(value)
	if err != nil {
		return errCatalogCompatibility
	}
	graph, err := server.scanSubscriptionCatalogReferenceGraph(ctx, revision)
	if err != nil || graph.compatibilityPrepared || len(graph.refs) != 0 {
		return errCatalogCompatibility
	}
	// This is only an absence proof. Existing retirement or recorded-resume
	// code still checks ownership, physical bindings, source epoch and hashes.
	// An unused unrecorded stage may belong to a prior producer/epoch.
	return nil
}
