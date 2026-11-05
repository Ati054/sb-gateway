package controlplane

import (
	"context"
	"errors"
)

// Read only after validateVerifiedLocalImage anchored the record to the
// immutable managed upload. Older verified uploads have no catalogue contract.
func (server *Server) verifiedLocalImageCatalogSchema(reference string) (int, error) {
	verification, err := server.repository.auxiliary("lifecycle-image-verifications")
	if err != nil {
		return 0, err
	}
	record := objectAt(objectAt(verification, "images"), reference)
	value, present := record["catalog_schema"]
	if !present {
		return 0, nil
	}
	schema, ok := numberToInt64(value)
	if !ok || (schema != 0 && schema != 1) {
		return 0, errors.New("the uploaded image catalogue contract is invalid")
	}
	return int(schema), nil
}

// The caller holds the mutation admission lock and has reconciled image
// probation. Preparation happens before the recovery archive and schedule.
func (server *Server) prepareLifecycleCatalogCompatibility(ctx context.Context, config map[string]any, targetSchema int) error {
	refs, err := server.subscriptionCatalogReferences(ctx)
	if errors.Is(err, errSubscriptionCatalogReferencesPending) {
		if err := server.repairIncompleteLifecycleCatalogCompatibility(ctx, config, targetSchema); err != nil {
			return err
		}
		refs, err = server.subscriptionCatalogReferences(ctx)
	}
	if err != nil {
		return err
	}
	if len(refs) == 0 {
		return nil
	}
	if targetSchema != 1 {
		return errors.New("the selected image cannot read the stored subscription catalogue; use a compatible verified image")
	}
	return server.prepareSubscriptionCatalogRuntimeCompatibility(ctx, config)
}
