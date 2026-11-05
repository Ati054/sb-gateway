package releasecontract

// SubscriptionCatalogSchemaLabel declares on-disk catalogue support. Release
// version names are deliberately not used as a substitute for this contract.
const SubscriptionCatalogSchemaLabel = "io.sb-gateway.data.subscription-catalog.schema"

func CatalogSchema(labels map[string]string) (int, bool) {
	value, present := labels[SubscriptionCatalogSchemaLabel]
	if !present {
		return 0, true
	}
	switch value {
	case "0":
		return 0, true
	case "1":
		return 1, true
	default:
		return 0, false
	}
}
