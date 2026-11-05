package runtimeconfig

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

// CatalogFingerprintKind versions the connection-only Node+Secrets digest. It
// must change if normalization changes; labels and selection/location metadata
// are excluded by the controller that produces the immutable generation.
const CatalogFingerprintKind = "connection-node-secrets-v1"

// RuntimeCatalogNode contains matching/endpoint metadata, never credentials or
// the complete TLS/transport definition. ID is already runtime-scoped.
type RuntimeCatalogNode struct {
	ID          string
	Generation  string
	Fingerprint string
	Metadata    map[string]any
}

// RuntimeNodeCatalog is supplied by the controller from the exact committed or
// desired immutable generation. InventoryCount counts enabled provider nodes;
// configuration-owned exits are added by runtimeconfig. LookupDefinition is
// reserved for explicitly required static leaves, not health-candidate scans.
type RuntimeNodeCatalog interface {
	WalkMetadata(context.Context, func(RuntimeCatalogNode) error) error
	LookupDefinition(context.Context, string) (subscriptioncatalog.Record, error)
	References() []subscriptioncatalog.Ref
	InventoryCount() int
}

// CatalogDefinition identifies an immutable lazy definition without embedding
// its opaque Node or Secrets in the health-pool file.
type CatalogDefinition struct {
	Generation      string `json:"generation"`
	Fingerprint     string `json:"fingerprint"`
	FingerprintKind string `json:"fingerprint_kind"`
}

// CatalogDynamicOutboundTag uses connection identity rather than catalogue
// generation, so a cosmetic inventory refresh does not change the live handler.
// The v4 raw-body tag algorithm remains separate for legacy contracts.
func CatalogDynamicOutboundTag(prefix, nodeID string, definition CatalogDefinition) string {
	sum := sha256.Sum256([]byte(nodeID + "\x00" + definition.FingerprintKind + "\x00" + definition.Fingerprint))
	return prefix + hex.EncodeToString(sum[:])[:12]
}

// RenderCatalogOutbound decodes exactly one private record. Secrets is an opaque
// reference-to-value JSON object; neither credentials nor records appear in
// error messages. The normalized provider ID is overridden by the checked,
// runtime-scoped record ID before using the maintained outbound converters.
func RenderCatalogOutbound(record subscriptioncatalog.Record) (json.RawMessage, error) {
	node, secrets, err := decodeValidatedCatalogRecord(record, "")
	if err != nil {
		return nil, err
	}
	node["id"] = record.ID
	readSecret := func(reference string) (string, error) {
		value, ok := secrets[reference]
		if !ok || value == "" {
			return "", errors.New("catalog definition secret is unavailable")
		}
		return value, nil
	}
	source, err := BuildXrayOutboundSource(nil, []map[string]any{node}, readSecret)
	if err != nil {
		return nil, errors.New("catalog outbound source is invalid")
	}
	var leaf []map[string]any
	for _, outbound := range source {
		if textValue(outbound["tag"]) == record.ID {
			leaf = append(leaf, outbound)
		}
	}
	if len(leaf) != 1 || (textValue(node["protocol"]) != "vless" && textValue(node["protocol"]) != "hysteria2") {
		return nil, errors.New("unsupported catalog outbound definition")
	}
	converted, err := ConvertXrayOutbounds(leaf, "", nil, nil)
	if err != nil || len(converted.Outbounds) != 1 {
		return nil, errors.New("catalog outbound conversion failed")
	}
	body, err := marshalCanonical(converted.Outbounds[0])
	if err != nil {
		return nil, errors.New("catalog outbound encoding failed")
	}
	return body, nil
}

// ValidateCatalogRecordSource checks the private record against its declared
// source before a caller overlays generation-specific/runtime ID fields.
func ValidateCatalogRecordSource(record subscriptioncatalog.Record, sourceID string) error {
	_, _, err := decodeValidatedCatalogRecord(record, sourceID)
	return err
}

func decodeValidatedCatalogRecord(record subscriptioncatalog.Record, sourceID string) (map[string]any, map[string]string, error) {
	var node map[string]any
	var secrets map[string]string
	var metadata struct {
		ID             string `json:"id"`
		SubscriptionID string `json:"subscription_id"`
		ProviderNodeID string `json:"provider_node_id"`
	}
	if json.Unmarshal(record.Node, &node) != nil || node == nil || json.Unmarshal(record.Secrets, &secrets) != nil || json.Unmarshal(record.Metadata, &metadata) != nil {
		return nil, nil, errors.New("invalid catalog definition record")
	}
	baseID := textValue(node["id"])
	subscriptionID := textValue(node["subscription_id"])
	if baseID == "" || subscriptionID == "" || sourceID != "" && sourceID != subscriptionID || metadata.ID != record.ID || metadata.SubscriptionID != subscriptionID || metadata.ProviderNodeID != baseID || !serviceIDPattern.MatchString(record.ID) {
		return nil, nil, errors.New("catalog definition source identity mismatch")
	}
	combined := subscriptionID + "-" + baseID
	if len(combined) > 64 {
		sum := sha256.Sum256([]byte(combined))
		combined = strings.TrimRight(combined[:53], "-") + "-" + hex.EncodeToString(sum[:])[:10]
	}
	if combined != record.ID {
		return nil, nil, errors.New("catalog definition scoped identity mismatch")
	}
	return node, secrets, nil
}
