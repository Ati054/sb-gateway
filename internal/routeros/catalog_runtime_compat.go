package routeros

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
)

// ValidateCatalogRuntimeImageProof permits only read-only reconstruction during
// probation. It does not install mounts, alter a handoff or publish new data.
// A different current root requires the exact verified-schema transfer receipt.
func (client *Client) ValidateCatalogRuntimeImageProof(ctx context.Context, producer CatalogImageContainer, fingerprint string) error {
	contract, err := client.ReadCatalogImageContract(ctx)
	if err != nil || contract == nil || contract.CatalogSchema != 1 || !compatIdentifier.MatchString(fingerprint) {
		return ErrCatalogImageCompatibility
	}
	rows, err := client.List(ctx, "/rest/container")
	if err != nil {
		return ErrCatalogImageCompatibility
	}
	var current *CatalogImageContainer
	var rollback *CatalogImageContainer
	var previous *CatalogImageContainer
	for _, row := range rows {
		role := text(row["comment"])
		if role != "SB-GATEWAY container" && role != "SB-GATEWAY container rollback" && role != "SB-GATEWAY container previous" {
			continue
		}
		value, err := compatContainer(row)
		if err != nil {
			return err
		}
		switch value.Role {
		case "SB-GATEWAY container":
			if current != nil {
				return ErrCatalogImageCompatibility
			}
			copy := value
			current = &copy
		case "SB-GATEWAY container rollback":
			if rollback != nil {
				return ErrCatalogImageCompatibility
			}
			copy := value
			rollback = &copy
		case "SB-GATEWAY container previous":
			if previous != nil {
				return ErrCatalogImageCompatibility
			}
			copy := value
			previous = &copy
		}
	}
	if current == nil || current.Stopped {
		return ErrCatalogImageCompatibility
	}
	promoted := contract.ProducerRoot == current.Root && current.Root != producer.Root
	if contract.ProducerRoot != producer.Root && !promoted {
		return ErrCatalogImageCompatibility
	}
	if current.Root == producer.Root {
		if current.ID != producer.ID {
			return ErrCatalogImageCompatibility
		}
	} else {
		receipts, err := client.List(ctx, "/rest/system/script?name="+imageUpdateTransfer)
		if err != nil {
			return ErrCatalogImageCompatibility
		}
		arrival := false
		name, comment := imageUpdateTransfer, "SB-GATEWAY image transfer metadata"
		if len(receipts) == 0 {
			arrival = true
			name, comment = CatalogImageArrivalName, "SB-GATEWAY catalog image arrival"
			receipts, err = client.List(ctx, "/rest/system/script?name="+CatalogImageArrivalName)
		}
		if err != nil || len(receipts) != 1 || text(receipts[0]["name"]) != name || text(receipts[0]["comment"]) != comment {
			return ErrCatalogImageCompatibility
		}
		var receipt struct {
			Candidate   string   `json:"candidate-root"`
			Previous    string   `json:"previous-root"`
			Schema      int      `json:"catalog-schema"`
			Phase       string   `json:"phase"`
			Mountlists  []string `json:"mountlists"`
			PreviousID  string   `json:"previous-id"`
			CandidateID string   `json:"candidate-id"`
		}
		if json.Unmarshal([]byte(text(receipts[0]["source"])), &receipt) != nil || receipt.Schema != 1 || strings.Trim(receipt.Candidate, "/") != current.Root || strings.Trim(receipt.Previous, "/") != producer.Root {
			return ErrCatalogImageCompatibility
		}
		if arrival {
			if receipt.Phase != "completed" || receipt.PreviousID != producer.ID || receipt.CandidateID != current.ID {
				return ErrCatalogImageCompatibility
			}
		} else if (receipt.Phase != "transfer" && receipt.Phase != "probation" && receipt.Phase != "commit") || rollback == nil || rollback.Root != producer.Root || rollback.ID != producer.ID || !rollback.Stopped {
			return ErrCatalogImageCompatibility
		}
		// Marker publication may precede the matching auxiliary rename. Only a
		// completed owned arrival bridges this crash window; a live transfer is
		// never authority to promote the producer during probation.
		if promoted {
			if !arrival || rollback != nil {
				return ErrCatalogImageCompatibility
			}
			if previous == nil {
				if contract.PreviousRoot != "" {
					return ErrCatalogImageCompatibility
				}
			} else if !previous.Stopped || previous.ID != producer.ID || previous.Root != producer.Root || contract.PreviousRoot != producer.Root || contract.PreviousCatalogSchema != 1 {
				return ErrCatalogImageCompatibility
			}
			if previous != nil {
				oldEnv, _ := json.Marshal(producer.Environment)
				previousEnv, _ := json.Marshal(previous.Environment)
				if string(oldEnv) != string(previousEnv) {
					return ErrCatalogImageCompatibility
				}
			}
		}
		sort.Strings(receipt.Mountlists)
		if len(receipt.Mountlists) != len(current.Mountlists) {
			return ErrCatalogImageCompatibility
		}
		for i, name := range receipt.Mountlists {
			if name != current.Mountlists[i] {
				return ErrCatalogImageCompatibility
			}
		}
	}
	mountRows, err := client.List(ctx, "/rest/container/mounts")
	if err != nil {
		return ErrCatalogImageCompatibility
	}
	var mounts []CatalogImageMount
	for _, row := range mountRows {
		if containsCompat(current.Mountlists, text(row["list"])) {
			if compatBool(row["disabled"]) {
				return ErrCatalogImageCompatibility
			}
			mounts = append(mounts, CatalogImageMount{List: text(row["list"]), Source: strings.Trim(text(row["src"]), "/"), Destination: text(row["dst"]), Comment: text(row["comment"])})
		}
	}
	sort.Slice(mounts, func(i, j int) bool { return mounts[i].Destination < mounts[j].Destination })
	adjusted := *current
	adjusted.ID = producer.ID
	adjusted.Root = producer.Root
	if currentCompatFingerprint(adjusted, mounts) != fingerprint {
		return ErrCatalogImageCompatibility
	}
	return nil
}
