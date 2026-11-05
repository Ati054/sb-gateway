package routeros

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
)

// ValidateCompletedCatalogImageArrival proves predecessor capability without
// inventing a historical runtime fingerprint. Pool format is deliberately not
// part of image capability. False means no positive predecessor claim; an
// existing positive claim with missing, stale or ambiguous proof is an error.
// This method is read-only and does not authorize snapshot retirement itself.
func (client *Client) ValidateCompletedCatalogImageArrival(ctx context.Context, expected CatalogImageInventory) (bool, error) {
	before, err := client.InspectCatalogImageCompatibility(ctx)
	if err != nil || !reflect.DeepEqual(before, expected) {
		return false, ErrCatalogImageCompatibility
	}
	contract, err := client.ReadCatalogImageContract(ctx)
	if err != nil {
		return false, err
	}
	if before.Previous == nil || contract == nil {
		return false, nil
	}
	previous := before.Previous
	claimed := contract.ProducerRoot == previous.Root ||
		contract.ProducerRoot == before.Current.Root && contract.PreviousRoot == previous.Root && contract.PreviousCatalogSchema == 1
	if !claimed {
		return false, nil
	}
	if !previous.Stopped || len(previous.Mountlists) != 0 || before.Current.Interface == "" || !reflect.DeepEqual(previous.Environment, before.Current.Environment) {
		return false, ErrCatalogImageCompatibility
	}
	transfers, err := client.List(ctx, "/rest/system/script?name="+imageUpdateTransfer)
	if err != nil || len(transfers) != 0 {
		return false, ErrCatalogImageCompatibility
	}
	arrival, err := client.completedCatalogArrival(ctx)
	if err != nil {
		return false, err
	}
	var receipt struct {
		CandidateID   string   `json:"candidate-id"`
		CandidateRoot string   `json:"candidate-root"`
		PreviousID    string   `json:"previous-id"`
		PreviousRoot  string   `json:"previous-root"`
		Schema        int      `json:"catalog-schema"`
		Phase         string   `json:"phase"`
		LiveInterface string   `json:"live-if"`
		Mountlists    []string `json:"mountlists"`
	}
	if json.Unmarshal([]byte(text(arrival["source"])), &receipt) != nil || receipt.Schema != 1 || receipt.Phase != "completed" ||
		receipt.CandidateID != before.Current.ID || strings.Trim(receipt.CandidateRoot, "/") != before.Current.Root ||
		receipt.PreviousID != previous.ID || strings.Trim(receipt.PreviousRoot, "/") != previous.Root || receipt.LiveInterface != before.Current.Interface ||
		!reflect.DeepEqual(compatList(receipt.Mountlists), before.Current.Mountlists) {
		return false, ErrCatalogImageCompatibility
	}
	// The inventory also covers four enabled mount rows and their actual sources.
	// Re-read every authority after the receipt: a changing proof is not evidence.
	after, err := client.InspectCatalogImageCompatibility(ctx)
	if err != nil || !reflect.DeepEqual(after, before) {
		return false, ErrCatalogImageCompatibility
	}
	secondContract, err := client.ReadCatalogImageContract(ctx)
	if err != nil || secondContract == nil || *secondContract != *contract {
		return false, ErrCatalogImageCompatibility
	}
	secondArrival, err := client.completedCatalogArrival(ctx)
	if err != nil || !reflect.DeepEqual(arrival, secondArrival) {
		return false, ErrCatalogImageCompatibility
	}
	transfers, err = client.List(ctx, "/rest/system/script?name="+imageUpdateTransfer)
	if err != nil || len(transfers) != 0 {
		return false, ErrCatalogImageCompatibility
	}
	return true, nil
}

func (client *Client) completedCatalogArrival(ctx context.Context) (map[string]any, error) {
	rows, err := client.List(ctx, "/rest/system/script?name="+CatalogImageArrivalName)
	if err != nil || len(rows) != 1 || !compatObjectID.MatchString(text(rows[0][".id"])) || text(rows[0]["name"]) != CatalogImageArrivalName || text(rows[0]["comment"]) != "SB-GATEWAY catalog image arrival" {
		return nil, ErrCatalogImageCompatibility
	}
	return rows[0], nil
}
