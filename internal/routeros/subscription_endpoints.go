package routeros

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"sort"
)

// SyncSubscriptionEndpoints owns ONLY static host entries with this exact
// renderer comment. Preparation is add-only; pruning follows runtime health.
// Repeating either phase after a crash is safe and never deletes foreign rows.
func (client *Client) SyncSubscriptionEndpoints(ctx context.Context, values []string, prune bool) error {
	const name = "SB_BYPASS_ENDPOINTS"
	const comment = "SB-GATEWAY loop bypass"
	wanted := map[string]bool{}
	for _, value := range values {
		p, err := netip.ParsePrefix(value)
		if err != nil || !p.Addr().Is4() || p.Bits() != 32 {
			return errors.New("invalid subscription endpoint")
		}
		wanted[p.String()] = true
	}
	read := func() (map[string][]map[string]any, error) {
		rows, err := client.List(ctx, "/rest/ip/firewall/address-list")
		if err != nil {
			return nil, err
		}
		entries := map[string][]map[string]any{}
		for _, row := range rows {
			if text(row["list"]) != name {
				continue
			}
			if text(row["comment"]) != comment || text(row["dynamic"]) == "true" || row["dynamic"] == true || text(row["disabled"]) == "true" || row["disabled"] == true {
				return nil, errors.New("subscription bypass list contains unowned or inactive entries")
			}
			entries[cdnRowAddress(row)] = append(entries[cdnRowAddress(row)], row)
		}
		return entries, nil
	}
	entries, err := read()
	if err != nil {
		return err
	}
	keys := make([]string, 0, len(wanted))
	for value := range wanted {
		keys = append(keys, value)
	}
	sort.Strings(keys)
	for _, value := range keys {
		if len(entries[value]) != 0 {
			continue
		}
		if _, err := client.request(ctx, http.MethodPut, "/rest/ip/firewall/address-list", map[string]any{"list": name, "address": value, "comment": comment}); err != nil {
			return err
		}
	}
	entries, err = read()
	if err != nil {
		return err
	}
	for value := range wanted {
		if len(entries[value]) == 0 {
			return errors.New("subscription endpoint preparation not confirmed")
		}
	}
	if !prune {
		return nil
	}
	for value, rows := range entries {
		for index, row := range rows {
			if wanted[value] && index == 0 {
				continue
			}
			id := text(row[".id"])
			if id == "" {
				return errors.New("subscription endpoint row identity missing")
			}
			if _, err := client.request(ctx, http.MethodDelete, "/rest/ip/firewall/address-list/"+routerOSResourceID(id), nil); err != nil {
				return err
			}
		}
	}
	entries, err = read()
	if err != nil {
		return err
	}
	if len(entries) != len(wanted) {
		return errors.New("subscription endpoint cleanup not confirmed")
	}
	for value := range wanted {
		if len(entries[value]) != 1 {
			return errors.New("subscription endpoint state not confirmed")
		}
	}
	return nil
}
