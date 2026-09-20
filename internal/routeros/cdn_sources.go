package routeros

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
)

// SyncCDNSources updates only one provider-owned static IPv4 list. The caller
// serializes this with Apply/rollback. New addresses are added before stale
// ones are removed; an interrupted preparation never empties the live list.
func (client *Client) SyncCDNSources(ctx context.Context, provider string, values []string) error {
	p, ok := cdnfeed.Lookup(provider)
	if !ok {
		return errors.New("unsupported managed CDN source list")
	}
	values, err := cdnfeed.Validate(values)
	if err != nil {
		return err
	}
	name := cdnfeed.ListName(p.ID)
	if p.ID == "cloudflare" {
		name = "SB_CDN_CLOUDFLARE_V4"
	}
	prefix := "SB-GATEWAY CDN " + p.ID + " "
	digest := sha256.Sum256([]byte(strings.Join(values, "\n")))
	comment := prefix + hex.EncodeToString(digest[:])[:12]
	rows, err := client.List(ctx, "/rest/ip/firewall/address-list")
	if err != nil {
		return err
	}
	if same, err := checkCDNRows(rows, name, prefix, comment, values); err != nil || same {
		return err
	}
	guard := fmt.Sprintf(`:foreach row in=[/ip/firewall/address-list/find where list="%s"] do={ :if ([:pick [/ip/firewall/address-list/get $row comment] 0 %d] != "%s") do={ :error "unowned CDN source entry" } }`, name, len(prefix), prefix)
	for start := 0; start < len(values); start += 200 {
		end := min(start+200, len(values))
		wireValues := make([]string, 0, end-start)
		for _, value := range values[start:end] {
			wireValues = append(wireValues, strings.TrimSuffix(value, "/32"))
		}
		// Do not name the loop variable `address`: inside RouterOS `find where`
		// that collides with the address property, turns address=$address into a
		// row-field comparison and makes every item after the first reuse row 1.
		source := guard + "\n" + fmt.Sprintf(`:foreach cidr in={"%s"} do={ :local row [/ip/firewall/address-list/find where list="%s" and address=$cidr]; :if ([:len $row] = 0) do={ /ip/firewall/address-list/add list="%s" address=$cidr comment="%s" } else={ /ip/firewall/address-list/set $row comment="%s" } }`, strings.Join(wireValues, `";"`), name, name, comment, comment)
		if err := client.runCDNSourceScript(ctx, source); err != nil {
			return err
		}
	}
	// A successful REST script response is not proof of RouterOS execution.
	// Verify every desired address before permitting any stale-entry removal.
	rows, err = client.List(ctx, "/rest/ip/firewall/address-list")
	if err != nil {
		return err
	}
	if _, err := checkCDNRows(rows, name, prefix, comment, values); err != nil {
		return err
	}
	marked := map[string]bool{}
	for _, row := range rows {
		if text(row["list"]) == name && text(row["comment"]) == comment {
			marked[cdnRowAddress(row)] = true
		}
	}
	for _, value := range values {
		if !marked[value] {
			return errors.New("CDN source preparation was not confirmed")
		}
	}
	source := guard + "\n" + fmt.Sprintf(`:foreach row in=[/ip/firewall/address-list/find where list="%s"] do={ :if ([/ip/firewall/address-list/get $row comment] != "%s") do={ /ip/firewall/address-list/remove $row } }`, name, comment)
	if err := client.runCDNSourceScript(ctx, source); err != nil {
		return err
	}
	rows, err = client.List(ctx, "/rest/ip/firewall/address-list")
	if err != nil {
		return err
	}
	same, err := checkCDNRows(rows, name, prefix, comment, values)
	if err != nil {
		return err
	}
	if !same {
		return errors.New("CDN source update was not confirmed")
	}
	return nil
}

func checkCDNRows(rows []map[string]any, name, prefix, comment string, values []string) (bool, error) {
	wanted := map[string]bool{}
	for _, value := range values {
		wanted[value] = true
	}
	count, same := 0, true
	seen := map[string]bool{}
	for _, row := range rows {
		if text(row["list"]) != name {
			continue
		}
		address := cdnRowAddress(row)
		if !strings.HasPrefix(text(row["comment"]), prefix) || text(row["dynamic"]) == "true" || row["dynamic"] == true || text(row["disabled"]) == "true" || row["disabled"] == true {
			return false, errors.New("CDN source list contains an unowned, disabled, or dynamic entry")
		}
		if seen[address] {
			return false, errors.New("CDN source list contains duplicate entries")
		}
		seen[address] = true
		count++
		same = same && wanted[address] && text(row["comment"]) == comment
	}
	return same && count == len(wanted), nil
}

func cdnRowAddress(row map[string]any) string {
	value := text(row["address"])
	if p, err := netip.ParsePrefix(value); err == nil {
		return p.Masked().String()
	}
	if a, err := netip.ParseAddr(value); err == nil && a.Is4() {
		return netip.PrefixFrom(a, 32).String()
	}
	return value
}

func (client *Client) runCDNSourceScript(ctx context.Context, source string) error {
	if len(source) > maxDirectScriptBytes {
		return errors.New("CDN source batch exceeds RouterOS script limit")
	}
	name, err := managedScriptName("apply", source)
	if err != nil {
		return err
	}
	id, err := client.installManagedScript(ctx, name, source)
	if err != nil {
		return err
	}
	_, runErr := client.requestAction(ctx, http.MethodPost, "/rest/system/script/run", map[string]any{".id": id})
	// Exact content-addressed script installed above, never a broad cleanup.
	_, cleanupErr := client.request(ctx, http.MethodDelete, "/rest/system/script/"+routerOSResourceID(id), nil)
	return errors.Join(runErr, cleanupErr)
}
