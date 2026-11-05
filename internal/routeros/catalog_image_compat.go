package routeros

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"regexp"
	"sort"
	"strings"
)

const CatalogImageContractName = "SB-GATEWAY-catalog-data-contract"
const CatalogImageArrivalName = "SB-GATEWAY-catalog-image-arrival"
const catalogImageContractComment = "SB-GATEWAY catalog data compatibility"

var ErrCatalogImageCompatibility = errors.New("RouterOS catalog image compatibility is unconfirmed")
var compatIdentifier = regexp.MustCompile(`^[0-9a-f]{64}$`)
var compatObjectID = regexp.MustCompile(`^\*[A-Za-z0-9]+$`)
var compatPath = regexp.MustCompile(`^[A-Za-z0-9._/-]{1,220}$`)

type CatalogImageContainer struct {
	ID          string   `json:"id"`
	Root        string   `json:"root"`
	Role        string   `json:"role"`
	Interface   string   `json:"interface"`
	Environment []string `json:"environment"`
	Mountlists  []string `json:"mountlists"`
	Stopped     bool     `json:"stopped"`
}

type CatalogImageMount struct {
	List        string `json:"list"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Comment     string `json:"comment"`
}

type CatalogImageInventory struct {
	Current     CatalogImageContainer  `json:"current"`
	Previous    *CatalogImageContainer `json:"previous,omitempty"`
	Mounts      []CatalogImageMount    `json:"mounts"`
	Fingerprint string                 `json:"fingerprint"`
}

// CatalogImageContract is a checked image-root capability and optional legacy
// standby handoff. It contains no credentials, endpoint addresses or file data.
type CatalogImageContract struct {
	FormatVersion         int       `json:"format_version"`
	State                 string    `json:"state"`
	ProducerRoot          string    `json:"producer_root"`
	CatalogSchema         int       `json:"catalog_schema"`
	PreviousRoot          string    `json:"previous_root,omitempty"`
	PreviousCatalogSchema int       `json:"previous_catalog_schema"`
	Mountlist             string    `json:"mountlist,omitempty"`
	Handoff               string    `json:"handoff,omitempty"`
	MountSources          [4]string `json:"mount_sources"`
}

func compatList(value any) []string {
	var result []string
	switch value := value.(type) {
	case []any:
		for _, item := range value {
			if s, ok := item.(string); ok && s != "" {
				result = append(result, s)
			} else {
				return nil
			}
		}
	case []string:
		result = append(result, value...)
	case string:
		if value != "" {
			result = strings.Split(value, ",")
		}
	}
	sort.Strings(result)
	for i, item := range result {
		if item == "" || i > 0 && result[i-1] == item {
			return nil
		}
	}
	return result
}

func compatBool(value any) bool { return value == true || fmt.Sprint(value) == "true" }

// REST uses envlists on current RouterOS versions. Accept the legacy spelling
// only when absent, or when both independently valid fields describe the same
// sorted list. A malformed preferred field must not fall back to legacy data.
func compatEnvironment(row map[string]any) ([]string, error) {
	preferred, hasPreferred := row["envlists"]
	legacy, hasLegacy := row["envlist"]
	var result []string
	if hasPreferred {
		result = compatList(preferred)
		if len(result) == 0 {
			return nil, ErrCatalogImageCompatibility
		}
	}
	if hasLegacy {
		old := compatList(legacy)
		if len(old) == 0 {
			return nil, ErrCatalogImageCompatibility
		}
		if !hasPreferred {
			result = old
		} else {
			if len(result) != len(old) {
				return nil, ErrCatalogImageCompatibility
			}
			for i := range result {
				if result[i] != old[i] {
					return nil, ErrCatalogImageCompatibility
				}
			}
		}
	}
	if len(result) == 0 {
		return nil, ErrCatalogImageCompatibility
	}
	return result, nil
}

func compatContainer(row map[string]any) (CatalogImageContainer, error) {
	environment, err := compatEnvironment(row)
	if err != nil {
		return CatalogImageContainer{}, err
	}
	return CatalogImageContainer{ID: text(row[".id"]), Root: strings.Trim(text(row["root-dir"]), "/"), Role: text(row["comment"]), Interface: text(row["interface"]), Environment: environment, Mountlists: compatList(row["mountlists"]), Stopped: compatBool(row["stopped"]) || text(row["status"]) == "stopped"}, nil
}

func safeCompatPath(path string) bool {
	if !compatPath.MatchString(path) {
		return false
	}
	for _, part := range strings.Split(strings.Trim(path, "/"), "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func containsCompat(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func currentCompatFingerprint(current CatalogImageContainer, mounts []CatalogImageMount) string {
	body, _ := json.Marshal(struct {
		Current CatalogImageContainer
		Mounts  []CatalogImageMount
	}{current, mounts})
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

// InspectCatalogImageCompatibility uses fresh authenticated inventories. Failure
// or ambiguity never means that a predecessor or a transaction is absent.
func (client *Client) InspectCatalogImageCompatibility(ctx context.Context) (CatalogImageInventory, error) {
	var result CatalogImageInventory
	containers, err := client.List(ctx, "/rest/container")
	if err != nil {
		return result, ErrCatalogImageCompatibility
	}
	schedulers, err := client.List(ctx, "/rest/system/scheduler?.proplist=name")
	if err != nil {
		return result, ErrCatalogImageCompatibility
	}
	for _, row := range schedulers {
		name := text(row["name"])
		if name == imageUpdateScheduler || strings.HasPrefix(name, "SB-GATEWAY-safe-rollback-") {
			return result, ErrCatalogImageCompatibility
		}
	}
	jobs, err := client.List(ctx, "/rest/system/script/job?.proplist=script")
	if err != nil {
		return result, ErrCatalogImageCompatibility
	}
	for _, row := range jobs {
		name := text(row["script"])
		if strings.HasPrefix(name, "SB-GATEWAY-image-") || strings.HasPrefix(name, "SB-GATEWAY-apply-") || strings.HasPrefix(name, "SB-GATEWAY-rollback-") {
			return result, ErrCatalogImageCompatibility
		}
	}
	for _, row := range containers {
		// Other containers are outside this compatibility proof; their optional
		// environment fields do not affect the managed image identities.
		role := text(row["comment"])
		if role != "SB-GATEWAY container" && role != "SB-GATEWAY container previous" && role != "SB-GATEWAY container candidate" && role != "SB-GATEWAY container rollback" && role != "SB-GATEWAY container failed" {
			continue
		}
		container, err := compatContainer(row)
		if err != nil {
			return result, err
		}
		switch container.Role {
		case "SB-GATEWAY container":
			if result.Current.ID != "" {
				return result, ErrCatalogImageCompatibility
			}
			result.Current = container
		case "SB-GATEWAY container previous":
			if result.Previous != nil || !container.Stopped {
				return result, ErrCatalogImageCompatibility
			}
			copy := container
			result.Previous = &copy
		case "SB-GATEWAY container candidate", "SB-GATEWAY container rollback", "SB-GATEWAY container failed":
			return result, ErrCatalogImageCompatibility
		}
	}
	current := result.Current
	if !compatObjectID.MatchString(current.ID) || !safeCompatPath(current.Root) || current.Stopped || len(current.Mountlists) == 0 || len(current.Environment) == 0 {
		return result, ErrCatalogImageCompatibility
	}
	if previous := result.Previous; previous != nil {
		if !compatObjectID.MatchString(previous.ID) || !safeCompatPath(previous.Root) || previous.Root == current.Root || len(previous.Environment) == 0 {
			return result, ErrCatalogImageCompatibility
		}
		for _, row := range containers {
			if text(row[".id"]) != previous.ID && strings.Trim(text(row["root-dir"]), "/") == previous.Root {
				return result, ErrCatalogImageCompatibility
			}
		}
	}
	mounts, err := client.List(ctx, "/rest/container/mounts")
	if err != nil {
		return result, ErrCatalogImageCompatibility
	}
	for _, row := range mounts {
		if !containsCompat(current.Mountlists, text(row["list"])) {
			continue
		}
		if compatBool(row["disabled"]) {
			return result, ErrCatalogImageCompatibility
		}
		mount := CatalogImageMount{List: text(row["list"]), Source: strings.Trim(text(row["src"]), "/"), Destination: text(row["dst"]), Comment: text(row["comment"])}
		if !safeCompatPath(mount.Source) {
			return result, ErrCatalogImageCompatibility
		}
		result.Mounts = append(result.Mounts, mount)
	}
	sort.Slice(result.Mounts, func(i, j int) bool { return result.Mounts[i].Destination < result.Mounts[j].Destination })
	if len(result.Mounts) != 4 {
		return result, ErrCatalogImageCompatibility
	}
	for i, dst := range []string{"/config", "/data", "/logs", "/state"} {
		if result.Mounts[i].Destination != dst {
			return result, ErrCatalogImageCompatibility
		}
	}
	result.Fingerprint = currentCompatFingerprint(current, result.Mounts)
	return result, nil
}

func (client *Client) ReadCatalogImageContract(ctx context.Context) (*CatalogImageContract, error) {
	rows, err := client.List(ctx, "/rest/system/script?name="+CatalogImageContractName)
	if err != nil {
		return nil, ErrCatalogImageCompatibility
	}
	if len(rows) == 0 {
		return nil, nil
	}
	if len(rows) != 1 || text(rows[0]["name"]) != CatalogImageContractName || text(rows[0]["comment"]) != catalogImageContractComment {
		return nil, ErrCatalogImageCompatibility
	}
	var result CatalogImageContract
	if json.Unmarshal([]byte(text(rows[0]["source"])), &result) != nil || result.FormatVersion != 1 || result.State != "prepared" || result.CatalogSchema != 1 || !safeCompatPath(result.ProducerRoot) {
		return nil, ErrCatalogImageCompatibility
	}
	if result.PreviousCatalogSchema < 0 || result.PreviousCatalogSchema > 1 || result.PreviousRoot != "" && !safeCompatPath(result.PreviousRoot) {
		return nil, ErrCatalogImageCompatibility
	}
	if result.PreviousRoot != "" && result.PreviousCatalogSchema == 0 && (result.Mountlist == "" || !compatIdentifier.MatchString(result.Handoff)) {
		return nil, ErrCatalogImageCompatibility
	}
	if result.PreviousRoot != "" && result.PreviousCatalogSchema == 0 {
		for _, source := range result.MountSources {
			if !safeCompatPath(source) {
				return nil, ErrCatalogImageCompatibility
			}
		}
	}
	return &result, nil
}

// AttachCatalogImageHandoff changes only an exact stopped predecessor and new
// owned mount rows; its current container and current mount fingerprint must
// remain identical. Readback is required even after a successful REST response.
func (client *Client) AttachCatalogImageHandoff(ctx context.Context, before CatalogImageInventory, identifier string, mounts []CatalogImageMount) (string, error) {
	if !compatIdentifier.MatchString(identifier) || before.Previous == nil || !before.Previous.Stopped || len(mounts) != 4 {
		return "", ErrCatalogImageCompatibility
	}
	list := "sb-catalog-compat-" + identifier[:16]
	comment := catalogImageContractComment + " " + identifier
	rows, err := client.List(ctx, "/rest/container/mounts")
	if err != nil {
		return "", ErrCatalogImageCompatibility
	}
	existing := map[string]CatalogImageMount{}
	for _, row := range rows {
		if text(row["list"]) == list {
			if text(row["comment"]) != comment || compatBool(row["disabled"]) {
				return "", ErrCatalogImageCompatibility
			}
			dst := text(row["dst"])
			if _, ok := existing[dst]; ok {
				return "", ErrCatalogImageCompatibility
			}
			existing[dst] = CatalogImageMount{Source: strings.Trim(text(row["src"]), "/"), Destination: dst}
		}
	}
	for i, mount := range mounts {
		if mount.Destination != []string{"/config", "/data", "/logs", "/state"}[i] || !safeCompatPath(mount.Source) {
			return "", ErrCatalogImageCompatibility
		}
		if found, ok := existing[mount.Destination]; ok {
			if found.Source != mount.Source {
				return "", ErrCatalogImageCompatibility
			}
			delete(existing, mount.Destination)
			continue
		}
		if _, err := client.request(ctx, http.MethodPut, "/rest/container/mounts", map[string]any{"list": list, "src": "/" + mount.Source, "dst": mount.Destination, "comment": comment, "disabled": false}); err != nil {
			return "", ErrCatalogImageCompatibility
		}
	}
	if len(existing) != 0 {
		return "", ErrCatalogImageCompatibility
	}
	fresh, err := client.InspectCatalogImageCompatibility(ctx)
	if err != nil || fresh.Fingerprint != before.Fingerprint || fresh.Previous == nil || fresh.Previous.ID != before.Previous.ID || fresh.Previous.Root != before.Previous.Root || fresh.Previous.Role != before.Previous.Role || !fresh.Previous.Stopped {
		return "", ErrCatalogImageCompatibility
	}
	if len(fresh.Previous.Mountlists) > 0 && !(len(fresh.Previous.Mountlists) == 1 && fresh.Previous.Mountlists[0] == list) {
		return "", ErrCatalogImageCompatibility
	}
	if len(fresh.Previous.Mountlists) == 0 {
		if _, err := client.request(ctx, http.MethodPatch, "/rest/container/"+before.Previous.ID, map[string]any{"mountlists": list}); err != nil {
			return "", ErrCatalogImageCompatibility
		}
	}
	after, err := client.InspectCatalogImageCompatibility(ctx)
	if err != nil || after.Fingerprint != before.Fingerprint || after.Previous == nil || after.Previous.ID != before.Previous.ID || after.Previous.Root != before.Previous.Root || !after.Previous.Stopped || len(after.Previous.Mountlists) != 1 || after.Previous.Mountlists[0] != list {
		return "", ErrCatalogImageCompatibility
	}
	readback, err := client.List(ctx, "/rest/container/mounts")
	if err != nil {
		return "", ErrCatalogImageCompatibility
	}
	count := 0
	for _, row := range readback {
		if text(row["list"]) == list {
			count++
			match := false
			for _, mount := range mounts {
				if text(row["dst"]) == mount.Destination && strings.Trim(text(row["src"]), "/") == mount.Source && text(row["comment"]) == comment && !compatBool(row["disabled"]) {
					match = true
				}
			}
			if !match {
				return "", ErrCatalogImageCompatibility
			}
		}
	}
	if count != 4 {
		return "", ErrCatalogImageCompatibility
	}
	return list, nil
}

func (client *Client) PublishCatalogImageContract(ctx context.Context, contract CatalogImageContract) error {
	if contract.FormatVersion != 1 || contract.State != "prepared" || contract.CatalogSchema != 1 || !safeCompatPath(contract.ProducerRoot) {
		return ErrCatalogImageCompatibility
	}
	rows, err := client.List(ctx, "/rest/system/script?name="+CatalogImageContractName)
	if err != nil || len(rows) > 1 {
		return ErrCatalogImageCompatibility
	}
	body, _ := json.Marshal(contract)
	payload := map[string]any{"name": CatalogImageContractName, "comment": catalogImageContractComment, "policy": "read", "source": string(body)}
	method, path := http.MethodPut, "/rest/system/script"
	if len(rows) == 1 {
		if text(rows[0]["comment"]) != catalogImageContractComment || !compatObjectID.MatchString(text(rows[0][".id"])) {
			return ErrCatalogImageCompatibility
		}
		var existing CatalogImageContract
		if json.Unmarshal([]byte(text(rows[0]["source"])), &existing) == nil && existing == contract {
			return nil
		}
		method = http.MethodPatch
		path += "/" + text(rows[0][".id"])
	}
	if _, err := client.request(ctx, method, path, payload); err != nil {
		return ErrCatalogImageCompatibility
	}
	actual, err := client.ReadCatalogImageContract(ctx)
	if err != nil || actual == nil || *actual != contract {
		return ErrCatalogImageCompatibility
	}
	return nil
}

// AssertCatalogImageHandoffUnused is a deletion veto for an incomplete stage.
// It never detaches a container, drops a mount or removes a handoff marker.
func (client *Client) AssertCatalogImageHandoffUnused(ctx context.Context, before CatalogImageInventory, id string) error {
	if !compatIdentifier.MatchString(id) {
		return ErrCatalogImageCompatibility
	}
	fresh, err := client.InspectCatalogImageCompatibility(ctx)
	if err != nil || fresh.Fingerprint != before.Fingerprint {
		return ErrCatalogImageCompatibility
	}
	l, _ := json.Marshal(before.Previous)
	r, _ := json.Marshal(fresh.Previous)
	if string(l) != string(r) {
		return ErrCatalogImageCompatibility
	}
	contract, err := client.ReadCatalogImageContract(ctx)
	if err != nil || contract != nil && contract.Handoff == id {
		return ErrCatalogImageCompatibility
	}
	stagePath := "/.catalog-compat/" + id
	stageReference := func(source string) bool {
		contains := func(value string) bool {
			return strings.Contains(value, stagePath+"/") || strings.HasSuffix(value, stagePath)
		}
		// RouterOS accepts relative storage paths. Check POSIX-normalized
		// aliases as well as the original spelling, conservatively retaining
		// the existing veto when a raw reference normalizes out of the stage.
		return contains(source) || contains(path.Clean("/"+source))
	}
	if contract != nil {
		for _, source := range contract.MountSources {
			if stageReference(source) {
				return ErrCatalogImageCompatibility
			}
		}
	}
	rows, err := client.List(ctx, "/rest/container/mounts")
	if err != nil {
		return ErrCatalogImageCompatibility
	}
	for _, row := range rows {
		source, ok := row["src"].(string)
		if !ok || strings.TrimSpace(source) == "" || strings.ContainsRune(source, '\\') || strings.IndexFunc(source, func(value rune) bool { return value < ' ' || value == 0x7f }) >= 0 {
			return ErrCatalogImageCompatibility
		}
		if text(row["list"]) == "sb-catalog-compat-"+id[:16] || stageReference(source) {
			return ErrCatalogImageCompatibility
		}
	}
	containers, err := client.List(ctx, "/rest/container")
	if err != nil {
		return ErrCatalogImageCompatibility
	}
	for _, row := range containers {
		value, present := row["mountlists"]
		lists := compatList(value)
		if present && len(lists) == 0 {
			empty := false
			switch typed := value.(type) {
			case string:
				empty = typed == ""
			case []any:
				empty = len(typed) == 0
			case []string:
				empty = len(typed) == 0
			}
			if !empty {
				return ErrCatalogImageCompatibility
			}
		}
		if containsCompat(lists, "sb-catalog-compat-"+id[:16]) {
			return ErrCatalogImageCompatibility
		}
	}
	return nil
}
