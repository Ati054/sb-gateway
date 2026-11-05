package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

// The lifecycle caller owns mutationMu. This repairs an actual unpublished
// legacy preparation before the ordinary strict graph/backup path runs again.
func (server *Server) repairIncompleteLifecycleCatalogCompatibility(ctx context.Context, config map[string]any, targetSchema int) error {
	if targetSchema != 1 {
		return errCatalogCompatibility
	}
	if !server.subscriptionMu.TryLock() {
		return errSubscriptionCommitBusy
	}
	defer server.subscriptionMu.Unlock()
	if !server.configMu.TryLock() {
		return errSubscriptionCommitBusy
	}
	defer server.configMu.Unlock()
	if conflict, err := server.stateMutationConflict(mutationLifecycle); err != nil {
		return err
	} else if conflict != "" {
		return errSubscriptionCommitBusy
	}
	lifecycle, err := server.repository.auxiliary("lifecycle-operation")
	if err != nil {
		return err
	}
	if lifecycleOperationActive(lifecycle) {
		return errSubscriptionCommitBusy
	}
	draft, err := server.getDraft()
	if err != nil {
		return err
	}
	if !equalJSONObject(draft, config) {
		return errSubscriptionCommitBusy
	}
	value, present, err := readSubscriptionCatalogRetentionDocument(ctx, filepath.Join(server.repository.root, catalogCompatibilityAuxiliary+".json"))
	if err != nil {
		return err
	}
	if !present {
		return errSubscriptionCatalogReferencesPending
	}
	body, err := canonicalJSON(value)
	if err != nil {
		return errSubscriptionCatalogReferenceGraph
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	var old catalogCompatibilityDescriptor
	if decoder.Decode(&old) != nil || decoder.Decode(new(any)) != io.EOF {
		return errSubscriptionCatalogReferenceGraph
	}
	refs, ok := value["catalog_refs"].([]any)
	_, recordedFiles := value["files"]
	if old.FormatVersion != 1 || old.ProducerCatalogSchema != 1 || old.State != "preparing" || old.Kind != "legacy-snapshot" || recordedFiles && len(old.Files) == 0 || !recordedFiles && old.Files != nil || old.Mountlist != "" || old.Previous == nil || !old.Previous.Stopped || !ok || len(refs) != 0 || !safeRevision(old.Identifier) || !safeRevision(old.SourceEpoch) || !safeRevision(old.CurrentFingerprint) {
		return errSubscriptionCatalogReferencesPending
	}
	if old.Producer.Role != "SB-GATEWAY container" || old.Producer.Stopped || old.Producer.ID == "" || old.Producer.Root == "" || len(old.Producer.Environment) == 0 || len(old.Producer.Mountlists) == 0 || old.Previous.Role != "SB-GATEWAY container previous" || old.Previous.ID == "" || old.Previous.Root == "" || len(old.Previous.Environment) == 0 {
		return errSubscriptionCatalogReferencesPending
	}
	poolPath := server.opts.Runtime.XrayHealthPool
	if native, ok := server.runtime.(*nativeRuntime); ok {
		poolPath = native.options.XrayHealthPool
	}
	version, err := catalogCompatibilityPoolVersion(poolPath)
	if err != nil || version >= 5 {
		return errCatalogCompatibility
	}
	revision, err := revisionFor(value)
	if err != nil {
		return errSubscriptionCatalogReferenceGraph
	}
	proof, err := server.scanSubscriptionCatalogReferenceGraph(ctx, revision)
	if err != nil {
		return err
	}
	if len(proof.refs) != 0 || proof.compatibilityPrepared {
		return errSubscriptionCatalogReferenceGraph
	}
	if recordedFiles {
		if err := server.validateRecordedLifecycleCatalogPreparation(ctx, config, old); err != nil {
			return err
		}
	}
	// This performs the normal authenticated global-reference veto, exact
	// ownership retirement for unrecorded copies, or verified recorded reuse,
	// and the checked mount handoff. Recorded files never enter retirement.
	if err := server.ensureSubscriptionCatalogCompatibility(ctx, config); err != nil {
		return err
	}
	// No relaxed graph result escapes this function.
	_, err = server.subscriptionCatalogReferences(ctx)
	return err
}

// Recorded preparations may only continue the same baseline, never replace it.
// All local and global-reference checks below are read-only and precede ensure's
// first mount or contract write. Ordinary retention/recovery remain unchanged.
func (server *Server) validateRecordedLifecycleCatalogPreparation(ctx context.Context, config map[string]any, old catalogCompatibilityDescriptor) error {
	epoch, err := server.catalogCompatibilityEpoch()
	if err != nil || epoch != old.SourceEpoch {
		return errCatalogCompatibility
	}
	client, _, err := server.newRouterOSRESTClient(config)
	if err != nil {
		return errCatalogCompatibility
	}
	defer client.CloseIdleConnections()
	inventory, err := client.InspectCatalogImageCompatibility(ctx)
	if err != nil || inventory.Fingerprint != old.CurrentFingerprint || inventory.Previous == nil || !catalogCompatSamePrevious(*old.Previous, *inventory.Previous) {
		return errCatalogCompatibility
	}
	producer, _ := json.Marshal(inventory.Current)
	previousProducer, _ := json.Marshal(old.Producer)
	if !bytes.Equal(producer, previousProducer) {
		return errCatalogCompatibility
	}
	previous := *inventory.Previous
	previous.Mountlists = nil
	seed, err := canonicalJSON(map[string]any{"epoch": epoch, "current": inventory.Current, "previous": previous})
	if err != nil {
		return errCatalogCompatibility
	}
	digest := sha256.Sum256(seed)
	if hex.EncodeToString(digest[:]) != old.Identifier {
		return errCatalogCompatibility
	}
	mounts := catalogCompatibilityMounts(inventory, old.Identifier)
	list := "sb-catalog-compat-" + old.Identifier[:16]
	if len(inventory.Previous.Mountlists) > 1 || len(inventory.Previous.Mountlists) == 1 && inventory.Previous.Mountlists[0] != list {
		return errCatalogCompatibility
	}
	if err := validateRecordedCatalogHandoffReferences(ctx, client, inventory, old.Identifier, mounts); err != nil {
		return err
	}
	if err := validateRecordedCatalogStageOwners(server.catalogCompatibilityRoots(), old.Identifier); err != nil {
		return err
	}
	// The normal recorded branch in ensure validates every copied file and
	// authoritative source before its first write. Do not hash the full baseline
	// twice; this preflight adds ownership/reference checks, not a bypass.
	if current, err := server.catalogCompatibilityEpoch(); err != nil || current != epoch {
		return errCatalogCompatibility
	}
	return nil
}

func validateRecordedCatalogHandoffReferences(ctx context.Context, client *routeros.Client, inventory routeros.CatalogImageInventory, id string, mounts []routeros.CatalogImageMount) error {
	list := "sb-catalog-compat-" + id[:16]
	comment := "SB-GATEWAY catalog data compatibility " + id
	expected := make(map[string]string, len(mounts))
	var sources [4]string
	if len(mounts) != len(sources) {
		return errCatalogCompatibility
	}
	for i, mount := range mounts {
		expected[mount.Destination] = mount.Source
		sources[i] = mount.Source
	}
	stage := "/" + catalogCompatDirectory + "/" + id
	stageReference := func(value string) bool {
		contains := func(s string) bool { return strings.Contains(s, stage+"/") || strings.HasSuffix(s, stage) }
		return contains(value) || contains(path.Clean("/"+value))
	}
	rows, err := client.List(ctx, "/rest/container/mounts")
	if err != nil {
		return errCatalogCompatibility
	}
	seen := make(map[string]bool, 4)
	for _, row := range rows {
		source, ok := row["src"].(string)
		if !ok || strings.TrimSpace(source) == "" || strings.ContainsRune(source, '\\') || strings.IndexFunc(source, func(r rune) bool { return r < ' ' || r == 0x7f }) >= 0 {
			return errCatalogCompatibility
		}
		rowList, ok := row["list"].(string)
		if !ok || rowList == "" || rowList != list && stageReference(source) {
			return errCatalogCompatibility
		}
		if rowList != list {
			continue
		}
		destination, ok := row["dst"].(string)
		wanted, known := expected[destination]
		if !ok || !known || seen[destination] || strings.Trim(source, "/") != wanted || row["comment"] != comment {
			return errCatalogCompatibility
		}
		if disabled, present := row["disabled"]; present && disabled != false && disabled != "false" {
			return errCatalogCompatibility
		}
		seen[destination] = true
	}
	containers, err := client.List(ctx, "/rest/container")
	if err != nil {
		return errCatalogCompatibility
	}
	for _, row := range containers {
		if value, present := row["mountlists"]; present && value == nil {
			return errCatalogCompatibility
		}
		lists, err := recordedCatalogMountlists(row["mountlists"])
		if err != nil {
			return err
		}
		for _, value := range lists {
			if value == list && row[".id"] != inventory.Previous.ID {
				return errCatalogCompatibility
			}
		}
	}
	if len(inventory.Previous.Mountlists) != 0 && len(seen) != 4 {
		return errCatalogCompatibility
	}
	contract, err := client.ReadCatalogImageContract(ctx)
	if err != nil {
		return errCatalogCompatibility
	}
	if contract != nil {
		wanted := routeros.CatalogImageContract{FormatVersion: 1, State: "prepared", ProducerRoot: inventory.Current.Root, CatalogSchema: 1, PreviousRoot: inventory.Previous.Root, Mountlist: list, Handoff: id, MountSources: sources}
		if *contract != wanted || len(seen) != 4 || len(inventory.Previous.Mountlists) != 1 {
			return errCatalogCompatibility
		}
		rows, err := client.List(ctx, "/rest/system/script?name="+routeros.CatalogImageContractName)
		if err != nil || len(rows) != 1 {
			return errCatalogCompatibility
		}
		body, ok := rows[0]["source"].(string)
		if !ok {
			return errCatalogCompatibility
		}
		decoder := json.NewDecoder(strings.NewReader(body))
		decoder.DisallowUnknownFields()
		var strict routeros.CatalogImageContract
		if decoder.Decode(&strict) != nil || decoder.Decode(new(any)) != io.EOF || strict != wanted {
			return errCatalogCompatibility
		}
	}
	return nil
}

func recordedCatalogMountlists(value any) ([]string, error) {
	var values []string
	switch value := value.(type) {
	case nil:
		return nil, nil
	case string:
		if value != "" {
			values = strings.Split(value, ",")
		}
	case []any:
		for _, item := range value {
			text, ok := item.(string)
			if !ok {
				return nil, errCatalogCompatibility
			}
			values = append(values, text)
		}
	case []string:
		values = value
	default:
		return nil, errCatalogCompatibility
	}
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if strings.TrimSpace(value) != value || value == "" || seen[value] {
			return nil, errCatalogCompatibility
		}
		seen[value] = true
	}
	return values, nil
}

func validateRecordedCatalogStageOwners(roots catalogCompatRoots, id string) error {
	for _, area := range roots.areas() {
		root, err := compatOpenRoot(area.path)
		if err != nil {
			return err
		}
		for _, directory := range []string{catalogCompatDirectory, catalogCompatDirectory + "/" + id} {
			info, err := root.Lstat(directory)
			if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || info.Mode()&os.ModeSymlink != 0 {
				root.Close()
				return errCatalogCompatibility
			}
		}
		name := catalogCompatDirectory + "/" + id + "/.owner.json"
		info, err := root.Lstat(name)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 4096 {
			root.Close()
			return errCatalogCompatibility
		}
		file, err := root.Open(name)
		if err != nil {
			root.Close()
			return errCatalogCompatibility
		}
		opened, statErr := file.Stat()
		var marker struct {
			Format int    `json:"format_version"`
			ID     string `json:"identifier"`
			Area   string `json:"area"`
		}
		decoder := json.NewDecoder(io.LimitReader(file, 4097))
		decoder.DisallowUnknownFields()
		decodeErr := decoder.Decode(&marker)
		valid := statErr == nil && os.SameFile(info, opened) && decodeErr == nil && decoder.Decode(new(any)) == io.EOF && marker.Format == 1 && marker.ID == id && marker.Area == area.name
		file.Close()
		root.Close()
		if !valid {
			return errCatalogCompatibility
		}
	}
	return nil
}
