package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

const subscriptionCatalogRetentionGrace = 24 * time.Hour
const subscriptionCatalogRetentionDocumentBytes = 16 << 20

var (
	errSubscriptionCatalogReferenceGraph    = errors.New("subscription catalog reference graph is incomplete")
	errSubscriptionCatalogReferencesPending = errors.New("subscription catalog references are changing")
	catalogRetentionFiles                   = [7]string{"records.bin", "metadata.bin", "id.idx", "stable.idx", "endpoint.idx", "logical.idx", "manifest.json"}
)

type subscriptionCatalogRetentionReport struct {
	Removed, KeptReferenced, KeptRecent, KeptBusy int
}

type subscriptionCatalogReferenceState struct {
	refs                  map[string]subscriptioncatalog.Ref
	compatibilityPrepared bool
}

// subscriptionCatalogReferences returns persisted reachable references for both
// retention and recovery exports. Callers coordinate mutationMu, subscriptionMu
// and configMu in their existing order. A file lease alone is a deletion veto,
// not an extra persisted backup root. Payload hashes are verified by Readers,
// scoped removal and the recovery stream; this collector checks manifests and
// file layout without repeatedly reading every private record.
func (server *Server) subscriptionCatalogReferences(ctx context.Context) (map[string]subscriptioncatalog.Ref, error) {
	state, err := server.collectSubscriptionCatalogReferences(ctx)
	if err != nil {
		return nil, err
	}
	return state.refs, nil
}

func (server *Server) collectSubscriptionCatalogReferences(ctx context.Context) (subscriptionCatalogReferenceState, error) {
	return server.scanSubscriptionCatalogReferenceGraph(ctx, "")
}

// A nonempty proof is private to lifecycle repair: it identifies one exact
// incomplete journal, never marks it prepared, and cannot authorize references,
// retention, export or deletion. Normal callers always pass the empty proof.
func (server *Server) scanSubscriptionCatalogReferenceGraph(ctx context.Context, preparingRevision string) (subscriptionCatalogReferenceState, error) {
	state := subscriptionCatalogReferenceState{refs: make(map[string]subscriptioncatalog.Ref)}
	read := func(name string) (map[string]any, bool, error) {
		return readSubscriptionCatalogRetentionDocument(ctx, filepath.Join(server.repository.root, name+".json"))
	}
	add := func(value any) error { return collectSubscriptionCatalogRefs(ctx, value, state.refs) }
	current, _, err := read("subscription-nodes")
	if err != nil {
		return state, err
	}
	for _, raw := range current {
		entry, ok := raw.(map[string]any)
		if !ok {
			return state, errSubscriptionCatalogReferenceGraph
		}
		if nodes, exists := entry["nodes"]; exists && !subscriptionCatalogNodeArray(nodes) {
			return state, errSubscriptionCatalogReferenceGraph
		}
	}
	if err := add(current); err != nil {
		return state, err
	}
	for _, name := range []string{"active", "last-known-good", "apply-metadata"} {
		value, present, err := read(name)
		if err != nil {
			return state, err
		}
		if !present {
			continue
		}
		if name != "apply-metadata" {
			if revision, ok := value["revision"].(string); !ok || !safeRevision(revision) {
				return state, errSubscriptionCatalogReferenceGraph
			}
		} else {
			for _, field := range []string{"revision", "previous_revision", "node_snapshot_revision", "previous_node_snapshot_revision", "runtime_revision", "previous_runtime_revision"} {
				if raw := value[field]; raw != nil {
					revision, ok := raw.(string)
					if !ok || revision != "" && !safeRevision(revision) {
						return state, errSubscriptionCatalogReferenceGraph
					}
				}
			}
		}
		if err := add(value); err != nil {
			return state, err
		}
	}
	revisions, err := server.subscriptionRetentionRevisions()
	if err != nil {
		return state, errSubscriptionCatalogReferenceGraph
	}
	missingSnapshot := false
	for _, revision := range revisions {
		value, present, err := read("subscription-nodes-" + revision)
		if err != nil {
			return state, err
		}
		if !present {
			// Pre-catalog installations can have no node snapshot. This is
			// insufficient proof as soon as any catalog reference is found.
			missingSnapshot = true
			continue
		}
		if value["revision"] != revision || !subscriptionCatalogNodeArray(value["nodes"]) {
			return state, errSubscriptionCatalogReferenceGraph
		}
		if err := add(value); err != nil {
			return state, err
		}
	}
	for _, name := range []string{"apply-operation", "subscription-runtime-operation", "subscription-catalog-handoff", "subscription-legacy-backup", "subscription-catalog-backup"} {
		value, _, err := read(name)
		if err != nil {
			return state, err
		}
		if raw := value["pending"]; raw != nil {
			pending, ok := raw.(bool)
			if !ok {
				return state, errSubscriptionCatalogReferenceGraph
			}
			if pending {
				return state, errSubscriptionCatalogReferencesPending
			}
		}
		if name != "apply-operation" && name != "subscription-runtime-operation" && len(value) > 0 {
			if _, ok := value["catalog_refs"].([]any); !ok {
				return state, errSubscriptionCatalogReferenceGraph
			}
			if stage := value["state"]; stage != nil && stage != "prepared" && stage != "settled" && stage != "completed" {
				if stage == "preparing" {
					return state, errSubscriptionCatalogReferencesPending
				}
				return state, errSubscriptionCatalogReferenceGraph
			}
		}
		if err := add(value); err != nil {
			return state, err
		}
	}
	compatibility, present, err := read("subscription-catalog-compatibility")
	if err != nil {
		return state, err
	}
	if present {
		incomplete := compatibility["state"] == "preparing"
		if preparingRevision != "" {
			revision, err := revisionFor(compatibility)
			if err != nil || !incomplete || revision != preparingRevision {
				return state, errSubscriptionCatalogReferencesPending
			}
		}
		if incomplete && preparingRevision == "" {
			return state, errSubscriptionCatalogReferencesPending
		}
		if compatibility["format_version"] != float64(1) || !incomplete && compatibility["state"] != "prepared" {
			return state, errSubscriptionCatalogReferenceGraph
		}
		if _, ok := compatibility["catalog_refs"].([]any); !ok {
			return state, errSubscriptionCatalogReferenceGraph
		}
		if err := add(compatibility); err != nil {
			return state, err
		}
		state.compatibilityPrepared = !incomplete
	} else if preparingRevision != "" {
		return state, errSubscriptionCatalogReferencesPending
	}
	poolPath := server.opts.Runtime.XrayHealthPool
	if native, ok := server.runtime.(*nativeRuntime); ok {
		poolPath = native.options.XrayHealthPool
	}
	if poolPath != "" {
		pool, present, err := readSubscriptionCatalogRetentionDocument(ctx, poolPath)
		if err != nil {
			return state, err
		}
		if !present && server.runtime != nil && len(revisions) > 0 {
			return state, errSubscriptionCatalogReferenceGraph
		}
		if present {
			if err := add(pool); err != nil {
				return state, err
			}
			if err := validateSubscriptionCatalogPoolReferences(pool); err != nil {
				return state, err
			}
		}
	}
	if len(state.refs) > 0 && (missingSnapshot || !state.compatibilityPrepared) {
		return state, errSubscriptionCatalogReferenceGraph
	}
	for _, ref := range state.refs {
		if err := ctx.Err(); err != nil {
			return state, err
		}
		actual, err := subscriptioncatalog.Inspect(server.secrets.subscriptionCatalogRoot(), ref.Generation)
		if err != nil || actual != ref {
			return state, errSubscriptionCatalogReferenceGraph
		}
		if _, err := subscriptionCatalogGenerationAge(server.secrets.subscriptionCatalogRoot(), ref.Generation); err != nil {
			return state, err
		}
	}
	return state, nil
}

func subscriptionCatalogNodeArray(value any) bool {
	nodes, ok := value.([]any)
	if !ok {
		return false
	}
	for _, node := range nodes {
		if _, ok := node.(map[string]any); !ok {
			return false
		}
	}
	return true
}

func collectSubscriptionCatalogRefs(ctx context.Context, value any, refs map[string]subscriptioncatalog.Ref) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	add := func(value any) error {
		ref, err := decodeSubscriptionCatalogRef(value)
		if err != nil {
			return errSubscriptionCatalogReferenceGraph
		}
		if previous, exists := refs[ref.Generation]; exists && previous != ref {
			return errSubscriptionCatalogReferenceGraph
		}
		refs[ref.Generation] = ref
		return nil
	}
	switch object := value.(type) {
	case map[string]any:
		for field, nested := range object {
			switch field {
			case "catalog_ref", subscriptionCatalogSentinel:
				if err := add(nested); err != nil {
					return err
				}
			case "catalog_refs":
				items, ok := nested.([]any)
				if !ok {
					return errSubscriptionCatalogReferenceGraph
				}
				for _, item := range items {
					if err := add(item); err != nil {
						return err
					}
				}
			case "catalogs":
				if nested == nil {
					continue
				}
				items, ok := nested.(map[string]any)
				if !ok {
					return errSubscriptionCatalogReferenceGraph
				}
				for generation, item := range items {
					ref, err := decodeSubscriptionCatalogRef(item)
					if err != nil || generation != ref.Generation {
						return errSubscriptionCatalogReferenceGraph
					}
					if err := add(item); err != nil {
						return err
					}
				}
			default:
				if err := collectSubscriptionCatalogRefs(ctx, nested, refs); err != nil {
					return err
				}
			}
		}
	case []any:
		for _, nested := range object {
			if err := collectSubscriptionCatalogRefs(ctx, nested, refs); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateSubscriptionCatalogPoolReferences(pool map[string]any) error {
	version, ok := pool["version"].(float64)
	if !ok || version < 1 || version > 5 || version != float64(int(version)) {
		return errSubscriptionCatalogReferenceGraph
	}
	if pool["catalog_definitions"] == nil {
		return nil
	}
	definitions, ok := pool["catalog_definitions"].(map[string]any)
	if !ok {
		return errSubscriptionCatalogReferenceGraph
	}
	catalogs, _ := pool["catalogs"].(map[string]any)
	for id, raw := range definitions {
		var definition runtimeconfig.CatalogDefinition
		encoded, err := json.Marshal(raw)
		if err != nil || json.Unmarshal(encoded, &definition) != nil || id == "" || !safeRevision(definition.Fingerprint) || definition.FingerprintKind != runtimeconfig.CatalogFingerprintKind {
			return errSubscriptionCatalogReferenceGraph
		}
		if _, exists := catalogs[definition.Generation]; !exists {
			return errSubscriptionCatalogReferenceGraph
		}
	}
	return nil
}

type subscriptionCatalogRetentionContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader subscriptionCatalogRetentionContextReader) Read(body []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(body)
}

func readSubscriptionCatalogRetentionDocument(ctx context.Context, path string) (map[string]any, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]any{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Size() > subscriptionCatalogRetentionDocumentBytes {
		return nil, false, errSubscriptionCatalogReferenceGraph
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, false, errSubscriptionCatalogReferenceGraph
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return nil, false, errSubscriptionCatalogReferenceGraph
	}
	decoder := json.NewDecoder(subscriptionCatalogRetentionContextReader{ctx, io.LimitReader(file, subscriptionCatalogRetentionDocumentBytes+1)})
	var document map[string]any
	if err := decoder.Decode(&document); err != nil || document == nil {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		return nil, false, errSubscriptionCatalogReferenceGraph
	}
	if decoder.Decode(new(any)) != io.EOF {
		if err := ctx.Err(); err != nil {
			return nil, false, err
		}
		return nil, false, errSubscriptionCatalogReferenceGraph
	}
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	return document, true, nil
}

func subscriptionCatalogGenerationAge(root, generation string) (time.Time, error) {
	if !safeRevision(generation) {
		return time.Time{}, errSubscriptionCatalogReferenceGraph
	}
	directory := filepath.Join(root, generation)
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || runtime.GOOS != "windows" && info.Mode().Perm() != 0700 {
		return time.Time{}, errSubscriptionCatalogReferenceGraph
	}
	newest := info.ModTime()
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != len(catalogRetentionFiles) {
		return time.Time{}, errSubscriptionCatalogReferenceGraph
	}
	for _, name := range catalogRetentionFiles {
		info, err := os.Lstat(filepath.Join(directory, name))
		if err != nil || !info.Mode().IsRegular() || runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
			return time.Time{}, errSubscriptionCatalogReferenceGraph
		}
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
	}
	return newest, nil
}

// pruneSubscriptionCatalogs is called only after settled publication under the
// normal mutation/subscription/configuration coordination. All graph and listing
// validation completes before any cache eviction or filesystem deletion.
func (server *Server) pruneSubscriptionCatalogs(ctx context.Context) (subscriptionCatalogRetentionReport, error) {
	return server.pruneSubscriptionCatalogGenerations(ctx, nil)
}

// The caller owns this exact completed but unpublished candidate and has released
// its reader. Reference proof and leases remain mandatory; only age is waived.
func (server *Server) pruneSubscriptionCatalogCandidate(ctx context.Context, ref subscriptioncatalog.Ref) (subscriptionCatalogRetentionReport, error) {
	return server.pruneSubscriptionCatalogGenerations(ctx, &ref)
}

func (server *Server) pruneSubscriptionCatalogGenerations(ctx context.Context, candidate *subscriptioncatalog.Ref) (subscriptionCatalogRetentionReport, error) {
	var report subscriptionCatalogRetentionReport
	if candidate != nil {
		if _, err := decodeSubscriptionCatalogRef(*candidate); err != nil {
			return report, errSubscriptionCatalogReferenceGraph
		}
	}
	state, err := server.collectSubscriptionCatalogReferences(ctx)
	if err != nil {
		return report, err
	}
	root := server.secrets.subscriptionCatalogRoot()
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return report, nil
	}
	if err != nil {
		return report, errSubscriptionCatalogReferenceGraph
	}
	if !state.compatibilityPrepared {
		return report, errSubscriptionCatalogReferenceGraph
	}
	var removals []subscriptioncatalog.Ref
	for _, entry := range entries {
		if err := ctx.Err(); err != nil {
			return report, err
		}
		if !safeRevision(entry.Name()) {
			continue
		}
		newest, err := subscriptionCatalogGenerationAge(root, entry.Name())
		if err != nil {
			return report, err
		}
		if _, keep := state.refs[entry.Name()]; keep {
			report.KeptReferenced++
			continue
		}
		if candidate != nil && candidate.Generation != entry.Name() {
			continue
		}
		ref, err := subscriptioncatalog.Inspect(root, entry.Name())
		if err != nil || candidate != nil && *candidate != ref {
			return report, errSubscriptionCatalogReferenceGraph
		}
		if candidate == nil && server.now().Sub(newest) < subscriptionCatalogRetentionGrace {
			report.KeptRecent++
			continue
		}
		removals = append(removals, ref)
	}
	for _, ref := range removals {
		cache := &server.secrets.catalogReaders
		cache.mu.Lock()
		entry := cache.entries[ref.Generation]
		if entry != nil && entry.users > 0 {
			cache.mu.Unlock()
			report.KeptBusy++
			continue
		}
		if entry != nil {
			delete(cache.entries, ref.Generation)
			if err := entry.reader.Close(); err != nil {
				cache.mu.Unlock()
				return report, err
			}
		}
		cache.mu.Unlock()
		if err := subscriptioncatalog.RemoveGeneration(ctx, root, ref); errors.Is(err, subscriptioncatalog.ErrBusy) {
			report.KeptBusy++
		} else if errors.Is(err, subscriptioncatalog.ErrNotFound) {
			continue
		} else if err != nil {
			return report, err
		} else {
			report.Removed++
		}
	}
	return report, nil
}
