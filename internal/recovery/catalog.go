package recovery

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"

	"github.com/sb-gateway/sb-gateway/internal/subscriptioncatalog"
)

var catalogSnapshotPath = regexp.MustCompile(`^state/subscription-nodes-[a-f0-9]{64}\.json$`)

func catalogueReferenceDocument(path string) bool {
	return path == "state/subscription-nodes.json" || catalogSnapshotPath.MatchString(path) ||
		path == "state/subscription-catalog-compatibility.json" || path == "state/apply-operation.json" ||
		path == "state/subscription-runtime-operation.json" || path == "state/subscription-catalog-handoff.json" ||
		path == "state/subscription-legacy-backup.json" || path == "state/subscription-catalog-backup.json"
}

func (prepared *preparedRestore) validateCatalogues(staging string, generations map[string]map[string]pendingFile) error {
	refs := make(map[string]subscriptioncatalog.Ref)
	for _, file := range prepared.files {
		if !catalogueReferenceDocument(file.entry.Path) {
			continue
		}
		if err := readCatalogueReferences(file.source, file.entry.Size, refs, generations); err != nil {
			return err
		}
	}
	for generation := range refs {
		if generations[generation] == nil {
			return errors.New("restored catalogue reference has no complete payload")
		}
	}
	root := filepath.Join(staging, "config", "secrets", "subscription-catalogs")
	names := []string{"manifest.json", "records.bin", "metadata.bin", "id.idx", "stable.idx", "endpoint.idx", "logical.idx"}
	for generation, files := range generations {
		if len(files) != len(names) {
			return errors.New("restored catalogue payload is incomplete")
		}
		for _, name := range names {
			if _, ok := files[name]; !ok {
				return errors.New("restored catalogue payload is incomplete")
			}
		}
		ref, err := subscriptioncatalog.Inspect(root, generation)
		if err != nil {
			return errors.New("restored catalogue manifest is invalid")
		}
		if expected, exists := refs[generation]; exists && expected != ref {
			return errors.New("restored catalogue reference mismatch")
		}
		digests := []subscriptioncatalog.FileDigest{ref.Records, ref.Metadata, ref.Indexes[0], ref.Indexes[1], ref.Indexes[2], ref.Indexes[3]}
		for index, name := range names[1:] {
			entry := files[name]
			if entry.Size != digests[index].Bytes || entry.SHA256 != digests[index].SHA256 {
				return errors.New("pending catalogue file differs from its checked reference")
			}
		}
		reader, err := subscriptioncatalog.Open(root, ref)
		if err != nil {
			return errors.New("restored catalogue is incomplete or corrupt")
		}
		prepared.readers = append(prepared.readers, reader)
	}
	return nil
}

// Visit JSON values without building a private node graph. Only small typed
// catalogue descriptors survive; ordinary inline legacy nodes remain tokens.
func readCatalogueReferences(path string, size int64, refs map[string]subscriptioncatalog.Ref, generations map[string]map[string]pendingFile) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(newRestoreFileReader(file), size+1))
	add := func(key string) error {
		var ref subscriptioncatalog.Ref
		if err := decoder.Decode(&ref); err != nil || !digestPattern.MatchString(ref.Generation) || ref.Schema != subscriptioncatalog.SchemaVersion {
			return errors.New("restored catalogue reference is invalid")
		}
		if key != "" && key != ref.Generation {
			return errors.New("restored catalogue generation key mismatch")
		}
		if generations[ref.Generation] == nil {
			return errors.New("restored catalogue reference has no complete payload")
		}
		if previous, exists := refs[ref.Generation]; exists && previous != ref {
			return errors.New("restored catalogue references disagree")
		}
		refs[ref.Generation] = ref
		return nil
	}
	var visit func(int) error
	visit = func(depth int) error {
		if depth > 128 {
			return errors.New("restored catalogue reference document is too deeply nested")
		}
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if depth == 0 && token != json.Delim('{') {
			return errors.New("restored catalogue reference document is not an object")
		}
		delimiter, container := token.(json.Delim)
		if !container {
			return nil
		}
		switch delimiter {
		case '{':
			for decoder.More() {
				token, err := decoder.Token()
				if err != nil {
					return err
				}
				key, ok := token.(string)
				if !ok {
					return errors.New("invalid catalogue reference object")
				}
				switch key {
				case "catalog_ref", "_subscription_catalog":
					if err := add(""); err != nil {
						return err
					}
				case "catalog_refs":
					token, err := decoder.Token()
					if err != nil || token != json.Delim('[') {
						return errors.New("invalid catalogue reference list")
					}
					for decoder.More() {
						if err := add(""); err != nil {
							return err
						}
					}
					if _, err := decoder.Token(); err != nil {
						return err
					}
				case "catalogs":
					token, err := decoder.Token()
					if err != nil {
						return err
					}
					if token == nil {
						continue
					}
					if token != json.Delim('{') {
						return errors.New("invalid catalogue reference map")
					}
					for decoder.More() {
						token, err := decoder.Token()
						if err != nil {
							return err
						}
						key, ok := token.(string)
						if !ok {
							return errors.New("invalid catalogue reference generation")
						}
						if err := add(key); err != nil {
							return err
						}
					}
					if _, err := decoder.Token(); err != nil {
						return err
					}
				default:
					if err := visit(depth + 1); err != nil {
						return err
					}
				}
			}
		case '[':
			for decoder.More() {
				if err := visit(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid catalogue reference JSON delimiter")
		}
		_, err = decoder.Token()
		return err
	}
	if err := visit(0); err != nil {
		return errors.New("restored catalogue reference document is invalid")
	}
	if _, err := decoder.Token(); err != io.EOF {
		return errors.New("restored catalogue reference document has trailing data")
	}
	return nil
}
