package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

// No files from an incomplete stage are reused after a producer or epoch
// change. Fresh global references and exact local ownership must both veto
// deletion before the caller can persist a replacement preparation journal.
func (server *Server) retireIncompleteCatalogCompatSnapshot(ctx context.Context, client *routeros.Client, inventory routeros.CatalogImageInventory, epoch string, old catalogCompatibilityDescriptor) error {
	if old.State != "preparing" || old.Kind != "legacy-snapshot" || len(old.Files) != 0 || old.Mountlist != "" || len(old.CatalogRefs) != 0 || old.Previous == nil || !safeRevision(old.Identifier) || !safeRevision(old.SourceEpoch) || !safeRevision(old.CurrentFingerprint) {
		return errCatalogCompatibility
	}
	if err := client.AssertCatalogImageHandoffUnused(ctx, inventory, old.Identifier); err != nil {
		return errCatalogCompatibility
	}
	if current, err := server.catalogCompatibilityEpoch(); err != nil || current != epoch {
		return errCatalogCompatibility
	}
	return removeIncompleteCatalogCompatSnapshot(ctx, server.catalogCompatibilityRoots(), old.Identifier)
}

// The caller must first prove the same epoch and an unchanged stopped target,
// and prove through fresh RouterOS inventories that no mount/contract refers to
// this ID. This deletes only an incomplete owned ID, never a frozen baseline.
func removeIncompleteCatalogCompatSnapshot(ctx context.Context, roots catalogCompatRoots, id string) error {
	if !safeRevision(id) {
		return errCatalogCompatibility
	}
	for _, area := range roots.areas() {
		root, err := compatOpenRoot(area.path)
		if err != nil {
			return err
		}
		base := catalogCompatDirectory + "/" + id
		info, err := root.Lstat(base)
		if errors.Is(err, os.ErrNotExist) {
			root.Close()
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			root.Close()
			return errCatalogCompatibility
		}
		parentInfo, parentErr := root.Lstat(catalogCompatDirectory)
		if parentErr != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 || parentInfo.Mode().Perm() != 0700 {
			root.Close()
			return errCatalogCompatibility
		}
		stage, err := root.OpenRoot(base)
		if err != nil {
			root.Close()
			return errCatalogCompatibility
		}
		opened, openErr := stage.Open(".")
		if openErr != nil {
			stage.Close()
			root.Close()
			return errCatalogCompatibility
		}
		openedInfo, statErr := opened.Stat()
		opened.Close()
		if statErr != nil || !os.SameFile(info, openedInfo) {
			stage.Close()
			root.Close()
			return errCatalogCompatibility
		}
		owned := false
		owner, ownerErr := stage.Open(".owner.json")
		if ownerErr == nil {
			var marker struct {
				Format int    `json:"format_version"`
				ID     string `json:"identifier"`
				Area   string `json:"area"`
			}
			decoder := json.NewDecoder(io.LimitReader(owner, 4097))
			decoder.DisallowUnknownFields()
			ownerErr = decoder.Decode(&marker)
			if ownerErr == nil && decoder.Decode(new(any)) != io.EOF {
				ownerErr = errCatalogCompatibility
			}
			owner.Close()
			owned = ownerErr == nil && marker.Format == 1 && marker.ID == id && marker.Area == area.name
			if !owned {
				stage.Close()
				root.Close()
				return errCatalogCompatibility
			}
		} else if !errors.Is(ownerErr, os.ErrNotExist) {
			stage.Close()
			root.Close()
			return errCatalogCompatibility
		}
		count := 0
		var walk func(string, int) error
		walk = func(path string, depth int) error {
			if depth > 64 {
				return errCatalogCompatibility
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			dir, err := stage.Open(path)
			if err != nil {
				return errCatalogCompatibility
			}
			defer dir.Close()
			for {
				entries, readErr := dir.ReadDir(32)
				if readErr != nil && readErr != io.EOF {
					return errCatalogCompatibility
				}
				for _, entry := range entries {
					count++
					if count > catalogCompatMaxFiles*4 {
						return errCatalogCompatibility
					}
					name := entry.Name()
					if path != "." {
						name = path + "/" + name
					}
					stat, err := stage.Lstat(name)
					if err != nil || stat.Mode()&os.ModeSymlink != 0 {
						return errCatalogCompatibility
					}
					if path == "." && name != ".owner.json" && name != area.name {
						return errCatalogCompatibility
					}
					if stat.IsDir() {
						if stat.Mode().Perm() != 0700 {
							return errCatalogCompatibility
						}
						if err := walk(name, depth+1); err != nil {
							return err
						}
					} else {
						if !owned || !stat.Mode().IsRegular() || stat.Mode().Perm() != 0600 {
							return errCatalogCompatibility
						}
					}
				}
				if readErr == io.EOF {
					break
				}
			}
			return nil
		}
		err = walk(".", 0)
		stage.Close()
		if err != nil {
			root.Close()
			return err
		}
		last, lastErr := root.Lstat(base)
		if lastErr != nil || !os.SameFile(info, last) {
			root.Close()
			return errCatalogCompatibility
		}
		if err := root.RemoveAll(base); err != nil {
			root.Close()
			return errCatalogCompatibility
		}
		parent, parentErr := root.Open(catalogCompatDirectory)
		if parentErr == nil {
			parentErr = parent.Sync()
			parent.Close()
		}
		if parentErr != nil {
			root.Close()
			return errCatalogCompatibility
		}
		root.Close()
	}
	return nil
}
