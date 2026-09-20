package routeros

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const managedRouterOSBackupRetention = 3

var (
	managedBackupFilePattern  = regexp.MustCompile(`^(SB-GATEWAY-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12})(?:-export\.rsc|\.backup)$`)
	managedStorageRootPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)+$`)
	managedImageArchiveName   = regexp.MustCompile(`^sb-gateway-[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?-linux-arm64\.tar(?:\.sha256)?$`)
)

var managedBootstrapArtifacts = map[string]bool{
	"bootstrap.rsc":        true,
	"fasttrack-patch.rsc":  true,
	"install.rsc":          true,
	"preflight.rsc":        true,
	"variables.rsc":        true,
	"watchdog.rsc":         true,
	"webfig-bootstrap.rsc": true,
}

type ManagedFilePruneResult struct {
	Backups int
	Install int
}

// PruneManagedFiles removes only exact SB Gateway-owned files. The newest
// three RouterOS backup/export generations are retained, while one-shot
// bootstrap scripts and extracted local image archives are removed from the
// confirmed external-storage project root. Unknown files and nested runtime
// data are never selected.
func (client *Client) PruneManagedFiles(ctx context.Context, storageRoot string) (ManagedFilePruneResult, error) {
	storageRoot = strings.Trim(strings.TrimSpace(storageRoot), "/")
	if !managedStorageRootPattern.MatchString(storageRoot) {
		return ManagedFilePruneResult{}, errors.New("managed storage root is invalid")
	}
	for _, part := range strings.Split(storageRoot, "/") {
		if part == "." || part == ".." {
			return ManagedFilePruneResult{}, errors.New("managed storage root is invalid")
		}
	}
	rows, err := client.List(ctx, "/rest/file?.proplist=.id,name,type")
	if err != nil {
		return ManagedFilePruneResult{}, err
	}

	backupFiles := make(map[string][]map[string]any)
	installFiles := []map[string]any{}
	prefix := storageRoot + "/"
	for _, row := range rows {
		name := text(row["name"])
		if matches := managedBackupFilePattern.FindStringSubmatch(name); len(matches) == 2 {
			backupFiles[matches[1]] = append(backupFiles[matches[1]], row)
			continue
		}
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		relative := strings.TrimPrefix(name, prefix)
		if strings.Contains(relative, "/") {
			continue
		}
		if managedBootstrapArtifacts[relative] || managedImageArchiveName.MatchString(relative) {
			installFiles = append(installFiles, row)
		}
	}

	bases := make([]string, 0, len(backupFiles))
	for base := range backupFiles {
		bases = append(bases, base)
	}
	sort.Sort(sort.Reverse(sort.StringSlice(bases)))
	result := ManagedFilePruneResult{}
	for _, base := range bases[min(len(bases), managedRouterOSBackupRetention):] {
		for _, row := range backupFiles[base] {
			if err := client.removeManagedFile(ctx, row); err != nil {
				return result, err
			}
			result.Backups++
		}
	}
	for _, row := range installFiles {
		if err := client.removeManagedFile(ctx, row); err != nil {
			return result, err
		}
		result.Install++
	}
	return result, nil
}

func (client *Client) removeManagedFile(ctx context.Context, row map[string]any) error {
	id := text(row[".id"])
	if id == "" {
		return errors.New("managed RouterOS file has no identifier")
	}
	_, err := client.request(ctx, http.MethodDelete, "/rest/file/"+routerOSResourceID(id), nil)
	return err
}
