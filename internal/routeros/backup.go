package routeros

import (
	"context"
	"errors"
	"net/http"
	"regexp"
)

var managedBackupBasePattern = regexp.MustCompile(`^SB-GATEWAY-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}$`)

type BackupRef struct {
	Export string `json:"export"`
	Binary string `json:"binary"`
}

// CreateBackup asks RouterOS to write a normal non-sensitive export and an
// encrypted binary backup before a managed connectivity transaction.
func (client *Client) CreateBackup(ctx context.Context, name, password string) (BackupRef, error) {
	if !managedBackupBasePattern.MatchString(name) {
		return BackupRef{}, errors.New("managed RouterOS backup name is invalid")
	}
	if password == "" || len(password) > 4096 {
		return BackupRef{}, errors.New("RouterOS backup password is unavailable")
	}
	exportName := name + "-export"
	// RouterOS action endpoints are inconsistent across releases: successful
	// /export may return either an object or an empty JSON array. The command's
	// HTTP status is authoritative here; its response body is not used.
	if _, err := client.requestAction(ctx, http.MethodPost, "/rest/export", map[string]any{
		"compact": "", "file": exportName,
	}); err != nil {
		return BackupRef{}, err
	}
	result, err := client.requestAction(ctx, http.MethodPost, "/rest/system/backup/save", map[string]any{
		"name": name, "password": password, "encryption": "aes-sha256", "dont-encrypt": "no",
	})
	if err != nil {
		return BackupRef{}, err
	}
	binary := text(result["name"])
	if binary == "" {
		binary = name + ".backup"
	}
	return BackupRef{Export: exportName + ".rsc", Binary: binary}, nil
}
