package routeros

import (
	"context"
	"errors"
	"strings"
)

// SchedulerGuardRequired reports whether Apply must avoid the interactive SSH
// Safe Mode console. RouterOS 7.24 can terminate that console immediately after
// acknowledging Safe Mode; the RouterOS-local rollback scheduler provides the
// same bounded rollback ownership without exercising the unstable SSH path.
func (client *Client) SchedulerGuardRequired(ctx context.Context) (bool, error) {
	rows, err := client.List(ctx, "/rest/system/resource?.proplist=version")
	if err != nil {
		return false, err
	}
	if len(rows) != 1 {
		return false, errors.New("RouterOS version is missing or ambiguous")
	}
	fields := strings.Fields(text(rows[0]["version"]))
	if len(fields) == 0 {
		return false, errors.New("RouterOS version format is unsupported")
	}
	version := strings.TrimPrefix(fields[0], "v")
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return false, errors.New("RouterOS version format is unsupported")
	}
	major, majorOK := versionNumber(parts[0])
	minor, minorOK := versionNumber(parts[1])
	if !majorOK || !minorOK {
		return false, errors.New("RouterOS version format is unsupported")
	}
	return major == 7 && minor == 24, nil
}

func versionNumber(value string) (int, bool) {
	result, digits := 0, 0
	for _, character := range value {
		if character < '0' || character > '9' {
			break
		}
		result = result*10 + int(character-'0')
		digits++
	}
	return result, digits > 0
}
