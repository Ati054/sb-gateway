package routeros

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const rollbackSchedulerComment = "SB-GATEWAY Safe Mode rollback fallback"

var rollbackSchedulerNamePattern = regexp.MustCompile(`^SB-GATEWAY-safe-rollback-[0-9a-f]{8}$`)

var ErrRollbackGuardPending = errors.New("previous RouterOS rollback guard remains armed")

type RollbackOptions struct {
	Delay          time.Duration
	ResumeWatchdog bool
	ManagedImport  string
}

// ArmRollback creates a one-shot RouterOS-local fallback. It survives loss of
// the control-plane process and is intentionally independent from SSH Safe
// Mode. RouterOS' own clock is used so host clock skew cannot delay rollback.
func (client *Client) ArmRollback(ctx context.Context, scriptName string, options RollbackOptions) (string, error) {
	if !managedNamePattern.MatchString(scriptName) || !strings.HasPrefix(scriptName, "SB-GATEWAY-rollback-") {
		return "", errors.New("managed RouterOS rollback script name is invalid")
	}
	if options.ManagedImport != "" && !managedImportNamePattern.MatchString(options.ManagedImport) {
		return "", errors.New("managed RouterOS rollback import name is invalid")
	}
	if err := client.ensureNoPendingRollbackGuard(ctx); err != nil {
		return "", err
	}
	delay := options.Delay
	if delay == 0 {
		delay = 10 * time.Minute
	}
	if delay < time.Minute {
		delay = time.Minute
	}
	if delay > time.Hour {
		delay = time.Hour
	}

	// /system/clock is a singleton and RouterOS 7.24 returns it as a JSON
	// object, while older fixtures and some releases expose a one-row array.
	clockRows, err := client.List(ctx, "/rest/system/clock?.proplist=date,time")
	if err != nil {
		return "", err
	}
	if len(clockRows) != 1 {
		return "", errors.New("RouterOS clock is missing or ambiguous")
	}
	now, err := parseRouterOSClock(text(clockRows[0]["date"]), text(clockRows[0]["time"]))
	if err != nil {
		return "", err
	}
	runAt := now.Add(delay)

	var nonce [4]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", errors.New("generate RouterOS rollback scheduler name")
	}
	name := "SB-GATEWAY-safe-rollback-" + hex.EncodeToString(nonce[:])
	commands := []string{"/system script run " + scriptName}
	if options.ResumeWatchdog {
		commands = append(commands, `/system scheduler enable [find where name="SB-GATEWAY-health-watchdog"]`)
	}
	if options.ManagedImport != "" {
		commands = append(commands, `/file remove [find where name="`+options.ManagedImport+`"]`)
	}
	commands = append(commands, `/system scheduler remove [find where name="`+name+`"]`)

	_, err = client.request(ctx, http.MethodPut, "/rest/system/scheduler", map[string]any{
		"name":       name,
		"start-date": runAt.Format("2006-01-02"),
		"start-time": runAt.Format("15:04:05"),
		"interval":   "0s",
		"on-event":   strings.Join(commands, "; "),
		"policy":     "ftp,read,write,test,policy",
		"comment":    rollbackSchedulerComment,
		"disabled":   "false",
	})
	if err != nil {
		return "", err
	}
	return name, nil
}

// ensureNoPendingRollbackGuard prevents two independent rollback generations
// from overlapping. A guard with run-count zero can still restore an older
// configuration, so no later candidate may be applied until that guard has
// either fired or been removed successfully.
func (client *Client) ensureNoPendingRollbackGuard(ctx context.Context) error {
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=name,comment,run-count")
	if err != nil {
		return err
	}
	for _, row := range rows {
		name := text(row["name"])
		if !rollbackSchedulerNamePattern.MatchString(name) || text(row["comment"]) != rollbackSchedulerComment {
			continue
		}
		count, countErr := strconv.Atoi(text(row["run-count"]))
		if countErr != nil || count == 0 {
			return ErrRollbackGuardPending
		}
	}
	return nil
}

// DisarmRollback removes only the exact scheduler owned by this project. A
// successful RouterOS DELETE is authoritative; no retry loop burns CPU or
// extends the Apply critical section.
func (client *Client) DisarmRollback(ctx context.Context, name string) error {
	if !rollbackSchedulerNamePattern.MatchString(name) {
		return errors.New("RouterOS rollback scheduler name is invalid")
	}
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment")
	if err != nil {
		return err
	}
	var id string
	for _, row := range rows {
		if text(row["name"]) != name {
			continue
		}
		if id != "" {
			return errors.New("RouterOS rollback scheduler is ambiguous")
		}
		if text(row["comment"]) != rollbackSchedulerComment {
			return errors.New("refusing to remove an unowned RouterOS scheduler")
		}
		id = text(row[".id"])
	}
	if id == "" {
		return nil
	}
	_, err = client.request(ctx, http.MethodDelete, "/rest/system/scheduler/"+routerOSResourceID(id), nil)
	return err
}

// PruneCompletedRollbacks removes one-shot project schedulers only after
// RouterOS reports that no floating Safe Mode history exists.
func (client *Client) PruneCompletedRollbacks(ctx context.Context) (int, error) {
	history, err := client.list(ctx, "/rest/system/history?.proplist=floating-undo")
	if err != nil {
		return 0, err
	}
	for _, row := range history {
		if strings.EqualFold(text(row["floating-undo"]), "true") {
			return 0, nil
		}
	}
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment,run-count")
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, row := range rows {
		name := text(row["name"])
		count, _ := strconv.Atoi(text(row["run-count"]))
		if !rollbackSchedulerNamePattern.MatchString(name) || text(row["comment"]) != rollbackSchedulerComment || count < 1 {
			continue
		}
		id := text(row[".id"])
		if id == "" {
			return removed, errors.New("completed RouterOS rollback scheduler has no identifier")
		}
		if _, err := client.request(ctx, http.MethodDelete, "/rest/system/scheduler/"+routerOSResourceID(id), nil); err != nil {
			return removed, err
		}
		removed++
	}
	return removed, nil
}

// WaitSafeModeSettled is the one bounded poll in Apply. It is required before
// removing the independent scheduler because a deletion made while history is
// still floating would itself be rolled back when the SSH owner exits.
func (client *Client) WaitSafeModeSettled(ctx context.Context, timeout time.Duration) error {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	deadline := time.Now().Add(timeout)
	for {
		rows, err := client.list(ctx, "/rest/system/history?.proplist=floating-undo")
		if err != nil {
			return err
		}
		floating := false
		for _, row := range rows {
			floating = floating || strings.EqualFold(text(row["floating-undo"]), "true")
		}
		if !floating {
			return nil
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return errors.New("RouterOS Safe Mode floating history did not settle")
		}
		timer := time.NewTimer(min(250*time.Millisecond, remaining))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func parseRouterOSClock(dateValue, timeValue string) (time.Time, error) {
	clock := strings.SplitN(strings.TrimSpace(timeValue), ".", 2)[0]
	for _, layout := range []string{"2006-01-02 15:04:05", "Jan/02/2006 15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, strings.TrimSpace(dateValue)+" "+clock, time.Local); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, errors.New("RouterOS local clock format is unsupported")
}
