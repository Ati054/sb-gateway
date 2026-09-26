package routeros

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// SuppressFetchInfoLogs removes successful fetch chatter from ordinary RouterOS
// logging rules. It never changes the watchdog cadence or warning/error rules.
// Re-reading first makes a lost PATCH response safe to retry after an update.
func (client *Client) SuppressFetchInfoLogs(ctx context.Context) (bool, error) {
	rules, err := client.list(ctx, "/rest/system/logging?.proplist=.id,topics,disabled")
	if err != nil {
		return false, err
	}
	changed := false
	for _, rule := range rules {
		if rule["disabled"] == true || text(rule["disabled"]) == "true" {
			continue
		}
		topics, update := withoutFetchInfoTopic(text(rule["topics"]))
		if !update {
			continue
		}
		id := text(rule[".id"])
		if id == "" {
			return changed, errors.New("RouterOS logging rule has no resource ID")
		}
		if _, err := client.request(ctx, http.MethodPatch, "/rest/system/logging/"+routerOSResourceID(id), map[string]any{"topics": topics}); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// RouterOS topic lists are conjunctive. Only broad info and fetch rules can
// record fetch,info without another required topic; leave custom topic filters
// and all severity-specific rules untouched.
func withoutFetchInfoTopic(value string) (string, bool) {
	if value == "" {
		return "", false
	}
	parts := strings.Split(value, ",")
	positiveInfo, positiveFetch := false, false
	for _, part := range parts {
		topic := strings.TrimSpace(part)
		switch topic {
		case "info":
			positiveInfo = true
		case "fetch":
			positiveFetch = true
		default:
			return "", false
		}
	}
	if !positiveInfo && !positiveFetch {
		return "", false
	}
	if positiveInfo {
		return value + ",!fetch", true
	}
	return value + ",!info", true
}
