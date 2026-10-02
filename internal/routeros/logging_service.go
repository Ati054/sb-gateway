package routeros

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

const serviceLogCommentPrefix = "SB-GATEWAY auth-log v1 "
const serviceLogSourceFilter = "^($|[^u])"
const serviceLogRuleProperties = "/rest/system/logging?.proplist=.id,topics,action,prefix,regex,disabled,comment"
const maxServiceLogSources = 8
const maxServiceLogClones = 256

var serviceLogUsernamePattern = regexp.MustCompile(`^[A-Za-z0-9_.@-]{1,32}$`)
var serviceLogIDPattern = regexp.MustCompile(`^\*[0-9A-Fa-f]{1,16}$`)
var serviceLogDigestPattern = regexp.MustCompile(`^[0-9a-f]{12}$`)

type serviceLogRule struct {
	id, topics, action, prefix, regex, comment string
	disabled                                   bool
}

type serviceLogClone struct {
	rule                            serviceLogRule
	sourceID, username, fingerprint string
	index                           int
}

// Each shard accepts a different first mismatch or proper-prefix termination.
// Their union is the exact complement of the successful-account log prefix.
func serviceAccountInfoFilters(username string) []string {
	if !serviceLogUsernamePattern.MatchString(username) {
		return nil
	}
	prefix := "user " + username + " logged "
	filters := make([]string, len(prefix))
	for index := range prefix {
		filters[index] = "^" + regexp.QuoteMeta(prefix[:index]) + "($|[^" + string(prefix[index]) + "])"
	}
	return filters
}

// SuppressServiceInfoLogs preserves ordinary account auditing while removing
// only successful login/logout chatter from the verified dedicated REST user.
// Separate writes cannot be atomic: install may briefly duplicate messages,
// but the source remains unfiltered until every disjoint clone is verified.
func (client *Client) SuppressServiceInfoLogs(ctx context.Context) (bool, error) {
	changed, err := client.SuppressFetchInfoLogs(ctx)
	if err != nil {
		return changed, err
	}
	schedulers, err := client.list(ctx, "/rest/system/scheduler?.proplist=name,comment,disabled")
	if err != nil {
		return changed, fmt.Errorf("check pending RouterOS uninstall before log filtering: %w", err)
	}
	for _, scheduler := range schedulers {
		if text(scheduler["name"]) == fullUninstallScheduler && text(scheduler["comment"]) == "SB-GATEWAY autonomous full uninstall" && scheduler["disabled"] != true && text(scheduler["disabled"]) != "true" {
			return changed, nil
		}
	}
	users, err := client.list(ctx, "/rest/user?.proplist=name,group,comment")
	if err != nil {
		return changed, fmt.Errorf("verify dedicated RouterOS log account: %w", err)
	}
	owned, matches := false, 0
	for _, user := range users {
		if text(user["name"]) == client.username {
			matches++
			owned = text(user["group"]) == "sb-gateway-api" && text(user["comment"]) == "SB-GATEWAY control-plane REST user"
		}
	}
	if matches > 1 {
		return changed, errors.New("dedicated RouterOS log account is ambiguous")
	}
	if matches != 1 || !owned {
		restored, err := client.RestoreServiceInfoLogs(ctx)
		return changed || restored, err
	}
	filters := serviceAccountInfoFilters(client.username)
	if len(filters) == 0 {
		restored, err := client.RestoreServiceInfoLogs(ctx)
		if err != nil {
			return changed || restored, err
		}
		return changed || restored, errors.New("dedicated RouterOS log account name is unsupported")
	}
	rules, groups, err := client.readServiceLogRules(ctx)
	if err != nil {
		return changed, err
	}
	sources := make([]string, 0)
	for id, rule := range rules {
		if !strings.HasPrefix(rule.comment, serviceLogCommentPrefix) && !rule.disabled && recordsAccountInfo(rule.topics) && (rule.regex == "" || len(groups[id]) > 0 && rule.regex == filters[0]) {
			sources = append(sources, id)
		}
	}
	if len(sources) > maxServiceLogSources || len(sources)*(len(filters)-1) > maxServiceLogClones {
		restored, err := client.RestoreServiceInfoLogs(ctx)
		if err != nil {
			return changed || restored, err
		}
		return changed || restored, errors.New("RouterOS account-log filtering exceeds the bounded rule count")
	}
	for _, id := range sortedServiceLogGroups(groups) {
		clones := groups[id]
		source, exists := rules[id]
		if !serviceLogOwnershipProven(clones) {
			return changed, fmt.Errorf("RouterOS log group for source %s has ambiguous ownership", id)
		}
		if exists && source.regex == filters[0] {
			if !source.disabled && recordsAccountInfo(source.topics) && serviceLogClonesMatch(source, client.username, clones, true) {
				continue
			}
			if err := client.patchServiceLogRegex(ctx, source.id, ""); err != nil {
				return changed, err
			}
			changed = true
			source.regex = ""
			rules[id] = source
		}
		if exists && source.regex == "" && !source.disabled && recordsAccountInfo(source.topics) && serviceLogClonesMatch(source, client.username, clones, false) {
			continue
		}
		if err := client.deleteServiceLogClones(ctx, clones); err != nil {
			return changed, err
		}
		changed = changed || len(clones) > 0
		delete(groups, id)
	}
	sort.Strings(sources)
	for _, id := range sources {
		source := rules[id]
		if source.regex != "" {
			continue
		}
		present := make(map[int]bool)
		for _, clone := range groups[id] {
			present[clone.index] = true
		}
		for index := 1; index < len(filters); index++ {
			if present[index] {
				continue
			}
			comment := serviceLogCloneComment(source, client.username, index)
			_, err := client.request(ctx, http.MethodPut, "/rest/system/logging", map[string]any{
				"topics": source.topics, "action": source.action, "prefix": source.prefix,
				"regex": filters[index], "comment": comment, "disabled": "false",
			})
			if err != nil {
				// An unknown PUT outcome is left for the next inventory read;
				// retrying it blindly could create a duplicate shard.
				if DefinitiveRequestRejection(err) {
					_, cleanupErr := client.RestoreServiceInfoLogs(ctx)
					if cleanupErr != nil {
						return changed, fmt.Errorf("RouterOS log shard rejected; cleanup pending: %w", cleanupErr)
					}
				}
				return changed, fmt.Errorf("install RouterOS account-log shard %d: %w", index, err)
			}
			changed = true
		}
		verified, verifiedGroups, err := client.readServiceLogRules(ctx)
		if err != nil {
			return changed, err
		}
		if verified[id] != source || !serviceLogClonesMatch(source, client.username, verifiedGroups[id], true) {
			return changed, errors.New("RouterOS log source or clone coverage changed before activation")
		}
		if err := client.patchServiceLogRegex(ctx, id, filters[0]); err != nil {
			return changed, err
		}
		changed = true
	}
	return changed, nil
}

// RestoreServiceInfoLogs widens recognized sources before removing their
// explicitly owned clones. An uncertain restore response never drops coverage.
func (client *Client) RestoreServiceInfoLogs(ctx context.Context) (bool, error) {
	rules, groups, err := client.readServiceLogRules(ctx)
	if err != nil {
		return false, err
	}
	changed := false
	for _, id := range sortedServiceLogGroups(groups) {
		clones := groups[id]
		source, exists := rules[id]
		if !serviceLogOwnershipProven(clones) {
			return changed, fmt.Errorf("cannot restore RouterOS log group for source %s with ambiguous ownership", id)
		}
		if exists && source.regex == serviceLogSourceFilter {
			if err := client.patchServiceLogRegex(ctx, id, ""); err != nil {
				return changed, err
			}
			changed = true
			source.regex = ""
		}
		// A different source regex belongs to the operator. Removing only
		// our clones respects that choice without widening their filter.
		if err := client.deleteServiceLogClones(ctx, clones); err != nil {
			return changed, err
		}
		changed = changed || len(clones) > 0
	}
	return changed, nil
}

func (client *Client) readServiceLogRules(ctx context.Context) (map[string]serviceLogRule, map[string][]serviceLogClone, error) {
	rows, err := client.list(ctx, serviceLogRuleProperties)
	if err != nil {
		return nil, nil, err
	}
	rules, groups := make(map[string]serviceLogRule), make(map[string][]serviceLogClone)
	cloneCount := 0
	for _, row := range rows {
		rule := serviceLogRule{id: text(row[".id"]), topics: text(row["topics"]), action: text(row["action"]), prefix: text(row["prefix"]), regex: text(row["regex"]), comment: text(row["comment"]), disabled: row["disabled"] == true || text(row["disabled"]) == "true"}
		if !serviceLogIDPattern.MatchString(rule.id) {
			return nil, nil, errors.New("RouterOS logging rule has an invalid resource ID")
		}
		if _, duplicate := rules[rule.id]; duplicate {
			return nil, nil, errors.New("RouterOS logging rule identifier is ambiguous")
		}
		rules[rule.id] = rule
		if !strings.HasPrefix(rule.comment, serviceLogCommentPrefix) {
			continue
		}
		clone, err := parseServiceLogClone(rule)
		if err != nil {
			return nil, nil, err
		}
		groups[clone.sourceID] = append(groups[clone.sourceID], clone)
		cloneCount++
	}
	if len(groups) > maxServiceLogSources || cloneCount > maxServiceLogClones {
		return nil, nil, errors.New("owned RouterOS account-log rules exceed the safety bound")
	}
	for id, rule := range rules {
		if !rule.disabled && recordsAccountInfo(rule.topics) && rule.regex == serviceLogSourceFilter && len(groups[id]) == 0 {
			return nil, nil, fmt.Errorf("RouterOS log source %s has a shard filter without ownership evidence; inspect its regex before retrying", id)
		}
	}
	return rules, groups, nil
}

func parseServiceLogClone(rule serviceLogRule) (serviceLogClone, error) {
	parts := strings.Split(strings.TrimPrefix(rule.comment, serviceLogCommentPrefix), " ")
	if len(parts) == 4 && serviceLogIDPattern.MatchString(parts[0]) && serviceLogDigestPattern.MatchString(parts[2]) {
		username, decodeErr := hex.DecodeString(parts[1])
		index, indexErr := strconv.Atoi(parts[3])
		filters := serviceAccountInfoFilters(string(username))
		if decodeErr == nil && indexErr == nil && index > 0 && index < len(filters) && strconv.Itoa(index) == parts[3] && hex.EncodeToString(username) == parts[1] && parts[0] != rule.id {
			return serviceLogClone{rule: rule, sourceID: parts[0], username: string(username), fingerprint: parts[2], index: index}, nil
		}
	}
	return serviceLogClone{}, errors.New("owned RouterOS account-log comment is malformed")
}

func serviceLogFingerprint(source serviceLogRule, username string) string {
	encoded, _ := json.Marshal([]string{source.id, username, source.topics, source.action, source.prefix})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])[:12]
}

func serviceLogCloneComment(source serviceLogRule, username string, index int) string {
	return serviceLogCommentPrefix + source.id + " " + hex.EncodeToString([]byte(username)) + " " + serviceLogFingerprint(source, username) + " " + strconv.Itoa(index)
}

func serviceLogOwnershipProven(clones []serviceLogClone) bool {
	for _, clone := range clones {
		source := clone.rule
		source.id = clone.sourceID
		if clone.fingerprint == serviceLogFingerprint(source, clone.username) && clone.rule.regex == serviceAccountInfoFilters(clone.username)[clone.index] {
			return true
		}
	}
	return false
}

func serviceLogClonesMatch(source serviceLogRule, username string, clones []serviceLogClone, complete bool) bool {
	filters := serviceAccountInfoFilters(username)
	if complete && len(clones) != len(filters)-1 {
		return false
	}
	seen := make(map[int]bool)
	for _, clone := range clones {
		if seen[clone.index] || clone.username != username || clone.fingerprint != serviceLogFingerprint(source, username) || clone.rule.comment != serviceLogCloneComment(source, username, clone.index) || clone.rule.topics != source.topics || clone.rule.action != source.action || clone.rule.prefix != source.prefix || clone.rule.regex != filters[clone.index] || clone.rule.disabled {
			return false
		}
		seen[clone.index] = true
	}
	return true
}

func sortedServiceLogGroups(groups map[string][]serviceLogClone) []string {
	ids := make([]string, 0, len(groups))
	for id := range groups {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (client *Client) patchServiceLogRegex(ctx context.Context, id, value string) error {
	_, err := client.request(ctx, http.MethodPatch, "/rest/system/logging/"+routerOSResourceID(id), map[string]any{"regex": value})
	return err
}

func (client *Client) deleteServiceLogClones(ctx context.Context, clones []serviceLogClone) error {
	for _, clone := range clones {
		if _, err := client.request(ctx, http.MethodDelete, "/rest/system/logging/"+routerOSResourceID(clone.rule.id), nil); err != nil {
			return err
		}
	}
	return nil
}

func recordsAccountInfo(value string) bool {
	info := false
	for _, part := range strings.Split(value, ",") {
		switch topic := strings.TrimSpace(part); topic {
		case "info":
			info = true
		case "system", "account":
		case "!info", "!system", "!account":
			return false
		default:
			if len(topic) < 2 || topic[0] != '!' {
				return false
			}
		}
	}
	return info
}
