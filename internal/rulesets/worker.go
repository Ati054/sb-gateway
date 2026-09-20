package rulesets

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"
)

const (
	maxSourceBytes   = 4 << 20
	maxIncludedFiles = 96
	maxRuleValues    = 250_000
	upstreamBase     = "https://raw.githubusercontent.com/v2fly/domain-list-community/master/data/"
)

type Options struct {
	RulesetDir string
	StatusPath string
	StateDir   string
	Timeout    time.Duration
}

type Fetch func(name string) (string, error)

func OptionsFromEnvironment() Options {
	rulesetDir := os.Getenv("SB_RULESET_DIR")
	if rulesetDir == "" {
		rulesetDir = "/config/rulesets"
	}
	statusPath := os.Getenv("SB_RULESET_STATUS_PATH")
	if statusPath == "" {
		statusPath = "/state/control-plane/rulesets-update.json"
	}
	stateDir := os.Getenv("SB_GATEWAY_STATE_DIR")
	if stateDir == "" {
		stateDir = "/state/control-plane"
	}
	return Options{RulesetDir: rulesetDir, StatusPath: statusPath, StateDir: stateDir, Timeout: 20 * time.Second}
}

func SeedPayload(pack ServicePack) map[string]any {
	rules := make([]any, 0, 3)
	base := make(map[string]any)
	if len(pack.FallbackDomains) > 0 {
		base["domain_suffix"] = append([]string(nil), pack.FallbackDomains...)
	}
	if len(pack.IPCIDRs) > 0 {
		base["ip_cidr"] = append([]string(nil), pack.IPCIDRs...)
	}
	if len(base) > 0 {
		rules = append(rules, base)
	}
	if len(pack.TCPPorts) > 0 || len(pack.TCPPortRanges) > 0 {
		rule := map[string]any{"network": "tcp"}
		if len(pack.TCPPorts) > 0 {
			rule["port"] = append([]int(nil), pack.TCPPorts...)
		}
		if len(pack.TCPPortRanges) > 0 {
			rule["port_range"] = append([]string(nil), pack.TCPPortRanges...)
		}
		rules = append(rules, rule)
	}
	if len(pack.UDPPorts) > 0 || len(pack.UDPPortRanges) > 0 {
		rule := map[string]any{"network": "udp"}
		if len(pack.UDPPorts) > 0 {
			rule["port"] = append([]int(nil), pack.UDPPorts...)
		}
		if len(pack.UDPPortRanges) > 0 {
			rule["port_range"] = append([]string(nil), pack.UDPPortRanges...)
		}
		rules = append(rules, rule)
	}
	return map[string]any{"version": 3, "rules": rules}
}

func EnsureSeeds(root string, packs []ServicePack) ([]string, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	updated := make([]string, 0)
	for _, pack := range packs {
		path := filepath.Join(root, pack.ID+".json")
		baseline := SeedPayload(pack)
		payload, err := readObject(path, maxSourceBytes)
		if errors.Is(err, os.ErrNotExist) {
			if err := writeJSON(path, baseline); err != nil {
				return nil, err
			}
			updated = append(updated, path)
			continue
		}
		if err != nil {
			continue
		}
		if pack.UpdateMode == "builtin" && !jsonEqual(payload, baseline) {
			if err := writeJSON(path, baseline); err != nil {
				return nil, err
			}
			updated = append(updated, path)
			continue
		}
		version, versionOK := integer(payload["version"])
		if !versionOK || version != 3 {
			continue
		}
		if mergeBaseline(payload, pack) {
			if err := writeJSON(path, payload); err != nil {
				return nil, err
			}
			updated = append(updated, path)
		}
	}
	return updated, nil
}

func mergeBaseline(payload map[string]any, pack ServicePack) bool {
	rules, ok := payload["rules"].([]any)
	if !ok {
		return false
	}
	baselineRules, _ := SeedPayload(pack)["rules"].([]any)
	changed := false
	for _, baselineValue := range baselineRules {
		baseline, ok := baselineValue.(map[string]any)
		if !ok {
			continue
		}
		baselineNetwork, hasNetwork := baseline["network"]
		var target map[string]any
		for _, currentValue := range rules {
			current, currentOK := currentValue.(map[string]any)
			if !currentOK {
				continue
			}
			currentNetwork, currentHasNetwork := current["network"]
			if reflect.DeepEqual(currentNetwork, baselineNetwork) && (hasNetwork || !currentHasNetwork) {
				target = current
				break
			}
		}
		if target == nil {
			rules = append(rules, cloneMap(baseline))
			changed = true
			continue
		}
		for field, additionsValue := range baseline {
			if field == "network" {
				continue
			}
			additions := toAnySlice(additionsValue)
			values := toAnySlice(target[field])
			for _, addition := range additions {
				if !contains(values, addition) {
					values = append(values, addition)
					changed = true
				}
			}
			target[field] = values
		}
	}
	payload["rules"] = rules
	return changed
}

func CompileDomainList(rootName string, fetch Fetch) (map[string]any, error) {
	fields := map[string]map[string]struct{}{
		"domain": {}, "domain_suffix": {}, "domain_keyword": {}, "domain_regex": {},
	}
	visited := make(map[string]bool)
	valueCount := 0
	var visit func(string) error
	visit = func(name string) error {
		if visited[name] {
			return nil
		}
		if len(visited) >= maxIncludedFiles || !upstreamNamePattern.MatchString(name) {
			return errors.New("rule-set include graph is invalid or too large")
		}
		visited[name] = true
		body, err := fetch(name)
		if err != nil {
			return err
		}
		scanner := bufio.NewScanner(strings.NewReader(body))
		scanner.Buffer(make([]byte, 64<<10), maxSourceBytes)
		lineNumber := 0
		for scanner.Scan() {
			lineNumber++
			line := strings.TrimSpace(strings.SplitN(scanner.Text(), "#", 2)[0])
			if line == "" {
				continue
			}
			token := strings.Fields(line)[0]
			if strings.HasPrefix(token, "include:") {
				included := strings.TrimSpace(strings.TrimPrefix(token, "include:"))
				if included == "" {
					return fmt.Errorf("empty include in %s:%d", name, lineNumber)
				}
				if err := visit(included); err != nil {
					return err
				}
				continue
			}
			prefix, value, separated := strings.Cut(token, ":")
			field := "domain_suffix"
			if !separated {
				value = prefix
			} else {
				field = map[string]string{"full": "domain", "domain": "domain_suffix", "keyword": "domain_keyword", "regexp": "domain_regex"}[prefix]
				if field == "" {
					return fmt.Errorf("unsupported rule type %q in %s:%d", prefix, name, lineNumber)
				}
			}
			value = strings.TrimSpace(value)
			if field != "domain_regex" {
				value = strings.ToLower(value)
			}
			if value == "" || len(value) > 1024 {
				return fmt.Errorf("invalid rule in %s:%d", name, lineNumber)
			}
			if _, exists := fields[field][value]; !exists {
				fields[field][value] = struct{}{}
				valueCount++
				if valueCount > maxRuleValues {
					return errors.New("rule-set contains too many values")
				}
			}
		}
		return scanner.Err()
	}
	if err := visit(rootName); err != nil {
		return nil, err
	}
	rule := make(map[string]any)
	for field, values := range fields {
		if len(values) == 0 {
			continue
		}
		items := make([]string, 0, len(values))
		for value := range values {
			items = append(items, value)
		}
		sort.Strings(items)
		rule[field] = items
	}
	if len(rule) == 0 {
		return nil, errors.New("rule-set contains no supported domain rules")
	}
	return map[string]any{"version": 3, "rules": []any{rule}}, nil
}

func ValidateLocal(root string) ([]string, error) {
	matches, err := filepath.Glob(filepath.Join(root, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	for _, path := range matches {
		payload, err := readObject(path, maxSourceBytes)
		if err != nil {
			return nil, fmt.Errorf("invalid local rule set %s: %w", filepath.Base(path), err)
		}
		if err := Validate(payload); err != nil {
			return nil, fmt.Errorf("invalid local rule set %s: %w", filepath.Base(path), err)
		}
	}
	if err := removeObsoleteSRS(root); err != nil {
		return nil, err
	}
	return matches, nil
}

func Validate(payload map[string]any) error {
	version, ok := integer(payload["version"])
	if !ok || version != 3 {
		return errors.New("rule set has an unsupported schema version")
	}
	rules, ok := payload["rules"].([]any)
	if !ok {
		return errors.New("rule set has no rules array")
	}
	allowed := map[string]bool{
		"domain": true, "domain_suffix": true, "domain_keyword": true,
		"domain_regex": true, "ip_cidr": true, "network": true,
		"port": true, "port_range": true,
	}
	valueCount := 0
	for _, ruleValue := range rules {
		rule, ok := ruleValue.(map[string]any)
		if !ok || len(rule) == 0 {
			return errors.New("rule set contains an invalid rule")
		}
		for field, value := range rule {
			if !allowed[field] {
				return errors.New("rule set contains unsupported fields")
			}
			values := toAnySlice(value)
			if len(values) == 0 {
				return errors.New("rule set contains invalid values")
			}
			for _, item := range values {
				switch item.(type) {
				case string, json.Number, float64, int:
				default:
					return errors.New("rule set contains invalid values")
				}
			}
			valueCount += len(values)
		}
	}
	if valueCount > maxRuleValues {
		return errors.New("rule set contains too many values")
	}
	return nil
}

func RefreshPack(pack ServicePack, root string, fetch Fetch) (map[string]any, error) {
	if pack.UpdateMode != "catalog" || pack.UpstreamName == nil || *pack.UpstreamName == "" {
		return nil, errors.New("this pack uses bundled official endpoints")
	}
	payload, err := CompileDomainList(*pack.UpstreamName, fetch)
	if err != nil {
		return nil, err
	}
	mergeBaseline(payload, pack)
	if err := Validate(payload); err != nil {
		return nil, err
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(root, pack.ID+".json"), payload); err != nil {
		return nil, err
	}
	digest := sha256.Sum256(encoded)
	return map[string]any{
		"status": "ok", "updated_at": time.Now().UTC().Format(time.RFC3339Nano),
		"sha256": hex.EncodeToString(digest[:]), "rules": ruleValueCount(payload),
	}, nil
}

func RefreshAll(options Options, packs []ServicePack) (map[string]any, error) {
	catalog, err := Catalog()
	if err != nil {
		return nil, err
	}
	if _, err := EnsureSeeds(options.RulesetDir, catalog); err != nil {
		return nil, err
	}
	if err := removeObsoleteSRS(options.RulesetDir); err != nil {
		return nil, err
	}
	fetch := HTTPFetch(options.Timeout)
	results := make(map[string]any, len(packs))
	index := catalogIndex(catalog)
	for _, pack := range packs {
		if pack.UpdateMode != "catalog" {
			results[pack.ID] = map[string]any{
				"status": "bundled", "checked_at": time.Now().UTC().Format(time.RFC3339Nano),
				"message": "Built-in service rules are shipped with this SB Gateway release.",
				"rules":   reviewedRuleCount(pack, index),
			}
			continue
		}
		result, refreshErr := RefreshPack(pack, options.RulesetDir, fetch)
		if refreshErr != nil {
			results[pack.ID] = map[string]any{
				"status": "stale", "checked_at": time.Now().UTC().Format(time.RFC3339Nano),
				"message": "Update failed; the last-known-good pack remains active.",
			}
			continue
		}
		results[pack.ID] = result
	}
	status := map[string]any{
		"schema": 1, "checked_at": time.Now().UTC().Format(time.RFC3339Nano), "packs": results,
	}
	if err := writeJSON(options.StatusPath, status); err != nil {
		return nil, err
	}
	return status, nil
}

func HTTPFetch(timeout time.Duration) Fetch {
	client := &http.Client{
		Timeout: timeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return errors.New("rule-set download redirects are not allowed")
		},
	}
	return func(name string) (string, error) {
		if !upstreamNamePattern.MatchString(name) {
			return "", errors.New("invalid upstream rule-set name")
		}
		target := upstreamBase + url.PathEscape(name)
		parsed, err := url.Parse(target)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() != "raw.githubusercontent.com" {
			return "", errors.New("rule-set source is outside the trusted host")
		}
		request, err := http.NewRequest(http.MethodGet, target, nil)
		if err != nil {
			return "", err
		}
		request.Header.Set("Accept", "text/plain")
		request.Header.Set("User-Agent", "sb-gateway-ruleset-updater/1.0")
		response, err := client.Do(request)
		if err != nil {
			return "", errors.New("rule-set source is unavailable")
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			return "", errors.New("rule-set source is unavailable")
		}
		if response.ContentLength > maxSourceBytes {
			return "", errors.New("rule-set source exceeds the size limit")
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, maxSourceBytes+1))
		if err != nil {
			return "", errors.New("rule-set source is unavailable")
		}
		if len(body) > maxSourceBytes {
			return "", errors.New("rule-set source exceeds the size limit")
		}
		if !bytes.Equal(bytes.ToValidUTF8(body, nil), body) {
			return "", errors.New("rule-set source is not valid UTF-8")
		}
		return string(body), nil
	}
}

func ConfiguredCustomPacks(stateDir string, catalog []ServicePack) ([]ServicePack, error) {
	config, err := loadDraftOrActive(stateDir)
	if err != nil {
		return nil, err
	}
	known := catalogIndex(catalog)
	values, _ := config["service_packs"].([]any)
	result := make([]ServicePack, 0)
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok || item["enabled"] == false {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(textValue(item["id"])))
		upstream := strings.ToLower(strings.TrimSpace(textValue(item["upstream_name"])))
		if upstream == "" {
			upstream = id
		}
		if id == "" || id != upstream || !upstreamNamePattern.MatchString(id) {
			continue
		}
		if _, exists := known[id]; exists {
			continue
		}
		pack, packErr := CustomPack(upstream, textValue(item["name"]))
		if packErr == nil {
			known[id] = pack
			result = append(result, pack)
		}
	}
	return result, nil
}

func ActivePacks(stateDir string, catalog []ServicePack) ([]ServicePack, error) {
	config, err := loadActive(stateDir)
	if errors.Is(err, os.ErrNotExist) {
		return []ServicePack{}, nil
	}
	if err != nil {
		return nil, err
	}
	custom, err := customPacksFromConfig(config, catalog)
	if err != nil {
		return nil, err
	}
	available := catalogIndex(append(append([]ServicePack(nil), catalog...), custom...))
	selected := make(map[string]bool)
	collect := func(value any) {
		item, ok := value.(map[string]any)
		if !ok || item["enabled"] == false {
			return
		}
		if services, ok := item["direct_services"].([]any); ok {
			for _, service := range services {
				selected[strings.ToLower(strings.TrimSpace(textValue(service)))] = true
			}
		}
		if routes, ok := item["service_routes"].(map[string]any); ok {
			for service := range routes {
				selected[strings.ToLower(strings.TrimSpace(service))] = true
			}
		}
		if item["traffic_mode"] == "vless_with_wan_exceptions" {
			for _, pack := range catalog {
				if pack.AlwaysDirect {
					selected[pack.ID] = true
				}
			}
		}
	}
	for _, key := range []string{"policies", "local_clients", "remote_users"} {
		values, _ := config[key].([]any)
		for _, value := range values {
			collect(value)
		}
	}
	for id := range selected {
		for _, dependency := range dependencyIDs(id, available) {
			selected[dependency] = true
		}
	}
	ids := make([]string, 0, len(selected))
	for id := range selected {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := make([]ServicePack, 0, len(ids))
	for _, id := range ids {
		if pack, exists := available[id]; exists {
			result = append(result, pack)
		}
	}
	return result, nil
}

func customPacksFromConfig(config map[string]any, catalog []ServicePack) ([]ServicePack, error) {
	known := catalogIndex(catalog)
	values, _ := config["service_packs"].([]any)
	result := make([]ServicePack, 0)
	for _, value := range values {
		item, ok := value.(map[string]any)
		if !ok || item["enabled"] == false {
			continue
		}
		id := strings.ToLower(strings.TrimSpace(textValue(item["id"])))
		upstream := strings.ToLower(strings.TrimSpace(textValue(item["upstream_name"])))
		if upstream == "" {
			upstream = id
		}
		if id == "" || id != upstream || !upstreamNamePattern.MatchString(id) {
			continue
		}
		if _, exists := known[id]; exists {
			continue
		}
		pack, err := CustomPack(upstream, textValue(item["name"]))
		if err != nil {
			continue
		}
		known[id] = pack
		result = append(result, pack)
	}
	return result, nil
}

func loadDraftOrActive(stateDir string) (map[string]any, error) {
	draft, err := readObject(filepath.Join(stateDir, "draft.json"), maxSourceBytes)
	if err == nil && len(draft) > 0 {
		return draft, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	active, activeErr := loadActive(stateDir)
	if errors.Is(activeErr, os.ErrNotExist) {
		return map[string]any{}, nil
	}
	return active, activeErr
}

func loadActive(stateDir string) (map[string]any, error) {
	pointer, err := readObject(filepath.Join(stateDir, "active.json"), maxSourceBytes)
	if err != nil {
		return nil, err
	}
	revision := textValue(pointer["revision"])
	if len(revision) != 64 {
		return nil, errors.New("active generation revision is invalid")
	}
	for _, character := range revision {
		if !strings.ContainsRune("0123456789abcdef", character) {
			return nil, errors.New("active generation revision is invalid")
		}
	}
	return readObject(filepath.Join(stateDir, "generations", revision+".json"), 64<<20)
}

func readObject(path string, limit int64) (map[string]any, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > limit {
		return nil, errors.New("JSON document exceeds the safety limit")
	}
	decoder := json.NewDecoder(io.LimitReader(file, limit+1))
	decoder.UseNumber()
	value := make(map[string]any)
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, errors.New("JSON file must contain one object")
	}
	return value, nil
}

func writeJSON(path string, value any) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	return writeAtomic(path, buffer.Bytes(), 0o600)
}

func writeAtomic(path string, body []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryName, path)
}

func removeObsoleteSRS(root string) error {
	matches, err := filepath.Glob(filepath.Join(root, "*.srs"))
	if err != nil {
		return err
	}
	for _, path := range matches {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

func ruleValueCount(payload map[string]any) int {
	count := 0
	rules, _ := payload["rules"].([]any)
	for _, value := range rules {
		rule, _ := value.(map[string]any)
		for _, item := range rule {
			count += len(toAnySlice(item))
		}
	}
	return count
}

func toAnySlice(value any) []any {
	if values, ok := value.([]any); ok {
		return append([]any(nil), values...)
	}
	switch values := value.(type) {
	case []string:
		result := make([]any, len(values))
		for index, item := range values {
			result[index] = item
		}
		return result
	case []int:
		result := make([]any, len(values))
		for index, item := range values {
			result[index] = item
		}
		return result
	case nil:
		return nil
	default:
		return []any{value}
	}
}

func contains(values []any, wanted any) bool {
	for _, value := range values {
		if reflect.DeepEqual(value, wanted) || fmt.Sprint(value) == fmt.Sprint(wanted) {
			return true
		}
	}
	return false
}

func cloneMap(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		switch typed := item.(type) {
		case []string:
			result[key] = append([]string(nil), typed...)
		case []int:
			result[key] = append([]int(nil), typed...)
		case []any:
			result[key] = append([]any(nil), typed...)
		default:
			result[key] = typed
		}
	}
	return result
}

func jsonEqual(left, right any) bool {
	leftBody, leftErr := json.Marshal(left)
	rightBody, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBody, rightBody)
}

func integer(value any) (int64, bool) {
	switch typed := value.(type) {
	case json.Number:
		result, err := typed.Int64()
		return result, err == nil
	case float64:
		return int64(typed), typed == float64(int64(typed))
	case int:
		return int64(typed), true
	default:
		return 0, false
	}
}

func textValue(value any) string {
	text, _ := value.(string)
	return text
}
