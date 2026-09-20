package agent

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

const (
	telemetryStateVersion = 1
	telemetryTable        = "sb_gateway_client_telemetry"
	onlineWindow          = 45 * time.Second
)

type telemetryCollector struct {
	opts Options

	loaded       bool
	month        string
	totals       map[string]counterPair
	baselines    map[string]counterPair
	lastActivity map[string]string
	lastSample   time.Time
}

type counterPair struct {
	Uplink   int64 `json:"uplink"`
	Downlink int64 `json:"downlink"`
}

type telemetryState struct {
	Version      int                    `json:"version"`
	Month        string                 `json:"month"`
	UpdatedAt    string                 `json:"updated_at"`
	Totals       map[string]counterPair `json:"totals"`
	Baselines    map[string]counterPair `json:"baselines"`
	LastActivity map[string]string      `json:"last_activity"`
	Snapshot     telemetrySnapshot      `json:"snapshot"`
}

type telemetrySnapshot struct {
	SampledAt          *string           `json:"sampled_at"`
	Month              string            `json:"month"`
	Clients            []telemetryRow    `json:"clients"`
	Sources            map[string]string `json:"sources"`
	OnlineWindowSecond int               `json:"online_window_seconds"`
}

type telemetryRow struct {
	ID                     string   `json:"id"`
	Kind                   string   `json:"kind"`
	Name                   string   `json:"name"`
	Active                 bool     `json:"active"`
	Available              bool     `json:"available"`
	UplinkBytesPerSecond   *float64 `json:"uplink_bytes_per_second"`
	DownlinkBytesPerSecond *float64 `json:"downlink_bytes_per_second"`
	MonthUplinkBytes       int64    `json:"month_uplink_bytes"`
	MonthDownlinkBytes     int64    `json:"month_downlink_bytes"`
	MonthTotalBytes        int64    `json:"month_total_bytes"`
	LastActivity           *string  `json:"last_activity"`
	PolicyID               string   `json:"policy_id"`
	PolicyName             string   `json:"policy_name"`
	SourceCIDRs            []string `json:"source_cidrs"`
}

type activeConfig struct {
	LocalClients []clientConfig `json:"local_clients"`
	RemoteUsers  []clientConfig `json:"remote_users"`
	Policies     []policyConfig `json:"policies"`
}

type clientConfig struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Enabled     *bool    `json:"enabled"`
	PolicyID    string   `json:"policy_id"`
	SourceCIDRs []string `json:"source_cidrs"`
}

type policyConfig struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

func newTelemetryCollector(opts Options) *telemetryCollector {
	return &telemetryCollector{
		opts:         opts,
		totals:       make(map[string]counterPair),
		baselines:    make(map[string]counterPair),
		lastActivity: make(map[string]string),
	}
}

func (collector *telemetryCollector) Tick(ctx context.Context, now time.Time) error {
	month := now.UTC().Format("2006-01")
	collector.load(month)
	if collector.month != month {
		collector.month = month
		collector.totals = make(map[string]counterPair)
	}
	config, err := loadActiveConfig(collector.opts.StateRoot)
	if err != nil {
		return err
	}
	localClients := enabledClients(config.LocalClients)
	remoteUsers := enabledClients(config.RemoteUsers)

	type remoteResult struct {
		measurements map[string]counterPair
		online       map[string]struct{}
		err          error
	}
	type localResult struct {
		measurements map[string]counterPair
		err          error
	}
	remoteChannel := make(chan remoteResult, 1)
	localChannel := make(chan localResult, 1)
	go func() {
		measurements, online, remoteErr := collector.remoteMeasurements(ctx)
		remoteChannel <- remoteResult{measurements, online, remoteErr}
	}()
	go func() {
		measurements, localErr := collector.localMeasurements(ctx, localClients)
		localChannel <- localResult{measurements, localErr}
	}()
	remote := <-remoteChannel
	local := <-localChannel

	sources := map[string]string{"xray": "available", "local": "available"}
	measurements := make(map[string]counterPair)
	if remote.err != nil {
		sources["xray"] = "unavailable"
	} else {
		for key, value := range remote.measurements {
			measurements["remote:"+key] = value
		}
	}
	if local.err != nil {
		sources["local"] = "unavailable"
	} else {
		for key, value := range local.measurements {
			measurements["local:"+key] = value
		}
	}

	elapsed := time.Duration(0)
	if !collector.lastSample.IsZero() {
		elapsed = now.Sub(collector.lastSample)
		if elapsed < time.Millisecond {
			elapsed = time.Millisecond
		}
	}
	rates := make(map[string]*counterRate)
	for key, current := range measurements {
		previous, exists := collector.baselines[key]
		delta := counterPair{}
		if exists {
			delta.Uplink = counterDelta(current.Uplink, previous.Uplink)
			delta.Downlink = counterDelta(current.Downlink, previous.Downlink)
		}
		if exists && elapsed > 0 {
			rates[key] = &counterRate{
				uplink:   float64(delta.Uplink) / elapsed.Seconds(),
				downlink: float64(delta.Downlink) / elapsed.Seconds(),
			}
		}
		total := collector.totals[key]
		total.Uplink += delta.Uplink
		total.Downlink += delta.Downlink
		collector.totals[key] = total
		collector.baselines[key] = current
		remoteID := strings.TrimPrefix(key, "remote:")
		_, isOnline := remote.online[remoteID]
		if delta.Uplink > 0 || delta.Downlink > 0 || (strings.HasPrefix(key, "remote:") && isOnline) {
			collector.lastActivity[key] = now.UTC().Format(time.RFC3339Nano)
		}
	}

	policies := make(map[string]string)
	for _, policy := range config.Policies {
		policies[policy.ID] = policy.Name
	}
	rows := make([]telemetryRow, 0, len(localClients)+len(remoteUsers))
	rows = append(rows, collector.rowsFor("local", localClients, policies, rates, sources, remote.online, now)...)
	rows = append(rows, collector.rowsFor("remote", remoteUsers, policies, rates, sources, remote.online, now)...)
	sort.SliceStable(rows, func(left, right int) bool {
		if rows[left].Active != rows[right].Active {
			return rows[left].Active
		}
		if rows[left].Kind != rows[right].Kind {
			return rows[left].Kind < rows[right].Kind
		}
		return strings.ToLower(rows[left].Name) < strings.ToLower(rows[right].Name)
	})
	sampledAt := now.UTC().Format(time.RFC3339Nano)
	state := telemetryState{
		Version:      telemetryStateVersion,
		Month:        month,
		UpdatedAt:    sampledAt,
		Totals:       collector.totals,
		Baselines:    collector.baselines,
		LastActivity: collector.lastActivity,
		Snapshot: telemetrySnapshot{
			SampledAt:          &sampledAt,
			Month:              month,
			Clients:            rows,
			Sources:            sources,
			OnlineWindowSecond: int(onlineWindow / time.Second),
		},
	}
	if err := writeJSONAtomic(statePath(collector.opts.StateRoot, "client-telemetry"), state); err != nil {
		return err
	}
	collector.lastSample = now
	return nil
}

type counterRate struct {
	uplink   float64
	downlink float64
}

func (collector *telemetryCollector) rowsFor(kind string, clients []clientConfig, policies map[string]string, rates map[string]*counterRate, sources map[string]string, online map[string]struct{}, now time.Time) []telemetryRow {
	rows := make([]telemetryRow, 0, len(clients))
	for _, client := range clients {
		key := kind + ":" + client.ID
		total := collector.totals[key]
		lastActivityValue, hasActivity := collector.lastActivity[key]
		var lastActivity *string
		recent := false
		if hasActivity {
			copy := lastActivityValue
			lastActivity = &copy
			if parsed, err := time.Parse(time.RFC3339Nano, lastActivityValue); err == nil {
				age := now.Sub(parsed)
				recent = age >= 0 && age <= onlineWindow
			}
		}
		active := recent
		if kind == "remote" {
			_, active = online[client.ID]
		}
		policyName := policies[client.PolicyID]
		if policyName == "" {
			policyName = client.PolicyID
		}
		if policyName == "" {
			policyName = "Не назначен"
		}
		var upRate, downRate *float64
		if rate := rates[key]; rate != nil {
			up, down := rate.uplink, rate.downlink
			upRate, downRate = &up, &down
		}
		sourceCIDRs := []string{}
		if kind == "local" {
			sourceCIDRs = append(sourceCIDRs, client.SourceCIDRs...)
		}
		source := "local"
		if kind == "remote" {
			source = "xray"
		}
		rows = append(rows, telemetryRow{
			ID:                     client.ID,
			Kind:                   kind,
			Name:                   firstNonEmpty(client.Name, client.ID),
			Active:                 active,
			Available:              sources[source] == "available",
			UplinkBytesPerSecond:   upRate,
			DownlinkBytesPerSecond: downRate,
			MonthUplinkBytes:       total.Uplink,
			MonthDownlinkBytes:     total.Downlink,
			MonthTotalBytes:        total.Uplink + total.Downlink,
			LastActivity:           lastActivity,
			PolicyID:               client.PolicyID,
			PolicyName:             policyName,
			SourceCIDRs:            sourceCIDRs,
		})
	}
	return rows
}

func (collector *telemetryCollector) load(month string) {
	if collector.loaded {
		return
	}
	var state telemetryState
	if readJSON(statePath(collector.opts.StateRoot, "client-telemetry"), &state) == nil {
		collector.month = state.Month
		if state.Month == month && state.Totals != nil {
			collector.totals = state.Totals
		}
		if state.Baselines != nil {
			collector.baselines = state.Baselines
		}
		if state.LastActivity != nil {
			collector.lastActivity = state.LastActivity
		}
	}
	if collector.month == "" {
		collector.month = month
	}
	collector.loaded = true
}

func (collector *telemetryCollector) remoteMeasurements(ctx context.Context) (map[string]counterPair, map[string]struct{}, error) {
	statsChannel := make(chan commandResult, 1)
	onlineChannel := make(chan commandResult, 1)
	go func() {
		body, err := runXrayCommand(ctx, 4*time.Second, collector.opts.XrayBinary, "api", "statsquery", "--server="+collector.opts.XrayAPIServer, "-pattern", "user>>>")
		statsChannel <- commandResult{body, err}
	}()
	go func() {
		body, err := runXrayCommand(ctx, 4*time.Second, collector.opts.XrayBinary, "api", "statsgetallonlineusers", "--server="+collector.opts.XrayAPIServer)
		onlineChannel <- commandResult{body, err}
	}()
	statsResult, onlineResult := <-statsChannel, <-onlineChannel
	if statsResult.err != nil {
		return nil, nil, statsResult.err
	}
	if onlineResult.err != nil {
		return nil, nil, onlineResult.err
	}
	stats, err := parseXrayStats(statsResult.body)
	if err != nil {
		return nil, nil, err
	}
	online, err := parseXrayOnlineUsers(onlineResult.body)
	return stats, online, err
}

type commandResult struct {
	body []byte
	err  error
}

func (collector *telemetryCollector) localMeasurements(ctx context.Context, clients []clientConfig) (map[string]counterPair, error) {
	body, err := runCommand(ctx, collector.opts.NFTBinary, "-j", "list", "table", "inet", telemetryTable)
	if err != nil {
		return nil, err
	}
	counters, err := parseNFTCounters(body)
	if err != nil {
		return nil, err
	}
	result := make(map[string]counterPair)
	for _, client := range clients {
		uplink, downlink := telemetryCounterNames(client.ID)
		result[client.ID] = counterPair{Uplink: counters[uplink], Downlink: counters[downlink]}
	}
	return result, nil
}

func loadActiveConfig(root string) (activeConfig, error) {
	var pointer struct {
		Revision string `json:"revision"`
	}
	var config activeConfig
	if err := readJSON(filepath.Join(root, "active.json"), &pointer); err == nil && safeRevision(pointer.Revision) {
		if err := readJSON(filepath.Join(root, "generations", pointer.Revision+".json"), &config); err == nil {
			return config, nil
		}
	}
	if err := readJSON(filepath.Join(root, "draft.json"), &config); err != nil {
		return activeConfig{}, fmt.Errorf("load active or draft configuration: %w", err)
	}
	return config, nil
}

func parseXrayStats(body []byte) (map[string]counterPair, error) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	result := make(map[string]counterPair)
	visitJSON(value, func(object map[string]any) {
		name, ok := object["name"].(string)
		if !ok {
			return
		}
		parts := strings.Split(name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[2] != "traffic" {
			return
		}
		amount := jsonInteger(object["value"])
		pair := result[parts[1]]
		if parts[3] == "uplink" {
			pair.Uplink = amount
		} else if parts[3] == "downlink" {
			pair.Downlink = amount
		}
		result[parts[1]] = pair
	})
	return result, nil
}

func parseXrayOnlineUsers(body []byte) (map[string]struct{}, error) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	result := make(map[string]struct{})
	var visit func(any, string)
	visit = func(item any, key string) {
		switch typed := item.(type) {
		case map[string]any:
			for childKey, child := range typed {
				lower := strings.ToLower(childKey)
				if text, ok := child.(string); ok && (lower == "email" || lower == "user") && text != "" {
					result[text] = struct{}{}
				} else {
					visit(child, lower)
				}
			}
		case []any:
			for _, child := range typed {
				if text, ok := child.(string); ok && onlineListKey(key) && text != "" {
					result[text] = struct{}{}
				} else {
					visit(child, key)
				}
			}
		}
	}
	visit(value, "")
	return result, nil
}

func parseNFTCounters(body []byte) (map[string]int64, error) {
	var value any
	if err := json.Unmarshal(body, &value); err != nil {
		return nil, err
	}
	result := make(map[string]int64)
	visitJSON(value, func(object map[string]any) {
		counter, ok := object["counter"].(map[string]any)
		if !ok {
			return
		}
		name, ok := counter["name"].(string)
		if ok {
			result[name] = jsonInteger(counter["bytes"])
		}
	})
	return result, nil
}

func visitJSON(value any, callback func(map[string]any)) {
	switch typed := value.(type) {
	case map[string]any:
		callback(typed)
		for _, child := range typed {
			visitJSON(child, callback)
		}
	case []any:
		for _, child := range typed {
			visitJSON(child, callback)
		}
	}
}

func jsonInteger(value any) int64 {
	var result int64
	switch typed := value.(type) {
	case float64:
		result = int64(typed)
	case string:
		result, _ = strconv.ParseInt(typed, 10, 64)
	case json.Number:
		result, _ = typed.Int64()
	}
	if result < 0 {
		return 0
	}
	return result
}

func telemetryCounterNames(clientID string) (string, string) {
	return runtimeconfig.TelemetryCounterNames(clientID)
}

func enabledClients(values []clientConfig) []clientConfig {
	result := make([]clientConfig, 0, len(values))
	for _, value := range values {
		if value.ID != "" && (value.Enabled == nil || *value.Enabled) {
			result = append(result, value)
		}
	}
	return result
}

func counterDelta(current, previous int64) int64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func runCommand(parent context.Context, name string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, 4*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, name, arguments...)
	command.Stdin = nil
	body, err := command.Output()
	if err != nil {
		return nil, err
	}
	return body, nil
}

func readJSON(path string, destination any) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewDecoder(io.LimitReader(file, 32<<20)).Decode(destination)
}

func writeJSONAtomic(path string, value any) error {
	body, err := json.Marshal(value)
	if err != nil {
		return err
	}
	body = append(body, '\n')
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(body); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	// Unix rename atomically replaces an existing state file. Windows does not,
	// but the repository's native test/development path still needs repeatable
	// state publication; production images always take the atomic Unix branch.
	if runtime.GOOS == "windows" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return os.Rename(temporaryName, path)
}

func safeRevision(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func onlineListKey(key string) bool {
	switch key {
	case "email", "emails", "user", "users", "onlineusers":
		return true
	default:
		return false
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
