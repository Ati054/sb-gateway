package routeros

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const maxResponseBytes = 4 << 20
const maxDirectScriptBytes = 16 << 10

const (
	recoveryRestartWorker    = "SB-GATEWAY-recovery-restart-worker"
	recoveryRestartScheduler = "SB-GATEWAY-recovery-restart-once"
	watchdogConfigScript     = "SB-GATEWAY-watchdog-config"
	startupFailOpenScript    = "SB-GATEWAY-startup-fail-open"
)

var managedRolePattern = regexp.MustCompile(`^(apply|rollback)$`)
var managedNamePattern = regexp.MustCompile(`^SB-GATEWAY-(?:apply|rollback)-[0-9a-f]{12}$`)
var prohibitedScriptPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)/system\s+(reset|reboot|shutdown|package\s+update)`),
	regexp.MustCompile(`(?i)/user\b`),
	regexp.MustCompile(`(?i)/certificate\b[^\r\n]*\bremove\b`),
	regexp.MustCompile(`(?i)\bset\s+channel\s*=`),
	regexp.MustCompile(`(?i)\bremove\s+\[find\](?:\s|$)`),
}

type Options struct {
	BaseURL       string
	Username      string
	Password      string
	RootCAs       *x509.CertPool
	Timeout       time.Duration
	ActionTimeout time.Duration
}

type Client struct {
	baseURL    string
	username   string
	password   string
	http       *http.Client
	actionHTTP *http.Client
}

// HTTPError preserves the RouterOS response class so callers can distinguish
// a command that was explicitly rejected from a transport failure where the
// command may already have been accepted and only its response was lost.
type HTTPError struct {
	StatusCode int
}

func (err HTTPError) Error() string {
	return fmt.Sprintf("RouterOS REST returned HTTP %d", err.StatusCode)
}

func DefinitiveRequestRejection(err error) bool {
	var httpErr HTTPError
	return errors.As(err, &httpErr) && httpErr.StatusCode >= 400 && httpErr.StatusCode < 500
}

func NewClient(options Options) (*Client, error) {
	parsed, err := url.Parse(strings.TrimSpace(options.BaseURL))
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.Port() == "" || parsed.User != nil || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("RouterOS REST endpoint must be an HTTPS origin with an explicit port")
	}
	if options.Username == "" || options.Password == "" {
		return nil, errors.New("RouterOS REST credentials are required")
	}
	timeout := options.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if timeout > 2*time.Minute {
		return nil, errors.New("RouterOS REST timeout exceeds two minutes")
	}
	actionTimeout := options.ActionTimeout
	if actionTimeout <= 0 {
		actionTimeout = timeout
	}
	if actionTimeout > 5*time.Minute {
		return nil, errors.New("RouterOS REST action timeout exceeds five minutes")
	}
	dialer := &net.Dialer{Timeout: min(timeout, 10*time.Second), KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		ForceAttemptHTTP2:     false,
		MaxIdleConns:          2,
		MaxIdleConnsPerHost:   2,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   min(timeout, 10*time.Second),
		ResponseHeaderTimeout: actionTimeout,
		DisableCompression:    true,
		TLSClientConfig:       &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: options.RootCAs},
	}
	return &Client{
		baseURL: strings.TrimSuffix(options.BaseURL, "/"), username: options.Username, password: options.Password,
		http:       &http.Client{Transport: transport, Timeout: timeout},
		actionHTTP: &http.Client{Transport: transport, Timeout: actionTimeout},
	}, nil
}

func (client *Client) CloseIdleConnections() {
	client.http.CloseIdleConnections()
	client.actionHTTP.CloseIdleConnections()
}

// Health verifies the authenticated REST management path used by Apply. The
// shared client bounds the response and this call does not retry or retain a
// discovery snapshot.
func (client *Client) Health(ctx context.Context) error {
	value, err := client.request(ctx, http.MethodGet, "/rest/system/resource", nil)
	if err != nil {
		return err
	}
	if text(value["uptime"]) == "" && text(value["version"]) == "" {
		return errors.New("RouterOS health response is incomplete")
	}
	return nil
}

// List reads one fixed RouterOS inventory endpoint. Callers choose the path;
// response size, authentication, TLS and deadlines remain enforced by Client.
func (client *Client) List(ctx context.Context, path string) ([]map[string]any, error) {
	value, err := client.requestValue(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return []map[string]any{}, nil
	}
	if object, ok := value.(map[string]any); ok {
		return []map[string]any{object}, nil
	}
	raw, ok := value.([]any)
	if !ok {
		return nil, errors.New("RouterOS REST response is not a list")
	}
	result := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("RouterOS REST list contains an invalid item")
		}
		result = append(result, object)
	}
	return result, nil
}

// ExecuteDirectDelta installs and runs one bounded renderer-owned section
// delta. Complete candidates use the later SCP/Safe Mode transport and are not
// silently pushed through RouterOS' small script source property.
func (client *Client) ExecuteDirectDelta(ctx context.Context, role, source string) (map[string]any, error) {
	_, id, err := client.prepareDirectDelta(ctx, role, source)
	if err != nil {
		return nil, err
	}
	return client.requestAction(ctx, http.MethodPost, "/rest/system/script/run", map[string]any{".id": id})
}

// PrepareDirectDelta validates and installs a generated delta without running
// it. This lets the caller arm rollback before opening the Safe Mode owner.
func (client *Client) PrepareDirectDelta(ctx context.Context, role, source string) (string, error) {
	name, _, err := client.prepareDirectDelta(ctx, role, source)
	return name, err
}

func (client *Client) prepareDirectDelta(ctx context.Context, role, source string) (string, string, error) {
	name, err := managedScriptName(role, source)
	if err != nil {
		return "", "", err
	}
	if err := validateDirectDelta(source); err != nil {
		return "", "", err
	}
	id, err := client.installManagedScript(ctx, name, source)
	if err != nil {
		return "", "", err
	}
	return name, id, nil
}

// RunManagedScript resolves an exact content-addressed project script to its
// RouterOS resource ID and runs only that ID.
func (client *Client) RunManagedScript(ctx context.Context, name string) (map[string]any, error) {
	if !managedNamePattern.MatchString(name) {
		return nil, errors.New("managed RouterOS script name is invalid")
	}
	rows, err := client.list(ctx, "/rest/system/script?.proplist=.id,name,comment")
	if err != nil {
		return nil, err
	}
	var id string
	for _, row := range rows {
		if text(row["name"]) != name {
			continue
		}
		if id != "" {
			return nil, errors.New("managed RouterOS script name is ambiguous")
		}
		if text(row["comment"]) != "SB-GATEWAY managed script "+name {
			return nil, errors.New("refusing to run an unowned RouterOS script")
		}
		id = text(row[".id"])
	}
	if id == "" {
		return nil, errors.New("managed RouterOS script is missing")
	}
	return client.requestAction(ctx, http.MethodPost, "/rest/system/script/run", map[string]any{".id": id})
}

// EnforceStartupTrafficSafety migrates an existing installation from the
// legacy container-only health gate to the route-aware traffic gate, then
// immediately enters the already-owned fail-open startup state. It touches
// only two exact scripts with exact project comments; foreign or ambiguous
// resources stop the operation without mutation.
func (client *Client) EnforceStartupTrafficSafety(ctx context.Context) (bool, error) {
	rows, err := client.list(ctx, "/rest/system/script?.proplist=.id,name,comment,source")
	if err != nil {
		return false, err
	}
	type ownedScript struct{ id, source string }
	wanted := map[string]struct {
		comment string
		item    ownedScript
		seen    bool
	}{
		watchdogConfigScript:  {comment: "SB-GATEWAY watchdog persisted config"},
		startupFailOpenScript: {comment: "SB-GATEWAY startup fail-open"},
	}
	for _, row := range rows {
		name := text(row["name"])
		target, exists := wanted[name]
		if !exists {
			continue
		}
		if target.seen {
			return false, fmt.Errorf("%s is ambiguous", name)
		}
		if text(row["comment"]) != target.comment {
			return false, fmt.Errorf("refusing to modify unowned %s", name)
		}
		target.item = ownedScript{id: text(row[".id"]), source: text(row["source"])}
		target.seen = true
		wanted[name] = target
	}
	config := wanted[watchdogConfigScript]
	failOpen := wanted[startupFailOpenScript]
	if !config.seen || config.item.id == "" || !failOpen.seen || failOpen.item.id == "" {
		return false, errors.New("startup traffic safety scripts are missing")
	}
	source := config.item.source
	migrated := false
	switch {
	case strings.Count(source, ":9080/traffic-ready") == 1 && !strings.Contains(source, ":9080/healthz"):
	case strings.Count(source, ":9080/healthz") == 1 && !strings.Contains(source, ":9080/traffic-ready"):
		source = strings.Replace(source, ":9080/healthz", ":9080/traffic-ready", 1)
		if _, err := client.request(ctx, http.MethodPatch, "/rest/system/script/"+routerOSResourceID(config.item.id), map[string]any{"source": source}); err != nil {
			return false, err
		}
		migrated = true
	default:
		return false, errors.New("watchdog health URL is missing or ambiguous")
	}
	if _, err := client.requestAction(ctx, http.MethodPost, "/rest/system/script/run", map[string]any{".id": config.item.id}); err != nil {
		return false, fmt.Errorf("load traffic-ready watchdog config: %w", err)
	}
	if _, err := client.requestAction(ctx, http.MethodPost, "/rest/system/script/run", map[string]any{".id": failOpen.item.id}); err != nil {
		return false, fmt.Errorf("enter startup fail-open: %w", err)
	}
	return migrated, nil
}

// PrepareImportScript installs a bounded wrapper for a previously uploaded
// project-owned RSC. The full candidate never passes through REST JSON.
func (client *Client) PrepareImportScript(ctx context.Context, role, importName string) (string, error) {
	if !managedRolePattern.MatchString(role) || !managedImportNamePattern.MatchString(importName) || !strings.HasPrefix(importName, "SB-GATEWAY-"+role+"-") {
		return "", errors.New("managed RouterOS import role or name is invalid")
	}
	source := `/import file-name="` + importName + `" verbose=no`
	name, err := managedScriptName(role, source)
	if err != nil {
		return "", err
	}
	if _, err := client.installManagedScript(ctx, name, source); err != nil {
		return "", err
	}
	return name, nil
}

// ScheduleRecoveryRestart creates one project-owned one-shot scheduler. The
// worker removes the scheduler before restarting the sole managed container,
// so an interrupted HTTP request cannot turn into an endless restart loop.
func (client *Client) ScheduleRecoveryRestart(ctx context.Context) (map[string]any, error) {
	workerSource := strings.Join([]string{
		"# SB-GATEWAY one-shot recovery restart",
		`:local scheduler [/system/scheduler/find where name="` + recoveryRestartScheduler + `"]`,
		`:if ([:len $scheduler] = 1) do={ /system/scheduler/remove $scheduler }`,
		`:local target [/container/find where comment="SB-GATEWAY container"]`,
		`:if ([:len $target] != 1) do={ :error "managed container is missing or ambiguous" }`,
		`/container/stop $target`,
		`:delay 3s`,
		`/container/start $target`,
		`:log warning "SB-GATEWAY: recovery restore restart executed"`,
	}, "\n")
	if _, err := client.installFixedManagedScript(ctx, recoveryRestartWorker, workerSource); err != nil {
		return nil, err
	}
	rows, err := client.list(ctx, "/rest/system/scheduler?.proplist=.id,name,comment")
	if err != nil {
		return nil, err
	}
	var existingID string
	for _, row := range rows {
		if text(row["name"]) != recoveryRestartScheduler {
			continue
		}
		if existingID != "" {
			return nil, errors.New("recovery restart scheduler is ambiguous")
		}
		if text(row["comment"]) != "SB-GATEWAY one-shot recovery restart" {
			return nil, errors.New("refusing to replace an unowned recovery restart scheduler")
		}
		existingID = text(row[".id"])
		if existingID == "" {
			return nil, errors.New("recovery restart scheduler identifier is unavailable")
		}
	}
	if existingID != "" {
		if _, err := client.request(ctx, http.MethodDelete, "/rest/system/scheduler/"+routerOSResourceID(existingID), nil); err != nil {
			return nil, err
		}
	}
	if _, err := client.request(ctx, http.MethodPut, "/rest/system/scheduler", map[string]any{
		"name": recoveryRestartScheduler, "interval": "60s", "on-event": "/system/script/run " + recoveryRestartWorker,
		"policy": "read,write,test,policy", "comment": "SB-GATEWAY one-shot recovery restart", "disabled": "false",
	}); err != nil {
		return nil, err
	}
	return map[string]any{"scheduled": true, "delay_seconds": 60, "scheduler": recoveryRestartScheduler}, nil
}

func (client *Client) installFixedManagedScript(ctx context.Context, name, source string) (string, error) {
	if !validFixedManagedScript(name, source) {
		return "", errors.New("fixed managed RouterOS script is invalid")
	}
	comment := "SB-GATEWAY managed script " + name
	rows, err := client.list(ctx, "/rest/system/script?.proplist=.id,name,comment")
	if err != nil {
		return "", err
	}
	var id string
	for _, row := range rows {
		if text(row["name"]) != name {
			continue
		}
		if id != "" {
			return "", errors.New("fixed managed RouterOS script name is ambiguous")
		}
		if text(row["comment"]) != comment {
			return "", errors.New("refusing to replace an unowned fixed RouterOS script")
		}
		id = text(row[".id"])
	}
	payload := map[string]any{"name": name, "source": source, "comment": comment, "policy": "read,write,test,policy"}
	if id == "" {
		created, err := client.request(ctx, http.MethodPut, "/rest/system/script", payload)
		if err != nil {
			return "", err
		}
		id = text(created[".id"])
	} else if _, err := client.request(ctx, http.MethodPatch, "/rest/system/script/"+routerOSResourceID(id), payload); err != nil {
		return "", err
	}
	if id == "" {
		return "", errors.New("RouterOS did not return a fixed managed script identifier")
	}
	return id, nil
}

func (client *Client) installManagedScript(ctx context.Context, name, source string) (string, error) {
	if !managedNamePattern.MatchString(name) {
		return "", errors.New("managed RouterOS script name is invalid")
	}
	rows, err := client.list(ctx, "/rest/system/script?.proplist=.id,name,comment")
	if err != nil {
		return "", err
	}
	var id string
	for _, row := range rows {
		if text(row["name"]) != name {
			continue
		}
		if id != "" {
			return "", errors.New("managed RouterOS script name is ambiguous")
		}
		if text(row["comment"]) != "SB-GATEWAY managed script "+name {
			return "", errors.New("refusing to replace an unowned RouterOS script")
		}
		id = text(row[".id"])
	}
	payload := map[string]any{
		"name": name, "source": source, "comment": "SB-GATEWAY managed script " + name,
		"policy": "ftp,read,write,test,policy",
	}
	if id == "" {
		created, requestErr := client.request(ctx, http.MethodPut, "/rest/system/script", payload)
		if requestErr != nil {
			return "", requestErr
		}
		id = text(created[".id"])
	} else {
		if _, err := client.request(ctx, http.MethodPatch, "/rest/system/script/"+routerOSResourceID(id), payload); err != nil {
			return "", err
		}
	}
	if id == "" {
		return "", errors.New("RouterOS did not return a managed script identifier")
	}
	return id, nil
}

func (client *Client) list(ctx context.Context, path string) ([]map[string]any, error) {
	value, err := client.requestValue(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	rows, ok := value.([]any)
	if !ok {
		return nil, errors.New("RouterOS REST list response is not an array")
	}
	result := make([]map[string]any, 0, len(rows))
	for _, raw := range rows {
		row, ok := raw.(map[string]any)
		if !ok {
			return nil, errors.New("RouterOS REST list row is not an object")
		}
		result = append(result, row)
	}
	return result, nil
}

func (client *Client) request(ctx context.Context, method, path string, payload map[string]any) (map[string]any, error) {
	value, err := client.requestValue(ctx, method, path, payload)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return map[string]any{}, nil
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, errors.New("RouterOS REST response is not an object")
	}
	return object, nil
}

// requestAction accepts the response shapes RouterOS uses for successful
// command endpoints across releases: object, empty body, or an empty/one-row
// array. Callers still rely on the HTTP status and bounded JSON decoder.
func (client *Client) requestAction(ctx context.Context, method, path string, payload map[string]any) (map[string]any, error) {
	value, err := client.requestValueWithHTTP(ctx, client.actionHTTP, method, path, payload)
	if err != nil {
		return nil, err
	}
	if value == nil {
		return map[string]any{}, nil
	}
	if object, ok := value.(map[string]any); ok {
		return object, nil
	}
	rows, ok := value.([]any)
	if !ok || len(rows) > 1 {
		return nil, errors.New("RouterOS REST action response is invalid")
	}
	if len(rows) == 0 {
		return map[string]any{}, nil
	}
	object, ok := rows[0].(map[string]any)
	if !ok {
		return nil, errors.New("RouterOS REST action row is invalid")
	}
	return object, nil
}

func (client *Client) requestValue(ctx context.Context, method, path string, payload map[string]any) (any, error) {
	return client.requestValueWithHTTP(ctx, client.http, method, path, payload)
}

func (client *Client) requestValueWithHTTP(ctx context.Context, requester *http.Client, method, path string, payload map[string]any) (any, error) {
	if !strings.HasPrefix(path, "/rest/") || strings.ContainsAny(path, "\r\n") {
		return nil, errors.New("RouterOS REST path is invalid")
	}
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, client.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	request.SetBasicAuth(client.username, client.password)
	request.Header.Set("Accept", "application/json")
	if payload != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := requester.Do(request)
	if err != nil {
		return nil, fmt.Errorf("RouterOS REST request failed: %w", err)
	}
	defer response.Body.Close()
	limited := io.LimitReader(response.Body, maxResponseBytes+1)
	responseBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(responseBody) > maxResponseBytes {
		return nil, errors.New("RouterOS REST response exceeds 4 MiB")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, HTTPError{StatusCode: response.StatusCode}
	}
	if len(bytes.TrimSpace(responseBody)) == 0 {
		return nil, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(responseBody))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, errors.New("RouterOS REST returned invalid JSON")
	}
	return value, nil
}

func managedScriptName(role, source string) (string, error) {
	if !managedRolePattern.MatchString(role) {
		return "", errors.New("managed RouterOS script role is invalid")
	}
	digest := sha256.Sum256([]byte(source))
	return "SB-GATEWAY-" + role + "-" + hex.EncodeToString(digest[:])[:12], nil
}

func validateDirectDelta(source string) error {
	if len(source) == 0 || len(source) > maxDirectScriptBytes {
		return errors.New("direct RouterOS delta must contain 1 to 16384 bytes")
	}
	if !strings.HasPrefix(source, "# SB-GATEWAY generated minimal delta; complete managed sections\n") {
		return errors.New("direct RouterOS script is not a generated section delta")
	}
	for _, pattern := range prohibitedScriptPatterns {
		if pattern.MatchString(source) {
			return errors.New("direct RouterOS delta contains a prohibited command")
		}
	}
	return nil
}

func routerOSResourceID(value string) string {
	encoded := url.PathEscape(value)
	encoded = strings.ReplaceAll(encoded, "%2A", "*")
	return strings.ReplaceAll(encoded, "%2a", "*")
}

func text(value any) string {
	result, _ := value.(string)
	return result
}
