package geoiprefresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxXrayConfigBytes = 32 << 20
	maxGeoIPPackBytes  = 4 << 20
)

var managedRuleTag = regexp.MustCompile(`^sb-geoip-(geoip-[a-z]{2})-[0-9]+-[0-9]+$`)

var ErrDeferred = errors.New("Xray routing activation is waiting for Apply or startup")

type Options struct {
	XrayConfig string
	RulesetDir string
	ReadyFile  string
	ApplyGuard string
	APIServer  string
	XrayBinary string
	Run        func(context.Context, string, ...string) ([]byte, error)
}

func OptionsFromEnvironment() Options {
	return Options{
		XrayConfig: env("SB_XRAY_CONFIG", "/config/generated/xray.json"),
		RulesetDir: env("SB_RULESET_DIR", "/config/rulesets"),
		ReadyFile:  env("SB_XRAY_READY_FILE", "/run/sb-gateway/xray-selectors-ready"),
		ApplyGuard: env("SB_APPLY_GUARD", "/run/sb-gateway/apply-in-progress"),
		APIServer:  env("SB_XRAY_API_SERVER", "127.0.0.1:10085"),
		XrayBinary: env("SB_XRAY_BINARY", "/usr/local/bin/xray"),
	}
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

type State struct {
	confirmed string
}

// Activate replaces the complete Xray routing table atomically through its
// RoutingService. It never restarts Xray, edits the generated config, or admits
// client traffic during startup. The bundled Xray patch carries balancer
// overrides across this replacement; established flows retain their route.
func Activate(ctx context.Context, options Options, state *State) (bool, error) {
	if state == nil {
		return false, errors.New("GeoIP activation state is required")
	}
	if guarded(options.ApplyGuard) {
		return false, ErrDeferred
	}
	pid, err := readyPID(options.ReadyFile)
	if err != nil {
		return false, ErrDeferred
	}
	body, err := boundedRead(options.XrayConfig, maxXrayConfigBytes)
	if err != nil {
		return false, err
	}
	var config map[string]any
	if err := json.Unmarshal(body, &config); err != nil {
		return false, fmt.Errorf("decode Xray routing source: %w", err)
	}
	routing, ok := config["routing"].(map[string]any)
	if !ok {
		return false, errors.New("Xray routing source is missing")
	}
	rules, ok := routing["rules"].([]any)
	if !ok || len(rules) == 0 {
		return false, errors.New("Xray routing rules are missing")
	}
	oldRouting, err := json.Marshal(map[string]any{"routing": routing})
	if err != nil {
		return false, err
	}
	packRules := make(map[string][]map[string]any)
	managed := 0
	for _, raw := range rules {
		rule, ok := raw.(map[string]any)
		if !ok {
			return false, errors.New("Xray routing rule is invalid")
		}
		tag, _ := rule["ruleTag"].(string)
		if !strings.HasPrefix(tag, "sb-geoip-") {
			continue
		}
		match := managedRuleTag.FindStringSubmatch(tag)
		if match == nil || rule["type"] != "field" {
			return false, errors.New("Xray managed GeoIP rule tag is invalid")
		}
		packRules[match[1]] = append(packRules[match[1]], rule)
		managed++
	}
	if managed == 0 {
		state.confirmed = ""
		return false, nil
	}
	packIDs := make([]string, 0, len(packRules))
	for id := range packRules {
		packIDs = append(packIDs, id)
	}
	sort.Strings(packIDs)
	signature := sha256.New()
	signature.Write([]byte(pid))
	signature.Write(body)
	for _, id := range packIDs {
		packBody, err := boundedRead(filepath.Join(options.RulesetDir, id+".json"), maxGeoIPPackBytes)
		if err != nil {
			return false, fmt.Errorf("read %s: %w", id, err)
		}
		signature.Write(packBody)
		cidrs, err := parseGeoIPPack(packBody)
		if err != nil {
			return false, fmt.Errorf("validate %s: %w", id, err)
		}
		for _, rule := range packRules[id] {
			if _, exists := rule["ip"]; !exists {
				return false, errors.New("managed GeoIP rule has no IP condition")
			}
			rule["ip"] = cidrs
		}
	}
	want := hex.EncodeToString(signature.Sum(nil))
	if state.confirmed == want {
		return false, nil
	}
	if guarded(options.ApplyGuard) || !stillReady(options.ReadyFile, pid, options.XrayConfig, body) {
		return false, ErrDeferred
	}
	desired, err := json.Marshal(map[string]any{"routing": routing})
	if err != nil {
		return false, err
	}
	// The generated config is a baseline, not a readback of Xray's live table.
	// A prior hot update may still be active after the pack returns to that
	// baseline, so equality here cannot prove that no reload is needed.
	run := options.Run
	if run == nil {
		run = runXray
	}
	if err := applyRouting(ctx, options, run, desired); err != nil {
		if stillReady(options.ReadyFile, pid, options.XrayConfig, body) {
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 330*time.Second)
			defer cancel()
			if rollbackErr := applyRouting(rollbackCtx, options, run, oldRouting); rollbackErr != nil {
				return false, fmt.Errorf("activate GeoIP routing: %w; rollback unconfirmed: %v", err, rollbackErr)
			}
		}
		return false, fmt.Errorf("activate GeoIP routing: %w", err)
	}
	if !stillReady(options.ReadyFile, pid, options.XrayConfig, body) {
		return false, ErrDeferred // A new Xray process owns its own startup routing.
	}
	listed, err := run(ctx, options.XrayBinary, "api", "lsrules", "-s="+options.APIServer, "-t=20")
	if err == nil {
		err = confirmRules(listed, rules)
	}
	if err != nil {
		if stillReady(options.ReadyFile, pid, options.XrayConfig, body) {
			rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 330*time.Second)
			defer cancel()
			if rollbackErr := applyRouting(rollbackCtx, options, run, oldRouting); rollbackErr != nil {
				return false, fmt.Errorf("confirm GeoIP routing: %w; rollback unconfirmed: %v", err, rollbackErr)
			}
		}
		return false, fmt.Errorf("confirm GeoIP routing: %w", err)
	}
	state.confirmed = want
	return true, nil
}

func parseGeoIPPack(body []byte) ([]string, error) {
	var document struct {
		Rules []struct {
			IP []string `json:"ip_cidr"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &document); err != nil || len(document.Rules) != 1 || len(document.Rules[0].IP) == 0 || len(document.Rules[0].IP) > 250_000 {
		return nil, errors.New("GeoIP CIDR document is invalid")
	}
	for _, value := range document.Rules[0].IP {
		prefix, err := netip.ParsePrefix(value)
		if err != nil || prefix.Masked().String() != value {
			return nil, errors.New("GeoIP CIDR is invalid")
		}
	}
	return document.Rules[0].IP, nil
}

func confirmRules(body []byte, expected []any) error {
	var response struct {
		Rules []struct {
			RuleTag string `json:"ruleTag"`
		} `json:"rules"`
	}
	if err := json.Unmarshal(body, &response); err != nil || len(response.Rules) != len(expected) {
		return errors.New("Xray rule count readback differs")
	}
	for index, raw := range expected {
		rule := raw.(map[string]any)
		if response.Rules[index].RuleTag != rule["ruleTag"] && !(response.Rules[index].RuleTag == "" && rule["ruleTag"] == nil) {
			return errors.New("Xray rule order readback differs")
		}
	}
	return nil
}

func applyRouting(ctx context.Context, options Options, run func(context.Context, string, ...string) ([]byte, error), body []byte) error {
	file, err := os.CreateTemp("", "sb-geoip-routing-*.json")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(body); err != nil {
		file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	_, err = run(ctx, options.XrayBinary, "api", "adrules", "-s="+options.APIServer, "-t=300", file.Name())
	return err
}

func runXray(ctx context.Context, binary string, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 330*time.Second)
	defer cancel()
	output, err := exec.CommandContext(call, binary, args...).CombinedOutput()
	if len(output) > 1<<20 {
		return nil, errors.New("Xray API response exceeds the limit")
	}
	if err != nil {
		return nil, fmt.Errorf("Xray API request failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func boundedRead(path string, maximum int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, errors.New("GeoIP activation input is not a bounded regular file")
	}
	body, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return nil, errors.New("GeoIP activation input exceeds the limit")
	}
	return body, nil
}

func readyPID(path string) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(body))
	pid, err := strconv.Atoi(value)
	if err != nil || pid < 1 {
		return "", errors.New("Xray readiness PID is invalid")
	}
	return value, nil
}

func stillReady(readyFile, pid, configPath string, original []byte) bool {
	current, err := readyPID(readyFile)
	if err != nil || current != pid {
		return false
	}
	body, err := boundedRead(configPath, maxXrayConfigBytes)
	return err == nil && string(body) == string(original)
}

func guarded(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil || !errors.Is(err, os.ErrNotExist)
}
