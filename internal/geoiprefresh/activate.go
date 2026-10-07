package geoiprefresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/geoipasset"
	"github.com/sb-gateway/sb-gateway/internal/runtimeproof"
)

const (
	maxXrayConfigBytes = 32 << 20
	maxGeoIPPackBytes  = 4 << 20
)

var managedRuleTag = regexp.MustCompile(`^sb-geoip-(geoip-[a-z]{2})-[0-9]+-[0-9]+$`)

var ErrDeferred = errors.New("Xray routing activation is waiting for Apply or startup")

type Options struct {
	XrayConfig         string
	RulesetDir         string
	ReadyFile          string
	ApplyGuard         string
	ApplyOperationFile string
	ValidatedFile      string
	ProcRoot           string
	APIServer          string
	XrayBinary         string
	Run                func(context.Context, string, ...string) ([]byte, error)
	CandidateDir       string
	LKGConfig          string
}

func OptionsFromEnvironment() Options {
	return Options{
		XrayConfig:         env("SB_XRAY_CONFIG", "/config/generated/xray.json"),
		RulesetDir:         env("SB_RULESET_DIR", "/config/rulesets"),
		ReadyFile:          env("SB_XRAY_READY_FILE", "/run/sb-gateway/xray-selectors-ready"),
		ApplyGuard:         env("SB_APPLY_GUARD", "/run/sb-gateway/apply-in-progress"),
		ApplyOperationFile: filepath.Join(env("SB_GATEWAY_STATE_DIR", "/state/control-plane"), "apply-operation.json"),
		ValidatedFile:      env("SB_XRAY_VALIDATED_FILE", "/run/sb-gateway/xray-validated"),
		ProcRoot:           "/proc",
		APIServer:          env("SB_XRAY_API_SERVER", "127.0.0.1:10085"),
		XrayBinary:         env("SB_XRAY_BINARY", "/usr/local/bin/xray"),
		CandidateDir:       env("SB_RUNTIME_CANDIDATE_DIR", "/state/runtime-candidates"),
		LKGConfig:          env("SB_XRAY_LKG_CONFIG", filepath.Join(env("SB_GATEWAY_DATA_DIR", "/data"), "last-known-good", "xray.json")),
	}
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

type State struct {
	mu                sync.Mutex
	baselineProof     string
	mayReuseStartup   bool
	generation        string
	mutationAttempted bool
	confirmed         string
	confirmedAssets   []byte
	lastCleanup       time.Time
}

// The appliance retains this state across monitor-only restarts. A newly
// attached monitor must not assume an older core still has baseline routing.
func NewState(options Options) *State {
	state := &State{}
	body, err := boundedRead(options.ValidatedFile, 256)
	if err == nil {
		state.baselineProof = string(body)
		state.mayReuseStartup = true
	} else if errors.Is(err, os.ErrNotExist) {
		state.mayReuseStartup = true
	}
	return state
}

// Activate replaces the complete Xray routing table atomically through its
// RoutingService. It never restarts Xray, edits the generated config, or admits
// client traffic during startup. The bundled Xray patch carries balancer
// overrides across this replacement; established flows retain their route.
func Activate(ctx context.Context, options Options, state *State) (bool, error) {
	if state == nil {
		return false, errors.New("GeoIP activation state is required")
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if activationGuarded(options) {
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
		state.confirmedAssets = nil
		return false, cleanup(options, state, oldRouting)
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
		reference, err := geoipasset.Publish(options.RulesetDir, id, packBody)
		if err != nil {
			return false, fmt.Errorf("validate %s: %w", id, err)
		}
		for _, rule := range packRules[id] {
			if _, exists := rule["ip"]; !exists {
				return false, errors.New("managed GeoIP rule has no IP condition")
			}
			rule["ip"] = []string{reference}
		}
	}
	want := hex.EncodeToString(signature.Sum(nil))
	coreSum := sha256.Sum256(body)
	coreHash := hex.EncodeToString(coreSum[:])
	validated := runtimeproof.XrayValidated(options.ValidatedFile, options.ReadyFile, options.XrayConfig, options.ProcRoot, coreHash)
	generation := pid
	if options.ProcRoot != "" {
		generation = runtimeproof.XrayGeneration(options.ReadyFile, options.XrayConfig, options.ProcRoot)
		if generation == "" {
			return false, ErrDeferred
		}
	}
	proof := ""
	if validated {
		proofBody, proofErr := boundedRead(options.ValidatedFile, 256)
		if proofErr != nil {
			return false, ErrDeferred
		}
		proof = string(proofBody)
	}
	if state.generation != generation {
		state.generation, state.confirmed, state.mutationAttempted = generation, "", false
		state.confirmedAssets = nil
	}
	if state.confirmed == want {
		return false, cleanup(options, state, state.confirmedAssets)
	}
	if activationGuarded(options) || !stillReady(options.ReadyFile, pid, options.XrayConfig, body) {
		return false, ErrDeferred
	}
	desired, err := json.Marshal(map[string]any{"routing": routing})
	if err != nil {
		return false, err
	}
	if validated && state.mayReuseStartup && proof != state.baselineProof &&
		!state.mutationAttempted && string(desired) == string(oldRouting) {
		state.confirmed = want
		state.confirmedAssets = routingAssets(rules)
		return false, cleanup(options, state, state.confirmedAssets)
	}
	// The generated config is a baseline, not a readback of Xray's live table.
	// A prior hot update may still be active after the pack returns to that
	// baseline, so equality here cannot prove that no reload is needed.
	run := options.Run
	if run == nil {
		run = func(ctx context.Context, binary string, args ...string) ([]byte, error) {
			return runXrayWithAssets(ctx, options.RulesetDir, binary, args...)
		}
	}
	if len(state.confirmedAssets) != 0 {
		oldRouting, err = rollbackRouting(oldRouting, state.confirmedAssets)
		if err != nil {
			return false, err
		}
	}
	state.confirmed = ""
	state.mutationAttempted = true
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
	state.confirmedAssets = routingAssets(rules)
	return true, cleanup(options, state, state.confirmedAssets)
}

// Keep only the small reference map across ticks, not another full routing table.
func routingAssets(rules []any) []byte {
	assets := make(map[string]string)
	for _, raw := range rules {
		rule := raw.(map[string]any)
		tag, _ := rule["ruleTag"].(string)
		if managedRuleTag.MatchString(tag) {
			assets[tag] = rule["ip"].([]string)[0]
		}
	}
	body, _ := json.Marshal(assets)
	return body
}

func rollbackRouting(baseline, assets []byte) ([]byte, error) {
	var previous map[string]string
	var config struct {
		Routing map[string]any `json:"routing"`
	}
	if err := json.Unmarshal(assets, &previous); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(baseline, &config); err != nil {
		return nil, err
	}
	for _, raw := range config.Routing["rules"].([]any) {
		rule := raw.(map[string]any)
		tag, _ := rule["ruleTag"].(string)
		if reference, ok := previous[tag]; ok {
			rule["ip"] = []string{reference}
		}
	}
	return json.Marshal(config)
}

func cleanup(options Options, state *State, live []byte) error {
	if options.CandidateDir == "" || activationGuarded(options) || time.Since(state.lastCleanup) < time.Minute {
		return nil
	}
	_, err := geoipasset.Prune(options.RulesetDir, []string{options.XrayConfig, options.LKGConfig}, []string{options.CandidateDir}, live, time.Now())
	if err != nil {
		return fmt.Errorf("cleanup obsolete GeoIP assets: %w", err)
	}
	state.lastCleanup = time.Now()
	return nil
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
	return runXrayWithAssets(ctx, env("SB_RULESET_DIR", "/config/rulesets"), binary, args...)
}

func runXrayWithAssets(ctx context.Context, root, binary string, args ...string) ([]byte, error) {
	call, cancel := context.WithTimeout(ctx, 330*time.Second)
	defer cancel()
	command := exec.CommandContext(call, binary, args...)
	command.Env = append(os.Environ(), "XRAY_LOCATION_ASSET="+root)
	output, err := command.CombinedOutput()
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

// The short runtime guard ends before traffic readiness is recovered; the
// durable journal keeps a heavy hot reload out of the remaining Apply phases.
func activationGuarded(options Options) bool {
	if guarded(options.ApplyGuard) {
		return true
	}
	if options.ApplyOperationFile == "" {
		return false
	}
	body, err := boundedRead(options.ApplyOperationFile, 64<<10)
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	var operation struct {
		Pending bool `json:"pending"`
	}
	return strings.TrimSpace(string(body)) == "null" || json.Unmarshal(body, &operation) != nil || operation.Pending
}
