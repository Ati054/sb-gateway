package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/policydns"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type RuntimeController interface {
	Restart(context.Context, []string) error
	Probe(context.Context, []string) error
}

type runtimeApplier interface {
	prepare(map[string]any, []map[string]any) (runtimeconfig.RuntimeCandidate, error)
	activate(context.Context, runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, error)
	activateSubscription(context.Context, runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, error)
	rollback(context.Context, runtimeconfig.ActivationReceipt) error
	rollbackSubscription(context.Context, runtimeconfig.ActivationReceipt) error
	commit(runtimeconfig.RuntimeCandidate) error
}

type RuntimeOptions struct {
	CandidateDir            string
	RuleSetDir              string
	NginxTemplate           string
	XrayConfig              string
	XrayErrorLog            string
	XrayProcessLog          string
	ControlPlaneLog         string
	NginxErrorLog           string
	XrayHealthPool          string
	PolicyDNSConfig         string
	NginxConfig             string
	OriginCIDRRoot          string
	WatchdogEnvironment     string
	ClientTelemetryNFT      string
	TransparentExclusions   string
	SubscriptionRelaySource string
	BootstrapTLSCertificate string
	BootstrapTLSPrivateKey  string
	ApplyGuardFile          string
	XrayPrevalidatedMarker  string
	XrayReadyFile           string
	XrayHotRuntimeReadyFile string
	XrayAPIServer           string
	XrayBinary              string
	NginxBinary             string
	NFTBinary               string
	PolicyDNS               policydns.Options
}

func RuntimeOptionsFromEnvironment() RuntimeOptions {
	return RuntimeOptions{
		CandidateDir:            envOr("SB_RUNTIME_CANDIDATE_DIR", "/state/runtime-candidates"),
		RuleSetDir:              envOr("SB_RULESET_DIR", "/config/rulesets"),
		NginxTemplate:           envOr("SB_NGINX_TEMPLATE", "/opt/sb-gateway/templates/nginx.conf.j2"),
		XrayConfig:              envOr("SB_XRAY_CONFIG", "/config/generated/xray.json"),
		XrayErrorLog:            envOr("SB_XRAY_ERROR_LOG", "/logs/xray-error.log"),
		XrayProcessLog:          envOr("SB_XRAY_PROCESS_LOG", "/logs/xray-process.log"),
		ControlPlaneLog:         envOr("SB_GATEWAY_CONTROL_PLANE_LOG", "/logs/control-plane.log"),
		NginxErrorLog:           envOr("SB_NGINX_ERROR_LOG", "/logs/nginx/error.log"),
		XrayHealthPool:          envOr("SB_XRAY_URLTEST_POOL", "/config/generated/urltest-pool.json"),
		PolicyDNSConfig:         envOr("SB_POLICY_DNS_CONFIG", "/config/generated/policy-dns.json"),
		NginxConfig:             envOr("SB_NGINX_RUNTIME_CONFIG", "/run/sb-gateway/nginx.conf"),
		OriginCIDRRoot:          envOr("SB_ORIGIN_CIDR_ROOT", "/state/control-plane/cdn-origin"),
		WatchdogEnvironment:     envOr("SB_WATCHDOG_ENV", "/config/generated/watchdog.env"),
		ClientTelemetryNFT:      envOr("SB_CLIENT_TELEMETRY_NFT", "/config/generated/client-telemetry.nft"),
		TransparentExclusions:   envOr("SB_TRANSPARENT_EXCLUSIONS", "/config/generated/transparent-exclusions.txt"),
		SubscriptionRelaySource: strings.TrimSpace(os.Getenv("SB_GATEWAY_SUBSCRIPTION_RELAY_SOURCE")),
		BootstrapTLSCertificate: envOr("SB_BOOTSTRAP_TLS_CERT", "/config/certs/bootstrap.pem"),
		BootstrapTLSPrivateKey:  envOr("SB_BOOTSTRAP_TLS_KEY", "/config/certs/bootstrap.key"),
		ApplyGuardFile:          envOr("SB_APPLY_GUARD", "/run/sb-gateway/apply-in-progress"),
		XrayPrevalidatedMarker:  envOr("SB_XRAY_PREVALIDATED_MARKER", "/run/sb-gateway/xray-prevalidated.sha256"),
		XrayReadyFile:           envOr("SB_XRAY_READY_FILE", "/run/sb-gateway/xray-selectors-ready"),
		XrayHotRuntimeReadyFile: envOr("SB_XRAY_HOT_RUNTIME_READY_FILE", "/run/sb-gateway/xray-hot-runtime-ready.json"),
		XrayAPIServer:           envOr("SB_XRAY_API_SERVER", "127.0.0.1:10085"),
		XrayBinary:              envOr("SB_XRAY_BINARY", "/usr/local/bin/xray"),
		NginxBinary:             envOr("SB_NGINX_BINARY", "/usr/sbin/nginx"),
		NFTBinary:               envOr("SB_NFT_BINARY", "/usr/sbin/nft"),
		PolicyDNS:               policydns.OptionsFromEnvironment(),
	}
}

type nativeRuntime struct {
	options                    RuntimeOptions
	store                      *runtimeconfig.CandidateStore
	secrets                    *secretStore
	controller                 RuntimeController
	validate                   func(context.Context, runtimeconfig.RuntimeCandidate, []string) error
	nginxCommand               func(context.Context, ...string) error
	subscriptionRestartPending atomic.Bool
}

func newNativeRuntime(options RuntimeOptions, secrets *secretStore, controller RuntimeController) (*nativeRuntime, error) {
	if controller == nil {
		return nil, errors.New("native runtime requires secret store and process controller")
	}
	runtime, err := newNativeRuntimeStore(options, secrets)
	if err != nil {
		return nil, err
	}
	runtime.controller = controller
	return runtime, nil
}

func newNativeRuntimeStore(options RuntimeOptions, secrets *secretStore) (*nativeRuntime, error) {
	if secrets == nil {
		return nil, errors.New("native runtime requires secret store")
	}
	if options.OriginCIDRRoot == "" {
		options.OriginCIDRRoot = filepath.Join(options.CandidateDir, "origin-cidrs")
	}
	if err := initializeOriginCIDRs(options.OriginCIDRRoot); err != nil {
		return nil, err
	}
	destinations := map[string]string{
		"xray.json": options.XrayConfig, "policy-dns.json": options.PolicyDNSConfig,
		"urltest-pool.json": options.XrayHealthPool,
		"nginx.conf":        options.NginxConfig, "watchdog.env": options.WatchdogEnvironment,
		"client-telemetry.nft":       options.ClientTelemetryNFT,
		"transparent-exclusions.txt": options.TransparentExclusions,
	}
	store, err := runtimeconfig.NewCandidateStore(options.CandidateDir, destinations)
	if err != nil {
		return nil, err
	}
	runtime := &nativeRuntime{options: options, store: store, secrets: secrets}
	runtime.validate = runtime.validateCandidate
	return runtime, nil
}

func (runtime *nativeRuntime) prepare(config map[string]any, nodes []map[string]any) (runtimeconfig.RuntimeCandidate, error) {
	template, err := os.ReadFile(runtime.options.NginxTemplate)
	if err != nil {
		return runtimeconfig.RuntimeCandidate{}, fmt.Errorf("read nginx template: %w", err)
	}
	artifacts, err := runtimeconfig.BuildNativeRuntimeArtifacts(
		config, nodes,
		func(reference string) (string, error) { return runtime.secrets.read(reference, true) },
		func(reference string) (string, error) { return runtime.secrets.path(reference) },
		runtimeconfig.NativeArtifactOptions{
			RuleSetRoot: runtime.options.RuleSetDir,
			Nginx:       runtime.nginxRenderOptions(string(template)),
		},
	)
	if err != nil {
		return runtimeconfig.RuntimeCandidate{}, err
	}
	revision := artifactRevision(artifacts)
	return runtime.store.Prepare(revision, artifacts)
}

func (runtime *nativeRuntime) nginxRenderOptions(template string) runtimeconfig.NginxRenderOptions {
	return runtimeconfig.NginxRenderOptions{
		Template:                template,
		SubscriptionRelaySource: runtime.options.SubscriptionRelaySource,
		OriginCIDRRoot:          runtime.options.OriginCIDRRoot,
		BootstrapTLSCertificate: runtime.options.BootstrapTLSCertificate,
		BootstrapTLSPrivateKey:  runtime.options.BootstrapTLSPrivateKey,
	}
}

func (runtime *nativeRuntime) activate(ctx context.Context, candidate runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, error) {
	return runtime.activateWithXrayRestartHook(ctx, candidate, nil)
}

func (runtime *nativeRuntime) activateWithXrayRestartHook(ctx context.Context, candidate runtimeconfig.RuntimeCandidate, beforeXrayRestart func(context.Context) error) (runtimeconfig.ActivationReceipt, error) {
	return runtime.activateWithHooks(ctx, candidate, beforeXrayRestart, nil)
}

const hotPolicyActivationTimeout = 90 * time.Second

// Include the runner's 180-second routing compilation window and setup time.
const xrayRuntimeReadinessTimeout = 210 * time.Second

func runtimeReadinessTimeout(programs []string) time.Duration {
	for _, program := range programs {
		if program == "xray" {
			return xrayRuntimeReadinessTimeout
		}
	}
	return 30 * time.Second
}

func hotPolicyChange(changed []string) bool {
	return len(changed) == 1 && changed[0] == "urltest-pool.json"
}

func (runtime *nativeRuntime) activateWithHooks(ctx context.Context, candidate runtimeconfig.RuntimeCandidate, beforeXrayRestart, beforeHotPolicy func(context.Context) error) (runtimeconfig.ActivationReceipt, error) {
	var policyScope hotRuntimeScope
	releaseGuard := func() {}
	defer func() { releaseGuard() }()
	receipt, err := runtime.store.ActivateAfter(candidate, func(changed []string) error {
		if err := runtime.validate(ctx, candidate, changed); err != nil {
			return err
		}
		// This proof is made under the store's publication lock. Only policy
		// eligibility changed: Xray, listeners, DNS and routing stay untouched.
		if hotPolicyChange(changed) {
			var scopeErr error
			policyScope, scopeErr = hotPolicyScope(runtime.options.XrayHealthPool, candidate.Files["urltest-pool.json"])
			if scopeErr != nil {
				return scopeErr
			}
			if beforeHotPolicy != nil {
				return beforeHotPolicy(ctx)
			}
			return nil
		}
		if len(runtime.restartOrder(changed)) > 0 {
			var guardErr error
			// Protect publication itself: watchdog must not validate a new
			// config against the previous core before Restart is called.
			releaseGuard, guardErr = runtime.beginApplyGuard()
			if guardErr != nil {
				releaseGuard = func() {}
				return fmt.Errorf("create watchdog apply guard: %w", guardErr)
			}
		}
		return nil
	})
	if err != nil {
		return runtimeconfig.ActivationReceipt{}, err
	}
	if hotPolicyChange(receipt.Changed()) {
		readyContext, cancelReady := context.WithTimeout(ctx, hotPolicyActivationTimeout)
		defer cancelReady()
		if err := runtime.waitHotRuntime(readyContext, runtime.options.XrayHealthPool, policyScope); err != nil {
			return receipt, fmt.Errorf("activate policy selector generation without restart: %w", err)
		}
		return receipt, nil
	}
	programs := runtime.restartOrder(receipt.Changed())
	if len(programs) == 0 {
		return receipt, nil
	}
	if containsRuntimeArtifact(receipt.Changed(), "xray.json") {
		if err := runtime.markXrayPrevalidated(candidate.Files["xray.json"]); err != nil {
			log.Printf("runtime Xray prevalidation marker: %v", err)
		}
	}
	if containsRuntimeArtifact(receipt.Changed(), "xray.json") && beforeXrayRestart != nil {
		if err := beforeXrayRestart(ctx); err != nil {
			return receipt, fmt.Errorf("prepare planned Xray restart on RouterOS: %w", err)
		}
	}
	if err := runtime.controller.Restart(ctx, programs); err != nil {
		return receipt, fmt.Errorf("restart runtime: %w", err)
	}
	probeContext, cancelProbe := context.WithTimeout(ctx, runtimeReadinessTimeout(programs))
	defer cancelProbe()
	if err := runtime.controller.Probe(probeContext, programs); err != nil {
		return receipt, fmt.Errorf("probe runtime: %w", err)
	}
	return receipt, nil
}

// Endpoint-only updates remain hot. Changed probe listeners require a guarded
// core restart before the new health pool can use them.
func (runtime *nativeRuntime) activateSubscription(ctx context.Context, candidate runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, error) {
	return runtime.activateSubscriptionWithXrayRestartHook(ctx, candidate, nil)
}

func (runtime *nativeRuntime) activateSubscriptionWithXrayRestartHook(ctx context.Context, candidate runtimeconfig.RuntimeCandidate, beforeXrayRestart func(context.Context) error) (runtimeconfig.ActivationReceipt, error) {
	var policyScope hotRuntimeScope
	restartCore := runtime.subscriptionRestartPending.Load()
	releaseGuard := func() {}
	defer func() { releaseGuard() }()
	armRestart := func() error {
		var err error
		releaseGuard, err = runtime.beginApplyGuard()
		if err != nil {
			releaseGuard = func() {}
			return err
		}
		runtime.subscriptionRestartPending.Store(true)
		return nil
	}
	if restartCore {
		if err := armRestart(); err != nil {
			return runtimeconfig.ActivationReceipt{}, err
		}
	}
	receipt, err := runtime.store.ActivateAfter(candidate, func(changed []string) error {
		if err := runtime.validate(ctx, candidate, changed); err != nil {
			return err
		}
		if !restartCore && containsRuntimeArtifact(changed, "xray.json") {
			var err error
			restartCore, err = subscriptionProbeGeometryChanged(runtime.options.XrayConfig, candidate.Files["xray.json"])
			if err != nil {
				return err
			}
			if restartCore {
				if err := armRestart(); err != nil {
					return err
				}
			}
		}
		if containsRuntimeArtifact(changed, "urltest-pool.json") {
			var err error
			policyScope, err = hotPolicyScope(runtime.options.XrayHealthPool, candidate.Files["urltest-pool.json"])
			return err
		}
		return nil
	})
	if err != nil {
		return runtimeconfig.ActivationReceipt{}, err
	}
	changed := receipt.Changed()
	if restartCore {
		return receipt, runtime.restartSubscriptionCore(ctx, changed, beforeXrayRestart)
	}
	if !containsRuntimeArtifact(changed, "xray.json") && !containsRuntimeArtifact(changed, "urltest-pool.json") {
		return receipt, runtime.restartChangedWithoutXray(ctx, changed)
	}
	if !containsRuntimeArtifact(changed, "urltest-pool.json") {
		return receipt, errors.New("subscription Xray change has no matching health-pool generation")
	}
	if err := runtime.restartChangedWithoutXray(ctx, changed); err != nil {
		return receipt, err
	}
	if err := runtime.waitHotRuntime(ctx, runtime.options.XrayHealthPool, policyScope); err != nil {
		return receipt, fmt.Errorf("activate Xray subscription generation without restart: %w", err)
	}
	return receipt, nil
}

func (runtime *nativeRuntime) restartChangedWithoutXray(ctx context.Context, changed []string) error {
	programs := runtime.restartOrder(changed)
	filtered := programs[:0]
	for _, program := range programs {
		if program != "xray" {
			filtered = append(filtered, program)
		}
	}
	if len(filtered) == 0 {
		return nil
	}
	releaseGuard, err := runtime.beginApplyGuard()
	if err != nil {
		return err
	}
	defer releaseGuard()
	if err := runtime.controller.Restart(ctx, filtered); err != nil {
		return err
	}
	probeContext, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return runtime.controller.Probe(probeContext, filtered)
}

func (runtime *nativeRuntime) rollbackSubscription(ctx context.Context, receipt runtimeconfig.ActivationReceipt) error {
	return runtime.rollbackSubscriptionWithXrayRestartHook(ctx, receipt, nil)
}

func (runtime *nativeRuntime) rollbackSubscriptionWithXrayRestartHook(ctx context.Context, receipt runtimeconfig.ActivationReceipt, beforeXrayRestart func(context.Context) error) error {
	var policyScope hotRuntimeScope
	restartCore := runtime.subscriptionRestartPending.Load()
	releaseGuard := func() {}
	defer func() { releaseGuard() }()
	armRestart := func() error {
		var err error
		releaseGuard, err = runtime.beginApplyGuard()
		if err != nil {
			releaseGuard = func() {}
			return err
		}
		runtime.subscriptionRestartPending.Store(true)
		return nil
	}
	if restartCore {
		if err := armRestart(); err != nil {
			return err
		}
	}
	var err error
	if len(receipt.Changed()) > 0 {
		err = runtime.store.RollbackAfter(receipt, func(restoring map[string]string) error {
			if path, changed := restoring["xray.json"]; changed && !restartCore {
				var err error
				restartCore, err = subscriptionProbeGeometryChanged(runtime.options.XrayConfig, path)
				if err != nil {
					return err
				}
				if restartCore {
					if err := armRestart(); err != nil {
						return err
					}
				}
			}
			if path := restoring["urltest-pool.json"]; path != "" {
				var err error
				policyScope, err = hotPolicyScope(runtime.options.XrayHealthPool, path)
				return err
			}
			return nil
		})
	}
	if err != nil {
		return err
	}
	if restartCore {
		return runtime.restartSubscriptionCore(ctx, receipt.Changed(), beforeXrayRestart)
	}
	if err := runtime.restartChangedWithoutXray(ctx, receipt.Changed()); err != nil {
		return err
	}
	if containsRuntimeArtifact(receipt.Changed(), "urltest-pool.json") {
		return runtime.waitHotRuntime(ctx, runtime.options.XrayHealthPool, policyScope)
	}
	return nil
}

// Keep the restart obligation across failed activation or rollback, including
// retries whose files already match. A fresh appliance starts from disk.
func (runtime *nativeRuntime) restartSubscriptionCore(ctx context.Context, changed []string, beforeXrayRestart func(context.Context) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	programs := runtime.restartOrder(changed)
	if !containsRuntimeArtifact(programs, "xray") {
		programs = append([]string{"xray"}, programs...)
	}
	if err := runtime.markXrayPrevalidated(runtime.options.XrayConfig); err != nil {
		log.Printf("runtime subscription Xray prevalidation marker: %v", err)
	}
	if beforeXrayRestart != nil {
		if err := beforeXrayRestart(ctx); err != nil {
			return fmt.Errorf("prepare subscription Xray restart on RouterOS: %w", err)
		}
	}
	if err := runtime.controller.Restart(ctx, programs); err != nil {
		return fmt.Errorf("restart subscription runtime: %w", err)
	}
	probeContext, cancel := context.WithTimeout(ctx, runtimeReadinessTimeout(programs))
	defer cancel()
	if err := runtime.controller.Probe(probeContext, programs); err != nil {
		return fmt.Errorf("probe subscription runtime: %w", err)
	}
	runtime.subscriptionRestartPending.Store(false)
	return nil
}

func subscriptionProbeGeometryChanged(previous, target string) (bool, error) {
	read := func(path string) (map[string]any, error) {
		body, err := readRuntimeMigrationArtifact(path)
		if err != nil || len(body) == 0 {
			return nil, err
		}
		var config map[string]any
		if err := json.Unmarshal(body, &config); err != nil {
			return nil, fmt.Errorf("decode subscription probe geometry: %w", err)
		}
		managed := func(tag string) bool {
			return tag == "outbound-health-probe" || strings.HasPrefix(tag, "outbound-health-background")
		}
		inbounds, balancers := map[string]any{}, map[string]any{}
		for _, inbound := range objects(config["inbounds"]) {
			if tag := text(inbound["tag"]); managed(tag) {
				if _, duplicate := inbounds[tag]; duplicate {
					return nil, errors.New("duplicate subscription probe inbound")
				}
				inbounds[tag] = inbound
			}
		}
		routing := objectAt(config, "routing")
		for _, balancer := range objects(routing["balancers"]) {
			if tag := text(balancer["tag"]); managed(tag) {
				balancers[tag] = balancer
			}
		}
		rules := []any{}
		for _, rule := range objects(routing["rules"]) {
			tags := []any{}
			for _, raw := range collectionArray(rule["inboundTag"]) {
				if tag := text(raw); managed(tag) {
					tags = append(tags, tag)
				}
			}
			if len(tags) > 0 {
				rule["inboundTag"] = tags
				rules = append(rules, rule)
			}
		}
		return map[string]any{"inbounds": inbounds, "balancers": balancers, "rules": rules}, nil
	}
	before, err := read(previous)
	if err != nil {
		return false, err
	}
	after, err := read(target)
	return !reflect.DeepEqual(before, after), err
}

func (runtime *nativeRuntime) restoreHotPolicyScope(receipt runtimeconfig.ActivationReceipt) (hotRuntimeScope, error) {
	var policyScope hotRuntimeScope
	err := runtime.store.RollbackAfter(receipt, func(restoring map[string]string) error {
		if path := restoring["urltest-pool.json"]; path != "" {
			var err error
			policyScope, err = hotPolicyScope(runtime.options.XrayHealthPool, path)
			return err
		}
		return nil
	})
	return policyScope, err
}

func (runtime *nativeRuntime) waitHotRuntime(ctx context.Context, poolPath string, policyScope hotRuntimeScope) error {
	expected, expectedMTime, err := hashFileGeneration(poolPath)
	if err != nil {
		return err
	}
	if policyScope.PoolSHA256 != "" && policyScope.PoolSHA256 != expected {
		return errors.New("published hot pool no longer matches its activation scope")
	}
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		body, readErr := os.ReadFile(runtime.options.XrayHotRuntimeReadyFile)
		if readErr == nil {
			var marker struct {
				PoolSHA256        string            `json:"pool_sha256"`
				PoolMTimeUnixNano int64             `json:"pool_mtime_unix_nano"`
				XrayPID           int               `json:"xray_pid"`
				PolicySelections  map[string]string `json:"policy_selections"`
			}
			if json.Unmarshal(body, &marker) == nil && marker.PoolSHA256 == expected &&
				marker.PoolMTimeUnixNano == expectedMTime && marker.XrayPID > 0 &&
				hotPolicyScopeReady(policyScope.RequiredPolicies, marker.PolicySelections) {
				ready, readyErr := os.ReadFile(runtime.options.XrayReadyFile)
				if readyErr == nil && strings.TrimSpace(string(ready)) == strconv.Itoa(marker.XrayPID) {
					current, statErr := os.Stat(poolPath)
					if statErr != nil || current.ModTime().UnixNano() != expectedMTime {
						return errors.New("hot pool generation changed while awaiting selectors")
					}
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func hashFileGeneration(path string) (string, int64, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	info, statErr := file.Stat()
	digest := sha256.New()
	_, copyErr := io.Copy(digest, io.LimitReader(file, (32<<20)+1))
	closeErr := file.Close()
	if statErr != nil || copyErr != nil || closeErr != nil {
		return "", 0, errors.Join(statErr, copyErr, closeErr)
	}
	return hex.EncodeToString(digest.Sum(nil)), info.ModTime().UnixNano(), nil
}

func (runtime *nativeRuntime) rollback(ctx context.Context, receipt runtimeconfig.ActivationReceipt) error {
	var policyScope hotRuntimeScope
	var err error
	if !hotPolicyChange(receipt.Changed()) && len(runtime.restartOrder(receipt.Changed())) > 0 {
		releaseGuard, guardErr := runtime.beginApplyGuard()
		if guardErr != nil {
			return fmt.Errorf("create watchdog rollback guard: %w", guardErr)
		}
		defer releaseGuard()
	}
	if hotPolicyChange(receipt.Changed()) {
		policyScope, err = runtime.restoreHotPolicyScope(receipt)
	} else {
		err = runtime.store.Rollback(receipt)
	}
	if err != nil {
		return err
	}
	if hotPolicyChange(receipt.Changed()) {
		return runtime.waitHotRuntime(ctx, runtime.options.XrayHealthPool, policyScope)
	}
	programs := runtime.restartOrder(receipt.Changed())
	if len(programs) == 0 {
		return nil
	}
	if containsRuntimeArtifact(receipt.Changed(), "xray.json") {
		if err := runtime.markXrayPrevalidated(runtime.options.XrayConfig); err != nil {
			log.Printf("runtime rollback Xray prevalidation marker: %v", err)
		}
	}
	if err := runtime.controller.Restart(ctx, programs); err != nil {
		return err
	}
	probeContext, cancelProbe := context.WithTimeout(ctx, runtimeReadinessTimeout(programs))
	defer cancelProbe()
	return runtime.controller.Probe(probeContext, programs)
}

func (runtime *nativeRuntime) beginApplyGuard() (func(), error) {
	path := strings.TrimSpace(runtime.options.ApplyGuardFile)
	if path == "" {
		return func() {}, nil
	}
	started := time.Now().Unix()
	write := func(refreshed int64) error {
		body := []byte(fmt.Sprintf("%d %d %d\n", os.Getpid(), started, refreshed))
		return writeAtomic(path, body, 0o644, false)
	}
	if err := write(started); err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-ticker.C:
				if err := write(now.Unix()); err != nil {
					log.Printf("runtime apply guard heartbeat: %v", err)
				}
			}
		}
	}()
	return func() {
		close(stop)
		<-done
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("runtime apply guard cleanup: %v", err)
		}
	}, nil
}

func (runtime *nativeRuntime) markXrayPrevalidated(config string) error {
	marker := strings.TrimSpace(runtime.options.XrayPrevalidatedMarker)
	if marker == "" || strings.TrimSpace(config) == "" {
		return nil
	}
	file, err := os.Open(config)
	if err != nil {
		return err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, io.LimitReader(file, 32<<20+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil {
		return errors.Join(copyErr, closeErr)
	}
	body := []byte(hex.EncodeToString(digest.Sum(nil)) + "\n")
	return writeAtomic(marker, body, 0o600, false)
}

func containsRuntimeArtifact(names []string, expected string) bool {
	for _, name := range names {
		if name == expected {
			return true
		}
	}
	return false
}

func (runtime *nativeRuntime) commit(candidate runtimeconfig.RuntimeCandidate) error {
	return runtime.store.CommitLastKnownGood(candidate)
}

func (runtime *nativeRuntime) restartOrder(changed []string) []string {
	programs := affectedPrograms(changed)
	nginx, err := os.ReadFile(runtime.options.NginxConfig)
	if err != nil || !bytes.Contains(nginx, []byte("ssl_preread on;")) {
		return programs
	}
	// Release the former direct Reality socket before Nginx binds shared 443.
	for index, name := range programs {
		if name == "xray" {
			programs = append([]string{"xray"}, append(programs[:index], programs[index+1:]...)...)
			break
		}
	}
	return programs
}

func (runtime *nativeRuntime) validateCandidate(ctx context.Context, candidate runtimeconfig.RuntimeCandidate, changed []string) error {
	for _, name := range changed {
		var err error
		switch name {
		case "xray.json":
			err = runValidationCommandWithEnv(ctx, []string{"XRAY_LOCATION_ASSET=" + runtime.options.RuleSetDir}, runtime.options.XrayBinary, "run", "-test", "-config", candidate.Files[name])
		case "nginx.conf":
			err = runValidationCommand(ctx, runtime.options.NginxBinary, "-t", "-c", candidate.Files[name], "-p", "/")
		case "policy-dns.json":
			err = policydns.ValidateFile(candidate.Files[name], runtime.options.PolicyDNS)
		case "client-telemetry.nft":
			info, statErr := os.Stat(candidate.Files[name])
			if statErr != nil {
				err = statErr
			} else if info.Size() > 0 {
				err = runValidationCommand(ctx, runtime.options.NFTBinary, "--check", "--file", candidate.Files[name])
			}
		}
		if err != nil {
			return fmt.Errorf("validate runtime artifact %s: %w", name, err)
		}
	}
	return nil
}

func runValidationCommand(ctx context.Context, executable string, arguments ...string) error {
	return runValidationCommandWithEnv(ctx, nil, executable, arguments...)
}

func runValidationCommandWithEnv(ctx context.Context, environment []string, executable string, arguments ...string) error {
	command := exec.CommandContext(ctx, executable, arguments...)
	command.Env = append(os.Environ(), environment...)
	output := &limitedWriter{remaining: 64 << 10}
	command.Stdout = output
	command.Stderr = output
	if err := command.Run(); err != nil {
		detail := strings.TrimSpace(output.String())
		if detail != "" {
			return fmt.Errorf("%w: %s", err, detail)
		}
		return err
	}
	return nil
}

type limitedWriter struct {
	buffer    bytes.Buffer
	remaining int
}

func (writer *limitedWriter) Write(body []byte) (int, error) {
	length := len(body)
	if writer.remaining > 0 {
		portion := body
		if len(portion) > writer.remaining {
			portion = portion[:writer.remaining]
		}
		_, _ = writer.buffer.Write(portion)
		writer.remaining -= len(portion)
	}
	return length, nil
}

func (writer *limitedWriter) String() string { return writer.buffer.String() }

func artifactRevision(artifacts map[string][]byte) string {
	names := make([]string, 0, len(artifacts))
	for name := range artifacts {
		names = append(names, name)
	}
	sort.Strings(names)
	digest := sha256.New()
	for _, name := range names {
		_, _ = io.WriteString(digest, name)
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(artifacts[name])
		_, _ = digest.Write([]byte{0})
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func affectedPrograms(changed []string) []string {
	set := make(map[string]struct{}, 4)
	for _, name := range changed {
		switch name {
		case "xray.json", "client-telemetry.nft", "transparent-exclusions.txt":
			set["xray"] = struct{}{}
		case "policy-dns.json":
			set["dns"] = struct{}{}
		case "nginx.conf":
			set["nginx"] = struct{}{}
		case "watchdog.env":
			set["monitor"] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for name := range set {
		result = append(result, name)
	}
	sort.Strings(result)
	return result
}
