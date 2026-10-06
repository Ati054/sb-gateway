package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type subscriptionGeometryController struct {
	t                    *testing.T
	guard                string
	restarts, probes     int
	restartErr, probeErr error
	observe              func()
}

func (controller *subscriptionGeometryController) Restart(_ context.Context, programs []string) error {
	controller.t.Helper()
	controller.restarts++
	if !containsRuntimeArtifact(programs, "xray") {
		controller.t.Fatal("cold subscription did not restart Xray")
	}
	if _, err := os.Stat(controller.guard); err != nil {
		controller.t.Fatalf("core restart is not guarded: %v", err)
	}
	if controller.observe != nil {
		controller.observe()
	}
	return controller.restartErr
}

func (controller *subscriptionGeometryController) Probe(ctx context.Context, _ []string) error {
	controller.t.Helper()
	controller.probes++
	deadline, ok := ctx.Deadline()
	if remaining := time.Until(deadline); !ok || remaining < 209*time.Second || remaining > 210*time.Second {
		controller.t.Fatalf("cold readiness deadline=%v remaining=%s", ok, remaining)
	}
	if _, err := os.Stat(controller.guard); err != nil {
		controller.t.Fatalf("core probe is not guarded: %v", err)
	}
	return controller.probeErr
}

func subscriptionGeometryBody(t *testing.T, lanes int, endpoint string) []byte {
	t.Helper()
	inbounds, balancers, rules := []any{}, []any{}, []any{}
	for index := 0; index <= lanes; index++ {
		tag := "outbound-health-probe"
		if index == 1 {
			tag = "outbound-health-background"
		} else if index > 1 {
			tag = fmt.Sprintf("outbound-health-background-%d", index)
		}
		inbounds = append(inbounds, map[string]any{"tag": tag, "listen": "127.0.0.1", "port": 19082 + index, "protocol": "http"})
		balancers = append(balancers, map[string]any{"tag": tag, "selector": []any{"sb-health-"}})
		rules = append(rules, map[string]any{"type": "field", "inboundTag": []any{tag}, "balancerTag": tag})
	}
	body, err := json.Marshal(map[string]any{
		"inbounds": inbounds, "routing": map[string]any{"balancers": balancers, "rules": rules},
		"outbounds": []any{map[string]any{"tag": "provider", "settings": map[string]any{"address": endpoint}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func subscriptionGeometryFixture(t *testing.T, old, next []byte) (*nativeRuntime, runtimeconfig.RuntimeCandidate, *subscriptionGeometryController) {
	t.Helper()
	root := t.TempDir()
	core, pool := filepath.Join(root, "xray.json"), filepath.Join(root, "pool.json")
	for path, body := range map[string][]byte{core: old, pool: []byte(hotPolicyOldPool), filepath.Join(root, "ready"): []byte("4321\n")} {
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(pool, time.Unix(1000, 0), time.Unix(1000, 0)); err != nil {
		t.Fatal(err)
	}
	store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "state"), map[string]string{"xray.json": core, "urltest-pool.json": pool})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[string][]byte{"xray.json": next, "urltest-pool.json": []byte(hotPolicyNewPool)}
	candidate, err := store.Prepare(artifactRevision(artifacts), artifacts)
	if err != nil {
		t.Fatal(err)
	}
	controller := &subscriptionGeometryController{t: t, guard: filepath.Join(root, "guard")}
	native := &nativeRuntime{
		options: RuntimeOptions{XrayConfig: core, XrayHealthPool: pool, ApplyGuardFile: controller.guard,
			XrayReadyFile: filepath.Join(root, "ready"), XrayHotRuntimeReadyFile: filepath.Join(root, "hot-ready")},
		store: store, controller: controller,
		validate: func(context.Context, runtimeconfig.RuntimeCandidate, []string) error { return nil },
	}
	return native, candidate, controller
}

func TestSubscriptionProbeGeometryColdGrowthAndShrink(t *testing.T) {
	for _, sizes := range [][2]int{{1, 10}, {10, 1}} {
		t.Run(fmt.Sprintf("%d-to-%d", sizes[0], sizes[1]), func(t *testing.T) {
			old, next := subscriptionGeometryBody(t, sizes[0], "old"), subscriptionGeometryBody(t, sizes[1], "new")
			native, candidate, controller := subscriptionGeometryFixture(t, old, next)
			hooks := 0
			hook := func(context.Context) error {
				hooks++
				if _, err := os.Stat(controller.guard); err != nil {
					t.Fatal("RouterOS hook ran without publication guard")
				}
				return nil
			}
			controller.observe = func() {
				if hooks != controller.restarts {
					t.Fatal("core restarted before RouterOS planned gate")
				}
			}
			receipt, err := native.activateSubscriptionWithXrayRestartHook(context.Background(), candidate, hook)
			if err != nil || controller.restarts != 1 || controller.probes != 1 || native.subscriptionRestartPending.Load() {
				t.Fatalf("cold activation=%v restarts=%d probes=%d", err, controller.restarts, controller.probes)
			}
			if err := native.rollbackSubscriptionWithXrayRestartHook(context.Background(), receipt, hook); err != nil {
				t.Fatal(err)
			}
			if controller.restarts != 2 || controller.probes != 2 || hooks != 2 || native.subscriptionRestartPending.Load() {
				t.Fatal("rollback did not restore the live core geometry")
			}
			if !bytes.Equal(old, mustReadFile(t, native.options.XrayConfig)) {
				t.Fatal("old core file not restored")
			}
			if _, err := os.Stat(controller.guard); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("guard survived completed rollback")
			}
		})
	}
}

func TestSubscriptionProbeGeometryEndpointOnlyStaysHot(t *testing.T) {
	native, candidate, controller := subscriptionGeometryFixture(t, subscriptionGeometryBody(t, 2, "old"), subscriptionGeometryBody(t, 2, "new"))
	stamp := testPoolStamp(t, native.options.XrayHealthPool)
	done := make(chan error, 1)
	var receipt runtimeconfig.ActivationReceipt
	go func() {
		var err error
		receipt, err = native.activateSubscriptionWithXrayRestartHook(context.Background(), candidate, func(context.Context) error { return errors.New("hot update called restart hook") })
		done <- err
	}()
	waitTestPool(t, native.options.XrayHealthPool, hotPolicyNewPool, stamp, done)
	acknowledgeTestPool(t, native)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	stamp = testPoolStamp(t, native.options.XrayHealthPool)
	go func() { done <- native.rollbackSubscription(context.Background(), receipt) }()
	waitTestPool(t, native.options.XrayHealthPool, hotPolicyOldPool, stamp, done)
	acknowledgeTestPool(t, native)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if controller.restarts != 0 || controller.probes != 0 || native.subscriptionRestartPending.Load() {
		t.Fatal("endpoint-only update or rollback restarted core")
	}
}

func TestSubscriptionProbeGeometryRetriesZeroDiffAfterFailure(t *testing.T) {
	for _, failure := range []string{"restart", "probe", "hook"} {
		t.Run(failure, func(t *testing.T) {
			native, candidate, controller := subscriptionGeometryFixture(t, subscriptionGeometryBody(t, 1, "old"), subscriptionGeometryBody(t, 10, "new"))
			fail := errors.New("injected " + failure)
			var hook func(context.Context) error
			switch failure {
			case "restart":
				controller.restartErr = fail
			case "probe":
				controller.probeErr = fail
			case "hook":
				hook = func(context.Context) error { return fail }
			}
			if _, err := native.activateSubscriptionWithXrayRestartHook(context.Background(), candidate, hook); !errors.Is(err, fail) || !native.subscriptionRestartPending.Load() {
				t.Fatalf("restart debt lost: %v", err)
			}
			controller.restartErr, controller.probeErr = nil, nil
			before := controller.restarts
			receipt, err := native.activateSubscription(context.Background(), candidate)
			if err != nil || len(receipt.Changed()) != 0 || controller.restarts != before+1 || native.subscriptionRestartPending.Load() {
				t.Fatalf("zero-diff retry skipped restart/probe: %v changed=%v", err, receipt.Changed())
			}
		})
	}
}

func TestSubscriptionProbeGeometryRollbackFailureRetainsRestart(t *testing.T) {
	old := subscriptionGeometryBody(t, 10, "old")
	native, candidate, controller := subscriptionGeometryFixture(t, old, subscriptionGeometryBody(t, 1, "new"))
	receipt, err := native.activateSubscription(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	controller.restartErr = errors.New("rollback restart failed")
	if err := native.rollbackSubscription(context.Background(), receipt); err == nil || !native.subscriptionRestartPending.Load() {
		t.Fatalf("rollback failure lost: %v", err)
	}
	if !bytes.Equal(old, mustReadFile(t, native.options.XrayConfig)) {
		t.Fatal("rollback files not restored")
	}
	artifacts := map[string][]byte{"xray.json": old, "urltest-pool.json": []byte(hotPolicyOldPool)}
	recovering, err := native.store.Prepare(artifactRevision(artifacts), artifacts)
	if err != nil {
		t.Fatal(err)
	}
	controller.restartErr = nil
	before := controller.restarts
	retry, err := native.activateSubscription(context.Background(), recovering)
	if err != nil || len(retry.Changed()) != 0 || controller.restarts != before+1 || native.subscriptionRestartPending.Load() {
		t.Fatalf("pending recovery skipped restored core restart: %v", err)
	}
}

func TestSubscriptionProbeGeometryUsesRenderedGraph(t *testing.T) {
	server, config, _ := startupProbeMigrationFixture(t, nil)
	metadata, _ := server.repository.metadata()
	nodes, err := committedRuntimeMigrationNodes(server.repository, metadata, text(metadata["revision"]))
	if err != nil {
		t.Fatal(err)
	}
	native, err := newNativeRuntimeStore(server.opts.Runtime, server.secrets)
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{1, 12, 13} {
		next := append([]map[string]any(nil), nodes...)
		if count < len(next) {
			next = next[:count]
		}
		if count > len(next) {
			extra := cloneJSONObject(nodes[0])
			extra["id"] = "additional-node"
			next = append(next, extra)
		}
		candidate, err := native.prepare(config, next)
		if err != nil {
			t.Fatal(err)
		}
		changed, err := subscriptionProbeGeometryChanged(server.opts.Runtime.XrayConfig, candidate.Files["xray.json"])
		if err != nil || changed != (count == 1) {
			t.Fatalf("rendered inventory%d changed=%t err=%v", count, changed, err)
		}
	}
	if _, err := subscriptionProbeGeometryChanged(server.opts.Runtime.XrayConfig, filepath.Join(t.TempDir(), strings.Repeat("x", 20))); err != nil {
		t.Fatal(err)
	}
}
