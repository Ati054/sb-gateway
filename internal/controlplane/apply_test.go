package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type fakeRuntimeApplier struct {
	revision      string
	prepareCalls  int
	activateCalls int
	commitCalls   int
	rollbackCalls int
	commitErr     error
}

func (runtime *fakeRuntimeApplier) prepare(map[string]any, []map[string]any) (runtimeconfig.RuntimeCandidate, error) {
	runtime.prepareCalls++
	return runtimeconfig.RuntimeCandidate{Revision: runtime.revision}, nil
}

func (runtime *fakeRuntimeApplier) activate(context.Context, runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, error) {
	runtime.activateCalls++
	return runtimeconfig.ActivationReceipt{}, nil
}

func (runtime *fakeRuntimeApplier) activateSubscription(ctx context.Context, candidate runtimeconfig.RuntimeCandidate) (runtimeconfig.ActivationReceipt, error) {
	return runtime.activate(ctx, candidate)
}

func (runtime *fakeRuntimeApplier) rollback(context.Context, runtimeconfig.ActivationReceipt) error {
	runtime.rollbackCalls++
	return nil
}

func (runtime *fakeRuntimeApplier) rollbackSubscription(ctx context.Context, receipt runtimeconfig.ActivationReceipt) error {
	return runtime.rollback(ctx, receipt)
}

func (runtime *fakeRuntimeApplier) commit(runtimeconfig.RuntimeCandidate) error {
	runtime.commitCalls++
	return runtime.commitErr
}

func TestApplyEndpointCommitsRuntimeAndStateAfterRouterOSTransactionFinalizes(t *testing.T) {
	server := newTestServer(t)
	cookie, csrf := bootstrapSession(t, server)
	active := routerOSReadyConfig(t)
	activeWatchdog := active["watchdog"].(map[string]any)
	activeWatchdog["interval_seconds"] = float64(5)
	activeRevision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	oldRuntimeRevision := strings.Repeat("1", 64)
	if err := server.repository.commitActive(commitMetadata{
		Revision: activeRevision, RuntimeRevision: oldRuntimeRevision,
		Actor: "test", CommittedAt: server.now(),
	}); err != nil {
		t.Fatal(err)
	}
	desired := cloneJSONObject(active)
	desired["watchdog"].(map[string]any)["interval_seconds"] = float64(6)
	newRuntimeRevision := strings.Repeat("2", 64)
	runtime := &fakeRuntimeApplier{revision: newRuntimeRevision}
	server.runtime = runtime
	var healthBeforeFinalize bool
	server.applyRouterOS = func(
		ctx context.Context, _ map[string]any, _, _ string,
		health func(context.Context) error,
		finalize func(context.Context, routeros.BackupRef) error,
	) (routerOSApplyOutput, error) {
		if err := health(ctx); err != nil {
			return routerOSApplyOutput{}, err
		}
		healthBeforeFinalize = runtime.activateCalls == 1
		backup := routeros.BackupRef{Export: "safe.rsc", Binary: "safe.backup"}
		if err := finalize(ctx, backup); err != nil {
			return routerOSApplyOutput{}, err
		}
		return routerOSApplyOutput{Backup: backup, Kind: "delta", Sections: []string{"watchdog"}}, nil
	}

	response := performRequest(t, server, http.MethodPost, apiPrefix+"/drafts/apply", map[string]any{"config": desired}, map[string]string{csrfHeader: csrf}, cookie)
	if response.Code != http.StatusOK {
		t.Fatalf("apply failed: %d %s", response.Code, response.Body.String())
	}
	body := decodeResponse(t, response)
	if body["operation"] != "applied" || body["routeros_apply_kind"] != "delta" || !healthBeforeFinalize {
		t.Fatalf("unexpected apply response: %#v", body)
	}
	normalizeXHTTPModeCompatibility(desired)
	desiredRevision, _ := revisionFor(desired)
	committed, err := server.repository.activeRevision()
	if err != nil || committed != desiredRevision {
		t.Fatalf("active revision = %q, err=%v", committed, err)
	}
	if runtime.prepareCalls != 1 || runtime.activateCalls != 1 || runtime.commitCalls != 1 || runtime.rollbackCalls != 0 {
		t.Fatalf("runtime calls = %#v", runtime)
	}
	snapshot, err := server.repository.auxiliary("subscription-nodes-" + desiredRevision)
	if err != nil || snapshot["revision"] != desiredRevision {
		t.Fatalf("subscription snapshot = %#v, err=%v", snapshot, err)
	}
}

func TestApplyFailureResponseDistinguishesRecoveryState(t *testing.T) {
	tests := []struct {
		name string
		err  error
		code string
	}{
		{
			name: "rolled back",
			err: classifyApplyFailure(&routeros.TransactionFailure{
				State: routeros.TransactionRolledBack, Err: errors.New("probe failed"),
			}, nil),
			code: "apply_rolled_back",
		},
		{
			name: "recovery pending",
			err: classifyApplyFailure(&routeros.TransactionFailure{
				State: routeros.TransactionRecoveryPending, Err: errors.New("guard remains armed"),
			}, nil),
			code: "apply_recovery_pending",
		},
		{
			name: "runtime rollback failed",
			err: classifyApplyFailure(&routeros.TransactionFailure{
				State: routeros.TransactionRolledBack, Err: errors.New("router restored"),
			}, errors.New("runtime rollback failed")),
			code: "apply_state_unconfirmed",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, message := applyFailureResponse(test.err)
			if code != test.code || message == "" {
				t.Fatalf("code=%q message=%q", code, message)
			}
		})
	}
}

func TestApplyFirstNativeRouterOSChangeUsesFailOpenRollbackBaseline(t *testing.T) {
	server := newTestServer(t)
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("3", 64)}
	server.runtime = runtime
	var previousSource string
	server.applyRouterOS = func(
		ctx context.Context, _ map[string]any, _, previous string,
		health func(context.Context) error,
		finalize func(context.Context, routeros.BackupRef) error,
	) (routerOSApplyOutput, error) {
		previousSource = previous
		operation, journalErr := server.repository.auxiliary("apply-operation")
		if journalErr != nil {
			return routerOSApplyOutput{}, journalErr
		}
		recoveryRevision := text(operation["recovery_revision"])
		if !safeRevision(recoveryRevision) || text(operation["previous_revision"]) != "" {
			return routerOSApplyOutput{}, fmt.Errorf("first Apply recovery journal is invalid: %#v", operation)
		}
		if _, loadErr := server.repository.loadGeneration(recoveryRevision); loadErr != nil {
			return routerOSApplyOutput{}, loadErr
		}
		if err := health(ctx); err != nil {
			return routerOSApplyOutput{}, err
		}
		backup := routeros.BackupRef{Export: "first-export.rsc", Binary: "first.backup"}
		if err := finalize(ctx, backup); err != nil {
			return routerOSApplyOutput{}, err
		}
		return routerOSApplyOutput{Backup: backup, Kind: "full"}, nil
	}
	result, status, err := server.applyConfiguration(context.Background(), routerOSReadyConfig(t), "admin")
	if err != nil || status != http.StatusOK {
		t.Fatalf("status=%d err=%v", status, err)
	}
	if previousSource == "" || !strings.Contains(previousSource, `:local wantedManaged [:toarray ""]`) {
		t.Fatalf("first Apply rollback is not fail-open: %q", previousSource)
	}
	if strings.Contains(previousSource, `disabled=no comment="SB-GATEWAY public dstnat`) {
		t.Fatalf("first Apply rollback exposes a public listener: %q", previousSource)
	}
	if runtime.prepareCalls != 1 || runtime.activateCalls != 1 || runtime.commitCalls != 1 || runtime.rollbackCalls != 0 {
		t.Fatalf("runtime calls = %#v", runtime)
	}
	if result["previous_revision"] != nil || result["operation"] != "applied" {
		t.Fatalf("unexpected first Apply response: %#v", result)
	}
}

func TestFirstApplyRollbackConfigRemovesTrafficAndExposure(t *testing.T) {
	config := routerOSReadyConfig(t)
	config["local_clients"] = []any{map[string]any{"id": "lan", "enabled": true, "source_cidrs": []any{"192.168.50.10/32"}}}
	config["remote_users"] = []any{map[string]any{"id": "remote", "enabled": true}}
	networking := config["system"].(map[string]any)["networking"].(map[string]any)
	networking["wireguard_egress_enabled"] = true
	networking["wireguard_egress_exits"] = []any{map[string]any{"id": "wg", "enabled": true}}

	baseline := firstApplyRollbackConfig(config)
	for _, collection := range []string{"local_clients", "policies", "remote_users", "reverse_vless_exits", "service_packs", "subscription_reserves", "transports"} {
		if values, ok := baseline[collection].([]any); !ok || len(values) != 0 {
			t.Fatalf("rollback collection %s = %#v", collection, baseline[collection])
		}
	}
	rollbackIngress := baseline["ingress"].(map[string]any)
	if rollbackIngress["subscription_endpoint_enabled"] != false || rollbackIngress["status_hostname"] != "" {
		t.Fatalf("rollback ingress = %#v", rollbackIngress)
	}
	rollbackNetworking := baseline["system"].(map[string]any)["networking"].(map[string]any)
	if rollbackNetworking["wireguard_egress_enabled"] != false || len(rollbackNetworking["wireguard_egress_exits"].([]any)) != 0 {
		t.Fatalf("rollback networking = %#v", rollbackNetworking)
	}
	if len(config["local_clients"].([]any)) != 1 || len(config["transports"].([]any)) == 0 {
		t.Fatal("rollback construction mutated the desired configuration")
	}
}

func TestApplyOperationContextSurvivesClientDisconnectAndRemainsBounded(t *testing.T) {
	parent, cancelParent := context.WithCancel(context.Background())
	operation, cancelOperation := applyOperationContext(parent)
	defer cancelOperation()
	cancelParent()

	if err := operation.Err(); err != nil {
		t.Fatalf("operation was cancelled with client request: %v", err)
	}
	deadline, ok := operation.Deadline()
	if !ok {
		t.Fatal("operation has no deadline")
	}
	remaining := time.Until(deadline)
	if remaining <= 0 || remaining > applyOperationTimeout {
		t.Fatalf("unexpected operation deadline: %v", remaining)
	}
}

func TestInterruptedApplyRecoveryConvergesToAuthoritativeActiveGeneration(t *testing.T) {
	for _, test := range []struct {
		name         string
		phase        string
		commitTarget bool
		wantName     string
	}{
		{name: "after guard disarm before active commit", phase: "runtime_activated", wantName: "A"},
		{name: "after active commit", phase: "active_committed", commitTarget: true, wantName: "B"},
		{name: "before runtime LKG commit", phase: "active_committed", commitTarget: true, wantName: "B"},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := newTestServer(t)
			activeA := routerOSReadyConfig(t)
			activeA["name"] = "A"
			revisionA, err := server.repository.stageGeneration(activeA)
			if err != nil {
				t.Fatal(err)
			}
			if err := server.repository.commitActive(commitMetadata{
				Revision: revisionA, RuntimeRevision: strings.Repeat("a", 64), RouterOSSource: "router-A", Actor: "test", CommittedAt: server.now(),
			}); err != nil {
				t.Fatal(err)
			}
			activeB := cloneJSONObject(activeA)
			activeB["name"] = "B"
			revisionB, err := server.repository.stageGeneration(activeB)
			if err != nil {
				t.Fatal(err)
			}
			if test.commitTarget {
				if err := server.repository.commitActive(commitMetadata{
					Revision: revisionB, PreviousRevision: revisionA, RuntimeRevision: strings.Repeat("b", 64),
					PreviousRuntimeRevision: strings.Repeat("a", 64), RouterOSSource: "router-B", Actor: "test", CommittedAt: server.now(),
				}); err != nil {
					t.Fatal(err)
				}
			}
			if err := server.repository.saveAuxiliary("apply-operation", map[string]any{
				"kind": "apply", "pending": true, "state": test.phase,
				"previous_revision": revisionA, "target_revision": revisionB,
				"previous_routeros_source": "router-A", "target_routeros_source": "router-B",
			}); err != nil {
				t.Fatal(err)
			}
			runtime := &fakeRuntimeApplier{revision: strings.Repeat("c", 64)}
			server.runtime = runtime
			var recoveredName string
			var recoveredSource string
			server.applyRouterOS = func(
				ctx context.Context, config map[string]any, desired, _ string,
				health func(context.Context) error, finalize func(context.Context, routeros.BackupRef) error,
			) (routerOSApplyOutput, error) {
				recoveredName = text(config["name"])
				recoveredSource = desired
				if err := health(ctx); err != nil {
					return routerOSApplyOutput{}, err
				}
				if err := finalize(ctx, routeros.BackupRef{}); err != nil {
					return routerOSApplyOutput{}, err
				}
				return routerOSApplyOutput{Kind: "full"}, nil
			}
			worked, err := server.reconcilePendingApply(context.Background())
			if err != nil || !worked {
				t.Fatalf("recovery worked=%t err=%v", worked, err)
			}
			wantSource := "router-A"
			wantRevision := revisionA
			if test.commitTarget {
				wantSource = "router-B"
				wantRevision = revisionB
			}
			if recoveredName != test.wantName || recoveredSource != wantSource {
				t.Fatalf("recovered name=%q source=%q; want %q %q", recoveredName, recoveredSource, test.wantName, wantSource)
			}
			if revision, _ := server.repository.activeRevision(); revision != wantRevision {
				t.Fatalf("recovery changed the commit decision: %q", revision)
			}
			operation, err := server.repository.auxiliary("apply-operation")
			if err != nil || len(operation) != 0 {
				t.Fatalf("recovery journal remains: %#v, %v", operation, err)
			}
			if runtime.prepareCalls != 1 || runtime.activateCalls != 1 || runtime.commitCalls != 1 {
				t.Fatalf("runtime was not reconciled exactly once: %#v", runtime)
			}
		})
	}
}

func TestInterruptedFirstApplyRecoveryRestoresSafeBaselineWithoutPublishingActive(t *testing.T) {
	server := newTestServer(t)
	target := routerOSReadyConfig(t)
	target["name"] = "first-target"
	targetRevision, err := server.repository.stageGeneration(target)
	if err != nil {
		t.Fatal(err)
	}
	baseline := firstApplyRollbackConfig(target)
	baseline["name"] = "safe-installation-baseline"
	recoveryRevision, err := server.repository.stageGeneration(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("apply-operation", map[string]any{
		"kind": "apply", "pending": true, "state": "runtime_activated",
		"previous_revision": nil, "target_revision": targetRevision,
		"recovery_revision":        recoveryRevision,
		"previous_routeros_source": "router-safe", "target_routeros_source": "router-target",
	}); err != nil {
		t.Fatal(err)
	}
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("f", 64)}
	server.runtime = runtime
	var recoveredName, recoveredSource string
	server.applyRouterOS = func(
		ctx context.Context, config map[string]any, desired, _ string,
		health func(context.Context) error, finalize func(context.Context, routeros.BackupRef) error,
	) (routerOSApplyOutput, error) {
		recoveredName, recoveredSource = text(config["name"]), desired
		if err := health(ctx); err != nil {
			return routerOSApplyOutput{}, err
		}
		if err := finalize(ctx, routeros.BackupRef{}); err != nil {
			return routerOSApplyOutput{}, err
		}
		return routerOSApplyOutput{Kind: "full"}, nil
	}

	worked, err := server.reconcilePendingApply(context.Background())
	if err != nil || !worked {
		t.Fatalf("first Apply recovery worked=%t err=%v", worked, err)
	}
	if recoveredName != "safe-installation-baseline" || recoveredSource != "router-safe" {
		t.Fatalf("recovered name=%q source=%q", recoveredName, recoveredSource)
	}
	if revision, err := server.repository.activeRevision(); err != nil || revision != "" {
		t.Fatalf("safe recovery published active revision %q, err=%v", revision, err)
	}
	operation, err := server.repository.auxiliary("apply-operation")
	if err != nil || len(operation) != 0 {
		t.Fatalf("first Apply recovery journal remains: %#v, %v", operation, err)
	}
	if runtime.prepareCalls != 1 || runtime.activateCalls != 1 || runtime.commitCalls != 1 {
		t.Fatalf("safe runtime was not reconciled exactly once: %#v", runtime)
	}
	if conflict, err := server.stateMutationConflict(""); err != nil || conflict != "" {
		t.Fatalf("repeat Apply remains blocked: conflict=%q err=%v", conflict, err)
	}
	if result, status, err := server.applyConfiguration(context.Background(), target, "admin"); err != nil || status != http.StatusOK || result["operation"] != "applied" {
		t.Fatalf("repeat first Apply result=%#v status=%d err=%v", result, status, err)
	}
	if revision, err := server.repository.activeRevision(); err != nil || revision == "" {
		t.Fatalf("repeated first Apply did not publish active revision: %q, %v", revision, err)
	}
}

func TestReadinessStaysFalseWhileApplyRecoveryIsPending(t *testing.T) {
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	config := routerOSReadyConfig(t)
	revision, err := server.repository.stageGeneration(config)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{Revision: revision, Actor: "test", CommittedAt: server.now()}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("apply-operation", map[string]any{"pending": true, "state": "runtime_activated"}); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/health/ready", nil, nil, cookie)
	if response.Code != http.StatusServiceUnavailable || decodeResponse(t, response)["apply_recovery_pending"] != true {
		t.Fatalf("pending recovery was reported ready: %d %s", response.Code, response.Body.String())
	}
}

func TestApplyRuntimeLKGWriteFailureRemainsRecoverable(t *testing.T) {
	server := newTestServer(t)
	active := routerOSReadyConfig(t)
	revision, err := server.repository.stageGeneration(active)
	if err != nil {
		t.Fatal(err)
	}
	if err := server.repository.commitActive(commitMetadata{
		Revision: revision, RuntimeRevision: strings.Repeat("1", 64), RouterOSSource: "router-old", Actor: "test", CommittedAt: server.now(),
	}); err != nil {
		t.Fatal(err)
	}
	desired := cloneJSONObject(active)
	desired["watchdog"].(map[string]any)["interval_seconds"] = float64(7)
	runtime := &fakeRuntimeApplier{revision: strings.Repeat("2", 64), commitErr: errors.New("no space left on device")}
	server.runtime = runtime
	server.applyRouterOS = func(
		ctx context.Context, _ map[string]any, _, _ string,
		health func(context.Context) error, finalize func(context.Context, routeros.BackupRef) error,
	) (routerOSApplyOutput, error) {
		if err := health(ctx); err != nil {
			return routerOSApplyOutput{}, err
		}
		if err := finalize(ctx, routeros.BackupRef{}); err != nil {
			return routerOSApplyOutput{}, err
		}
		return routerOSApplyOutput{Kind: "delta"}, nil
	}
	result, status, err := server.applyConfiguration(context.Background(), desired, "admin")
	if err != nil || status != http.StatusOK || result["cleanup_pending"] != true {
		t.Fatalf("status=%d result=%#v err=%v", status, result, err)
	}
	operation, err := server.repository.auxiliary("apply-operation")
	if err != nil || operation["pending"] != true || operation["state"] != "recovery_pending" {
		t.Fatalf("missing recovery journal: %#v, %v", operation, err)
	}
	runtime.commitErr = nil
	worked, err := server.reconcilePendingApply(context.Background())
	if err != nil || !worked {
		t.Fatalf("LKG recovery worked=%t err=%v", worked, err)
	}
	operation, _ = server.repository.auxiliary("apply-operation")
	if len(operation) != 0 {
		t.Fatalf("recovery journal remains: %#v", operation)
	}
}

func routerOSReadyConfig(t *testing.T) map[string]any {
	t.Helper()
	config := currentConfigFixture(t)
	system := config["system"].(map[string]any)
	system["deployment_ready"] = true
	management := system["management"].(map[string]any)
	management["allowed_ingress_interfaces"] = []any{"ether1"}
	management["allowed_source_cidrs"] = []any{"192.168.88.0/24"}
	networking := system["networking"].(map[string]any)
	networking["bridge_name"] = "sb-gateway"
	networking["veth_name"] = "veth-sb"
	networking["container_address"] = "172.19.0.2/30"
	networking["tun_address"] = "172.30.0.1/30"
	networking["routeros_gateway"] = "172.19.0.1"
	config["dns"].(map[string]any)["internal_server"] = "172.19.0.1"
	routerOS := config["routeros"].(map[string]any)
	routerOS["base_url"] = "https://192.0.2.1:8729"
	routerOS["ssh_port"] = float64(22)
	ingress := config["ingress"].(map[string]any)
	ingress["subscription_hostname"] = "subscription.example.test"
	ingress["subscription_origin_server_name"] = "subscription-origin.example.test"
	tlsProfile := config["tls_profiles"].([]any)[0].(map[string]any)
	tlsProfile["certificate_secret_ref"] = "tls-profiles/cdn-default/certificate.pem"
	tlsProfile["private_key_secret_ref"] = "tls-profiles/cdn-default/private-key.pem"
	for index, raw := range config["transports"].([]any) {
		transport := raw.(map[string]any)
		if transport["kind"] != "ws" && transport["kind"] != "grpc" {
			continue
		}
		transport["cdn_deployments"] = []any{map[string]any{
			"id": "primary", "enabled": true, "cdn_provider": "cloudflare",
			"hostname":           fmt.Sprintf("transport-%d.example.test", index),
			"origin_server_name": fmt.Sprintf("origin-%d.example.test", index),
			"listen_port":        float64(443), "origin_port": float64(18443 + index),
			"origin_protection_mode": "auto-cidr", "tls_profile_id": "cdn-default",
		}}
	}
	return config
}

func TestRouterOSNodesForRevisionPreservesAnEmptySnapshot(t *testing.T) {
	server := newTestServer(t)
	revision := strings.Repeat("a", 64)
	if err := server.repository.saveAuxiliary("subscription-nodes-"+revision, map[string]any{
		"revision": revision, "nodes": []any{},
	}); err != nil {
		t.Fatal(err)
	}
	fallback := []map[string]any{{"id": "new"}}
	if nodes := server.routerOSNodesForRevision(revision, fallback); len(nodes) != 0 {
		t.Fatalf("empty historical snapshot replaced by current nodes: %#v", nodes)
	}
}
