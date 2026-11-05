package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

func legacyManagedDNSFixture(t *testing.T, expected map[string][]byte) ([]byte, []byte) {
	t.Helper()
	var core, dns map[string]any
	if json.Unmarshal(expected["xray.json"], &core) != nil || json.Unmarshal(expected["policy-dns.json"], &dns) != nil {
		t.Fatal("decode generated fixture")
	}
	core["inbounds"] = append(collectionArray(core["inbounds"]), map[string]any{
		"tag": "routeros-client-dns", "listen": "198.18.0.2", "port": 1053, "protocol": "dokodemo-door",
		"settings": map[string]any{"address": "127.0.0.1", "port": 53, "network": "tcp,udp"}, "sniffing": map[string]any{"enabled": false},
	})
	delete(dns, "managed_ingress")
	dns["lane_layout_version"] = 1
	coreBytes, _ := json.Marshal(core)
	dnsBytes, _ := json.Marshal(dns)
	return coreBytes, dnsBytes
}

func TestManagedDNSRestartDirectionAndSubscriptionGeometry(t *testing.T) {
	server, _, expected := startupProbeMigrationFixture(t, nil)
	legacyCore, legacyDNS := legacyManagedDNSFixture(t, expected)
	native, err := newNativeRuntimeStore(server.opts.Runtime, server.secrets)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []struct {
		name      string
		core, dns []byte
		order     []string
	}{
		{"go", expected["xray.json"], expected["policy-dns.json"], []string{"xray", "dns", "nginx"}},
		{"legacy", legacyCore, legacyDNS, []string{"dns", "xray", "nginx"}},
	} {
		t.Run(target.name, func(t *testing.T) {
			if err := os.WriteFile(native.options.XrayConfig, target.core, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(native.options.PolicyDNSConfig, target.dns, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(native.options.NginxConfig, []byte("ssl_preread on;"), 0600); err != nil {
				t.Fatal(err)
			}
			if got := native.restartOrder([]string{"xray.json", "policy-dns.json", "nginx.conf"}); !reflect.DeepEqual(got, target.order) {
				t.Fatalf("restart order: %v", got)
			}
		})
	}
	oldPath, newPath := filepath.Join(t.TempDir(), "old.json"), filepath.Join(t.TempDir(), "new.json")
	if err := os.WriteFile(oldPath, legacyCore, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, expected["xray.json"], 0600); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][2]string{{oldPath, newPath}, {newPath, oldPath}} {
		changed, err := subscriptionStartupGraphChanged(paths[0], paths[1])
		if err != nil || !changed {
			t.Fatalf("managed listener transition stayed hot: %t %v", changed, err)
		}
	}
}

func TestStartupPendingMixedManagedDNSRebuildsOnlyCommittedArtifacts(t *testing.T) {
	for _, journal := range []string{"apply-operation", "subscription-runtime-operation"} {
		for _, mix := range []string{"two-owners", "no-owner"} {
			t.Run(journal+"/"+mix, func(t *testing.T) {
				server, config, expected := startupProbeMigrationFixture(t, nil)
				legacyCore, legacyDNS := legacyManagedDNSFixture(t, expected)
				if mix == "two-owners" {
					if err := os.WriteFile(server.opts.Runtime.XrayConfig, legacyCore, 0600); err != nil {
						t.Fatal(err)
					}
				} else {
					if err := os.WriteFile(server.opts.Runtime.PolicyDNSConfig, legacyDNS, 0600); err != nil {
						t.Fatal(err)
					}
				}
				active, _ := server.repository.activeRevision()
				operation := map[string]any{"pending": true, "state": "runtime_activated", "previous_revision": active, "recovery_revision": active}
				if err := server.repository.saveAuxiliary(journal, operation); err != nil {
					t.Fatal(err)
				}
				draft := cloneJSONObject(config)
				objectAt(draft, "dns")["internal_server"] = "203.0.113.53"
				draftRevision, err := server.repository.saveDraft(draft)
				if err != nil {
					t.Fatal(err)
				}
				// draft.json stores the raw draft, whereas the public handler calls
				// getDraft, which removes retired controls and overlays runtime
				// network facts. Capture both BEFORE the migration; comparing that
				// observable view to the raw fixture is invalid even without work.
				draftPath := filepath.Join(server.opts.StateDir, "draft.json")
				draftBefore := mustReadFile(t, draftPath)
				generationPath := filepath.Join(server.repository.generations, active+".json")
				generationBefore := mustReadFile(t, generationPath)
				unstagedDraftPath := filepath.Join(server.repository.generations, draftRevision+".json")
				if _, err := os.Stat(unstagedDraftPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("fixture draft was unexpectedly staged")
				}
				observableBefore, err := server.getDraft()
				if err != nil {
					t.Fatal(err)
				}
				observableRevisionBefore, err := revisionFor(observableBefore)
				if err != nil {
					t.Fatal(err)
				}
				activePath := filepath.Join(server.opts.StateDir, "active.json")
				activeBefore := mustReadFile(t, activePath)
				journalPath := filepath.Join(server.opts.StateDir, journal+".json")
				journalBefore := mustReadFile(t, journalPath)
				lkg := filepath.Join(server.opts.Runtime.CandidateDir, "runtime-lkg", "untouched")
				if err := os.MkdirAll(filepath.Dir(lkg), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(lkg, []byte("existing LKG"), 0600); err != nil {
					t.Fatal(err)
				}
				changed, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
				if err != nil || !changed {
					t.Fatalf("mixed pending rebuild: %t %v", changed, err)
				}
				for name, body := range expected {
					if got := mustReadFile(t, map[string]string{"xray.json": server.opts.Runtime.XrayConfig, "policy-dns.json": server.opts.Runtime.PolicyDNSConfig, "urltest-pool.json": server.opts.Runtime.XrayHealthPool, "nginx.conf": server.opts.Runtime.NginxConfig, "watchdog.env": server.opts.Runtime.WatchdogEnvironment, "client-telemetry.nft": server.opts.Runtime.ClientTelemetryNFT, "transparent-exclusions.txt": server.opts.Runtime.TransparentExclusions}[name]); !bytes.Equal(got, body) {
						t.Fatalf("did not reconstruct committed %s", name)
					}
				}
				if !bytes.Equal(activeBefore, mustReadFile(t, activePath)) || !bytes.Equal(journalBefore, mustReadFile(t, journalPath)) || string(mustReadFile(t, lkg)) != "existing LKG" {
					t.Fatal("startup repair committed transaction or replaced LKG")
				}
				if !bytes.Equal(draftBefore, mustReadFile(t, draftPath)) || !bytes.Equal(generationBefore, mustReadFile(t, generationPath)) {
					t.Fatal("startup changed persisted draft or committed generation bytes")
				}
				if _, err := os.Stat(unstagedDraftPath); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("startup staged the unapplied draft")
				}
				observableAfter, err := server.getDraft()
				if err != nil || !equalJSONObject(observableAfter, observableBefore) {
					t.Fatal("startup changed the observable draft configuration")
				}
				if revision, err := revisionFor(observableAfter); err != nil || revision != observableRevisionBefore {
					t.Fatal("startup changed the observable draft revision")
				}
				if err := ValidateStartupManagedDNSRuntime(server.opts); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestStartupPendingManagedDNSMissingSnapshotDoesNotPublish(t *testing.T) {
	server, _, expected := startupProbeMigrationFixture(t, nil)
	legacyCore, _ := legacyManagedDNSFixture(t, expected)
	if err := os.WriteFile(server.opts.Runtime.XrayConfig, legacyCore, 0600); err != nil {
		t.Fatal(err)
	}
	active, _ := server.repository.activeRevision()
	if err := server.repository.saveAuxiliary("apply-operation", map[string]any{"pending": true, "previous_revision": active}); err != nil {
		t.Fatal(err)
	}
	if err := server.repository.saveAuxiliary("subscription-nodes-"+active, map[string]any{"revision": active, "nodes": "invalid"}); err != nil {
		t.Fatal(err)
	}
	coreBefore := mustReadFile(t, server.opts.Runtime.XrayConfig)
	changed, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
	if changed || !errors.Is(err, ErrManagedDNSStartupContract) {
		t.Fatalf("unverified snapshot accepted: %t %v", changed, err)
	}
	if !bytes.Equal(coreBefore, mustReadFile(t, server.opts.Runtime.XrayConfig)) {
		t.Fatal("invalid authority published artifacts")
	}
}

func TestStartupManagedDNSCoherentLegacyFallbackAndMissingOwner(t *testing.T) {
	server, _, expected := startupProbeMigrationFixture(t, nil)
	legacyCore, legacyDNS := legacyManagedDNSFixture(t, expected)
	if err := os.WriteFile(server.opts.Runtime.XrayConfig, legacyCore, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(server.opts.Runtime.PolicyDNSConfig, legacyDNS, 0600); err != nil {
		t.Fatal(err)
	}
	server.opts.Runtime.NginxTemplate = "/synthetic-missing-template"
	if changed, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts); changed || err == nil {
		t.Fatalf("expected optional migration failure: %t %v", changed, err)
	}
	if err := ValidateStartupManagedDNSRuntime(server.opts); err != nil {
		t.Fatalf("coherent legacy fallback rejected: %v", err)
	}
	if err := os.WriteFile(server.opts.Runtime.XrayConfig, expected["xray.json"], 0600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateStartupManagedDNSRuntime(server.opts); !errors.Is(err, ErrManagedDNSStartupContract) {
		t.Fatalf("missing required1053 owner accepted: %v", err)
	}
}

func TestStartupMixedFirstApplyUsesPersistedSafeGeneration(t *testing.T) {
	server, config, expected := startupProbeMigrationFixture(t, nil)
	baseline := firstApplyRollbackConfig(config)
	recoveryRevision, err := server.repository.stageGeneration(baseline)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(server.opts.StateDir, "active.json")); err != nil {
		t.Fatal(err)
	}
	legacyCore, _ := legacyManagedDNSFixture(t, expected)
	if err := os.WriteFile(server.opts.Runtime.XrayConfig, legacyCore, 0600); err != nil {
		t.Fatal(err)
	}
	operation := map[string]any{"pending": true, "state": "runtime_activated", "previous_revision": nil, "recovery_revision": recoveryRevision}
	if err := server.repository.saveAuxiliary("apply-operation", operation); err != nil {
		t.Fatal(err)
	}
	changed, err := MigrateLegacyDynamicRuntime(context.Background(), server.opts)
	if err != nil || !changed {
		t.Fatalf("safe first Apply reconstruction: %t %v", changed, err)
	}
	if active, err := server.repository.activeRevision(); err != nil || active != "" {
		t.Fatalf("first Apply recovery committed active: %q %v", active, err)
	}
	if saved, err := server.repository.auxiliary("apply-operation"); err != nil || !equalJSONObject(saved, operation) {
		t.Fatal("first Apply journal changed")
	}
	var core map[string]any
	if err := json.Unmarshal(mustReadFile(t, server.opts.Runtime.XrayConfig), &core); err != nil {
		t.Fatal(err)
	}
	for _, outbound := range objects(core["outbounds"]) {
		if strings.HasPrefix(text(outbound["tag"]), "subscription-") {
			t.Fatal("first Apply restored target subscription routes")
		}
	}
	// The saved safe model is the authority, not the still-present target draft.
	native, err := newNativeRuntimeStore(server.opts.Runtime, server.secrets)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := native.prepare(baseline, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(mustReadFile(t, candidate.Files["xray.json"]), mustReadFile(t, server.opts.Runtime.XrayConfig)) {
		t.Fatal("first Apply did not reconstruct safe generation")
	}
}

func TestRecoveredRuntimeRevisionPreservesConfigurationAndIsIdempotent(t *testing.T) {
	server, _, _ := startupProbeMigrationFixture(t, nil)
	before, err := server.repository.metadata()
	if err != nil {
		t.Fatal(err)
	}
	runtimeRevision := strings.Repeat("e", 64)
	if err := server.updateRecoveredRuntimeRevision(runtimeRevision); err != nil {
		t.Fatal(err)
	}
	after, err := server.repository.metadata()
	if err != nil {
		t.Fatal(err)
	}
	if after["revision"] != before["revision"] || after["node_snapshot_revision"] != before["node_snapshot_revision"] || after["routeros_source"] != before["routeros_source"] || after["runtime_revision"] != runtimeRevision || after["previous_runtime_revision"] != before["runtime_revision"] {
		t.Fatal("runtime recovery changed committed model")
	}
	activePath := filepath.Join(server.opts.StateDir, "active.json")
	activeBefore := mustReadFile(t, activePath)
	if err := server.updateRecoveredRuntimeRevision(runtimeRevision); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(activeBefore, mustReadFile(t, activePath)) {
		t.Fatal("equal runtime hash retry rewrote active pointer")
	}
}

func managedDNSPublicationFixture(t *testing.T) (*nativeRuntime, runtimeconfig.RuntimeCandidate, *recordingRuntimeController, map[string][]byte) {
	t.Helper()
	server, _, expected := startupProbeMigrationFixture(t, nil)
	store, err := runtimeconfig.NewCandidateStore(filepath.Join(t.TempDir(), "state"), map[string]string{"xray.json": server.opts.Runtime.XrayConfig, "policy-dns.json": server.opts.Runtime.PolicyDNSConfig})
	if err != nil {
		t.Fatal(err)
	}
	artifacts := map[string][]byte{"xray.json": append(append([]byte(nil), expected["xray.json"]...), '\n'), "policy-dns.json": append(append([]byte(nil), expected["policy-dns.json"]...), '\n')}
	candidate, err := store.Prepare(artifactRevision(artifacts), artifacts)
	if err != nil {
		t.Fatal(err)
	}
	controller := &recordingRuntimeController{}
	options := server.opts.Runtime
	options.ApplyGuardFile = filepath.Join(t.TempDir(), "apply-guard")
	native := &nativeRuntime{options: options, store: store, secrets: server.secrets, controller: controller}
	native.validate = native.validateCandidate
	return native, candidate, controller, expected
}

func TestManagedDNSInvalidActivationIsRejectedBeforePublication(t *testing.T) {
	native, candidate, controller, expected := managedDNSPublicationFixture(t)
	legacyCore, _ := legacyManagedDNSFixture(t, expected)
	artifacts := map[string][]byte{"xray.json": legacyCore, "policy-dns.json": expected["policy-dns.json"]}
	var err error
	candidate, err = native.store.Prepare(artifactRevision(artifacts), artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := native.activate(context.Background(), candidate); err == nil {
		t.Fatal("mixed ownership candidate was activated")
	}
	if !bytes.Equal(mustReadFile(t, native.options.XrayConfig), expected["xray.json"]) || !bytes.Equal(mustReadFile(t, native.options.PolicyDNSConfig), expected["policy-dns.json"]) {
		t.Fatal("invalid activation replaced live files")
	}
	if len(controller.restarts) != 0 || len(controller.probes) != 0 {
		t.Fatal("invalid activation restarted a program")
	}
}

func TestManagedDNSInvalidRollbackPreservesWorkingBundle(t *testing.T) {
	for _, mode := range []string{"ordinary", "subscription", "hot-scope"} {
		t.Run(mode, func(t *testing.T) {
			native, candidate, controller, expected := managedDNSPublicationFixture(t)
			receipt, err := native.store.Activate(candidate)
			if err != nil {
				t.Fatal(err)
			}
			legacyCore, _ := legacyManagedDNSFixture(t, expected)
			if err := os.WriteFile(filepath.Join(candidate.Directory, ".previous-runtime", "xray.json"), legacyCore, 0600); err != nil {
				t.Fatal(err)
			}
			coreBefore, dnsBefore := mustReadFile(t, native.options.XrayConfig), mustReadFile(t, native.options.PolicyDNSConfig)
			switch mode {
			case "ordinary":
				err = native.rollback(context.Background(), receipt)
			case "subscription":
				err = native.rollbackSubscription(context.Background(), receipt)
			case "hot-scope":
				_, err = native.restoreHotPolicyScope(receipt)
			}
			if err == nil {
				t.Fatal("mixed restoring pair was published")
			}
			if !bytes.Equal(coreBefore, mustReadFile(t, native.options.XrayConfig)) || !bytes.Equal(dnsBefore, mustReadFile(t, native.options.PolicyDNSConfig)) {
				t.Fatal("invalid rollback replaced working files")
			}
			if len(controller.restarts) != 0 || len(controller.probes) != 0 {
				t.Fatal("invalid rollback restarted a program")
			}
		})
	}
}

func TestManagedDNSGoToGoApplyUsesOnlyRequestedRestarts(t *testing.T) {
	native, candidate, controller, _ := managedDNSPublicationFixture(t)
	observed := 0
	controller.observe = func() {
		if _, err := os.Stat(native.options.ApplyGuardFile); err != nil {
			t.Fatal("restart/probe ran without Apply guard")
		}
		observed++
	}
	if _, err := native.activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(controller.restarts, [][]string{{"xray", "dns"}}) || !reflect.DeepEqual(controller.probes, controller.restarts) || observed != 2 {
		t.Fatalf("extra or missing Go-to-Go restart: %v %v", controller.restarts, controller.probes)
	}
	if _, err := os.Stat(native.options.ApplyGuardFile); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("Apply guard was not released")
	}
}

func TestManagedDNSScopedMappedRollbackPreservesWorkingBundle(t *testing.T) {
	for _, mode := range []string{"ordinary", "subscription", "hot-scope"} {
		t.Run(mode, func(t *testing.T) {
			native, candidate, controller, expected := managedDNSPublicationFixture(t)
			receipt, err := native.store.Activate(candidate)
			if err != nil {
				t.Fatal(err)
			}
			var dns map[string]any
			if err := json.Unmarshal(expected["policy-dns.json"], &dns); err != nil {
				t.Fatal(err)
			}
			listeners := objects(objectAt(dns, "managed_ingress")["listeners"])
			if len(listeners) != 1 {
				t.Fatal("fixture must contain exactly one managed Go listener")
			}
			listeners[0]["host"] = "::ffff:198.18.0.2%eth0"
			badBackup, err := json.Marshal(dns)
			if err != nil {
				t.Fatal(err)
			}
			backupPath := filepath.Join(candidate.Directory, ".previous-runtime", "policy-dns.json")
			if err := os.WriteFile(backupPath, badBackup, 0600); err != nil {
				t.Fatal(err)
			}
			coreBefore := mustReadFile(t, native.options.XrayConfig)
			dnsBefore := mustReadFile(t, native.options.PolicyDNSConfig)
			switch mode {
			case "ordinary":
				err = native.rollback(context.Background(), receipt)
			case "subscription":
				err = native.rollbackSubscription(context.Background(), receipt)
			case "hot-scope":
				_, err = native.restoreHotPolicyScope(receipt)
			}
			if err == nil {
				t.Fatal("scoped mapped Go backup was accepted for rollback")
			}
			if !bytes.Equal(coreBefore, mustReadFile(t, native.options.XrayConfig)) ||
				!bytes.Equal(dnsBefore, mustReadFile(t, native.options.PolicyDNSConfig)) {
				t.Fatal("invalid scoped backup replaced the working bundle")
			}
			if !bytes.Equal(badBackup, mustReadFile(t, backupPath)) {
				t.Fatal("rollback inspection modified the backup")
			}
			if len(controller.restarts) != 0 || len(controller.probes) != 0 {
				t.Fatal("invalid scoped backup restarted or probed a program")
			}
		})
	}
}
