package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"testing/synctest"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

// Import through the real refresh/identity reconciliation boundary and render
// both immutable generations. Only the process controller below is simulated.
func subscriptionCatalogStartupPair(t *testing.T, placement, change string) (map[string][]byte, map[string][]byte) {
	t.Helper()
	server, cookie, csrf := catalogIntegrationServer(t, "provider")
	old := "vless://" + catalogIntegrationUUID + "@edge.example.test:443?security=tls&sni=edge.example.test&type=ws&host=front.example.test&path=%2Fold#Stable"
	next := old
	switch change {
	case "credential":
		next = "vless://223e4567-e89b-42d3-a456-426614174000@edge.example.test:443?security=tls&sni=edge.example.test&type=ws&host=front.example.test&path=%2Fold#Stable"
	case "sni":
		next = replaceStartupText(t, old, "sni=edge.example.test", "sni=next.example.test")
	case "host":
		next = replaceStartupText(t, old, "host=front.example.test", "host=next-front.example.test")
	case "path":
		next = replaceStartupText(t, old, "path=%2Fold", "path=%2Fnext")
	case "metadata":
		next = replaceStartupText(t, old, "#Stable", "#Renamed")
	default:
		t.Fatal("unknown synthetic change")
	}
	catalogIntegrationRefresh(t, server, cookie, csrf, "provider", []byte(old), 1893456000)
	draft, _, catalog := catalogIntegrationAdapter(t, server)
	var first runtimeconfig.RuntimeCatalogNode
	if err := catalog.WalkMetadata(context.Background(), func(node runtimeconfig.RuntimeCatalogNode) error { first = node; return nil }); err != nil {
		t.Fatal(err)
	}
	state, err := server.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}
	rows := runtimeSubscriptionNodes(draft, state)
	var config map[string]any
	before, native := catalogIntegrationNative(t, server, draft["subscriptions"], rows, "group:all", func(value map[string]any) {
		config = value
		policy := objects(config["policies"])[0]
		switch placement {
		case "final":
			policy["final"] = first.ID
		case "service":
			policy["service_routes"] = map[string]any{"bybit": first.ID}
		case "dynamic":
		default:
			t.Fatal("unknown synthetic placement")
		}
	})
	read := func(candidate runtimeconfig.RuntimeCandidate) map[string][]byte {
		result := make(map[string][]byte)
		for _, name := range []string{"xray.json", "urltest-pool.json", "policy-dns.json"} {
			result[name] = mustReadFile(t, candidate.Files[name])
		}
		return result
	}
	previous := read(before)
	catalogIntegrationRefresh(t, server, cookie, csrf, "provider", []byte(next), 1893456000)
	draft, _, catalog = catalogIntegrationAdapter(t, server)
	var second runtimeconfig.RuntimeCatalogNode
	if err := catalog.WalkMetadata(context.Background(), func(node runtimeconfig.RuntimeCatalogNode) error { second = node; return nil }); err != nil {
		t.Fatal(err)
	}
	if first.ID == "" || first.ID != second.ID || first.Generation == second.Generation {
		t.Fatal("refresh did not preserve the stable ID across distinct catalog generations")
	}
	if (first.Fingerprint == second.Fingerprint) != (change == "metadata") {
		t.Fatal("connection fingerprint does not distinguish semantic from cosmetic changes")
	}
	state, err = server.repository.auxiliary("subscription-nodes")
	if err != nil {
		t.Fatal(err)
	}
	after, err := native.prepare(config, runtimeSubscriptionNodes(draft, state))
	if err != nil {
		t.Fatal(err)
	}
	target := read(after)
	for _, artifacts := range []map[string][]byte{previous, target} {
		var pool struct {
			Base        []string                                   `json:"base_outbound_tags"`
			Definitions map[string]runtimeconfig.CatalogDefinition `json:"catalog_definitions"`
		}
		if err := json.Unmarshal(artifacts["urltest-pool.json"], &pool); err != nil {
			t.Fatal(err)
		}
		_, dynamic := pool.Definitions[first.ID]
		if dynamic != (placement == "dynamic") || containsRuntimeArtifact(pool.Base, first.ID) == dynamic {
			t.Fatal("rendered catalog leaf has the wrong static/dynamic activation contract")
		}
	}
	return previous, target
}

func replaceStartupText(t *testing.T, value, old, next string) string {
	t.Helper()
	if !bytes.Contains([]byte(value), []byte(old)) {
		t.Fatal("synthetic replacement has no source")
	}
	return string(bytes.ReplaceAll([]byte(value), []byte(old), []byte(next)))
}

func subscriptionStartupFixture(t *testing.T, previous, target map[string][]byte) (*nativeRuntime, runtimeconfig.RuntimeCandidate, *subscriptionGeometryController) {
	t.Helper()
	native, candidate, controller := subscriptionGeometryFixtureWithPools(t, previous["xray.json"], target["xray.json"], previous["urltest-pool.json"], target["urltest-pool.json"])
	// A rollback must validate the real core/DNS ownership pair, even though
	// these tests only exercise publication of the core and health pool.
	native.options.PolicyDNSConfig = filepath.Join(t.TempDir(), "policy-dns.json")
	if err := os.WriteFile(native.options.PolicyDNSConfig, previous["policy-dns.json"], 0600); err != nil {
		t.Fatal(err)
	}
	return native, candidate, controller
}

func TestSubscriptionStaticCatalogStartupReloadsAndRollsBack(t *testing.T) {
	for _, placement := range []string{"final", "service"} {
		for _, change := range []string{"credential", "sni", "host", "path"} {
			t.Run(placement+"/"+change, func(t *testing.T) {
				previous, target := subscriptionCatalogStartupPair(t, placement, change)
				if bytes.Equal(previous["xray.json"], target["xray.json"]) {
					t.Fatal("static definition rotation did not reach the startup artifact")
				}
				synctest.Test(t, func(t *testing.T) {
					native, candidate, controller := subscriptionStartupFixture(t, previous, target)
					// The old handler remains healthy. An agent can acknowledge the
					// new pool using the same selected ID without loading new bytes.
					live := previous["xray.json"]
					hooks := 0
					hook := func(context.Context) error { hooks++; return nil }
					controller.observe = func() {
						if hooks != controller.restarts {
							t.Fatal("static core restarted before planned fail-open hook")
						}
						live = mustReadFile(t, native.options.XrayConfig)
					}
					type result struct {
						receipt runtimeconfig.ActivationReceipt
						err     error
					}
					done := make(chan result, 1)
					go func() {
						receipt, err := native.activateSubscriptionWithXrayRestartHook(context.Background(), candidate, hook)
						done <- result{receipt, err}
					}()
					synctest.Wait()
					// This deliberately reproduces the formerly sufficient hot ack.
					// It must never substitute for loading the static startup graph.
					acknowledgeTestPool(t, native)
					outcome := <-done
					if outcome.err != nil || controller.restarts != 1 || controller.probes != 1 || !bytes.Equal(live, target["xray.json"]) {
						t.Fatalf("static activation accepted an unloaded definition: err=%v restarts=%d probes=%d", outcome.err, controller.restarts, controller.probes)
					}
					if err := native.rollbackSubscriptionWithXrayRestartHook(context.Background(), outcome.receipt, hook); err != nil {
						t.Fatal(err)
					}
					if hooks != 2 || controller.restarts != 2 || controller.probes != 2 || !bytes.Equal(live, previous["xray.json"]) || native.subscriptionRestartPending.Load() {
						t.Fatal("rollback did not reload the previous static definition")
					}
				})
			})
		}
	}
}

func TestSubscriptionCatalogDynamicAndCosmeticRefreshStayHot(t *testing.T) {
	for _, scenario := range [][2]string{{"dynamic", "credential"}, {"final", "metadata"}, {"service", "metadata"}} {
		t.Run(scenario[0]+"/"+scenario[1], func(t *testing.T) {
			previous, target := subscriptionCatalogStartupPair(t, scenario[0], scenario[1])
			if !bytes.Equal(previous["xray.json"], target["xray.json"]) || bytes.Equal(previous["urltest-pool.json"], target["urltest-pool.json"]) {
				t.Fatal("hot fixture did not isolate the pool change from the startup graph")
			}
			synctest.Test(t, func(t *testing.T) {
				native, candidate, controller := subscriptionStartupFixture(t, previous, target)
				type result struct {
					receipt runtimeconfig.ActivationReceipt
					err     error
				}
				done := make(chan result, 1)
				go func() {
					receipt, err := native.activateSubscription(context.Background(), candidate)
					done <- result{receipt, err}
				}()
				synctest.Wait()
				acknowledgeTestPool(t, native)
				outcome := <-done
				if outcome.err != nil {
					t.Fatal(outcome.err)
				}
				rollback := make(chan error, 1)
				go func() { rollback <- native.rollbackSubscription(context.Background(), outcome.receipt) }()
				synctest.Wait()
				acknowledgeTestPool(t, native)
				if err := <-rollback; err != nil {
					t.Fatal(err)
				}
				if controller.restarts != 0 || controller.probes != 0 || native.subscriptionRestartPending.Load() {
					t.Fatal("dynamic-only or cosmetic refresh restarted the core")
				}
			})
		})
	}
}

func TestSubscriptionStaticStartupFailureRetainsRestartAndPreviousLKG(t *testing.T) {
	previous, target := subscriptionCatalogStartupPair(t, "final", "credential")
	for _, failure := range []string{"hook", "restart", "probe"} {
		t.Run(failure, func(t *testing.T) {
			native, _, controller := subscriptionStartupFixture(t, previous, target)
			oldArtifacts := map[string][]byte{"xray.json": previous["xray.json"], "urltest-pool.json": previous["urltest-pool.json"]}
			baseline, err := native.store.Prepare(artifactRevision(oldArtifacts), oldArtifacts)
			if err != nil {
				t.Fatal(err)
			}
			if err := native.commit(baseline); err != nil {
				t.Fatal(err)
			}
			lkg := filepath.Join(filepath.Dir(filepath.Dir(baseline.Directory)), "runtime-lkg", "xray.json")
			newArtifacts := map[string][]byte{"xray.json": target["xray.json"], "urltest-pool.json": target["urltest-pool.json"]}
			candidate, err := native.store.Prepare(artifactRevision(newArtifacts), newArtifacts)
			if err != nil {
				t.Fatal(err)
			}
			injected := errors.New("injected static activation failure")
			hook := func(context.Context) error { return nil }
			switch failure {
			case "hook":
				hook = func(context.Context) error { return injected }
			case "restart":
				controller.restartErr = injected
			case "probe":
				controller.probeErr = injected
			}
			receipt, err := native.activateSubscriptionWithXrayRestartHook(context.Background(), candidate, hook)
			if !errors.Is(err, injected) || !native.subscriptionRestartPending.Load() {
				t.Fatalf("failed static activation lost restart obligation: %v", err)
			}
			if !bytes.Equal(mustReadFile(t, lkg), previous["xray.json"]) {
				t.Fatal("failed activation published the new definition as LKG")
			}
			before := controller.restarts
			controller.restartErr, controller.probeErr = nil, nil
			if err := native.rollbackSubscription(context.Background(), receipt); err != nil {
				t.Fatal(err)
			}
			if controller.restarts != before+1 || native.subscriptionRestartPending.Load() || !bytes.Equal(mustReadFile(t, native.options.XrayConfig), previous["xray.json"]) {
				t.Fatal("failed static activation did not restore and reload its previous graph")
			}
		})
	}
}

func TestSubscriptionStartupGraphComparisonIsSemanticAndFailClosed(t *testing.T) {
	for _, test := range []struct {
		name, before, after string
		changed, invalid    bool
	}{
		{"object-order", `{"outbounds":[{"tag":"a","settings":{}}]}`, ` {"outbounds":[{"settings":{},"tag":"a"}]} `, false, false},
		{"large-integer", `{"policy":{"n":9007199254740992}}`, `{"policy":{"n":9007199254740993}}`, true, false},
		{"static-body", `{"outbounds":[{"tag":"a","settings":{"v":1}}]}`, `{"outbounds":[{"tag":"a","settings":{"v":2}}]}`, true, false},
		{"outbound-order", `{"outbounds":[{"tag":"a"},{"tag":"b"}]}`, `{"outbounds":[{"tag":"b"},{"tag":"a"}]}`, true, false},
		{"null", `{}`, `null`, false, true},
		{"trailing", `{}`, `{} {}`, false, true},
		{"malformed", `{}`, `{"outbounds":`, false, true},
		{"duplicate-probe", `{}`, `{"inbounds":[{"tag":"outbound-health-probe"},{"tag":"outbound-health-probe"}]}`, false, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			before, after := filepath.Join(root, "before.json"), filepath.Join(root, "after.json")
			for path, value := range map[string]string{before: test.before, after: test.after} {
				if err := os.WriteFile(path, []byte(value), 0600); err != nil {
					t.Fatal(err)
				}
			}
			changed, err := subscriptionStartupGraphChanged(before, after)
			if (err != nil) != test.invalid || (err == nil && changed != test.changed) {
				t.Fatalf("changed=%t err=%v", changed, err)
			}
		})
	}
}
