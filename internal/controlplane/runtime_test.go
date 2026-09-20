package controlplane

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

type recordingRuntimeController struct {
	restarts [][]string
	probes   [][]string
	observe  func()
}

func (controller *recordingRuntimeController) Restart(_ context.Context, names []string) error {
	if controller.observe != nil {
		controller.observe()
	}
	controller.restarts = append(controller.restarts, append([]string(nil), names...))
	return nil
}

func (controller *recordingRuntimeController) Probe(_ context.Context, names []string) error {
	if controller.observe != nil {
		controller.observe()
	}
	controller.probes = append(controller.probes, append([]string(nil), names...))
	return nil
}

func TestNativeRuntimeValidatesAndRestartsOnlyChangedPrograms(t *testing.T) {
	root := t.TempDir()
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	destinations := map[string]string{
		"xray.json":  filepath.Join(root, "live", "xray.json"),
		"nginx.conf": filepath.Join(root, "live", "nginx.conf"),
	}
	store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "state"), destinations)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(destinations["xray.json"]), 0o700); err != nil {
		t.Fatal(err)
	}
	for name, body := range map[string]string{"xray.json": "same\n", "nginx.conf": "old\n"} {
		if err := os.WriteFile(destinations[name], []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	candidate, err := store.Prepare(strings.Repeat("b", 64), map[string][]byte{
		"xray.json": []byte("same\n"), "nginx.conf": []byte("new\n"),
	})
	if err != nil {
		t.Fatal(err)
	}
	guardPath := filepath.Join(root, "run", "apply-in-progress")
	guardObservations := 0
	controller := &recordingRuntimeController{observe: func() {
		body, readErr := os.ReadFile(guardPath)
		if readErr != nil {
			t.Fatalf("runtime operation has no watchdog guard: %v", readErr)
		}
		if fields := strings.Fields(string(body)); len(fields) != 3 {
			t.Fatalf("invalid watchdog guard %q", body)
		}
		guardObservations++
	}}
	runtime := &nativeRuntime{options: RuntimeOptions{ApplyGuardFile: guardPath}, store: store, controller: controller}
	var validated []string
	runtime.validate = func(_ context.Context, _ runtimeconfig.RuntimeCandidate, changed []string) error {
		validated = append([]string(nil), changed...)
		return nil
	}
	receipt, err := runtime.activate(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(validated, []string{"nginx.conf"}) ||
		!reflect.DeepEqual(controller.restarts, [][]string{{"nginx"}}) ||
		!reflect.DeepEqual(controller.probes, [][]string{{"nginx"}}) {
		t.Fatalf("validated=%v restarts=%v probes=%v", validated, controller.restarts, controller.probes)
	}
	if body, _ := os.ReadFile(destinations["nginx.conf"]); string(body) != "new\n" {
		t.Fatalf("published nginx = %q", body)
	}
	if _, statErr := os.Stat(guardPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("watchdog guard remained after activate: %v", statErr)
	}
	if err := runtime.rollback(context.Background(), receipt); err != nil {
		t.Fatal(err)
	}
	if body, _ := os.ReadFile(destinations["nginx.conf"]); string(body) != "old\n" {
		t.Fatalf("rolled back nginx = %q", body)
	}
	if len(controller.restarts) != 2 || len(controller.probes) != 2 {
		t.Fatalf("rollback did not reconcile process: %#v %#v", controller.restarts, controller.probes)
	}
	if guardObservations != 4 {
		t.Fatalf("watchdog guard observations = %d, want 4", guardObservations)
	}
}

func TestArtifactRevisionIsStableAndContentAddressed(t *testing.T) {
	first := artifactRevision(map[string][]byte{"b": []byte("two"), "a": []byte("one")})
	second := artifactRevision(map[string][]byte{"a": []byte("one"), "b": []byte("two")})
	changed := artifactRevision(map[string][]byte{"a": []byte("one"), "b": []byte("three")})
	if first != second || first == changed || len(first) != 64 {
		t.Fatalf("unexpected revisions: %q %q %q", first, second, changed)
	}
}

func TestNativeRuntimePublishesPrevalidatedMarkerBeforeXrayRestart(t *testing.T) {
	root := t.TempDir()
	live := filepath.Join(root, "live", "xray.json")
	if err := os.MkdirAll(filepath.Dir(live), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(live, []byte("old\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "state"), map[string]string{"xray.json": live})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("new\n")
	candidate, err := store.Prepare(strings.Repeat("c", 64), map[string][]byte{"xray.json": body})
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(root, "run", "xray-prevalidated.sha256")
	guard := filepath.Join(root, "run", "apply-in-progress")
	wantDigest := sha256.Sum256(body)
	controller := &recordingRuntimeController{observe: func() {
		got, readErr := os.ReadFile(marker)
		if readErr != nil {
			t.Fatalf("prevalidation marker missing during restart: %v", readErr)
		}
		if strings.TrimSpace(string(got)) != hex.EncodeToString(wantDigest[:]) {
			t.Fatalf("prevalidation marker=%q", got)
		}
	}}
	runtime := &nativeRuntime{
		options: RuntimeOptions{ApplyGuardFile: guard, XrayPrevalidatedMarker: marker, XrayConfig: live},
		store:   store, controller: controller,
		validate: func(context.Context, runtimeconfig.RuntimeCandidate, []string) error { return nil },
	}
	if _, err := runtime.activate(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(controller.restarts, [][]string{{"xray"}}) {
		t.Fatalf("restarts=%v", controller.restarts)
	}
}

func TestAffectedProgramsAreUniqueAndStable(t *testing.T) {
	got := affectedPrograms([]string{
		"transparent-exclusions.txt", "xray.json", "urltest-pool.json", "policy-dns.json", "nginx.conf", "watchdog.env",
	})
	want := []string{"dns", "monitor", "nginx", "xray"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("affected programs = %v", got)
	}
}

func TestHealthPoolChangeIsReconciledWithoutProcessRestart(t *testing.T) {
	if got := affectedPrograms([]string{"urltest-pool.json"}); len(got) != 0 {
		t.Fatalf("health pool change restarted programs: %v", got)
	}
}

func TestSubscriptionActivationWaitsForHotSelectorGenerationWithoutRestartingXray(t *testing.T) {
	root := t.TempDir()
	liveRoot := filepath.Join(root, "live")
	if err := os.MkdirAll(liveRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	destinations := map[string]string{
		"xray.json":         filepath.Join(liveRoot, "xray.json"),
		"urltest-pool.json": filepath.Join(liveRoot, "urltest-pool.json"),
	}
	for name, body := range map[string]string{"xray.json": "old-xray\n", "urltest-pool.json": "old-pool\n"} {
		if err := os.WriteFile(destinations[name], []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	store, err := runtimeconfig.NewCandidateStore(filepath.Join(root, "state"), destinations)
	if err != nil {
		t.Fatal(err)
	}
	poolBody := []byte("new-pool\n")
	candidate, err := store.Prepare(strings.Repeat("d", 64), map[string][]byte{
		"xray.json": []byte("new-xray\n"), "urltest-pool.json": poolBody,
	})
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(root, "run", "xray-ready")
	hotReady := filepath.Join(root, "run", "xray-hot-ready.json")
	if err := os.MkdirAll(filepath.Dir(ready), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, []byte("4321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(poolBody)
	published := make(chan error, 1)
	controller := &recordingRuntimeController{}
	runtime := &nativeRuntime{
		options: RuntimeOptions{XrayHealthPool: destinations["urltest-pool.json"], XrayReadyFile: ready, XrayHotRuntimeReadyFile: hotReady},
		store:   store, controller: controller,
		validate: func(context.Context, runtimeconfig.RuntimeCandidate, []string) error {
			go func() {
				time.Sleep(100 * time.Millisecond)
				info, statErr := os.Stat(destinations["urltest-pool.json"])
				if statErr != nil {
					published <- statErr
					return
				}
				marker := []byte(`{"pool_sha256":"` + hex.EncodeToString(digest[:]) + `","pool_mtime_unix_nano":` + fmt.Sprint(info.ModTime().UnixNano()) + `,"xray_pid":4321}`)
				published <- os.WriteFile(hotReady, marker, 0o600)
			}()
			return nil
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := runtime.activateSubscription(ctx, candidate); err != nil {
		t.Fatal(err)
	}
	if err := <-published; err != nil {
		t.Fatal(err)
	}
	if len(controller.restarts) != 0 || len(controller.probes) != 0 {
		t.Fatalf("hot subscription activation restarted processes: restarts=%v probes=%v", controller.restarts, controller.probes)
	}
}

func TestHotRuntimeMarkerRejectsEarlierPublicationOfSamePoolContent(t *testing.T) {
	root := t.TempDir()
	pool := filepath.Join(root, "pool.json")
	ready := filepath.Join(root, "xray-ready")
	marker := filepath.Join(root, "hot-ready.json")
	if err := os.WriteFile(pool, []byte("same-pool\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	digest, mtime, err := hashFileGeneration(pool)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(ready, []byte("4321\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stale := []byte(fmt.Sprintf(`{"pool_sha256":%q,"pool_mtime_unix_nano":%d,"xray_pid":4321}`, digest, mtime-1))
	if err := os.WriteFile(marker, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	runtime := &nativeRuntime{options: RuntimeOptions{XrayReadyFile: ready, XrayHotRuntimeReadyFile: marker}}
	staleCtx, staleCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	err = runtime.waitHotRuntime(staleCtx, pool)
	staleCancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stale marker accepted: %v", err)
	}
	fresh := []byte(fmt.Sprintf(`{"pool_sha256":%q,"pool_mtime_unix_nano":%d,"xray_pid":4321}`, digest, mtime))
	if err := os.WriteFile(marker, fresh, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runtime.waitHotRuntime(context.Background(), pool); err != nil {
		t.Fatal(err)
	}
}

func TestNativeRuntimePreservesConfiguredSubscriptionRelaySource(t *testing.T) {
	t.Setenv("SB_GATEWAY_SUBSCRIPTION_RELAY_SOURCE", "172.30.78.1/32")
	options := RuntimeOptionsFromEnvironment()
	if options.SubscriptionRelaySource != "172.30.78.1/32" {
		t.Fatalf("subscription relay source = %q", options.SubscriptionRelaySource)
	}
	runtime := &nativeRuntime{options: options}
	render := runtime.nginxRenderOptions("nginx-template")
	if render.Template != "nginx-template" || render.SubscriptionRelaySource != "172.30.78.1/32" {
		t.Fatalf("nginx render options = %#v", render)
	}
}
