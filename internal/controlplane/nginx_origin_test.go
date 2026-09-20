package controlplane

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestOriginCIDRReloadRestoresLastGoodAndSkipsUnchanged(t *testing.T) {
	root := t.TempDir()
	if err := initializeOriginCIDRs(root); err != nil {
		t.Fatal(err)
	}
	controller := &recordingRuntimeController{}
	runtime := &nativeRuntime{options: RuntimeOptions{OriginCIDRRoot: root}, controller: controller}
	calls := 0
	fail := false
	runtime.nginxCommand = func(context.Context, ...string) error {
		calls++
		if fail {
			fail = false
			return errors.New("nginx -t failed")
		}
		return nil
	}
	ctx := context.Background()
	if err := runtime.updateOriginCIDRs(ctx, "gcore", []string{"8.8.8.0/24"}); err != nil {
		t.Fatal(err)
	}
	if calls != 2 || len(controller.restarts) != 0 {
		t.Fatal("not a graceful reload", calls, controller.restarts)
	}
	if err := runtime.updateOriginCIDRs(ctx, "gcore", []string{"8.8.8.0/24"}); err != nil || calls != 2 {
		t.Fatal("unchanged list reloaded")
	}
	fail = true
	if err := runtime.updateOriginCIDRs(ctx, "gcore", []string{"1.1.1.0/24"}); err == nil {
		t.Fatal("failed validation accepted")
	}
	body, err := os.ReadFile(filepath.Join(root, "gcore", "addresses.conf"))
	if err != nil || string(body) != "8.8.8.0/24 1;\n" {
		t.Fatal("old list lost", string(body), err)
	}
	if err := initializeOriginCIDRs(root); err != nil {
		t.Fatal(err)
	}
	body, _ = os.ReadFile(filepath.Join(root, "gcore", "addresses.conf"))
	if string(body) != "8.8.8.0/24 1;\n" {
		t.Fatal("restart wiped list")
	}
	before := calls
	if runtime.updateOriginCIDRs(ctx, "gcore", []string{"0.0.0.0/0"}) == nil || calls != before {
		t.Fatal("unsafe list reached nginx")
	}
}

func TestSharedSocketRestartOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nginx.conf")
	runtime := &nativeRuntime{options: RuntimeOptions{NginxConfig: path}}
	for _, tc := range []struct {
		source string
		want   []string
	}{{"stream { ssl_preread on; }", []string{"xray", "nginx"}}, {"http {}", []string{"nginx", "xray"}}} {
		if err := os.WriteFile(path, []byte(tc.source), 0600); err != nil {
			t.Fatal(err)
		}
		if got := runtime.restartOrder([]string{"xray.json", "nginx.conf"}); !reflect.DeepEqual(got, tc.want) {
			t.Fatal(got, tc.want)
		}
	}
}
