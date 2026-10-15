package controlplane

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestDiagnosticLogMaintenanceUsesOnlyManagedPathsAndReopen(t *testing.T) {
	root := t.TempDir()
	opts := RuntimeOptions{XrayErrorLog: filepath.Join(root, "xray-error"), XrayProcessLog: filepath.Join(root, "xray-process"), NginxErrorLog: filepath.Join(root, "nginx-error"), NginxPublicErrorLog: filepath.Join(root, "nginx-public"), NginxConfig: filepath.Join(root, "nginx.conf")}
	s := &Server{opts: Options{Runtime: opts}}
	calls := 0
	s.runtime = &nativeRuntime{nginxCommand: func(_ context.Context, args ...string) error {
		calls++
		if !reflect.DeepEqual(args, []string{"-s", "reopen", "-c", opts.NginxConfig, "-p", "/"}) {
			t.Fatalf("unexpected Nginx operation %v", args)
		}
		for _, path := range []string{opts.NginxErrorLog, opts.NginxPublicErrorLog} {
			if err := os.WriteFile(path, nil, 0600); err != nil {
				return err
			}
		}
		return nil
	}}
	for _, path := range []string{opts.XrayErrorLog, opts.XrayProcessLog, opts.NginxErrorLog, opts.NginxPublicErrorLog} {
		if err := os.WriteFile(path, []byte(strings.Repeat("x", externalLogMaximum+1024)), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := s.diagnosticLogRotator()
	if err := r.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("reopen count %d", calls)
	}
	for _, path := range append(r.AppendPaths, r.ReopenPaths...) {
		info, err := os.Stat(path + ".1")
		if err != nil || info.Size() != externalLogMaximum {
			t.Fatalf("unbounded archive %v", err)
		}
	}
	if err := r.Check(context.Background()); err != nil || calls != 1 {
		t.Fatalf("idle pass %v calls=%d", err, calls)
	}
}

func TestDiagnosticLogMaintenanceStopsDuringReopen(t *testing.T) {
	root := t.TempDir()
	opts := RuntimeOptions{XrayErrorLog: filepath.Join(root, "xray-error"), XrayProcessLog: filepath.Join(root, "xray-process"), NginxErrorLog: filepath.Join(root, "nginx-error"), NginxPublicErrorLog: filepath.Join(root, "nginx-public")}
	if err := os.WriteFile(opts.NginxErrorLog, []byte(strings.Repeat("x", externalLogMaximum+1)), 0600); err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{})
	s := &Server{opts: Options{Runtime: opts}, runtime: &nativeRuntime{nginxCommand: func(ctx context.Context, _ ...string) error { close(entered); <-ctx.Done(); return ctx.Err() }}}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { defer close(done); s.runDiagnosticLogMaintenance(ctx) }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("maintenance did not enter reopen")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("maintenance leaked during cancellation")
	}
}
