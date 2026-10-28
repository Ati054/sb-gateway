package appliance

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNginxReloadRequiresValidatedConfigurationAndNewWorker(t *testing.T) {
	for _, reason := range []string{"ready", "invalid", "signal-failed", "no-new-worker", "master-gone", "no-workers"} {
		t.Run(reason, func(t *testing.T) {
			reads := 0
			workers := func() (map[string]bool, error) {
				reads++
				if reason == "no-workers" {
					return nil, nil
				}
				if reads > 1 && reason == "master-gone" {
					return nil, os.ErrNotExist
				}
				if reads > 2 && reason == "ready" {
					return map[string]bool{"10": true, "11": true}, nil
				}
				return map[string]bool{"10": true}, nil
			}
			var commands []string
			run := func(args ...string) error {
				commands = append(commands, strings.Join(args, " "))
				if (reason == "invalid" && args[0] == "-t") || (reason == "signal-failed" && args[0] == "-s") {
					return errors.New(reason)
				}
				return nil
			}
			ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
			defer cancel()
			err := reloadNginxWith(ctx, "/config/nginx.conf", workers, run)
			if (err == nil) != (reason == "ready") {
				t.Fatalf("err=%v for %s", err, reason)
			}
			if reason == "invalid" && len(commands) != 1 {
				t.Fatal("invalid configuration was signalled")
			}
			if reason == "no-workers" && len(commands) != 0 {
				t.Fatal("no live master/worker was accepted")
			}
			if reason == "ready" && !reflect.DeepEqual(commands, []string{"-t -c /config/nginx.conf", "-s reload -c /config/nginx.conf"}) {
				t.Fatalf("commands: %v", commands)
			}
		})
	}
}

func TestNginxWorkersIgnoresCacheManagerExitedAndDrainingProcesses(t *testing.T) {
	proc := t.TempDir()
	write := func(path, body string) {
		t.Helper()
		path = filepath.Join(proc, path)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("5/task/5/children", "10 11 12 13 14")
	write("10/cmdline", "nginx: worker process\x00")
	write("10/stat", "10 (nginx) S 5 0")
	write("11/cmdline", "nginx: cache manager process\x00")
	write("11/stat", "11 (nginx) S 5 0")
	write("12/cmdline", "nginx: worker process\x00")
	write("12/stat", "12 (nginx) Z 5 0")
	write("13/cmdline", "nginx: worker process is shutting down\x00")
	write("13/stat", "13 (nginx) S 5 0")
	got, err := nginxWorkers(proc, 5)
	if err != nil || !reflect.DeepEqual(got, map[string]bool{"10": true}) {
		t.Fatalf("workers=%v err=%v", got, err)
	}
}

func TestSupervisorReloadKeepsServingProcessAndPropagatesFailure(t *testing.T) {
	var runs, reloads atomic.Int32
	program := blockingProgram("nginx", &runs)
	program.Reload = func(context.Context) error {
		if reloads.Add(1) == 2 {
			return errors.New("bad reload")
		}
		return nil
	}
	s, err := NewSupervisor([]Program{program})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitRuns(t, &runs, 1)
	request, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := s.Restart(request, []string{"nginx", "nginx"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Restart(request, []string{"nginx"}); err == nil || !strings.Contains(err.Error(), "bad reload") {
		t.Fatalf("reload failure: %v", err)
	}
	if err := s.Restart(request, []string{"nginx"}); err != nil {
		t.Fatal(err)
	}
	if runs.Load() != 1 || reloads.Load() != 3 || s.Status()[0].Generation != 1 {
		t.Fatalf("restart instead of reload: runs=%d reloads=%d", runs.Load(), reloads.Load())
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
