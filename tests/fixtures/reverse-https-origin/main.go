package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

type clientProcess struct {
	mu     sync.Mutex
	ctx    context.Context
	binary string
	work   string
	log    io.Writer
	cmd    *exec.Cmd
	done   chan error
}

func (client *clientProcess) launch() error {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.ctx.Err() != nil || client.cmd != nil {
		return nil
	}
	validation := exec.CommandContext(client.ctx, client.binary, "run", "-test", "-config", filepath.Join(client.work, "client.json"))
	validation.Stdout, validation.Stderr = client.log, client.log
	if err := validation.Run(); err != nil {
		return err
	}
	cmd := exec.Command(client.binary, "run", "-config", filepath.Join(client.work, "client.json"))
	cmd.Stdout, cmd.Stderr = client.log, client.log
	if err := cmd.Start(); err != nil {
		return err
	}
	client.cmd, client.done = cmd, make(chan error, 1)
	done := client.done
	go func() { done <- cmd.Wait() }()
	return nil
}

func (client *clientProcess) terminate() {
	client.mu.Lock()
	defer client.mu.Unlock()
	if client.cmd == nil {
		return
	}
	_ = client.cmd.Process.Signal(os.Interrupt)
	select {
	case <-client.done:
	case <-time.After(3 * time.Second):
		_ = client.cmd.Process.Kill()
		<-client.done
	}
	client.cmd = nil
}

func wait(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-ctx.Done():
		return false
	}
}

func run(ctx context.Context, work, binary string) error {
	log, err := os.OpenFile(filepath.Join(work, "client.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer log.Close()
	client := &clientProcess{ctx: ctx, binary: binary, work: work, log: log}
	defer client.terminate()
	go func() {
		for wait(ctx, 100*time.Millisecond) {
			if _, err := os.Stat(filepath.Join(work, "client.json")); err == nil {
				if wait(ctx, 3*time.Second) {
					if err := client.launch(); err != nil {
						fmt.Fprintln(log, "fixture client start:", err)
					}
				}
				return
			}
		}
	}()
	var delay atomic.Int64
	var reconnecting atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/data":
			w.WriteHeader(http.StatusNoContent)
			return
		case "/bulk", "/bulk/paced":
			w.Header().Set("Content-Length", "8388608")
			w.WriteHeader(http.StatusOK)
			block := make([]byte, 64*1024)
			for range 128 {
				if _, err := w.Write(block); err != nil {
					return
				}
				if r.URL.Path == "/bulk/paced" && !wait(r.Context(), 10*time.Millisecond) {
					return
				}
			}
			return
		case "/mode/slow":
			delay.Store(int64(4 * time.Second))
		case "/mode/silent":
			delay.Store(int64(30 * time.Second))
		case "/mode/normal":
			delay.Store(0)
		case "/mode/stop":
			if reconnecting.CompareAndSwap(false, true) {
				go func() {
					defer reconnecting.Store(false)
					if !wait(ctx, 400*time.Millisecond) {
						return
					}
					client.terminate()
					if wait(ctx, 12*time.Second) {
						if err := client.launch(); err != nil {
							fmt.Fprintln(log, "fixture client reconnect:", err)
						}
					}
				}()
			}
		default:
			if !wait(r.Context(), time.Duration(delay.Load())) {
				return
			}
		}
		w.WriteHeader(http.StatusNoContent)
	})
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}}
	defer server.Close()
	if err := os.WriteFile(filepath.Join(work, "origin.port"), []byte(fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)), 0o600); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() {
		result <- server.ServeTLS(listener, filepath.Join(work, "cert.pem"), filepath.Join(work, "key.pem"))
	}()
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return nil
	}
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: reverse-https-origin WORKDIR XRAY")
		os.Exit(2)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
