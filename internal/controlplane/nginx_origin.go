package controlplane

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/cdnfeed"
)

// ACLs are operational state, not configuration generations: rollback must
// not resurrect withdrawn provider networks. Seeded empty files mean deny-all.
func initializeOriginCIDRs(root string) error {
	for _, p := range []string{"cloudflare", "gcore", "edgecenter", "yandex", "beeline", "timeweb"} {
		path := filepath.Join(root, p, "addresses.conf")
		if _, err := os.Stat(path); err == nil {
			continue
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := writeAtomic(path, nil, 0o600, false); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *nativeRuntime) updateOriginCIDRs(ctx context.Context, provider string, values []string) error {
	p, ok := cdnfeed.Lookup(provider)
	if !ok {
		return errors.New("unsupported origin provider")
	}
	values, err := cdnfeed.Validate(values)
	if err != nil {
		return err
	}
	root := runtime.options.OriginCIDRRoot
	if root == "" {
		return errors.New("origin CIDR state root is not configured")
	}
	path := filepath.Join(root, p.ID, "addresses.conf")
	var body strings.Builder
	for _, v := range values {
		fmt.Fprintf(&body, "%s 1;\n", v)
	}
	next := []byte(body.String())
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if bytes.Equal(old, next) {
		return nil
	}
	if err := writeAtomic(path, next, 0o600, false); err != nil {
		return err
	}
	// Master loads the private file; request handling needs no IPC or disk I/O.
	command := runtime.nginxCommand
	if command == nil {
		command = func(ctx context.Context, args ...string) error {
			return runValidationCommand(ctx, runtime.options.NginxBinary, args...)
		}
	}
	reload := func(ctx context.Context) error {
		if err := command(ctx, "-t", "-c", runtime.options.NginxConfig, "-p", "/"); err != nil {
			return err
		}
		if err := command(ctx, "-s", "reload", "-c", runtime.options.NginxConfig, "-p", "/"); err != nil {
			return err
		}
		if runtime.controller != nil {
			return runtime.controller.Probe(ctx, []string{"nginx"})
		}
		return nil
	}
	if err := reload(ctx); err != nil {
		// An empty file also means deny-all, and avoids an unlink window.
		restoreErr := writeAtomic(path, old, 0o600, false)
		if restoreErr == nil {
			restoreContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			restoreErr = reload(restoreContext)
		}
		return errors.Join(err, restoreErr)
	}
	return nil
}
