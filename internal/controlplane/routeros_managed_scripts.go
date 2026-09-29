package controlplane

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
)

var errRouterOSScriptSyncDeferred = errors.New("RouterOS script sync deferred until active configuration is available")

// Installed RouterOS script bodies are reconciled after container probation,
// then infrequently for retries. No import or script execution is involved.
func (server *Server) runRouterOSManagedScriptsScheduler(ctx context.Context) {
	timer := time.NewTimer(time.Minute)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-server.routerOSScriptWake:
		}
		operation, cancel := context.WithTimeout(ctx, time.Minute)
		err := server.syncRouterOSManagedScripts(operation)
		cancel()
		if errors.Is(err, routeros.ErrImageUpdateInProgress) || errors.Is(err, errRouterOSScriptSyncDeferred) {
			timer.Reset(30 * time.Second)
		} else if err != nil {
			log.Printf("routeros-scripts: sync failed safely: %v", err)
			timer.Reset(5 * time.Minute)
		} else {
			timer.Reset(time.Hour)
		}
	}
}

func (server *Server) wakeRouterOSManagedScripts() {
	select {
	case server.routerOSScriptWake <- struct{}{}:
	default:
	}
}

func (server *Server) syncRouterOSManagedScripts(ctx context.Context) error {
	if !server.configMu.TryLock() {
		return errRouterOSScriptSyncDeferred
	}
	defer server.configMu.Unlock()
	revision, err := server.repository.activeRevision()
	if err != nil {
		return err
	}
	if revision == "" {
		return errRouterOSScriptSyncDeferred
	}
	config, err := server.repository.loadGeneration(revision)
	if err != nil {
		return err
	}
	if !routerOSCredentialsConfigured(config, server.secrets) {
		return errRouterOSScriptSyncDeferred
	}
	required, err := runtimeconfig.RequiresRouterOSCloudflareUpdater(config)
	if err != nil {
		return err
	}
	client, _, err := server.newRouterOSRESTClient(config)
	if err != nil {
		return err
	}
	defer client.CloseIdleConnections()
	changed := false
	if !required {
		changed, err = client.SetCloudflareUpdaterEnabled(ctx, false)
		if err != nil {
			return err
		}
	}
	updated, err := client.SyncInstalledScripts(ctx)
	if err != nil {
		return err
	}
	if required {
		changed, err = client.SetCloudflareUpdaterEnabled(ctx, true)
		if err != nil {
			return err
		}
	}
	if updated > 0 || changed {
		log.Printf("routeros-scripts: updated=%d cloudflare-required=%t scheduler-changed=%t", updated, required, changed)
	}
	return nil
}
