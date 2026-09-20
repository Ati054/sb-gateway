package controlplane

import (
	"context"
	"errors"
	"os"
	"time"
)

// EnforceStartupTrafficSafety is the update bridge for installations whose
// previous image still used /healthz to enable diversion. It runs before Xray
// starts, so managed clients remain on RouterOS WAN (or their configured
// fail-closed rule) while the new image restores real selector readiness.
func EnforceStartupTrafficSafety(ctx context.Context, opts Options) (bool, error) {
	repository, err := newStateRepository(opts.StateDir)
	if err != nil {
		return false, err
	}
	if err := repository.reconcileCommitPointers(); err != nil {
		return false, err
	}
	active, err := repository.loadActive()
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	secrets, err := newSecretStore(opts.SecretsDir)
	if err != nil {
		return false, err
	}
	server := &Server{opts: opts, repository: repository, secrets: secrets}
	client, _, err := server.newRouterOSRESTClient(active)
	if err != nil {
		return false, err
	}
	defer client.CloseIdleConnections()
	operation, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return client.EnforceStartupTrafficSafety(operation)
}
