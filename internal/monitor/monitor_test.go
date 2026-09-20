package monitor

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRunComponentsCancelsPeersAfterFailure(t *testing.T) {
	peerStopped := make(chan struct{})
	err := runComponents(context.Background(), []component{
		{name: "failed", run: func(context.Context) error { return errors.New("boom") }},
		{name: "peer", run: func(ctx context.Context) error {
			<-ctx.Done()
			close(peerStopped)
			return nil
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "failed: boom") {
		t.Fatalf("unexpected error: %v", err)
	}
	select {
	case <-peerStopped:
	case <-time.After(time.Second):
		t.Fatal("peer was not cancelled")
	}
}

func TestRunComponentsTreatsParentCancellationAsCleanShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := runComponents(ctx, []component{{name: "idle", run: func(ctx context.Context) error {
		<-ctx.Done()
		return nil
	}}})
	if err != nil {
		t.Fatalf("cancelled monitor failed: %v", err)
	}
}

func TestUnexpectedCleanComponentExitIsFailure(t *testing.T) {
	err := runComponents(context.Background(), []component{{name: "idle", run: func(context.Context) error { return nil }}})
	if err == nil || err.Error() != "idle stopped unexpectedly" {
		t.Fatalf("unexpected result: %v", err)
	}
}

func TestRulesetCadenceUsesBoundedEnvironment(t *testing.T) {
	t.Setenv("SB_RULESET_INITIAL_DELAY_SECONDS", "3")
	t.Setenv("SB_RULESET_UPDATE_INTERVAL", "999999999")
	options := OptionsFromEnvironment()
	if options.RulesetInitialDelay != 120*time.Second {
		t.Fatalf("unsafe initial delay accepted: %s", options.RulesetInitialDelay)
	}
	if options.RulesetInterval != 24*time.Hour {
		t.Fatalf("unsafe update interval accepted: %s", options.RulesetInterval)
	}
	t.Setenv("SB_RULESET_INITIAL_DELAY_SECONDS", "15")
	t.Setenv("SB_RULESET_UPDATE_INTERVAL", "7200")
	options = OptionsFromEnvironment()
	if options.RulesetInitialDelay != 15*time.Second || options.RulesetInterval != 2*time.Hour {
		t.Fatalf("valid cadence rejected: %#v", options)
	}
}
