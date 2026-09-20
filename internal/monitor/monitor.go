package monitor

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/agent"
	"github.com/sb-gateway/sb-gateway/internal/rulesets"
	"github.com/sb-gateway/sb-gateway/internal/watchdog"
)

type Options struct {
	Agent               agent.Options
	Watchdog            watchdog.Options
	Rulesets            rulesets.Options
	RulesetInitialDelay time.Duration
	RulesetInterval     time.Duration
}

type component struct {
	name string
	run  func(context.Context) error
}

type componentResult struct {
	name string
	err  error
}

func OptionsFromEnvironment() Options {
	return Options{
		Agent:               agent.OptionsFromEnvironment(),
		Watchdog:            watchdog.OptionsFromEnvironment(),
		Rulesets:            rulesets.OptionsFromEnvironment(),
		RulesetInitialDelay: boundedDuration("SB_RULESET_INITIAL_DELAY_SECONDS", 120, 10, 3600),
		RulesetInterval:     boundedDuration("SB_RULESET_UPDATE_INTERVAL", 86400, 3600, 604800),
	}
}

// Run shares one Go runtime and heap between the low-frequency appliance
// workers. Policy DNS remains a separately restartable component because its
// listener topology can change independently during Apply.
func Run(ctx context.Context, options Options) error {
	return runComponents(ctx, []component{
		{name: "agent", run: func(child context.Context) error {
			return agent.Run(child, options.Agent)
		}},
		{name: "watchdog", run: func(child context.Context) error {
			return watchdog.Run(child, options.Watchdog)
		}},
		{name: "rulesets", run: func(child context.Context) error {
			return runRulesetWorker(child, options)
		}},
	})
}

func runComponents(ctx context.Context, components []component) error {
	if len(components) == 0 {
		return nil
	}
	child, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan componentResult, len(components))
	for _, item := range components {
		item := item
		go func() { results <- componentResult{name: item.name, err: item.run(child)} }()
	}

	first := <-results
	if ctx.Err() != nil {
		cancel()
		for range len(components) - 1 {
			<-results
		}
		return nil
	}
	cancel()
	for range len(components) - 1 {
		<-results
	}
	if first.err == nil {
		return fmt.Errorf("%s stopped unexpectedly", first.name)
	}
	return fmt.Errorf("%s: %w", first.name, first.err)
}

func runRulesetWorker(ctx context.Context, options Options) error {
	if !wait(ctx, options.RulesetInitialDelay) {
		return nil
	}
	for {
		catalog, err := rulesets.Catalog()
		if err == nil {
			var active []rulesets.ServicePack
			active, err = rulesets.ActivePacks(options.Rulesets.StateDir, catalog)
			if err == nil {
				_, err = rulesets.RefreshAll(options.Rulesets, active)
			}
		}
		if err != nil {
			log.Printf("monitor: ruleset refresh failed safely: %v", err)
		}
		if !wait(ctx, options.RulesetInterval) {
			return nil
		}
	}
}

func boundedDuration(name string, fallback, minimum, maximum int) time.Duration {
	value := fallback
	if raw := os.Getenv(name); raw != "" && len(raw) <= 9 {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= minimum && parsed <= maximum {
			value = parsed
		}
	}
	return time.Duration(value) * time.Second
}

func wait(ctx context.Context, duration time.Duration) bool {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
