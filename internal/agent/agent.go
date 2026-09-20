package agent

import (
	"context"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

type Options struct {
	StateRoot           string
	InterestFile        string
	XrayBinary          string
	XrayAPIServer       string
	XrayReadyFile       string
	NFTBinary           string
	InitialDelay        time.Duration
	ActiveInterval      time.Duration
	IdleInterval        time.Duration
	ActiveWindow        time.Duration
	HealthInterval      time.Duration
	HealthPoolFile      string
	HotRuntimeReadyFile string
	ProbeURL            string
}

func OptionsFromEnvironment() Options {
	active := boundedDuration("SB_CLIENT_TELEMETRY_INTERVAL_SECONDS", 30, 15, 3600)
	idle := boundedDuration("SB_CLIENT_TELEMETRY_IDLE_INTERVAL_SECONDS", 300, int(active/time.Second), 86400)
	window := boundedDuration("SB_CLIENT_TELEMETRY_ACTIVE_WINDOW_SECONDS", 45, int(active/time.Second), 3600)
	return Options{
		StateRoot:           envOr("SB_GATEWAY_STATE_DIR", "/state/control-plane"),
		InterestFile:        envOr("SB_CLIENT_TELEMETRY_INTEREST_FILE", "/run/sb-gateway/client-telemetry-interest"),
		XrayBinary:          envOr("SB_XRAY_BIN", "xray"),
		XrayAPIServer:       envOr("SB_XRAY_API_SERVER", "127.0.0.1:10085"),
		XrayReadyFile:       envOr("SB_XRAY_READY_FILE", "/run/sb-gateway/xray-selectors-ready"),
		NFTBinary:           envOr("SB_NFT_BIN", "nft"),
		InitialDelay:        boundedDuration("SB_CLIENT_TELEMETRY_INITIAL_DELAY_SECONDS", 3, 0, 300),
		ActiveInterval:      active,
		IdleInterval:        idle,
		ActiveWindow:        window,
		HealthInterval:      boundedDuration("SB_OUTBOUND_HEALTH_INTERVAL", 60, 10, 3600),
		HealthPoolFile:      envOr("SB_XRAY_URLTEST_POOL", "/config/generated/urltest-pool.json"),
		HotRuntimeReadyFile: envOr("SB_XRAY_HOT_RUNTIME_READY_FILE", "/run/sb-gateway/xray-hot-runtime-ready.json"),
		ProbeURL:            envOr("SB_XRAY_HEALTH_PROBE_URL", "http://127.0.0.1:19082"),
	}
}

func Run(ctx context.Context, opts Options) error {
	errors := make(chan error, 2)
	go func() { errors <- runTelemetry(ctx, opts) }()
	go func() { errors <- runHealth(ctx, opts) }()
	select {
	case <-ctx.Done():
		return nil
	case err := <-errors:
		return err
	}
}

func runTelemetry(ctx context.Context, opts Options) error {
	collector := newTelemetryCollector(opts)
	if !wait(ctx, opts.InitialDelay) {
		return nil
	}
	var lastSample time.Time
	for {
		now := time.Now()
		interval := opts.IdleInterval
		if recentlyInterested(opts.InterestFile, now, opts.ActiveWindow) {
			interval = opts.ActiveInterval
		}
		if lastSample.IsZero() || now.Sub(lastSample) >= interval {
			if err := collector.Tick(ctx, now); err != nil {
				log.Printf("agent: client telemetry sample failed safely: %v", err)
			}
			lastSample = time.Now()
		}
		// The interest marker only changes when the overview requests telemetry.
		// Waking more often than the active sampling cadence cannot produce a
		// fresher snapshot and burns CPU on idle appliances.
		scheduler := opts.ActiveInterval
		if !wait(ctx, scheduler) {
			return nil
		}
	}
}

func recentlyInterested(path string, now time.Time, window time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	age := now.Sub(info.ModTime())
	return age >= 0 && age <= window
}

func boundedDuration(name string, fallback, minimum, maximum int) time.Duration {
	value := fallback
	if raw := os.Getenv(name); raw != "" && len(raw) <= 8 {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= minimum && parsed <= maximum {
			value = parsed
		}
	}
	return time.Duration(value) * time.Second
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func wait(ctx context.Context, duration time.Duration) bool {
	if duration <= 0 {
		select {
		case <-ctx.Done():
			return false
		default:
			return true
		}
	}
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func statePath(root, name string) string {
	return filepath.Join(root, name+".json")
}
