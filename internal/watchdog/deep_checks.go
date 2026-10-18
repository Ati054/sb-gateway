package watchdog

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

type deepCheckResult struct {
	identity string
	probe    *runner
}

type deepCheckTask struct {
	identity string
	epoch    uint64
	started  time.Time
	cancel   context.CancelFunc
	result   chan deepCheckResult
	settings settings
}

// Only this state machine's caller owns the cached proof. A worker receives
// an isolated cache snapshot and cannot renew a lease or restore an old epoch.
type deepChecks struct {
	opts       Options
	identity   string
	epoch      uint64
	proof      *runner
	verifiedAt time.Time
	next       time.Time
	reasons    []string
	task       *deepCheckTask
	probe      func(context.Context, *runner)
}

func newDeepChecks(opts Options) *deepChecks {
	return &deepChecks{opts: opts, probe: func(ctx context.Context, r *runner) {
		r.runDeepProbe(ctx)
	}}
}

func deepProbeIdentity(generation string, opts Options) string {
	if generation == "" {
		return ""
	}
	var identity strings.Builder
	identity.WriteString(generation)
	for _, path := range []string{opts.XrayConfig, opts.PolicyDNSConfig} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return ""
		}
		fmt.Fprintf(&identity, "|%d:%d", info.ModTime().UnixNano(), info.Size())
	}
	return identity.String()
}

func (d *deepChecks) reset() {
	d.epoch++
	if d.task != nil {
		d.task.cancel()
	}
	d.identity, d.proof = "", nil
	d.reasons = nil
	d.verifiedAt, d.next = time.Time{}, time.Time{}
}

func (d *deepChecks) close() {
	if d.task != nil {
		d.task.cancel()
		<-d.task.result
		d.task = nil
	}
}

func (d *deepChecks) accept(result deepCheckResult, now time.Time) {
	task := d.task
	d.task = nil
	task.cancel()
	if task.epoch != d.epoch || result.identity != d.identity || d.identity == "" {
		return
	}
	d.next = now.Add(task.settings.interval)
	d.reasons = append([]string(nil), result.probe.deepReasons...)
	if result.probe.deepHealthy {
		d.proof, d.verifiedAt = result.probe, task.started
		d.next = task.started.Add(task.settings.deepInterval)
	} else if !result.probe.deepUncertain || d.proof == nil {
		d.proof = result.probe
	}
}

func (d *deepChecks) observe(ctx context.Context, identity string, current settings, now time.Time) (bool, []string, bool) {
	if identity != d.identity {
		d.reset()
		d.identity = identity
	}
	if d.task != nil {
		select {
		case result := <-d.task.result:
			d.accept(result, now)
		default:
		}
	}
	if identity == "" {
		return false, nil, false
	}
	if d.task == nil && (d.next.IsZero() || !now.Before(d.next)) {
		probe := &runner{opts: d.opts}
		if d.proof != nil {
			probe.configFileSignature, probe.listenerSignature = d.proof.configFileSignature, d.proof.listenerSignature
			probe.dnsFileSignature, probe.dnsSignature = d.proof.dnsFileSignature, d.proof.dnsSignature
			probe.listeners = append([]listener(nil), d.proof.listeners...)
			probe.dnsPorts = append([]int(nil), d.proof.dnsPorts...)
		}
		jobCtx, cancel := context.WithTimeout(ctx, deepProbeTimeout)
		task := &deepCheckTask{identity: identity, epoch: d.epoch, started: now, cancel: cancel, result: make(chan deepCheckResult, 1), settings: current}
		d.task = task
		go func() {
			defer cancel()
			d.probe(jobCtx, probe)
			task.result <- deepCheckResult{identity, probe}
		}()
	}
	if d.proof == nil {
		pending := d.task != nil && d.task.identity == identity && now.Sub(d.task.started) >= 0 && now.Sub(d.task.started) < deepProbeTimeout
		return false, nil, pending
	}
	age := now.Sub(d.verifiedAt)
	fresh := !d.verifiedAt.IsZero() && age >= 0 && age < current.deepInterval+deepProbeTimeout
	if d.proof.deepHealthy && fresh {
		return true, nil, false
	}
	return false, append([]string(nil), d.reasons...), false
}

func (d *deepChecks) wait(ctx context.Context, duration time.Duration) bool {
	if d.task == nil {
		return wait(ctx, max(0, duration))
	}
	timer := time.NewTimer(max(0, duration))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case result := <-d.task.result:
		d.accept(result, time.Now())
		return ctx.Err() == nil
	case <-timer.C:
		return ctx.Err() == nil
	}
}
