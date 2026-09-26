package agent

import (
	"context"
	"errors"
	"net"
	"strconv"
	"sync"
	"syscall"
	"time"
)

type healthDialTarget struct {
	Address string `json:"address"`
	Port    int    `json:"port"`
}

type emergencyPreflightRuntime interface {
	PrioritizeEmergency([]string) ([]string, map[string]bool, error)
}

// Only a successful HTTPS probe through Xray can select a reserve. This
// bounded WAN-side TCP check merely brings responsive numeric-IP endpoints
// from anywhere in a large (or small) subscription into the next probe batch.
// Domains, UDP, and timeouts remain eligible for ordinary Xray probing.
func (runtime *responsiveSelectorRuntime) PrioritizeEmergency(candidates []string) ([]string, map[string]bool, error) {
	stamp := generationStamp(runtime.generationPaths)
	if stamp != runtime.generation {
		runtime.interrupted = errHealthYield
		return nil, nil, errHealthYield
	}
	base := runtime.ctx
	if base == nil {
		base = context.Background()
	}
	ctx, cancel := context.WithTimeout(base, 3*time.Second)
	defer cancel()
	dialer := &net.Dialer{Timeout: 750 * time.Millisecond}
	open, closed := emergencyTCPPreflight(ctx, candidates, runtime.currentPool.DialTargets, func(ctx context.Context, address string) error {
		conn, err := dialer.DialContext(ctx, "tcp", address)
		if err == nil {
			_ = conn.Close()
		}
		return err
	})
	if base.Err() != nil || generationStamp(runtime.generationPaths) != stamp {
		runtime.interrupted = errHealthYield
		return nil, nil, errHealthYield
	}
	return open, closed, nil
}

func emergencyTCPPreflight(ctx context.Context, candidates []string, targets map[string]healthDialTarget, dial func(context.Context, string) error) ([]string, map[string]bool) {
	type result struct {
		id     string
		open   bool
		closed bool
	}
	jobs := make(chan string)
	results := make(chan result, len(candidates))
	var workers sync.WaitGroup
	for i := 0; i < minInt(10, len(candidates)); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for id := range jobs {
				target, ok := targets[id]
				if !ok || target.Port < 1 || target.Port > 65535 || net.ParseIP(target.Address) == nil {
					continue
				}
				address := net.JoinHostPort(target.Address, strconv.Itoa(target.Port))
				err := dial(ctx, address)
				results <- result{id: id, open: err == nil, closed: errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, id := range candidates {
			select {
			case jobs <- id:
			case <-ctx.Done():
				return
			}
		}
	}()
	workers.Wait()
	close(results)
	opened := make(map[string]bool)
	closed := make(map[string]bool)
	for result := range results {
		if result.open {
			opened[result.id] = true
		} else if result.closed {
			closed[result.id] = true
		}
	}
	ordered := make([]string, 0, len(opened))
	for _, id := range candidates {
		if opened[id] {
			ordered = append(ordered, id)
		}
	}
	return ordered, closed
}

func (controller *healthController) emergencyTargets(now time.Time, candidates []string, item *policyHealthState, p effectivePolicySettings) []string {
	if len(candidates) == 0 {
		return nil
	}
	preflight, ok := controller.runtime.(emergencyPreflightRuntime)
	if !ok || (item.Selected == "block" && item.LastPreflightAt > 0 && float64(now.Unix())-item.LastPreflightAt < float64(p.blockRecovery)) {
		return outageProbeTargets(now, withoutClosedCandidates(candidates, item.PreflightClosed), item, p)
	}
	opened, closed, err := preflight.PrioritizeEmergency(candidates)
	if err != nil {
		return outageProbeTargets(now, candidates, item, p)
	}
	item.LastPreflightAt = float64(now.Unix())
	item.PreflightClosed = closed
	regular := outageProbeTargets(now, withoutClosedCandidates(candidates, closed), item, p)
	result := make([]string, 0, p.batch)
	for _, id := range opened {
		if len(result) >= p.batch {
			break
		}
		result = append(result, id)
	}
	for _, id := range regular {
		if len(result) >= p.batch {
			break
		}
		if !closed[id] && !contains(result, id) {
			result = append(result, id)
		}
	}
	return result
}

func withoutClosedCandidates(candidates []string, closed map[string]bool) []string {
	if len(closed) == 0 {
		return candidates
	}
	remaining := make([]string, 0, len(candidates))
	for _, id := range candidates {
		if !closed[id] {
			remaining = append(remaining, id)
		}
	}
	return remaining
}
