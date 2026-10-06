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
	limit := defaultInt(runtime.currentPool.ProbeBudget, 10, 1, 64)
	open, closed := emergencyTCPPreflight(ctx, candidates, runtime.currentPool.DialTargets, minInt(limit, 10), func(ctx context.Context, address string) error {
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

func emergencyTCPPreflight(ctx context.Context, candidates []string, targets map[string]healthDialTarget, limit int, dial func(context.Context, string) error) ([]string, map[string]bool) {
	type endpoint struct {
		address string
		ids     []string
	}
	// Shared transport endpoints need one WAN TCP check, not one per node.
	// HTTPS eligibility and selection are still checked separately through Xray.
	endpoints := []endpoint{}
	byAddress := make(map[string]int)
	for _, id := range candidates {
		target, ok := targets[id]
		ip := net.ParseIP(target.Address)
		if !ok || target.Port < 1 || target.Port > 65535 || ip == nil {
			continue
		}
		address := net.JoinHostPort(ip.String(), strconv.Itoa(target.Port))
		index, exists := byAddress[address]
		if !exists {
			index = len(endpoints)
			byAddress[address] = index
			endpoints = append(endpoints, endpoint{address: address})
		}
		endpoints[index].ids = append(endpoints[index].ids, id)
	}
	type result struct {
		ids    []string
		open   bool
		closed bool
	}
	jobs := make(chan endpoint)
	results := make(chan result, len(endpoints))
	var workers sync.WaitGroup
	for i := 0; i < minInt(maxInt(limit, 1), len(endpoints)); i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for target := range jobs {
				if ctx.Err() != nil {
					return
				}
				err := dial(ctx, target.address)
				results <- result{ids: target.ids, open: err == nil, closed: errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EHOSTUNREACH)}
			}
		}()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(jobs)
		for _, target := range endpoints {
			select {
			case jobs <- target:
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
		for _, id := range result.ids {
			if result.open {
				opened[id] = true
			} else if result.closed {
				closed[id] = true
			}
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
	// An open TCP port does not prove HTTPS health. Preserve sweep progress
	// when a repeated preflight finds the same silent endpoints still open.
	for _, id := range outageProbeTargets(now, opened, item, p) {
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
