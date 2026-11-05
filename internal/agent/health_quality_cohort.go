package agent

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var qualityWaveSequence atomic.Uint64

var errWarmPeerFailed = errors.New("paired cold request could not enter warm comparison")

// Preparation is outside the HTTPS measurement. A stuck peer must yield the
// batch rather than start a comparison against an already completed request.
const qualityPreparationTimeout = 5 * time.Second

type qualityStartBarrier struct {
	id             uint64
	left           atomic.Int32
	ready          chan struct{}
	cancel         context.CancelFunc
	readyCloseOnce sync.Once
	aborted        atomic.Bool
}

type qualityStartTicket struct {
	barrier *qualityStartBarrier
	once    sync.Once
}

func (ticket *qualityStartTicket) arrive() {
	if ticket != nil {
		ticket.once.Do(func() {
			if ticket.barrier.left.Add(-1) == 0 {
				ticket.barrier.readyCloseOnce.Do(func() { close(ticket.barrier.ready) })
			}
		})
	}
}

// Failure of a cold peer withdraws only the second phase. The other cold
// request retains its full independent deadline and availability result.
func (ticket *qualityStartTicket) abortWarm() {
	if ticket == nil {
		return
	}
	ticket.barrier.aborted.Store(true)
	ticket.barrier.readyCloseOnce.Do(func() { close(ticket.barrier.ready) })
	ticket.arrive()
}

func (ticket *qualityStartTicket) waitWarm(ctx context.Context) error {
	if ticket == nil {
		return ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		ticket.abortWarm()
		return err
	}
	ticket.arrive()
	select {
	case <-ticket.barrier.ready:
		if ticket.barrier.aborted.Load() {
			return errWarmPeerFailed
		}
		return ctx.Err()
	case <-ctx.Done():
		ticket.abortWarm()
		return ctx.Err()
	}
}

func (ticket *qualityStartTicket) wait(ctx context.Context) error {
	if ticket == nil {
		return nil
	}
	ticket.arrive()
	timer := time.NewTimer(qualityPreparationTimeout)
	defer timer.Stop()
	select {
	case <-ticket.barrier.ready:
		return ctx.Err()
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		ticket.barrier.cancel()
		return context.DeadlineExceeded
	}
}

type probeLaneJob struct {
	node      string
	start     *qualityStartTicket
	warmStart *qualityStartTicket
}

// Availability keeps its first-result worker pool. Quality assigns one peer to
// each lane and gates each physical wave after selector preparation.
func probeLaneJobs(candidates []string, workers int, quality bool, cancel context.CancelFunc) []<-chan probeLaneJob {
	return probeLaneJobsWithMeasurement(candidates, workers, quality, cancel, qualityMeasurementCold)
}

func probeLaneJobsWithMeasurement(candidates []string, workers int, quality bool, cancel context.CancelFunc, measurement qualityMeasurement) []<-chan probeLaneJob {
	queues := make([]<-chan probeLaneJob, workers)
	if !quality || workers < 2 {
		jobs := make(chan probeLaneJob, len(candidates))
		for _, candidate := range candidates {
			jobs <- probeLaneJob{node: candidate}
		}
		close(jobs)
		for i := range queues {
			queues[i] = jobs
		}
		return queues
	}
	lanes := make([]chan probeLaneJob, workers)
	for i := range lanes {
		lanes[i] = make(chan probeLaneJob, (len(candidates)+workers-1)/workers)
		queues[i] = lanes[i]
	}
	var barrier *qualityStartBarrier
	var warmBarrier *qualityStartBarrier
	for i, candidate := range candidates {
		if i%workers == 0 {
			barrier = &qualityStartBarrier{id: qualityWaveSequence.Add(1), ready: make(chan struct{}), cancel: cancel}
			barrier.left.Store(int32(minInt(workers, len(candidates)-i)))
			if measurement == qualityMeasurementWarm {
				warmBarrier = &qualityStartBarrier{id: qualityWaveSequence.Add(1), ready: make(chan struct{}), cancel: cancel}
				warmBarrier.left.Store(int32(minInt(workers, len(candidates)-i)))
			}
		}
		job := probeLaneJob{node: candidate, start: &qualityStartTicket{barrier: barrier}}
		if warmBarrier != nil {
			job.warmStart = &qualityStartTicket{barrier: warmBarrier}
		}
		lanes[i%workers] <- job
	}
	for _, lane := range lanes {
		close(lane)
	}
	return queues
}

func qualityProbeWidth(runtime selectorRuntime) int {
	if runtime, ok := runtime.(interface{ qualityLaneCount() int }); ok {
		return maxInt(1, runtime.qualityLaneCount())
	}
	return 1
}

func qualityIntervalsOverlap(active, candidate probeEvidence) bool {
	return !active.QualityStartedAt.IsZero() && !candidate.QualityStartedAt.IsZero() &&
		active.QualityStartedAt.Before(active.ObservedAt) && candidate.QualityStartedAt.Before(candidate.ObservedAt) &&
		active.QualityStartedAt.Before(candidate.ObservedAt) && candidate.QualityStartedAt.Before(active.ObservedAt)
}

// Shared evidence can serve another policy only as a complete physical wave.
// A recent active sample and a new reserve request are different experiments.
func (controller *healthController) incoherentQualityWave(policyID string, contract healthPolicyContract, nodes []string) bool {
	if qualityProbeWidth(controller.runtime) < 2 || controller.probeBudget == nil {
		return false
	}
	now := time.Now()
	cachedPeer, missingPeer, wave := false, false, uint64(0)
	for _, node := range nodes {
		key := controller.probeKey(policyID, node, contract)
		cached, ok := controller.probeBudget.Quality[key]
		age := now.Sub(cached.At)
		if ok && age >= 0 && age <= sharedProbeLifetime {
			id := cached.Evidence.QualityWave
			if isPairedPlanningMeasurement(controller.qualityMeasurementForPolicy(policyID, contract)) {
				id = 0
				if validPlanningQuality(cached.Evidence.planningQuality(), controller.qualityMeasurementForPolicy(policyID, contract)) {
					id = cached.Evidence.planningQuality().Wave
				}
			}
			if id == 0 || wave != 0 && wave != id {
				return true
			}
			cachedPeer, wave = true, id
		} else if controller.probeBudget.QualityAttempted[key] {
			return true
		} else {
			missingPeer = true
		}
	}
	return cachedPeer && missingPeer
}
