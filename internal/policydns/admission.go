package policydns

import (
	"context"
	"time"
)

type queryAdmission struct {
	deadline  time.Time
	queued    bool
	immediate bool
	answer    []byte
}

func (service *service) admitQuery(laneID string, query []byte) queryAdmission {
	service.runtimeMu.RLock()
	deadline := time.Now().Add(service.runtime.timeout)
	service.runtimeMu.RUnlock()
	admission := queryAdmission{deadline: deadline}
	if service.acquire() {
		return admission
	}
	if answer, local := service.localAnswer(laneID, query); local {
		admission.answer = answer
		admission.immediate = true
		return admission
	}
	select {
	case service.pending <- struct{}{}:
		admission.queued = true
	default:
		admission.answer = refusal(query, true)
		admission.immediate = true
	}
	return admission
}

func (service *service) resolveAdmitted(admission queryAdmission, laneID string, query []byte) ([]byte, error) {
	if admission.immediate {
		return admission.answer, nil
	}
	ctx, cancel := context.WithDeadline(service.context(), admission.deadline)
	defer cancel()
	if admission.queued {
		acquired := false
		select {
		case service.limit <- struct{}{}:
			acquired = true
		case <-ctx.Done():
		}
		<-service.pending
		if !acquired || ctx.Err() != nil {
			if acquired {
				service.release()
			}
			if service.context().Err() != nil {
				return nil, service.context().Err()
			}
			return service.overloadResponse(laneID, query), nil
		}
	}
	defer service.release()
	service.runtimeMu.RLock()
	defer service.runtimeMu.RUnlock()
	return service.runtime.resolve(ctx, laneID, query)
}

func (service *service) localAnswer(laneID string, query []byte) ([]byte, bool) {
	service.runtimeMu.RLock()
	defer service.runtimeMu.RUnlock()
	plan, err := service.runtime.planQuery(laneID, query)
	if err == nil && plan.local {
		return plan.answer, true
	}
	return nil, false
}
