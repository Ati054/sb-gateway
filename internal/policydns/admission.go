package policydns

import (
	"context"
	"time"
)

type queryAdmission struct {
	deadline                  time.Time
	queued, immediate, shared bool
	answer                    []byte
	plan                      queryPlan
	flight                    *flight
	route                     *routeBudget
	bytes                     int
}

func (service *service) admitQuery(laneID string, query []byte) queryAdmission {
	service.runtimeMu.RLock()
	defer service.runtimeMu.RUnlock()
	r := service.runtime
	a := queryAdmission{deadline: time.Now().Add(r.timeout)}
	plan, err := r.planQuery(laneID, query)
	if err != nil || plan.local {
		a.immediate = true
		a.answer = plan.answer
		if err != nil {
			a.answer = refusal(query, true)
		}
		return a
	}
	// Bound retained wire bytes independently of active work and duplicates.
	a.route = service.routeLimit(plan.tag, len(r.servers))
	service.admissionMu.Lock()
	if service.queryBytes+len(query) > max(1, cap(service.limit))*maxDNSMessage || (a.route != nil && a.route.bytes+len(query) > max(1, cap(service.limit)/2)*maxDNSMessage) {
		service.admissionMu.Unlock()
		return queryAdmission{deadline: a.deadline, immediate: true, answer: refusal(query, true)}
	}
	service.queryBytes += len(query)
	if a.route != nil {
		a.route.bytes += len(query)
	}
	service.admissionMu.Unlock()
	a.bytes, a.plan = len(query), plan
	active, owner := r.flights.begin(plan.key, max(2, cap(service.limit)*4))
	if active == nil {
		service.returnBytes(a.bytes, a.route)
		return queryAdmission{deadline: a.deadline, immediate: true, answer: refusal(query, true)}
	}
	a.flight = active
	if !owner {
		service.admissionMu.Lock()
		accepted := service.sharedQueries < max(1, cap(service.limit))*4 && (a.route == nil || a.route.shared < cap(service.limit)*3)
		if accepted {
			service.sharedQueries++
			if a.route != nil {
				a.route.shared++
			}
		}
		service.admissionMu.Unlock()
		if accepted {
			a.shared = true
			return a
		}
		r.flights.leave(active)
		service.returnBytes(a.bytes, a.route)
		return queryAdmission{deadline: a.deadline, immediate: true, answer: refusal(query, true)}
	}
	if a.route == nil || service.tryRoute(a.route.active) {
		if service.acquire() {
			return a
		}
		if a.route != nil {
			service.releaseRoute(a.route.active)
		}
	}
	profileQueued := a.route == nil || service.tryRoute(a.route.pending)
	if profileQueued {
		select {
		case service.pending <- struct{}{}:
			a.queued = true
			return a
		default:
			if a.route != nil {
				service.releaseRoute(a.route.pending)
			}
		}
	}
	r.flights.finish(plan.key, active, nil, context.DeadlineExceeded)
	r.flights.leave(active)
	service.returnBytes(a.bytes, a.route)
	return queryAdmission{deadline: a.deadline, immediate: true, answer: refusal(query, true)}
}

func (service *service) resolveAdmitted(a queryAdmission, laneID string, query []byte) ([]byte, error) {
	if a.immediate {
		return a.answer, nil
	}
	ctx, cancel := context.WithDeadline(service.context(), a.deadline)
	defer cancel()
	defer service.returnBytes(a.bytes, a.route)
	service.runtimeMu.RLock()
	defer service.runtimeMu.RUnlock()
	r := service.runtime
	defer r.flights.leave(a.flight)
	if a.shared {
		defer func() {
			service.admissionMu.Lock()
			service.sharedQueries--
			if a.route != nil {
				a.route.shared--
			}
			service.admissionMu.Unlock()
		}()
		response, err := a.flight.wait(ctx)
		return r.queryResult(a.plan, query, response, err), nil
	}
	var response []byte
	var err error
	acquired := !a.queued
	if a.queued {
		acquired = service.waitWork(ctx, a.route)
		<-service.pending
		if a.route != nil {
			service.releaseRoute(a.route.pending)
		}
	}
	if acquired {
		response, err = r.exchangePlan(ctx, a.plan, query)
		service.release()
		if a.route != nil {
			service.releaseRoute(a.route.active)
		}
	} else {
		err = ctx.Err()
	}
	r.flights.finish(a.plan.key, a.flight, response, err)
	if !acquired && service.context().Err() != nil {
		return nil, service.context().Err()
	}
	return r.queryResult(a.plan, query, response, err), nil
}

func (service *service) returnBytes(size int, route *routeBudget) {
	service.admissionMu.Lock()
	service.queryBytes -= size
	if route != nil {
		route.bytes -= size
	}
	service.admissionMu.Unlock()
}

type routeBudget struct {
	active, pending chan struct{}
	shared, bytes   int // guarded by admissionMu
}

// A single profile may use half the active/pending capacity when multiple
// profiles exist. Waiting for its allowance never holds global work capacity.
func (service *service) routeLimit(tag string, profiles int) *routeBudget {
	if profiles < 2 || cap(service.limit) < 2 {
		return nil
	}
	service.admissionMu.Lock()
	defer service.admissionMu.Unlock()
	if service.routes == nil {
		service.routes = make(map[string]*routeBudget)
	}
	if service.routes[tag] == nil {
		service.routes[tag] = &routeBudget{active: make(chan struct{}, max(1, cap(service.limit)/2)), pending: make(chan struct{}, max(1, cap(service.pending)/2))}
	}
	return service.routes[tag]
}

func (service *service) tryRoute(route chan struct{}) bool {
	if route == nil {
		return true
	}
	select {
	case route <- struct{}{}:
		return true
	default:
		return false
	}
}

func (service *service) releaseRoute(route chan struct{}) {
	if route != nil {
		<-route
	}
}

func (service *service) waitWork(ctx context.Context, route *routeBudget) bool {
	if route != nil {
		select {
		case route.active <- struct{}{}:
		case <-ctx.Done():
			return false
		}
	}
	select {
	case service.limit <- struct{}{}:
		return true
	case <-ctx.Done():
		if route != nil {
			service.releaseRoute(route.active)
		}
		return false
	}
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
