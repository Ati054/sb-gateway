package policydns

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/dnsroute"
)

var errDNSRouteRetired = errors.New("DNS route generation retired")

type routeProfile struct {
	mu                 sync.Mutex
	server             upstream
	config             serverConfig
	timeout            time.Duration
	factory            func(serverConfig, time.Duration) (upstream, error)
	core               dnsroute.Core
	selected           string
	seen, closed       bool
	epoch              uint64
	keyBase, keyPrefix string
	subscription       *dnsroute.Subscription
}

type failedRouteUpstream struct{}

func (failedRouteUpstream) exchange(context.Context, []byte) ([]byte, error) {
	return nil, errDNSRouteRetired
}
func (failedRouteUpstream) close() {}

func (p *routeProfile) changed(v dnsroute.Snapshot) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	if !p.seen {
		p.seen = true
		p.core, p.selected = v.Core, v.Selected
		p.mu.Unlock()
		return
	}
	if p.core == v.Core && p.selected == v.Selected {
		p.mu.Unlock()
		return
	}
	p.core, p.selected = v.Core, v.Selected
	old := p.server
	// The descriptor was already validated. A future unexpected factory failure
	// fails this profile closed, never reinstating a retired route or WAN fallback.
	var next upstream = failedRouteUpstream{}
	if p.epoch == ^uint64(0) {
		p.closed = true
	} else {
		created, err := p.factory(p.config, p.timeout)
		if err == nil && created != nil {
			next = created
		} else if created != nil {
			created.close()
		}
		p.epoch++
		p.keyPrefix = p.keyBase + strconv.FormatUint(p.epoch, 10)
	}
	p.server = next
	p.mu.Unlock()
	old.close() // drain idle; preserve already borrowed/healthy requests
}

func (r *runtime) attachRouteEpochs(registry *dnsroute.Registry) {
	if registry == nil {
		return
	}
	r.routeProfiles = make(map[string]*routeProfile)
	for tag, config := range r.serverConfigs {
		// Direct upstreams have no selector/core dependency: preserve their
		// existing pool, cache namespace and mutex-free planning fast path.
		if config.TunnelHost == "" || config.TunnelPort <= 0 {
			continue
		}
		base := tag + "\x00route-epoch:"
		p := &routeProfile{server: r.servers[tag], config: config, timeout: r.timeout, factory: newUpstream, keyBase: base, keyPrefix: base + "0"}
		r.routeProfiles[tag] = p
		p.subscription = registry.Subscribe(config.Detour, true, p.changed)
	}
}

func (p *routeProfile) close() {
	if p.subscription != nil {
		p.subscription.Close()
	}
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	server := p.server
	p.mu.Unlock()
	server.close()
}

func (r *runtime) profilePlan(tag string, query []byte) (queryPlan, error) {
	p := r.routeProfiles[tag]
	if p == nil {
		key, err := normalizedQueryKey(tag, query)
		return queryPlan{server: r.servers[tag], tag: tag, key: key}, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return queryPlan{}, errDNSRouteRetired
	}
	key, err := normalizedQueryKey(p.keyPrefix, query)
	return queryPlan{server: p.server, tag: tag, key: key, profile: p, epoch: p.epoch}, err
}

func (p *routeProfile) current(epoch uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.closed && p.epoch == epoch
}

func (r *runtime) cachePlan(plan queryPlan, response []byte, ttl time.Duration) {
	if plan.profile != nil {
		plan.profile.mu.Lock()
		defer plan.profile.mu.Unlock()
		if plan.profile.closed || plan.profile.epoch != plan.epoch {
			return
		}
	}
	r.cache.putOwned(plan.key, response, ttl, time.Now())
}

// Use the same profile -> cache lock order as insertion. A failed old request
// cannot pass an epoch check, then read stale data after retirement interleaves.
func (r *runtime) stalePlan(plan queryPlan, id []byte) ([]byte, bool) {
	if plan.profile != nil {
		plan.profile.mu.Lock()
		defer plan.profile.mu.Unlock()
		if plan.profile.closed || plan.profile.epoch != plan.epoch {
			return nil, false
		}
	}
	return r.cache.getStale(plan.key, id, time.Now())
}
