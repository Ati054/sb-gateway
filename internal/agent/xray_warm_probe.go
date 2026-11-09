package agent

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"
	"time"
)

// Measurement travels with the admitted job; a shared lane never owns a global
// policy-specific measurement mode.
type qualityMeasurement string

const (
	qualityMeasurementCold        qualityMeasurement = qualityMeasurement(latencyMeasurement)
	qualityMeasurementWarm        qualityMeasurement = "gstatic-warm-head-v1"
	qualityMeasurementFreshPaired qualityMeasurement = "gstatic-fresh-paired-head-v1"
)

type qualityProbeRequest struct {
	Measurement qualityMeasurement
	Start       *qualityStartTicket
	WarmStart   *qualityStartTicket
}

// The first request remains ordinary cold evidence. This optional observation
// belongs only to planned URLTest comparisons, never availability or history.
type planningQualityEvidence struct {
	Measurement qualityMeasurement
	StartedAt   time.Time
	ObservedAt  time.Time
	Wave        uint64
	DelayMS     *int
	Failed      bool
	Deferred    bool
}

// Kept for strict same-connection callers and test fixtures. Fresh evidence uses
// probeEvidence.Planning; the JSON warm_* envelope is a legacy storage name.
type warmQualityEvidence = planningQualityEvidence

func isPairedPlanningMeasurement(measurement qualityMeasurement) bool {
	return measurement == qualityMeasurementWarm || measurement == qualityMeasurementFreshPaired
}

func (evidence probeEvidence) planningQuality() *planningQualityEvidence {
	if evidence.Planning != nil {
		return evidence.Planning
	}
	return evidence.Warm
}

func validPlanningQuality(value *planningQualityEvidence, expected qualityMeasurement) bool {
	return isPairedPlanningMeasurement(expected) && value != nil && value.Measurement == expected && !value.Failed && !value.Deferred &&
		value.DelayMS != nil && *value.DelayMS > 0 && !value.StartedAt.IsZero() && value.ObservedAt.After(value.StartedAt)
}

type warmHTTPObservation struct {
	ColdStartedAt       time.Time
	ColdObservedAt      time.Time
	ColdDelayMS         int
	ColdResponseDelayMS *int
	ColdError           error
	WarmError           error
	Warm                warmQualityEvidence
}

var errWarmProbeReconnect = errors.New("warm probe requires the original connection")

func requestWarmThroughProxy(ctx context.Context, proxyURL, target, coldMethod string, coldLimit int, timeout time.Duration, expectedStatus int, ready *qualityStartTicket) warmHTTPObservation {
	defer ready.arrive()
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		ready.abortWarm()
		return warmHTTPObservation{ColdError: err, Warm: warmQualityEvidence{Measurement: qualityMeasurementWarm, Failed: true}}
	}
	transport := &http.Transport{Proxy: http.ProxyURL(parsed)}
	return measureWarmHTTP(ctx, transport, target, coldMethod, coldLimit, timeout, expectedStatus, ready)
}

// Keepalive is owned by this bounded two-request session. There is no connection
// pool across endpoints, controller turns or runtime generations.
func measureWarmHTTP(parent context.Context, transport *http.Transport, target, coldMethod string, coldLimit int, timeout time.Duration, expectedStatus int, ready *qualityStartTicket) (observation warmHTTPObservation) {
	observation.Warm = warmQualityEvidence{Measurement: qualityMeasurementWarm, Failed: true}
	if ready != nil {
		defer ready.arrive()
		observation.Warm.Wave = ready.barrier.id
	}
	transport.DisableKeepAlives = false
	transport.ForceAttemptHTTP2 = false
	transport.TLSNextProto = map[string]func(string, *tls.Conn) http.RoundTripper{}
	transport.MaxIdleConnsPerHost = 1
	defer transport.CloseIdleConnections()
	var warmPhase atomic.Bool
	dial := transport.DialContext
	if dial == nil {
		dial = (&net.Dialer{}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if warmPhase.Load() {
			return nil, errWarmProbeReconnect
		}
		return dial(ctx, network, address)
	}
	if dialTLS := transport.DialTLSContext; dialTLS != nil {
		transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			if warmPhase.Load() {
				return nil, errWarmProbeReconnect
			}
			return dialTLS(ctx, network, address)
		}
	}
	//lint:ignore SA1019 Legacy injected transports must also reject warm reconnects.
	if dialTLS := transport.DialTLS; dialTLS != nil {
		//lint:ignore SA1019 Preserve the legacy hook while adding the same reconnect guard.
		transport.DialTLS = func(network, address string) (net.Conn, error) {
			if warmPhase.Load() {
				return nil, errWarmProbeReconnect
			}
			return dialTLS(network, address)
		}
	}
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	observation.ColdStartedAt = time.Now()
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var first net.Conn
	coldTrace := &probeRequestTrace{}
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) { first = info.Conn }}
	requestContext := httptrace.WithClientTrace(httptrace.WithClientTrace(ctx, coldTrace.hooks()), trace)
	closeConnection, err := executeSessionProbe(client, requestContext, target, coldMethod, coldLimit, expectedStatus, coldTrace)
	observation.ColdObservedAt = time.Now()
	observation.ColdDelayMS = maxInt(1, int(observation.ColdObservedAt.Sub(observation.ColdStartedAt).Milliseconds()))
	observation.ColdError = err
	if delay, ok := coldTrace.responseDelayMS(); ok {
		observation.ColdResponseDelayMS = &delay
	}
	if err != nil {
		ready.abortWarm()
		observation.Warm.ObservedAt = observation.ColdObservedAt
		return observation
	}
	if closeConnection || first == nil {
		ready.abortWarm()
		observation.WarmError = errWarmProbeReconnect
		observation.Warm.ObservedAt = time.Now()
		return observation
	}
	// A failed cold peer aborts this comparison only. Cold evidence and its
	// independent availability fallback keep their ordinary contracts.
	if err := ready.waitWarm(ctx); err != nil {
		observation.WarmError = err
		observation.Warm.ObservedAt = time.Now()
		observation.Warm.Failed, observation.Warm.Deferred = false, true
		return observation
	}
	// Even a single lane must not start a doomed second request after its
	// first request consumed the session budget.
	if err := ctx.Err(); err != nil {
		ready.abortWarm()
		observation.WarmError = err
		observation.Warm.ObservedAt = time.Now()
		observation.Warm.Failed, observation.Warm.Deferred = false, true
		return observation
	}
	warmPhase.Store(true)
	var reused, same bool
	warmTrace := &probeRequestTrace{}
	trace = &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		reused, same = info.Reused, info.Conn == first
	}}
	requestContext = httptrace.WithClientTrace(httptrace.WithClientTrace(ctx, warmTrace.hooks()), trace)
	observation.Warm.StartedAt = time.Now()
	_, err = executeSessionProbe(client, requestContext, target, http.MethodHead, 0, expectedStatus, warmTrace)
	observation.Warm.ObservedAt = time.Now()
	observation.WarmError = err
	if err != nil {
		return observation
	}
	if !reused || !same {
		observation.WarmError = errWarmProbeReconnect
		return observation
	}
	delay := maxInt(1, int(observation.Warm.ObservedAt.Sub(observation.Warm.StartedAt).Milliseconds()))
	observation.Warm.DelayMS, observation.Warm.Failed = &delay, false
	return observation
}

// Return the server's close indication as well as status/body validation. A
// second TCP dial is forbidden even if the transport would normally retry HEAD.
func executeSessionProbe(client *http.Client, ctx context.Context, target, method string, limit, expectedStatus int, trace *probeRequestTrace) (bool, error) {
	request, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return false, err
	}
	request.Header.Set("User-Agent", "SB-Gateway-Go-Health/1")
	request.Header.Set("Accept-Encoding", "identity")
	response, err := client.Do(request)
	if err != nil {
		return false, trace.wrap(err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 || expectedStatus != 0 && response.StatusCode != expectedStatus {
		return response.Close, trace.wrap(fmt.Errorf("probe returned unexpected HTTP status %d", response.StatusCode))
	}
	trace.stage.Store(uint32(probeStageBody))
	if limit > 0 {
		if _, err := io.CopyN(io.Discard, response.Body, int64(limit)); err != nil && !errors.Is(err, io.EOF) {
			return response.Close, trace.wrap(err)
		}
	}
	return response.Close, nil
}

func (runtime *xraySelectorRuntime) ProbeWithQualityRequest(candidate string, request qualityProbeRequest) (evidence probeEvidence) {
	trace := beginHealthStage("quality_probe", runtime.stageLane(), "", candidate)
	defer func() { trace.finish(evidence.OK) }()
	defer func() {
		request.Start.arrive()
		if request.Measurement == qualityMeasurementWarm && evidence.Warm == nil {
			request.WarmStart.abortWarm()
		}
		request.WarmStart.arrive()
		if request.Start != nil {
			evidence.QualityWave = request.Start.barrier.id
		}
		if evidence.ObservedAt.IsZero() {
			evidence.ObservedAt = time.Now()
		}
		if request.Measurement == qualityMeasurementWarm && evidence.Warm == nil {
			evidence.Warm = &warmQualityEvidence{Measurement: qualityMeasurementWarm, Failed: true, ObservedAt: evidence.ObservedAt}
		}
		if request.Measurement == qualityMeasurementFreshPaired {
			if evidence.Planning == nil {
				evidence.Planning = &planningQualityEvidence{Measurement: qualityMeasurementFreshPaired, Failed: true, ObservedAt: evidence.ObservedAt}
			}
			evidence.Planning.Wave = evidence.QualityWave
		}
	}()
	return runtime.probeWithQualityRequest(candidate, xrayQualityProbe, request)
}
