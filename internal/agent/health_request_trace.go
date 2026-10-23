package agent

import (
	"crypto/tls"
	"errors"
	"net/http/httptrace"
	"sync/atomic"
	"time"
)

type probeRequestStage uint32

const (
	probeStageProxy probeRequestStage = iota
	probeStageTLS
	probeStageHeaders
	probeStageBody
)

func (stage probeRequestStage) String() string {
	switch stage {
	case probeStageProxy:
		return "proxy-connect"
	case probeStageTLS:
		return "tls-handshake"
	case probeStageHeaders:
		return "response-headers"
	case probeStageBody:
		return "response-body"
	default:
		return ""
	}
}

type probeRequestError struct {
	stage probeRequestStage
	err   error
}

func (err *probeRequestError) Error() string { return err.err.Error() }
func (err *probeRequestError) Unwrap() error { return err.err }

type probeRequestTrace struct {
	stage       atomic.Uint32
	started     time.Time
	connectedNS atomic.Int64
	responseNS  atomic.Int64
}

func (trace *probeRequestTrace) hooks() *httptrace.ClientTrace {
	trace.started = time.Now()
	return &httptrace.ClientTrace{
		TLSHandshakeStart: func() { trace.stage.Store(uint32(probeStageTLS)) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				trace.stage.Store(uint32(probeStageHeaders))
			}
		},
		GotConn: func(httptrace.GotConnInfo) {
			trace.stage.Store(uint32(probeStageHeaders))
			trace.connectedNS.Store(time.Since(trace.started).Nanoseconds() + 1)
		},
		GotFirstResponseByte: func() {
			if connected := trace.connectedNS.Load(); connected > 0 {
				trace.responseNS.CompareAndSwap(0, max(int64(1), time.Since(trace.started).Nanoseconds()+1-connected))
			}
		},
	}
}

func (trace *probeRequestTrace) responseDelayMS() (int, bool) {
	duration := trace.responseNS.Load()
	return max(1, int(time.Duration(duration).Milliseconds())), duration > 0
}

func (trace *probeRequestTrace) wrap(err error) error {
	if err == nil {
		return nil
	}
	return &probeRequestError{stage: probeRequestStage(trace.stage.Load()), err: err}
}

func probeErrorStage(err error) string {
	var requestErr *probeRequestError
	if errors.As(err, &requestErr) {
		return requestErr.stage.String()
	}
	return ""
}
