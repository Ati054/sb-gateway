package agent

import (
	"crypto/tls"
	"errors"
	"net/http/httptrace"
	"sync/atomic"
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

type probeRequestTrace struct{ stage atomic.Uint32 }

func (trace *probeRequestTrace) hooks() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		TLSHandshakeStart: func() { trace.stage.Store(uint32(probeStageTLS)) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			if err == nil {
				trace.stage.Store(uint32(probeStageHeaders))
			}
		},
		GotConn: func(httptrace.GotConnInfo) { trace.stage.Store(uint32(probeStageHeaders)) },
	}
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
