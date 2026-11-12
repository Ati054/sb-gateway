package policydns

import (
	"bytes"
	"context"
	"crypto/tls"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoHRealGoAwayAfterResponseHeadersRetriesFreshConnection(t *testing.T) {
	seed := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	seed.EnableHTTP2 = true
	seed.StartTLS()
	config := seed.TLS.Clone()
	config.NextProtos = []string{"h2"}
	transport := seed.Client().Transport.(*http.Transport).Clone()
	seed.Close()
	listener, err := tls.Listen("tcp4", "127.0.0.1:0", config)
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	var connections, requests atomic.Int32
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			ordinal := connections.Add(1)
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(3 * time.Second))
				var preface [len(http2.ClientPreface)]byte
				if _, err := io.ReadFull(conn, preface[:]); err != nil || string(preface[:]) != http2.ClientPreface {
					return
				}
				framer := http2.NewFramer(conn, conn)
				if framer.WriteSettings() != nil {
					return
				}
				var stream uint32
				var query []byte
				for {
					frame, err := framer.ReadFrame()
					if err != nil {
						return
					}
					switch f := frame.(type) {
					case *http2.SettingsFrame:
						if !f.IsAck() {
							if framer.WriteSettingsAck() != nil {
								return
							}
						}
					case *http2.HeadersFrame:
						stream = f.Header().StreamID
					case *http2.DataFrame:
						query = append(query, f.Data()...)
						if !f.StreamEnded() {
							continue
						}
						requests.Add(1)
						var encoded bytes.Buffer
						encoder := hpack.NewEncoder(&encoded)
						encoder.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
						encoder.WriteField(hpack.HeaderField{Name: "content-type", Value: "application/dns-message"})
						if framer.WriteHeaders(http2.HeadersFrameParam{StreamID: stream, BlockFragment: encoded.Bytes(), EndHeaders: true}) != nil {
							return
						}
						if ordinal == 1 {
							if framer.WriteData(stream, false, []byte{0x12, 0x34}) != nil {
								return
							}
							framer.WriteGoAway(stream, http2.ErrCodeNo, []byte("controlled-close"))
							return
						}
						if framer.WriteData(stream, true, dnsAResponse(query, 42)) != nil {
							return
						}
					}
				}
			}()
		}
	}()
	u := &dohUpstream{url: "https://" + listener.Addr().String() + "/dns-query", transport: transport, client: &http.Client{Transport: transport}}
	t.Cleanup(func() { u.close(); listener.Close(); workers.Wait() })
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	query := dnsQuery(61, "goaway.example")
	answer, err := u.exchange(ctx, query)
	if err != nil || !matchingQuestion(query, answer) || connections.Load() != 2 || requests.Load() != 2 {
		t.Fatalf("GOAWAY did not get one fresh bounded attempt: err=%v connections=%d requests=%d", err, connections.Load(), requests.Load())
	}
}
