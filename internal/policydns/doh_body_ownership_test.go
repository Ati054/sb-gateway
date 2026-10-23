package policydns

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"testing"
)

func TestDoHTransportOwnsBodyAfterEarlyReturn(t *testing.T) {
	for _, failure := range []error{context.Canceled, io.EOF} {
		t.Run(failure.Error(), func(t *testing.T) {
			var bodies []io.ReadCloser
			var replays []func() (io.ReadCloser, error)
			u := &dohUpstream{
				url: "https://resolver.example/dns-query",
				client: &http.Client{Transport: dohTestTransport(func(r *http.Request) (*http.Response, error) {
					// RoundTripper may close the body asynchronously after returning.
					bodies = append(bodies, r.Body)
					replays = append(replays, r.GetBody)
					return nil, failure
				})},
			}
			query := dnsQuery(17, "owned.example")
			original := bytes.Clone(query)
			if _, err := u.exchange(context.Background(), query); !errors.Is(err, failure) {
				t.Fatalf("exchange error = %v", err)
			}
			wantAttempts := 1
			if errors.Is(failure, io.EOF) {
				wantAttempts = 2
			}
			if len(bodies) != wantAttempts {
				t.Fatalf("attempts = %d, want %d", len(bodies), wantAttempts)
			}
			clear(query) // The listener has returned its datagram buffer to the pool.
			for i, body := range bodies {
				got, err := io.ReadAll(body)
				_ = body.Close()
				if err != nil || !bytes.Equal(got, original) {
					t.Errorf("late body %d changed after caller reuse: %x, error %v", i, got, err)
				}
				if replays[i] == nil {
					t.Fatal("request lost replay support")
				}
				replay, err := replays[i]()
				if err != nil {
					t.Fatal(err)
				}
				got, err = io.ReadAll(replay)
				_ = replay.Close()
				if err != nil || !bytes.Equal(got, original) {
					t.Errorf("replayed body %d changed after caller reuse: %x, error %v", i, got, err)
				}
			}
		})
	}
}
