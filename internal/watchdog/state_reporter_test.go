package watchdog

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSlowStateReportingIsBoundedAndCoalescesLatest(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := make(chan struct{})
	release := make(chan struct{})
	states := make(chan string, 4)
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		var p statusPayload
		if err := json.NewDecoder(request.Body).Decode(&p); err != nil {
			t.Error(err)
			return
		}
		states <- p.State
		if p.State == "first" {
			close(first)
			select {
			case <-release:
			case <-request.Context().Done():
			}
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer endpoint.Close()
	token := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(token, []byte("test-token"), 0600); err != nil {
		t.Fatal(err)
	}
	r := &runner{opts: Options{TokenFile: token, StatusURL: endpoint.URL}, http: endpoint.Client()}
	stop := r.startStateReporter(ctx)
	defer stop()
	r.postState(ctx, settings{}, "first", true, 0, "test")
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Fatal("reporter did not start")
	}
	begin := time.Now()
	for _, state := range []string{"obsolete", "latest"} {
		r.postState(ctx, settings{}, state, true, 0, "test")
	}
	if time.Since(begin) > 100*time.Millisecond || len(r.postQueue) > 1 {
		t.Fatal("reporting blocked or accumulated an unbounded backlog")
	}
	close(release)
	if got := <-states; got != "first" {
		t.Fatalf("first state=%s", got)
	}
	select {
	case got := <-states:
		if got != "latest" {
			t.Fatalf("queued stale state=%s", got)
		}
	case <-time.After(time.Second):
		t.Fatal("latest state was not delivered")
	}
}
