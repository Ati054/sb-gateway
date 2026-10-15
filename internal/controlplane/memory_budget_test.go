package controlplane

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/acmejob"
	"github.com/sb-gateway/sb-gateway/internal/memorybudget"
)

func TestPendingMemoryReductionSurvivesStatusPoll(t *testing.T) {
	router := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/rest/container" {
			fmt.Fprint(w, `[{"comment":"SB-GATEWAY container","root-dir":"/usb1/sb-gateway/root","memory-high":"224MiB","memory-max":"256MiB","healthy":"true"}]`)
		} else if r.URL.Path == "/rest/system/scheduler" {
			fmt.Fprint(w, `[{"name":"SB-GATEWAY-container-memory-once"}]`)
		} else {
			t.Errorf("unexpected path %s", r.URL.Path)
			http.Error(w, "unexpected", 404)
		}
	}))
	defer router.Close()
	server := newTestServer(t)
	cookie, _ := bootstrapSession(t, server)
	activateMemoryTestRouter(t, server, router)
	if err := server.repository.saveAuxiliary(containerMemoryOperation, map[string]any{"pending": true, "state": "scheduled", "root_dir": "/usb1/sb-gateway/root", "high_bytes": 112 << 20, "max_bytes": 128 << 20, "deadline": server.now().Add(time.Minute).UTC().Format(time.RFC3339Nano)}); err != nil {
		t.Fatal(err)
	}
	response := performRequest(t, server, http.MethodGet, apiPrefix+"/routeros/container/memory", nil, nil, cookie)
	if response.Code != 200 {
		t.Fatalf("status: %d", response.Code)
	}
	hint, err := server.repository.auxiliary(memorybudget.HintName)
	hintHigh, _ := numberToInt64(hint["high_bytes"])
	hintMax, _ := numberToInt64(hint["max_bytes"])
	if err != nil || hintHigh != 112<<20 || hintMax != 128<<20 {
		t.Fatalf("pending reduction lost: %v %v", hint, err)
	}
}

func TestValidationSlotWaitIsCancellable(t *testing.T) {
	validationCommandSlot <- struct{}{}
	defer func() { <-validationCommandSlot }()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runValidationCommand(ctx, "/must-not-start"); !errors.Is(err, context.Canceled) {
		t.Fatalf("validation wait: %v", err)
	}
}

func TestACMEMemoryEnvironmentDoesNotInheritAmbientProxy(t *testing.T) {
	t.Setenv("HTTP_PROXY", "http://do-not-inherit.invalid")
	var command *exec.Cmd
	original := acmeWorkerCommand
	acmeWorkerCommand = func(ctx context.Context, _ string) *exec.Cmd {
		command = exec.CommandContext(ctx, os.Args[0], "-test.run=^TestACMEWorkerExitHelper$")
		return command
	}
	defer func() { acmeWorkerCommand = original }()
	_, _ = runACMEWorker(context.Background(), acmejob.Request{})
	if command == nil || !slices.Contains(command.Env, fmt.Sprintf("GOMEMLIMIT=%d", memorybudget.Current().Worker)) || !slices.Contains(command.Env, "GODEBUG=disablethp=1") {
		t.Fatal("worker did not get its bounded memory/THP settings")
	}
	for _, value := range command.Env {
		if strings.HasPrefix(value, "HTTP_PROXY=") {
			t.Fatal("ambient environment escaped worker isolation")
		}
	}
}
