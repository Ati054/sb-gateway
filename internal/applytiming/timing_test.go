package applytiming

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func decodeReport(t *testing.T, body []byte) report {
	t.Helper()
	var value report
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestNestedSpansAreExplicitlyNonadditive(t *testing.T) {
	now := time.Unix(100, 0)
	var body []byte
	ctx, finish := begin(context.Background(), "0123456789abcdef", func(v []byte) { body = v }, func() time.Time { return now })
	outer := Start(ctx, RouterOSExecute)
	now = now.Add(5 * time.Second)
	inner := Start(ctx, RuntimeActivate)
	now = now.Add(7 * time.Second)
	inner()
	now = now.Add(3 * time.Second)
	outer()
	outer()
	finish(Success)
	r := decodeReport(t, body)
	if r.ElapsedMS != 15000 || !r.Nonadditive || r.Outcome != "success" || r.Incomplete != 0 || len(r.Stages) != 2 {
		t.Fatalf("unexpected record: %s", body)
	}
	if r.Stages[0].Stage != "routeros_execute" || r.Stages[0].Count != 1 || r.Stages[0].ElapsedMS != 15000 || r.Stages[1].ElapsedMS != 7000 {
		t.Fatalf("nested durations lost: %s", body)
	}
}

func TestPrivacyAllowlistAndOriginalError(t *testing.T) {
	secret := "https://credentials:password@example.invalid/private/config?token=secret"
	now := time.Unix(100, 0)
	var body []byte
	ctx, finish := begin(context.Background(), secret, func(v []byte) { body = v }, func() time.Time { return now })
	want := errors.New(secret)
	if got := Run(ctx, BackupExport, func() error { now = now.Add(time.Second); return want }); got != want {
		t.Fatal("measurement changed the original error")
	}
	Start(ctx, Stage(255))()
	finish(Outcome(255))
	r := decodeReport(t, body)
	if r.Outcome != "error" || r.RequestID != "" || len(r.Stages) != 1 || r.Stages[0].Stage != "backup_export" || strings.Contains(string(body), "password") || strings.Contains(string(body), "https") {
		t.Fatalf("unsafe record: %s", body)
	}
	for _, id := range []string{"", "0123456789abcde", strings.Repeat("a", 65), "0123456789abcdef\n", "0123456789abcdeg"} {
		if safeRequestID(id) {
			t.Fatal("accepted invalid request ID")
		}
	}
}

func TestBoundedRecordAndLateCompletion(t *testing.T) {
	now := time.Unix(100, 0)
	var body []byte
	emitted := 0
	ctx, finish := begin(context.Background(), strings.Repeat("a", 64), func(v []byte) { emitted++; body = v }, func() time.Time { return now })
	var pending []func()
	for i := 0; i < maxSpans*4; i++ {
		pending = append(pending, Start(ctx, Stage(i%int(stageCount))))
	}
	for i := 0; i < maxSpans/2; i++ {
		now = now.Add(maxDuration)
		pending[i]()
	}
	finish(Unchanged)
	before := string(body)
	for _, done := range pending {
		done()
	}
	Start(ctx, BackupBinary)()
	_, nestedFinish := Begin(ctx, "bbbbbbbbbbbbbbbb", func([]byte) { t.Error("nested emitter used") })
	nestedFinish(Error)
	finish(Error)
	r := decodeReport(t, body)
	if emitted != 1 || before != string(body) || len(body) > 2048 || len(r.Stages) > int(stageCount) || r.ElapsedMS != maxDuration.Milliseconds() || r.Incomplete != maxSpans/2 || r.Discarded != maxSpans || r.Outcome != "unchanged" {
		t.Fatalf("unbounded or repeated record: %s", body)
	}
	for _, s := range r.Stages {
		if s.ElapsedMS > maxDuration.Milliseconds() {
			t.Fatal("unbounded aggregate")
		}
	}
}

func TestConcurrentCompletionAndTerminalEmissionOnce(t *testing.T) {
	const count = 32
	now := time.Unix(100, 0)
	var bodies [][]byte
	ctx, finish := begin(context.Background(), "0123456789abcdef", func(v []byte) { bodies = append(bodies, v) }, func() time.Time { return now })
	done := make([]func(), count)
	for i := range done {
		done[i] = Start(ctx, RouterOSExecute)
	}
	var workers sync.WaitGroup
	release := make(chan struct{})
	for _, end := range done {
		workers.Add(1)
		go func(end func()) { defer workers.Done(); <-release; end(); end(); finish(Success) }(end)
	}
	close(release)
	workers.Wait()
	if len(bodies) != 1 {
		t.Fatalf("emitted %d records", len(bodies))
	}
	r := decodeReport(t, bodies[0])
	completed := 0
	for _, s := range r.Stages {
		completed += s.Count
	}
	if completed+r.Incomplete != count {
		t.Fatalf("completion accounting: %s", bodies[0])
	}
}

func TestOutsideApplyDoesNotChangeCalls(t *testing.T) {
	want := errors.New("original")
	calls := 0
	if got := Run(context.Background(), BackupBinary, func() error { calls++; return want }); got != want || calls != 1 {
		t.Fatal("outside-Apply behavior changed")
	}
}
