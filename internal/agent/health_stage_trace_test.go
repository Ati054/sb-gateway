package agent

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestHealthStageTraceIsOptIn(t *testing.T) {
	for _, value := range []string{"", "0", "true"} {
		t.Setenv("SB_HEALTH_STAGE_TRACE", value)
		trace := beginHealthStage("api", "active", "", "")
		if trace != nil {
			t.Fatalf("trace enabled for %q", value)
		}
		trace.command("secret")
		trace.target("https://secret")
		trace.acquiredSlot()
		trace.finish(false)
	}
	t.Setenv("SB_HEALTH_STAGE_TRACE", "1")
	if beginHealthStage("api", "active", "", "") == nil {
		t.Fatal("trace flag ignored")
	}
}

func TestHealthStageTraceSeparatesQueueAndExecution(t *testing.T) {
	started := time.Unix(1000, 0)
	trace := &healthStageTrace{record: healthStageRecord{Stage: "api"}, started: started, acquired: started.Add(7 * time.Millisecond)}
	result := trace.result(started.Add(19*time.Millisecond), false)
	if result.QueueMS != 7 || result.ExecMS != 12 || result.ElapsedMS != 19 || result.OK {
		t.Fatalf("wrong timing: %+v", result)
	}
	trace.acquired = time.Time{}
	result = trace.result(started.Add(19*time.Millisecond), false)
	if result.QueueMS != 19 || result.ExecMS != 0 {
		t.Fatalf("queue cancellation counted as execution: %+v", result)
	}
	if nonnegativeStageMS(started, started.Add(-time.Second)) != 0 {
		t.Fatal("negative duration")
	}
}

func TestHealthStageTraceDoesNotExposeUnknownOperationsOrTargets(t *testing.T) {
	trace := &healthStageTrace{record: healthStageRecord{Stage: "api"}, started: time.Unix(1000, 0)}
	trace.command("api-token=do-not-log")
	trace.target("https://user:password@private.example")
	body, err := json.Marshal(trace.result(trace.started.Add(time.Second), false))
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"api-token", "do-not-log", "private.example", "password"} {
		if strings.Contains(string(body), secret) {
			t.Fatalf("secret entered timing schema: %s", body)
		}
	}
	trace.command("bi")
	trace.target("gstatic-204")
	if trace.record.Operation != "bi" || trace.record.Target != "gstatic-204" {
		t.Fatal("fixed labels discarded")
	}
}
