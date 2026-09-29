package diagnosticlog

import (
	"bytes"
	"io"
	"strings"
	"testing"
)

func TestConsoleWriterKeepsSwitchesButNotRoutineRouteProbes(t *testing.T) {
	var console bytes.Buffer
	var persistent bytes.Buffer
	writer := io.MultiWriter(ConsoleWriter{Output: &console}, &persistent)
	for _, event := range []string{"probe-failed", "probe-recovered", "probe-suppressed", "switch", "health-evidence-reset"} {
		line := `agent: route-health {"event":"` + event + `"}` + "\n"
		if _, err := writer.Write([]byte(line)); err != nil {
			t.Fatal(err)
		}
	}
	if got := console.String(); strings.Contains(got, "probe-") || !strings.Contains(got, `"event":"switch"`) || !strings.Contains(got, `"event":"health-evidence-reset"`) {
		t.Fatalf("unexpected RouterOS console events: %q", got)
	}
	if got := persistent.String(); strings.Count(got, "agent: route-health ") != 5 {
		t.Fatalf("persistent log lost route events: %q", got)
	}
	if _, err := writer.Write([]byte("agent: unrelated failure\n")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(console.String(), "unrelated failure") {
		t.Fatal("ordinary errors were suppressed")
	}
}
