package watchdog

import (
	"bytes"
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCommandCompletionWinsCancellationRace(t *testing.T) {
	if err := commandResultError(nil, context.DeadlineExceeded); err != nil {
		t.Fatalf("successful child was reclassified after a cancellation race: %v", err)
	}
	failed := errors.New("process failed")
	if err := commandResultError(failed, context.DeadlineExceeded); !errors.Is(err, failed) || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lost process or deadline evidence: %v", err)
	}
}

func TestCommandJSONDoesNotIncludeStderrWarning(t *testing.T) {
	output, err := commandOutput(context.Background(), 4*time.Second, os.Args[0],
		"-test.run=^TestCommandJSONHelper$", "--", "watchdog-command-json")
	if err != nil || string(output) != `{"valid":true}` {
		t.Fatalf("stderr contaminated machine-readable stdout: %q, %v", output, err)
	}
}

func TestDeepCommandFailureLogsOnlyClassificationAndSizes(t *testing.T) {
	var captured bytes.Buffer
	before := log.Writer()
	log.SetOutput(&captured)
	defer log.SetOutput(before)
	if checkDeepCommand(context.Background(), "transparent_nft", func([]byte) bool { return false },
		os.Args[0], "-test.run=^TestCommandJSONHelper$", "--", "watchdog-command-json") {
		t.Fatal("invalid machine-readable state was accepted")
	}
	text := captured.String()
	if !strings.Contains(text, "class=invalid_response") || !strings.Contains(text, "stderr_bytes=") ||
		strings.Contains(text, `{"valid":true}`) || strings.Contains(text, "private-warning") {
		t.Fatalf("unsafe or incomplete deep-probe diagnostic: %s", text)
	}
}

func TestDeepCommandAcceptsValidStdoutDespiteWarning(t *testing.T) {
	if !checkDeepCommand(context.Background(), "transparent_nft", func(body []byte) bool {
		return string(body) == `{"valid":true}`
	}, os.Args[0], "-test.run=^TestCommandJSONHelper$", "--", "watchdog-command-json") {
		t.Fatal("stderr warning rejected valid machine-readable state")
	}
}

func TestCommandJSONHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] != "watchdog-command-json" {
		return
	}
	_, _ = os.Stdout.WriteString(`{"valid":true}`)
	_, _ = os.Stderr.WriteString("private-warning")
	os.Exit(0)
}

func TestCommandStderrClassificationIsBounded(t *testing.T) {
	for _, test := range []struct{ text, class string }{
		{"", "empty"},
		{"No buffer space available", "resource_exhausted"},
		{"Cannot allocate memory", "resource_exhausted"},
		{"Operation not permitted", "permission_denied"},
		{"No such file or directory", "missing_state"},
		{"private-warning", "other"},
	} {
		var stderr commandStderr
		_, _ = stderr.Write([]byte(test.text))
		if stderr.class() != test.class {
			t.Fatalf("class=%s, want %s", stderr.class(), test.class)
		}
	}
	var stderr commandStderr
	_, _ = stderr.Write([]byte(strings.Repeat("x", 4096)))
	if stderr.used != len(stderr.prefix) || stderr.count != 4096 {
		t.Fatal("stderr capture was not bounded independently of its byte count")
	}
}
