package diagnosticlog

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriterRotatesIntoOnePreviousSegment(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-plane.log")
	writer, err := Open(path, 1024)
	if err != nil {
		t.Fatal(err)
	}
	first := strings.Repeat("a", 900)
	second := strings.Repeat("b", 300)
	if _, err := writer.Write([]byte(first)); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(second)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	previous, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != second || string(previous) != first {
		t.Fatalf("rotation mismatch: current=%d previous=%d", len(current), len(previous))
	}
}
