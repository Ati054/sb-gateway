package controlplane

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/applytiming"
)

func TestApplyTimingEmitsOneTerminalRecordOnValidationError(t *testing.T) {
	server := newTestServer(t)
	var records [][]byte
	ctx, finish := applytiming.Begin(context.Background(), "0123456789abcdef", func(body []byte) { records = append(records, body) })
	_, status, err := server.applyConfiguration(ctx, map[string]any{}, "test")
	finish(applytiming.Success)
	if err == nil || status != http.StatusUnprocessableEntity || len(records) != 1 {
		t.Fatalf("status=%d err=%v records=%d", status, err, len(records))
	}
	var record struct {
		Outcome    string `json:"outcome"`
		Incomplete int    `json:"incomplete_spans"`
		Stages     []struct {
			Stage string `json:"stage"`
		} `json:"stages"`
	}
	if err := json.Unmarshal(records[0], &record); err != nil {
		t.Fatal(err)
	}
	if record.Outcome != "error" || record.Incomplete != 0 || len(record.Stages) != 1 || record.Stages[0].Stage != "prepare" {
		t.Fatalf("incorrect terminal record: %s", records[0])
	}
}
