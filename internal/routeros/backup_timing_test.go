package routeros

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/applytiming"
)

type backupTimingRoundTripper func(*http.Request) (*http.Response, error)

func (call backupTimingRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return call(request)
}

func TestBackupTimingSeparatesActionsWithoutChangingFailureOrder(t *testing.T) {
	for _, failAt := range []string{"", "/rest/export", "/rest/system/backup/save"} {
		t.Run(failAt, func(t *testing.T) {
			var paths []string
			transport := backupTimingRoundTripper(func(request *http.Request) (*http.Response, error) {
				paths = append(paths, request.URL.Path)
				status := http.StatusOK
				if request.URL.Path == failAt {
					status = http.StatusBadRequest
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`[]`))}, nil
			})
			httpClient := &http.Client{Transport: transport}
			client := &Client{baseURL: "https://router.example.invalid:443", username: "test", password: "credential-secret", http: httpClient, actionHTTP: httpClient}
			var records [][]byte
			ctx, finish := applytiming.Begin(context.Background(), "0123456789abcdef", func(body []byte) { records = append(records, body) })
			_, err := client.CreateBackup(ctx, "SB-GATEWAY-20260101T000000Z-0123456789ab", "backup-secret")
			outcome := applytiming.Success
			if err != nil {
				outcome = applytiming.Error
			}
			finish(outcome)
			if (err != nil) != (failAt != "") || len(records) != 1 {
				t.Fatalf("failure=%t records=%d", err != nil, len(records))
			}
			wantPaths := []string{"/rest/export", "/rest/system/backup/save"}
			wantStages := []string{"backup_export", "backup_binary"}
			if failAt == "/rest/export" {
				wantPaths = wantPaths[:1]
				wantStages = wantStages[:1]
			}
			if !reflect.DeepEqual(paths, wantPaths) {
				t.Fatalf("action order=%v", paths)
			}
			var record struct {
				Stages []struct {
					Stage string `json:"stage"`
					Count int    `json:"count"`
				} `json:"stages"`
			}
			if err := json.Unmarshal(records[0], &record); err != nil {
				t.Fatal(err)
			}
			var stages []string
			for _, stage := range record.Stages {
				stages = append(stages, stage.Stage)
				if stage.Count != 1 {
					t.Fatal("duplicate action span")
				}
			}
			if !reflect.DeepEqual(stages, wantStages) || strings.Contains(string(records[0]), "secret") || strings.Contains(string(records[0]), "router.example") || strings.Contains(string(records[0]), "SB-GATEWAY-") {
				t.Fatalf("unsafe or incorrect stages: %s", records[0])
			}
		})
	}
}
