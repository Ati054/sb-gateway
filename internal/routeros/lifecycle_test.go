package routeros

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScheduleFullUninstallStagesWorkerBeforeOneShotScheduler(t *testing.T) {
	var requests []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/script":
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil || payload["name"] != fullUninstallWorker || !strings.Contains(text(payload["source"]), `/file/remove $storageEntry`) {
				http.Error(response, "bad worker", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{".id":"*41"}`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/scheduler":
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil || payload["interval"] != "10s" || payload["on-event"] != "/system/script/run "+fullUninstallWorker {
				http.Error(response, "bad scheduler", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{".id":"*42"}`))
		default:
			http.Error(response, "unexpected", http.StatusNotFound)
		}
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	result, err := client.ScheduleFullUninstall(context.Background(), "usb1/sb-gateway")
	if err != nil {
		t.Fatal(err)
	}
	if result["scheduled"] != true || result["delay_seconds"] != 10 {
		t.Fatalf("schedule result = %#v", result)
	}
	want := []string{
		"GET /rest/system/script?.proplist=.id,name,comment",
		"PUT /rest/system/script",
		"GET /rest/system/scheduler?.proplist=.id,name,comment",
		"PUT /rest/system/scheduler",
	}
	if strings.Join(requests, "\n") != strings.Join(want, "\n") {
		t.Fatalf("requests = %#v", requests)
	}
}

func TestScheduleFullUninstallRejectsUnsafeStorageWithoutRouterOSRequest(t *testing.T) {
	for _, root := range []string{"usb1", "flash/sb-gateway", "usb1/../foreign", `usb1/bad"path`} {
		if _, err := (&Client{}).ScheduleFullUninstall(context.Background(), root); err == nil {
			t.Fatalf("unsafe storage root %q accepted", root)
		}
	}
}

func TestFullUninstallIncludesRetainedImageBeforeRemovingStorage(t *testing.T) {
	worker := renderFullUninstallWorker("usb1/sb-gateway")
	if !strings.Contains(worker, `comment="SB-GATEWAY container" || comment="SB-GATEWAY container previous"`) || !strings.Contains(worker, `container root is outside managed storage`) {
		t.Fatal("retained image is not included in guarded uninstall")
	}
	if strings.Index(worker, `/container/remove $containerId`) > strings.Index(worker, `/container/mounts/remove`) {
		t.Fatal("shared mounts removed before retained container")
	}
	if strings.Contains(worker, `] != nil`) || !strings.Contains(worker, `[:typeof [:find $containerRoot`) {
		t.Fatal("container-root validation must use RouterOS typeof for missing find results")
	}
	if strings.Contains(worker, `comment~"^SB-GATEWAY"]`) || !strings.Contains(worker, `comment~"^SB-GATEWAY "]`) {
		t.Fatal("uninstall must not claim foreign comment prefixes without the ownership delimiter")
	}
}
