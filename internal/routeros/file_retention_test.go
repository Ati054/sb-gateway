package routeros

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"
)

func TestPruneManagedFilesRetainsThreeBackupGenerationsAndRemovesInstallArtifacts(t *testing.T) {
	rows := `[
		{".id":"*1","name":"SB-GATEWAY-20260920T010000Z-aaaaaaaaaaaa.backup"},
		{".id":"*2","name":"SB-GATEWAY-20260920T010000Z-aaaaaaaaaaaa-export.rsc"},
		{".id":"*3","name":"SB-GATEWAY-20260920T020000Z-bbbbbbbbbbbb.backup"},
		{".id":"*4","name":"SB-GATEWAY-20260920T020000Z-bbbbbbbbbbbb-export.rsc"},
		{".id":"*5","name":"SB-GATEWAY-20260920T030000Z-cccccccccccc.backup"},
		{".id":"*6","name":"SB-GATEWAY-20260920T040000Z-dddddddddddd.backup"},
		{".id":"*7","name":"SB-GATEWAY-20260920T050000Z-eeeeeeeeeeee.backup"},
		{".id":"*8","name":"usb1/sb-gateway/sb-gateway-1.6.4-linux-arm64.tar"},
		{".id":"*9","name":"usb1/sb-gateway/sb-gateway-1.6.4-linux-arm64.tar.sha256"},
		{".id":"*10","name":"usb1/sb-gateway/install.rsc"},
		{".id":"*11","name":"usb1/sb-gateway/variables.rsc"},
		{".id":"*12","name":"usb1/sb-gateway/config/generated/xray.json"},
		{".id":"*13","name":"usb1/sb-gateway/data/lifecycle-uploads/sb-gateway-1.7.0-linux-arm64.tar"},
		{".id":"*14","name":"usb1/sb-gateway/routeros-ca.crt"},
		{".id":"*15","name":"autosupout.rif"},
		{".id":"*16","name":"foreign.backup"}
	]`
	deleted := []string{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		if request.Method == http.MethodGet && request.URL.Path == "/rest/file" {
			_, _ = response.Write([]byte(rows))
			return
		}
		if request.Method == http.MethodDelete {
			deleted = append(deleted, request.URL.Path)
			_, _ = response.Write([]byte(`{}`))
			return
		}
		http.Error(response, "unexpected request", http.StatusBadRequest)
	}))
	defer server.Close()
	client := newTestClient(t, server)
	defer client.CloseIdleConnections()

	result, err := client.PruneManagedFiles(context.Background(), "usb1/sb-gateway")
	if err != nil {
		t.Fatal(err)
	}
	if result.Backups != 4 || result.Install != 4 {
		t.Fatalf("prune result = %#v", result)
	}
	sort.Strings(deleted)
	want := []string{"/rest/file/*1", "/rest/file/*10", "/rest/file/*11", "/rest/file/*2", "/rest/file/*3", "/rest/file/*4", "/rest/file/*8", "/rest/file/*9"}
	sort.Strings(want)
	if len(deleted) != len(want) {
		t.Fatalf("deleted = %#v", deleted)
	}
	for index := range want {
		if deleted[index] != want[index] {
			t.Fatalf("deleted = %#v", deleted)
		}
	}
}

func TestPruneManagedFilesRejectsUnsafeStorageRootBeforeNetwork(t *testing.T) {
	client := &Client{}
	for _, root := range []string{"usb1", "../usb1/sb-gateway", "usb1/../flash", ""} {
		if _, err := client.PruneManagedFiles(context.Background(), root); err == nil {
			t.Fatalf("unsafe storage root accepted: %q", root)
		}
	}
}
