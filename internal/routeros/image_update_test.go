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

func TestScheduleImageUpdateInstallsBoundedWorkerBeforeScheduler(t *testing.T) {
	var requests []string
	var worker string
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.RequestURI())
		response.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/script":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/script":
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil || payload["name"] != imageUpdateWorker {
				http.Error(response, "bad worker", http.StatusBadRequest)
				return
			}
			worker = text(payload["source"])
			_, _ = response.Write([]byte(`{".id":"*51"}`))
		case request.Method == http.MethodGet && request.URL.Path == "/rest/system/scheduler":
			_, _ = response.Write([]byte(`[]`))
		case request.Method == http.MethodPut && request.URL.Path == "/rest/system/scheduler":
			var payload map[string]any
			if json.NewDecoder(request.Body).Decode(&payload) != nil || payload["interval"] != "5s" || payload["on-event"] != "/system/script/run "+imageUpdateWorker {
				http.Error(response, "bad scheduler", http.StatusBadRequest)
				return
			}
			_, _ = response.Write([]byte(`{".id":"*52"}`))
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
	result, err := client.ScheduleImageUpdate(context.Background(), ImageUpdateSpec{
		Version: "1.6.0", StorageRoot: "usb1/sb-gateway", CandidateRoot: "usb1/sb-gateway/root-1.6.0",
		CandidateSource: "local-file", CandidateReference: "usb1/sb-gateway/data/lifecycle-uploads/sb-gateway-upload-0123456789abcdef.tar",
		ContainerAddress: "192.0.2.2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result["scheduled"] != true || result["delay_seconds"] != 10 {
		t.Fatalf("schedule result = %#v", result)
	}
	for _, fragment := range []string{
		`:local memoryHigh [/container/get $current memory-high]`,
		`:local memoryMax [/container/get $current memory-max]`,
		`:if ($memoryHigh < 234881024) do={ :set memoryHigh 234881024 }`,
		`:if ($memoryMax < 268435456) do={ :set memoryMax 268435456 }`,
		"memory-high=$memoryHigh memory-max=$memoryMax",
		`file="usb1/sb-gateway/data/lifecycle-uploads/sb-gateway-upload-0123456789abcdef.tar"`,
		`root-dir=$candidateRoot`,
		`restart-policy=always restart-interval=10s`,
		`http://192.0.2.2:9080/healthz`,
		`http://192.0.2.2:9080/traffic-ready`,
		`\"traffic_ready\":true`,
		`comment="SB-GATEWAY container rollback"`,
		`sbGatewayImageProbation`,
		`[/container/get $candidate stopped] = true`,
		`[/container/get $failed stopped] = true`,
		`[/container/get $current stopped] = true`,
		`comment="SB-GATEWAY image update swap"`,
		`:return true`,
		`:local jobs [/system/script/job/find where script="SB-GATEWAY-image-update-worker"]`,
		`:if ([:len $jobs] > 1) do={ :return true }`,
	} {
		if !strings.Contains(worker, fragment) {
			t.Fatalf("worker is missing %q", fragment)
		}
	}
	if strings.Contains(worker, "SB_GATEWAY_IMAGE_") {
		t.Fatal("worker contains an unquoted RouterOS variable name")
	}
	if strings.Contains(worker, `interface=""`) {
		t.Fatal("worker tries to clear a required RouterOS container interface")
	}
	if !strings.Contains(worker, `/container/start $candidate`) || !strings.Contains(worker, `:local trafficReady false`) || strings.Contains(worker, `/ip/firewall/mangle/enable $gate`) {
		t.Fatal("candidate startup enables diversion before route-aware readiness")
	}
	if len(worker) > maxFixedScriptBytes {
		t.Fatalf("worker size = %d", len(worker))
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

func TestScheduleImageUpdateRejectsUnsafeInputBeforeRouterOSRequest(t *testing.T) {
	valid := ImageUpdateSpec{
		Version: "1.6.0", StorageRoot: "usb1/sb-gateway", CandidateRoot: "usb1/sb-gateway/root-1.6.0",
		CandidateSource: "registry", CandidateReference: "registry.example/sb-gateway@sha256:" + strings.Repeat("a", 64),
		ContainerAddress: "192.0.2.2",
	}
	cases := []ImageUpdateSpec{
		func() ImageUpdateSpec { value := valid; value.Version = `1.6.0"; /user/remove`; return value }(),
		func() ImageUpdateSpec { value := valid; value.CandidateRoot = "usb1/foreign/root-1.6.0"; return value }(),
		func() ImageUpdateSpec {
			value := valid
			value.CandidateReference = "registry.example/sb-gateway:latest"
			return value
		}(),
		func() ImageUpdateSpec { value := valid; value.ContainerAddress = "2001:db8::2"; return value }(),
	}
	for _, spec := range cases {
		if _, err := (&Client{}).ScheduleImageUpdate(context.Background(), spec); err == nil {
			t.Fatalf("unsafe image update accepted: %#v", spec)
		}
	}
}

func TestSetContainerMemoryLimits(t *testing.T) {
	var payload map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPatch || request.URL.Path != "/rest/container/*A" {
			http.Error(response, "unexpected", http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(response, "bad payload", http.StatusBadRequest)
			return
		}
		_, _ = response.Write([]byte(`{}`))
	}))
	defer server.Close()
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	client, err := NewClient(Options{BaseURL: server.URL, Username: "admin", Password: "secret", RootCAs: pool})
	if err != nil {
		t.Fatal(err)
	}
	defer client.CloseIdleConnections()
	if err := client.SetContainerMemoryLimits(context.Background(), "*A", 224<<20, 256<<20); err != nil {
		t.Fatal(err)
	}
	if payload["memory-high"] != float64(224<<20) || payload["memory-max"] != float64(256<<20) {
		t.Fatalf("payload = %#v", payload)
	}
	if err := client.SetContainerMemoryLimits(context.Background(), "foreign", 224<<20, 256<<20); err == nil {
		t.Fatal("unsafe RouterOS resource identifier accepted")
	}
}

func TestImageRetentionOnlyRunsAfterHealthyProbation(t *testing.T) {
	for _, keep := range []bool{false, true} {
		spec := ImageUpdateSpec{Version: "1.6.0", StorageRoot: "usb1/sb-gateway", CandidateRoot: "usb1/sb-gateway/root-1.6.0", CandidateSource: "local-file", CandidateReference: "usb1/sb-gateway/data/lifecycle-uploads/image.tar", ContainerAddress: "192.0.2.2", KeepPrevious: keep}
		worker := renderImageUpdateWorker(spec)
		setting := ":local retainPrevious false"
		if keep {
			setting = ":local retainPrevious true"
		}
		for _, fragment := range []string{setting, `previous image is ambiguous`, `previous image interface is not owned`, `previous image root is not owned`, `previous image root is nested`, `previous image root is shared`, `previous image is not stopped`, `candidate version is retained as previous image`, `interface="veth-sb-previous" start-on-boot=no`, `restart-policy=no`, `/container/start $rollback`} {
			if !strings.Contains(worker, fragment) {
				t.Fatalf("retention %v missing %s", keep, fragment)
			}
		}
		probation := strings.Index(worker, `:if ($sbGatewayImageProbation >= 3)`)
		cleanup := strings.Index(worker, `/container/remove $previous`)
		if probation < 0 || cleanup <= probation || strings.Count(worker, `/container/remove $previous`) != 1 {
			t.Fatal("previous image can be pruned before successful probation")
		}
		failure := worker[strings.Index(worker, `:local failed $current`):]
		if strings.Contains(failure, "$retainPrevious") || strings.Contains(failure, `/container/remove $previous`) {
			t.Fatal("retention affects failure rollback")
		}
	}
}

func TestImageUpdateTransfersPersistentMountOwnershipExclusively(t *testing.T) {
	spec := ImageUpdateSpec{Version: "1.6.0", StorageRoot: "pcie1/sb-gateway", CandidateRoot: "pcie1/sb-gateway/root-1.6.0", CandidateSource: "local-file", CandidateReference: "pcie1/sb-gateway/data/lifecycle-uploads/image.tar", ContainerAddress: "192.0.2.2", KeepPrevious: true}
	worker := renderImageUpdateWorker(spec)
	addStart := strings.Index(worker, `/container/add file=`)
	if addStart < 0 {
		t.Fatal("candidate add command is missing")
	}
	addEnd := strings.Index(worker[addStart:], "\n")
	if addEnd < 0 {
		addEnd = len(worker) - addStart
	}
	if strings.Contains(worker[addStart:addStart+addEnd], "mountlists=") {
		t.Fatal("candidate claims persistent mounts while the current container still owns them")
	}
	ordered := []string{
		`/container/stop $current`,
		`/container/set $current mountlists=""`,
		`/container/set $candidate mountlists=$mountlists`,
		`/container/start $candidate`,
	}
	position := -1
	for _, fragment := range ordered {
		next := strings.Index(worker[position+1:], fragment)
		if next < 0 {
			t.Fatalf("mount ownership transfer is missing %q", fragment)
		}
		position += next + 1
	}
	rollback := worker[strings.Index(worker, `:local failed $current`):]
	detachFailed := strings.Index(rollback, `/container/set $failed mountlists=""`)
	attachRollback := strings.Index(rollback, `/container/set $rollback mountlists=$failedMountlists`)
	startRollback := strings.Index(rollback, `/container/start $rollback`)
	if detachFailed < 0 || attachRollback <= detachFailed || startRollback <= attachRollback {
		t.Fatal("rollback does not restore exclusive persistent mount ownership before start")
	}
	for _, fragment := range []string{
		`/container/set $candidate mountlists=""`,
		`/container/set $current mountlists=$recoveryMountlists`,
		`:if ([:len $previous] = 1) do={ /container/set $previous mountlists="" }`,
		`persistent mount ownership transfer failed`,
	} {
		if !strings.Contains(worker, fragment) {
			t.Fatalf("mount ownership recovery is missing %q", fragment)
		}
	}
}

func TestImageUpdateFindChecksUseRouterOSType(t *testing.T) {
	spec := ImageUpdateSpec{Version: "1.5.44", StorageRoot: "pcie1/sb-gateway", CandidateRoot: "pcie1/sb-gateway/root-1.5.44", CandidateSource: "local-file", CandidateReference: "pcie1/sb-gateway/data/lifecycle-uploads/image.tar", ContainerAddress: "192.0.2.2", KeepPrevious: true}
	worker := renderImageUpdateWorker(spec)
	for _, want := range []string{`[:typeof [:find $previousRoot "/" 23]] = "num"`, `[:typeof [:find $probe "\"ready\":true"]] = "num"`} {
		if !strings.Contains(worker, want) {
			t.Fatalf("missing typed find check: %s", want)
		}
	}
	if strings.Contains(worker, `!= nil`) {
		t.Fatal("RouterOS bare nil comparison is not an absence check")
	}
	if strings.Contains(worker, `\"status\":\"ok\"`) {
		t.Fatal("image probation must consume the router readiness contract")
	}
}
