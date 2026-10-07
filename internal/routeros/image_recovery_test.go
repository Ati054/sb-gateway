package routeros

import (
	"strings"
	"testing"
)

func recoverySpec() ImageUpdateSpec {
	return ImageUpdateSpec{Version: "1.6.45-rc.2", StorageRoot: "usb1/sb-gateway", CandidateRoot: "usb1/sb-gateway/root-1.6.45-rc.2",
		CandidateSource: "local-file", CandidateReference: "usb1/sb-gateway/data/lifecycle-uploads/candidate.tar", ContainerAddress: "172.31.255.2"}
}

func TestOfflineRecoveryNeverRestartsBrokenPredecessor(t *testing.T) {
	spec := recoverySpec()
	spec.StoppedPredecessor = true
	worker := renderImageUpdateWorker(spec)
	for _, forbidden := range []string{"/container/start $rollback", "/container/start $current"} {
		if strings.Contains(worker, forbidden) {
			t.Fatalf("offline worker restarts broken predecessor: %s", forbidden)
		}
	}
	if !strings.Contains(worker, "/container/start $candidate") || strings.Count(worker, "start-on-boot=no") < 3 {
		t.Fatal("candidate startup or stopped-predecessor recovery paths are missing")
	}
	spec.StoppedPredecessor = false
	if !strings.Contains(renderImageUpdateWorker(spec), "/container/start $rollback") {
		t.Fatal("ordinary update lost working-image rollback")
	}
}

func TestImageRollbackDisablesDiversionEvenAfterReadyRestart(t *testing.T) {
	for _, offline := range []bool{false, true} {
		spec := recoverySpec()
		spec.StoppedPredecessor = offline
		worker := renderImageUpdateWorker(spec)
		boundary := strings.Index(worker, `:if (($sbGatewayImageMisses < 60) && ($restartCount = 0)) do={ :return true }`)
		if boundary < 0 {
			t.Fatal("failed probation boundary is missing")
		}
		tail := worker[boundary:]
		disable := strings.Index(tail, `/ip/firewall/mangle/disable $probationGate`)
		stop := strings.Index(tail, `/container/stop $failed`)
		if disable < 0 || stop < 0 || disable > stop {
			t.Fatal("ready restarted candidate can be stopped with diversion still enabled")
		}
	}
}

func TestImageTransferDoesNotBootBothImagesDuringRouterRestart(t *testing.T) {
	worker := renderImageUpdateWorker(recoverySpec())
	add := strings.Index(worker, `/container/add file=`)
	if add < 0 {
		t.Fatal("candidate extraction is missing")
	}
	line := strings.SplitN(worker[add:], "\n", 2)[0]
	if !strings.Contains(line, "start-on-boot=no") {
		t.Fatal("unfinished candidate can boot with the predecessor")
	}
	readback := strings.Index(worker, "metadata readback failed")
	disable := strings.Index(worker[readback:], `/container/set $current start-on-boot=no`)
	stop := strings.Index(worker[readback:], `/container/stop $current`)
	if stop < 0 || disable <= stop || !strings.Contains(worker, `start-on-boot=$previousBoot`) {
		t.Fatal("previous boot policy must be preserved, then disabled only after stop")
	}
	swap := strings.Index(worker, `/container/set $candidate interface=$liveIf comment="SB-GATEWAY container"`)
	enable := strings.Index(worker, `/container/set $candidate start-on-boot=yes`)
	start := strings.Index(worker, `/container/start $candidate`)
	if swap < 0 || enable <= swap || start <= enable || strings.Contains(worker, `/container/set $current start-on-boot=yes`) {
		t.Fatal("candidate boot policy must be set after exclusive transfer and before first start, never on live commit")
	}
	if !strings.Contains(worker, "candidate boot policy changed during probation") {
		t.Fatal("commit must reject drift instead of restarting the live candidate")
	}
}

func TestOfflineRecoveryGuardsPrecedeEveryMutation(t *testing.T) {
	script, err := RenderOfflineImageRecovery(recoverySpec(), 110319616, "MikroTik")
	if err != nil {
		t.Fatal(err)
	}
	mutation := strings.Index(script, `:if ([:len $script] = 0) do={ /system/script/add`)
	for _, guard := range []string{"router identity mismatch", "stop the broken container", "persistent settings are missing", "root does not match", "container address mismatch", "active transaction", "unfinished image update", "candidate root already exists", "archive size mismatch", "worker is not owned", "diversion gate is ambiguous"} {
		if index := strings.Index(script, guard); index < 0 || index > mutation {
			t.Fatalf("missing pre-mutation guard: %s", guard)
		}
	}
	if mutation < 0 || strings.Count(script, "/system/scheduler/add") != 1 || !strings.Contains(script, `:local retainPrevious true`) {
		t.Fatal("scheduler-last or retained-predecessor contract missing")
	}
	if strings.Index(script, "/system/scheduler/add") < strings.LastIndex(script, "/container/set $current restart-policy=no") {
		t.Fatal("scheduler is armed before stopping predecessor restart policy")
	}
}

func TestOfflineRecoveryRejectsUnsafeInputs(t *testing.T) {
	for _, identity := range []string{"", "router\n/quit", `router"`, "$router"} {
		if _, err := RenderOfflineImageRecovery(recoverySpec(), 123, identity); err == nil {
			t.Fatalf("unsafe identity accepted: %q", identity)
		}
	}
	for _, size := range []int64{0, -1, 2<<30 + 1} {
		if _, err := RenderOfflineImageRecovery(recoverySpec(), size, "MikroTik"); err == nil {
			t.Fatal("unsafe archive size accepted")
		}
	}
	spec := recoverySpec()
	spec.CandidateReference = "usb1/sb-gateway/../candidate.tar"
	if _, err := RenderOfflineImageRecovery(spec, 123, "MikroTik"); err == nil {
		t.Fatal("archive outside managed upload directory accepted")
	}
	if _, err := RenderOfflineImageRecovery(recoverySpec(), 123, "MikroTik"); err != nil {
		t.Fatal(err)
	}
}
