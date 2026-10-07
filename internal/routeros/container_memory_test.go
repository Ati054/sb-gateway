package routeros

import (
	"os"
	"strings"
	"testing"
)

func TestMemoryWorkerConsumesOneShotBeforeBothLimits(t *testing.T) {
	worker := renderContainerMemoryWorker("usb1/sb-gateway/root-1.6.45", 224<<20, 256<<20, 320<<20, 384<<20)
	remove := strings.Index(worker, `/system/scheduler/remove $scheduler`)
	change := strings.Index(worker, `/container/set $target memory-high=335544320 memory-max=402653184`)
	gate := strings.Index(worker, `/ip/firewall/mangle/disable $gate`)
	if remove < 0 || gate <= remove || change <= gate || strings.Count(worker, `/container/set`) != 1 {
		t.Fatal("memory mutation must be one command after consuming the one-shot and entering fail-open")
	}
	if strings.Contains(worker, "/container/start") || strings.Contains(worker, "/container/stop") || !strings.Contains(worker, "since confirmation") || !strings.Contains(worker, "memory readback failed") {
		t.Fatal("memory change needs stale-state/readback guards without extra stop/start")
	}
	if !validFixedManagedScript(containerMemoryWorker, worker) {
		t.Fatal("worker is not permitted")
	}
}

// The lab fixture redirects every ownership name to an isolated sleep container.
func TestEmitContainerMemoryCHRProbe(t *testing.T) {
	path := os.Getenv("SB_MEMORY_CHR_OUTPUT")
	if path == "" {
		t.Skip("CHR fixture output not requested")
	}
	worker := renderContainerMemoryWorker("pcie1/sb-gateway-boot-probe", 224<<20, 256<<20, 320<<20, 384<<20)
	worker = strings.NewReplacer(containerMemoryWorker, "SB-GATEWAY-boot-probe-memory-worker", ContainerMemoryScheduler, "SB-GATEWAY-boot-probe-memory-once", `comment="SB-GATEWAY container"`, `comment="SB-GATEWAY-boot-probe"`, `comment="SB-GATEWAY diversion-gate"`, `comment="SB-GATEWAY-boot-probe gate"`, `name="SB-GATEWAY-health-watchdog"`, `name="SB-GATEWAY-boot-probe-watchdog"`, `comment="SB-GATEWAY health scheduler"`, `comment="SB-GATEWAY-boot-probe watchdog"`).Replace(worker)
	source := `/ip/firewall/mangle/add chain=prerouting action=passthrough disabled=yes comment="SB-GATEWAY-boot-probe gate"` + "\n" +
		`/system/scheduler/add name="SB-GATEWAY-boot-probe-watchdog" interval=5s on-event=":local noop true" policy=read comment="SB-GATEWAY-boot-probe watchdog"` + "\n" +
		`/system/script/add name="SB-GATEWAY-boot-probe-memory-worker" policy=read,write,test,policy source={` + "\n" + worker + "\n}\n" +
		`/system/scheduler/add name="SB-GATEWAY-boot-probe-memory-once" interval=10s on-event="/system/script/run SB-GATEWAY-boot-probe-memory-worker" policy=read,write,test,policy comment="SB-GATEWAY one-shot container memory update"` + "\n"
	if err := os.WriteFile(path, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestMemoryLimitsRejectInversionAndOutOfRange(t *testing.T) {
	for _, pair := range [][2]int64{{0, 256 << 20}, {320 << 20, 256 << 20}, {16 << 20, 9 << 30}, {-1, 256 << 20}} {
		if ValidContainerMemoryLimits(pair[0], pair[1]) {
			t.Fatalf("accepted %v", pair)
		}
	}
	if !ValidContainerMemoryLimits(224<<20, 256<<20) {
		t.Fatal("normal limits rejected")
	}
}
