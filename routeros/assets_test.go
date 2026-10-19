package routerosassets

import (
	"os"
	"strings"
	"testing"
)

func TestContainerBootWaitsForStorageWithoutPeriodicRestart(t *testing.T) {
	installer := ContainerStartupInstallSource()
	ready := ContainerStorageReadySource()
	boot := ContainerBootSource()
	for _, fragment := range []string{`[/file/get $diskName type] != "disk"`, `[/file/get $path type]`, `($kind = "directory") || ($kind = "container store")`, `[/container/get $target root-dir]`, `[/container/get $target mountlists]`, `[/container/mounts/get $mountId src]`, `[/container/mounts/get $mountId disabled] = false`, `($checkedDisks->$diskName) != true`, `:local disksOnly ($2 = true)`} {
		if !strings.Contains(ready, fragment) {
			t.Fatalf("missing storage gate: %s", fragment)
		}
	}
	for _, folder := range []string{`"/config"`, `"/data"`, `"/logs"`, `"/state"`} {
		if strings.Contains(ready, folder) {
			t.Fatalf("storage gate must not hardcode mount layout: %s", folder)
		}
	}
	if !strings.Contains(boot, `[$ready $target true]`) || !strings.Contains(boot, `[$ready $target]`) || !strings.Contains(boot, "mount source folders are missing") {
		t.Fatal("boot must poll disks and check actual source folders once before start")
	}
	for _, fragment := range []string{`$attempt < 150`, `:delay 2s`, `$stable >= 2`, `SB-GATEWAY-image-update-transfer`, `SB-GATEWAY-image-update`, `[:len $targets] > 1`, `[/container/get $target running] = true`, `[/container/get $target stopped] = true`, `/container/start $target`, `:set finished true`, `boot storage wait expired`} {
		if !strings.Contains(boot, fragment) {
			t.Fatalf("missing bounded one-shot boot contract: %s", fragment)
		}
	}
	if strings.Contains(boot, ":return") {
		t.Fatal("scheduler script must finish normally, not throw a return value through script/run")
	}
	if !strings.Contains(boot, `[/container/get $target healthy] = true`) {
		t.Fatal("RouterOS healthy flag may replace running; boot must recognize both")
	}
	for _, forbidden := range []string{"/file/find", "/file/add", "/file/remove", "/disk/", "/container/stop", "/container/set"} {
		if strings.Contains(ready+boot, forbidden) {
			t.Fatalf("boot readiness may not mutate storage or lifecycle: %s", forbidden)
		}
	}
	mutation := strings.Index(installer, "/system/script/add")
	for _, guard := range []string{"startup objects are ambiguous", "storage probe is not owned", "startup script is not owned", "startup scheduler is not owned"} {
		if at := strings.Index(installer, guard); at < 0 || at >= mutation {
			t.Fatalf("ownership guard must precede every mutation: %s", guard)
		}
	}
	if !strings.Contains(installer, "interval=0s start-time=startup") {
		t.Fatal("startup must run only once per boot")
	}
	if !strings.HasPrefix(ready, "\n") || !strings.HasSuffix(ready, "\n") || !strings.HasPrefix(boot, "\n") || !strings.HasSuffix(boot, "\n") {
		t.Fatal("updater comparisons require the exact RouterOS source whitespace")
	}
}

func TestFreshInstallUsesStorageAwareBoot(t *testing.T) {
	dockerIgnore, err := os.ReadFile("../.dockerignore")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.ReplaceAll(string(dockerIgnore), "\r\n", "\n"), "!routeros/container-startup.rsc\n") {
		t.Fatal("Docker build must include the embedded storage-aware startup asset")
	}
	install, err := os.ReadFile("install.rsc")
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := os.ReadFile("bootstrap.rsc")
	if err != nil {
		t.Fatal(err)
	}
	source := string(install)
	if strings.Contains(source, "start-on-boot=yes") || strings.Count(source, "start-on-boot=no") != 3 {
		t.Fatal("fresh and re-imported containers must not race storage-aware startup")
	}
	if strings.Index(source, "mount source disk is not mounted") > strings.Index(source, "/file/add name=$path") {
		t.Fatal("initial folder creation must follow disk readiness")
	}
	if !strings.Contains(source, "restart-policy=always restart-interval=10s") || !strings.Contains(source, "[$storageReady $containerId] != true") {
		t.Fatal("explicit start and runtime restart policy must be preserved")
	}
	if strings.Index(string(bootstrap), `/import file-name=($bundleRoot . "/container-startup.rsc")`) > strings.Index(string(bootstrap), `/import file-name=($bundleRoot . "/install.rsc")`) {
		t.Fatal("startup helper must be installed before the container")
	}
}

func TestWatchdogReconcilesActualGateAfterFreshHealth(t *testing.T) {
	source := HealthWatchdogSource()
	fetch := strings.Index(source, `:local response [/tool/fetch`)
	healthy := strings.Index(source, `:if ($healthy = true)`)
	actual := strings.Index(source, `:local gateDisabled [/ip/firewall/mangle/get $gate disabled]`)
	enable := strings.Index(source, `/ip/firewall/mangle/enable $gate`)
	if fetch < 0 || healthy < fetch || actual < healthy || enable < actual {
		t.Fatal("gate reconciliation must follow fresh readiness")
	}
	for _, fragment := range []string{`($gateDisabled = true) && (($sbStartupSafety = true) || ($sbFailOpen = false) ||`, `SB_HEALTH_RECOVERY_THRESHOLD`, `SB_HEALTH_COOLDOWN_TICKS`} {
		if !strings.Contains(source, fragment) {
			t.Fatalf("missing drift recovery/hysteresis: %s", fragment)
		}
	}
	if strings.Contains(source, "reverse") || strings.Contains(source, "selector_health") {
		t.Fatal("router readiness must not depend on exit availability")
	}
}

func TestWatchdogConsumesRestartIdentityOnlyAfterFreshTrafficReadiness(t *testing.T) {
	source := HealthWatchdogSource()
	fetch := strings.Index(source, `:local response [/tool/fetch`)
	parse := strings.Index(source, `:local readiness [:deserialize from=json value=($response->"data")]`)
	proof := strings.Index(source, `:if (($readiness->"traffic_ready") = true)`)
	healthy := strings.Index(source, `:if ($healthy = true)`)
	consume := strings.Index(source, `:set sbReadyGeneration $readyGeneration`)
	if consume < 0 {
		t.Fatal("watchdog does not track successful startup identity")
	}
	startup := strings.Index(source[consume:], `:set sbStartupSafety true`)
	enable := strings.Index(source, `/ip/firewall/mangle/enable $gate`)
	if fetch < 0 || parse < fetch || proof < parse || healthy < proof || consume < healthy || startup < 0 || enable < consume+startup {
		t.Fatal("new startup identity must be consumed only after a successful current-process readiness proof")
	}
	for _, required := range []string{`($readiness->"runtime_started_at")`, `($sbReadyGeneration != $readyGeneration)`, `[:len $generation] <= 64`, `SB_HEALTH_RECOVERY_THRESHOLD`, `SB_HEALTH_COOLDOWN_TICKS`} {
		if !strings.Contains(source, required) {
			t.Fatalf("missing bounded startup identity or ordinary outage hysteresis: %s", required)
		}
	}
}

func TestWatchdogExpiresOnlyRecoveredManagedRouterDNS(t *testing.T) {
	source := HealthWatchdogSource()
	cleanup := strings.Index(source, "      $clearRecoveredDNS")
	if strings.Contains(source, `dst-address~":53$"`) {
		t.Fatal("RouterOS quoted regex anchors must be escaped, including inside imported script bodies")
	}
	if strings.Contains(source, `connection-mark=no-mark`) {
		t.Fatal("unmarked conntrack entries have an empty mark, not a literal no-mark value")
	}
	if cleanup < strings.Index(source, `/ip/firewall/mangle/enable $gate`) {
		t.Fatal("DNS conntrack cleanup must follow gate admission so concurrent queries cannot recreate the outage path")
	}
	for _, fragment := range []string{
		`:if ([:len $dnsNat] != 1) do={ :return false }`,
		`find where dst-address~":53\$"`,
		`($dnsFlows, [/ip/firewall/connection/find where dst-port=53 and dstnat=no])`,
		`:foreach flow in=$dnsFlows do={`,
		`:if ([:typeof $sourceColon] = "num") do={ :set source [:pick $source 0 $sourceColon] }`,
		`:if ([:typeof $destinationColon] = "num") do={ :set destinationIP [:pick $destinationIP 0 $destinationColon] }`,
		`:local sourceIP [:toip $source]`,
		`:local connectionMark [/ip/firewall/connection/get $flow connection-mark]`,
		`:if (([:len [:tostr $connectionMark]] = 0) && ([/ip/firewall/connection/get $flow dstnat] = false)) do={`,
		`($protocol = "udp") || ($protocol = "tcp")`,
		`($localDestination = true) && ([:tostr $sourceIP] != [:tostr $containerIP])`,
		`list="SB_MANAGED_CLIENTS"`,
		`($sourceIP >> (32 - $bits)) = ($networkIP >> (32 - $bits))`,
		`:if ($managed = true) do={ /ip/firewall/connection/remove $flow }`,
	} {
		if !strings.Contains(source, fragment) {
			t.Fatalf("missing DNS cleanup scope: %s", fragment)
		}
	}
}

func TestWatchdogSerializesRecoveryAndPurgesOnlyOnTransition(t *testing.T) {
	source := HealthWatchdogSource()
	guard := strings.Index(source, `:if ([/system/script/job/print count-only as-value where script=[:jobname]] <= 1) do={`)
	if guard < 0 || guard > strings.Index(source, `/system/script/run SB-GATEWAY-watchdog-config`) {
		t.Fatal("concurrent health jobs must exit without changing state")
	}
	enable := strings.Index(source, `/ip/firewall/mangle/enable $gate`)
	cleanup := strings.Index(source, "      $clearRecoveredDNS")
	if state := strings.Index(source[enable:], `:set sbFailOpen false`); state < 0 || enable+state > cleanup {
		t.Fatal("recovery state must commit before DNS maintenance")
	}
	transition := strings.Index(source, `:if (($gateWasEnabled = true) || ($sbFailOpen = false)) do={`)
	if transition < 0 || !strings.Contains(source[transition:], `/ip/firewall/connection/remove [find where connection-mark="sb-managed"]`) {
		t.Fatal("outage cleanup must be limited to the state transition")
	}
	flow := strings.Index(source, `:foreach flow in=$dnsFlows do={`)
	if flow < 0 || strings.Contains(source[flow:cleanup], `/ip/address/find`) ||
		strings.Contains(source[flow:cleanup], `/ip/firewall/address-list/find`) {
		t.Fatal("router addresses and managed prefixes must be read once, not per flow")
	}
	if strings.Count(source, "and dstnat=no") != 2 {
		t.Fatal("already translated DNS flows must be excluded before enumeration")
	}
}
