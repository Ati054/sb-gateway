package watchdog

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestSlowDeepCheckDoesNotBlockLiveProof(t *testing.T) {
	now := time.Now()
	s := settings{interval: 5 * time.Second, deepInterval: 30 * time.Second}
	d := newDeepChecks(Options{})
	d.identity, d.proof, d.verifiedAt = "current", &runner{deepHealthy: true}, now
	started := make(chan struct{})
	d.probe = func(ctx context.Context, r *runner) {
		close(started)
		<-ctx.Done()
		r.deepUncertain = true
		r.deepReasons = []string{"transparent_nft"}
	}
	defer d.close()
	begin := time.Now()
	healthy, _, pending := d.observe(context.Background(), "current", s, now)
	if !healthy || pending || time.Since(begin) > 100*time.Millisecond {
		t.Fatal("slow command blocked a verified live heartbeat")
	}
	<-started
	for n := 1; n <= 3; n++ {
		if healthy, _, _ := d.observe(context.Background(), "current", s, now.Add(time.Duration(n)*time.Second)); !healthy {
			t.Fatal("in-flight command discarded recent proof")
		}
	}
	if d.wait(context.Background(), time.Millisecond) != true {
		t.Fatal("heartbeat wait was coupled to command completion")
	}
}

func TestInconclusiveDeepChecksCannotRefreshOldProof(t *testing.T) {
	now := time.Unix(1000, 0)
	s := settings{interval: 5 * time.Second, deepInterval: 30 * time.Second}
	d := newDeepChecks(Options{})
	d.identity, d.proof, d.verifiedAt = "current", &runner{deepHealthy: true}, now
	for _, elapsed := range []time.Duration{30 * time.Second, 35 * time.Second, 40 * time.Second} {
		d.task = &deepCheckTask{identity: "current", started: now.Add(elapsed), settings: s, cancel: func() {}}
		d.accept(deepCheckResult{"current", &runner{deepUncertain: true, deepReasons: []string{"transparent_nft"}}}, now.Add(elapsed))
		if d.verifiedAt != now || !d.proof.deepHealthy {
			t.Fatal("inconclusive failure changed the age of positive evidence")
		}
	}
	d.next = now.Add(time.Hour)
	if ok, _, _ := d.observe(context.Background(), "current", s, now.Add(44*time.Second)); !ok {
		t.Fatal("bounded recent proof was discarded early")
	}
	if ok, reasons, _ := d.observe(context.Background(), "current", s, now.Add(45*time.Second)); ok || len(reasons) != 1 || reasons[0] != "transparent_nft" {
		t.Fatalf("old proof outlived its bound: healthy=%t reasons=%v", ok, reasons)
	}
}

func TestDefiniteDeepFailureOverridesRecentProof(t *testing.T) {
	now := time.Unix(1000, 0)
	s := settings{interval: time.Second, deepInterval: 30 * time.Second}
	d := newDeepChecks(Options{})
	d.identity, d.proof, d.verifiedAt = "current", &runner{deepHealthy: true}, now
	d.task = &deepCheckTask{identity: "current", settings: s, cancel: func() {}}
	d.accept(deepCheckResult{"current", &runner{deepReasons: []string{"transparent_nft"}}}, now)
	if healthy, _, _ := d.observe(context.Background(), "current", s, now); healthy {
		t.Fatal("missing rules inherited the uncertainty allowance")
	}
}

func TestInconclusiveFirstProbeCannotAdmitTraffic(t *testing.T) {
	now := time.Unix(1000, 0)
	s := settings{interval: time.Second, deepInterval: 30 * time.Second}
	d := newDeepChecks(Options{})
	d.identity = "current"
	d.task = &deepCheckTask{identity: "current", started: now, settings: s, cancel: func() {}}
	d.accept(deepCheckResult{"current", &runner{deepUncertain: true, deepReasons: []string{"transparent_nft"}}}, now)
	if healthy, _, pending := d.observe(context.Background(), "current", s, now); healthy || pending || !d.verifiedAt.IsZero() {
		t.Fatal("first inconclusive observation admitted unverified traffic")
	}
}

func TestDelayedDeepResultDoesNotMakeOldObservationFresh(t *testing.T) {
	now := time.Unix(1000, 0)
	s := settings{interval: time.Second, deepInterval: 30 * time.Second}
	d := newDeepChecks(Options{})
	d.identity = "current"
	d.task = &deepCheckTask{identity: "current", started: now.Add(-44 * time.Second), settings: s, cancel: func() {}}
	d.accept(deepCheckResult{"current", &runner{deepHealthy: true}}, now)
	d.next = now.Add(time.Hour)
	if ok, _, _ := d.observe(context.Background(), "current", s, now.Add(time.Second)); ok {
		t.Fatal("delayed result renewed the proof timestamp")
	}
}

func TestApplyResetRejectsLateResultWithSameIdentity(t *testing.T) {
	d := newDeepChecks(Options{})
	d.identity = "same"
	old := &deepCheckTask{identity: "same", cancel: func() {}, result: make(chan deepCheckResult, 1)}
	old.result <- deepCheckResult{"same", &runner{deepHealthy: true}}
	d.task = old
	d.reset()
	d.probe = func(ctx context.Context, r *runner) { <-ctx.Done() }
	defer d.close()
	if healthy, _, pending := d.observe(context.Background(), "same", settings{interval: time.Second, deepInterval: 30 * time.Second}, time.Now()); healthy || !pending || d.proof != nil {
		t.Fatal("a pre-Apply result admitted an identical post-Apply artifact")
	}
}

func TestDeepProbeEpochChangeCancelsWithoutOverlap(t *testing.T) {
	s := settings{interval: time.Second, deepInterval: 30 * time.Second}
	d := newDeepChecks(Options{})
	var active, maximum atomic.Int32
	started := make(chan struct{}, 4)
	d.probe = func(ctx context.Context, r *runner) {
		count := active.Add(1)
		if count > maximum.Load() {
			maximum.Store(count)
		}
		started <- struct{}{}
		<-ctx.Done()
		r.deepHealthy = true // A late success must not resurrect the old epoch.
		active.Add(-1)
	}
	defer d.close()
	d.observe(context.Background(), "first", s, time.Now())
	<-started
	if healthy, _, _ := d.observe(context.Background(), "second", s, time.Now()); healthy {
		t.Fatal("new epoch reused the old proof")
	}
	if !d.wait(context.Background(), time.Second) {
		t.Fatal("cancelled old worker did not finish")
	}
	if healthy, _, pending := d.observe(context.Background(), "second", s, time.Now()); healthy || !pending {
		t.Fatal("old worker success admitted the new epoch")
	}
	<-started
	if maximum.Load() != 1 {
		t.Fatal("deep workers overlapped")
	}
	d.reset()
	if d.proof != nil || d.identity != "" || !d.verifiedAt.IsZero() {
		t.Fatal("Apply reset retained proof")
	}
}

func TestDeepProbeIdentityIncludesBothRuntimeArtifacts(t *testing.T) {
	dir := t.TempDir()
	opts := Options{XrayConfig: filepath.Join(dir, "xray.json"), PolicyDNSConfig: filepath.Join(dir, "dns.json")}
	for _, path := range []string{opts.XrayConfig, opts.PolicyDNSConfig} {
		if err := os.WriteFile(path, []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := deepProbeIdentity("123 456", opts)
	if before == "" || before == deepProbeIdentity("123 457", opts) {
		t.Fatal("core generation was not bound to proof")
	}
	for _, path := range []string{opts.XrayConfig, opts.PolicyDNSConfig} {
		if err := os.WriteFile(path, []byte("{ }"), 0600); err != nil {
			t.Fatal(err)
		}
		after := deepProbeIdentity("123 456", opts)
		if after == "" || after == before {
			t.Fatal("runtime artifact change kept the old identity")
		}
		before = after
	}
	if err := os.Remove(opts.PolicyDNSConfig); err != nil {
		t.Fatal(err)
	}
	if deepProbeIdentity("123 456", opts) != "" {
		t.Fatal("missing DNS contract retained proof")
	}
}
