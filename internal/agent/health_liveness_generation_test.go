package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type publishingAvailabilityRuntime struct {
	*fakeSelectorRuntime
	duringProbe func()
}

func TestPlannedApplyPausesProofWithoutChangingSelection(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		t.Run(mode, func(t *testing.T) {
			controller, primary, item := livenessFixture(t, mode)
			guard := filepath.Join(t.TempDir(), "apply-in-progress")
			paths := []string{guard}
			runtime := &responsiveSelectorRuntime{selectorRuntime: primary, ctx: context.Background(),
				generationPaths: paths, generation: generationStamp(paths), applyGuardFile: guard}
			controller.runtime = runtime
			item.AvailabilityFailures["de"] = 1
			primary.probes["de"] = probeEvidence{Failure: probeFailureTimeout}
			now := time.Now()
			if err := os.WriteFile(guard, []byte(fmt.Sprintf("%d %d %d\n", os.Getpid(), now.Unix(), now.Unix())), 0600); err != nil {
				t.Fatal(err)
			}
			if err := controller.Tick(now); !errors.Is(err, errHealthPlannedApply) {
				t.Fatalf("Apply pause: %v", err)
			}
			if item.Selected != "de" || item.AvailabilityFailures["de"] != 1 {
				t.Fatal("planned pause changed routing or failure evidence")
			}
			if err := os.Remove(guard); err != nil {
				t.Fatal(err)
			}
			_, reset, err := runtime.Reload()
			if err != nil || !reset {
				t.Fatalf("resume must invalidate old proof: reset=%v err=%v", reset, err)
			}
			controller.runtime = primary
			primary.reset = reset
			if err := controller.Tick(now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if item.Selected != "de" || item.AvailabilityFailures["de"] != 1 {
				t.Fatalf("old failure combined after Apply: selected=%s failures=%d", item.Selected, item.AvailabilityFailures["de"])
			}
		})
	}
}

func TestDNSPublicationInvalidatesProofWithoutCoreRestart(t *testing.T) {
	controller, primary, item := livenessFixture(t, "best")
	path := filepath.Join(t.TempDir(), "policy-dns.json")
	if err := os.WriteFile(path, []byte("old-dns"), 0600); err != nil {
		t.Fatal(err)
	}
	paths := []string{path}
	runtime := &responsiveSelectorRuntime{selectorRuntime: primary, ctx: context.Background(),
		generationPaths: paths, generation: generationStamp(paths)}
	controller.runtime = runtime
	item.AvailabilityFailures["de"] = 1
	primary.probes["de"] = probeEvidence{Failure: probeFailureTimeout}
	if err := os.WriteFile(path, []byte("new-dns-settings"), 0600); err != nil {
		t.Fatal(err)
	}
	_, reset, err := runtime.Reload()
	if err != nil || !reset {
		t.Fatalf("DNS publication must reset proof: reset=%v err=%v", reset, err)
	}
	controller.runtime = primary
	primary.reset = reset
	if err := controller.Tick(time.Unix(1010, 0)); err != nil {
		t.Fatal(err)
	}
	if item.Selected != "de" || item.AvailabilityFailures["de"] != 1 {
		t.Fatalf("DNS restart counted as remote outage: selected=%s failures=%d", item.Selected, item.AvailabilityFailures["de"])
	}
}

func (runtime *publishingAvailabilityRuntime) ProbeAvailability(candidate string) probeEvidence {
	evidence := runtime.fakeSelectorRuntime.ProbeAvailability(candidate)
	if runtime.duringProbe != nil {
		runtime.duringProbe()
	}
	return evidence
}

func TestActiveAvailabilityRejectsEvidenceAcrossApply(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, change := range []string{"before", "during", "cancelled", "unchanged"} {
			t.Run(mode+"/"+change, func(t *testing.T) {
				controller, base, item := livenessFixture(t, mode)
				path := filepath.Join(t.TempDir(), "core-ready")
				if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				primary := &publishingAvailabilityRuntime{fakeSelectorRuntime: base}
				runtime := &responsiveSelectorRuntime{selectorRuntime: primary, ctx: ctx,
					generationPaths: []string{path}, generation: generationStamp([]string{path})}
				publish := func() {
					if err := os.WriteFile(path, []byte("replacement-core"), 0600); err != nil {
						t.Fatal(err)
					}
				}
				switch change {
				case "before":
					publish()
				case "during":
					primary.duringProbe = publish
				case "cancelled":
					primary.duringProbe = cancel
				}
				controller.runtime = runtime
				item.AvailabilityFailures["de"] = 1
				base.probes["de"] = probeEvidence{Failure: probeFailureTimeout}
				_, err := controller.checkActiveAvailability(time.Unix(1010, 0), "europe", base.pool.HealthPolicies["europe"], item, false)
				want := 1
				if change == "unchanged" {
					want = healthFailureConfirmations
				}
				if !errors.Is(err, errHealthYield) || item.AvailabilityFailures["de"] != want || item.Selected != "de" {
					t.Fatalf("generation=%s failures=%d want=%d selected=%s err=%v", change, item.AvailabilityFailures["de"], want, item.Selected, err)
				}
			})
		}
	}
}

func TestRuntimeResetDoesNotCombinePendingFailures(t *testing.T) {
	for _, mode := range []string{"best", "priority"} {
		for _, test := range []struct {
			name         string
			reset        bool
			failures     int
			want         string
			wantFailures int
		}{
			{"new generation", true, 1, "de", 1},
			{"same generation", false, 1, "nl", healthFailureConfirmations},
			{"confirmed outage", true, healthFailureConfirmations, "nl", healthFailureConfirmations},
		} {
			t.Run(mode+"/"+test.name, func(t *testing.T) {
				controller, runtime, item := livenessFixture(t, mode)
				runtime.reset = test.reset
				runtime.probes["de"] = probeEvidence{Failure: probeFailureTimeout}
				item.AvailabilityFailures["de"] = test.failures
				if err := controller.Tick(time.Unix(1010, 0)); err != nil {
					t.Fatal(err)
				}
				if item.Selected != test.want || item.AvailabilityFailures["de"] != test.wantFailures {
					t.Fatalf("selected=%s want=%s failures=%d want=%d", item.Selected, test.want, item.AvailabilityFailures["de"], test.wantFailures)
				}
			})
		}
	}
}
