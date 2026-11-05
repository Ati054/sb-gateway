package agent

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/dnsroute"
)

func TestDNSRoutePublicationRequiresConfirmedProductionSelector(t *testing.T) {
	for _, mode := range []string{"success", "rejected", "readback-mismatch", "readback-error", "lost-ack"} {
		t.Run(mode, func(t *testing.T) {
			r := newXraySelectorRuntime(Options{XrayBinary: "xray"})
			registry := dnsroute.New()
			p := registry.NewPublisher()
			defer p.Close()
			p.Sync(dnsroute.Core{PID: 1, StartTicks: 1}, []string{"policy-a"})
			p.Confirm("policy-a", "block")
			r.dnsPublisher = p
			r.pool.Policies = map[string][]string{"policy-a": {"direct-wan", "block"}}
			r.selectorMembers["policy-a"] = "block"
			var snapshots []dnsroute.Snapshot
			s := registry.Subscribe("policy-a", true, func(v dnsroute.Snapshot) { snapshots = append(snapshots, v) })
			defer s.Close()
			selected := "block"
			r.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
				if args[1] == "bo" {
					if mode == "rejected" {
						return nil, errors.New("synthetic rejection")
					}
					if mode != "readback-mismatch" {
						selected = "direct-wan"
					}
					if mode == "lost-ack" {
						return nil, errors.New("synthetic missing acknowledgement")
					}
					return nil, nil
				}
				if mode == "readback-error" {
					return nil, errors.New("synthetic readback failure")
				}
				return selectorInfo(selected), nil
			}
			err := r.Select("policy-a", "direct-wan")
			if mode != "success" {
				if err == nil || len(snapshots) != 1 {
					t.Fatal("failed/unconfirmed update advanced DNS route epoch")
				}
			} else {
				if err != nil || len(snapshots) != 2 || snapshots[1].Selected != "direct-wan" {
					t.Fatal("confirmed production update was not published")
				}
				if err = r.Select("policy-a", "direct-wan"); err != nil || len(snapshots) != 2 {
					t.Fatal("unchanged selection reset DNS")
				}
			}
			if mode == "lost-ack" {
				if _, err = r.Current("policy-a"); err != nil || len(snapshots) != 2 {
					t.Fatal("later confirmed lost acknowledgement was not reconciled")
				}
			}
			before := len(snapshots)
			r.probeSelector = "background-probe"
			r.publishDNSSelection("policy-a", "probe-candidate")
			if len(snapshots) != before {
				t.Fatal("background probe published a production route")
			}
		})
	}
}

func TestDNSRouteSameNodeChangedDefinitionPublishesNewRuntimeTag(t *testing.T) {
	r := newXraySelectorRuntime(Options{XrayBinary: "xray"})
	prefix := "sb-urltest-" + shortHash("policy-a", 12) + "-"
	r.pool = healthPool{Policies: map[string][]string{"policy-a": {"node-a"}}, HealthPolicies: map[string]healthPolicyContract{"policy-a": {Candidates: []string{"node-a"}}}, PolicyPrefixes: map[string]string{"policy-a": prefix}, Outbounds: map[string]json.RawMessage{"node-a": json.RawMessage(`{"protocol":"freedom","tag":"old"}`)}}
	old := r.dynamicTag(prefix, "node-a")
	registry := dnsroute.New()
	p := registry.NewPublisher()
	defer p.Close()
	p.Sync(dnsroute.Core{PID: 1, StartTicks: 1}, []string{"policy-a"})
	p.Confirm("policy-a", old)
	r.dnsPublisher = p
	var events []dnsroute.Snapshot
	s := registry.Subscribe("policy-a", true, func(v dnsroute.Snapshot) { events = append(events, v) })
	defer s.Close()
	r.activeByNode["node-a"], r.activeByPolicy["policy-a"], r.loadedDynamic[old] = old, old, true
	r.pool.Outbounds["node-a"] = json.RawMessage(`{"protocol":"freedom","tag":"new"}`)
	next := r.dynamicTag(prefix, "node-a")
	selected, installed := old, false
	r.command = func(_ context.Context, _ time.Duration, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "bi":
			return selectorInfo(selected), nil
		case "lso":
			if installed {
				return outboundTagsJSON(old, next), nil
			}
			return outboundTagsJSON(old), nil
		case "ado":
			installed = true
			return nil, nil
		case "bo":
			if !installed {
				t.Error("override preceded handler installation")
			}
			selected = next
			return nil, nil
		default:
			t.Errorf("unexpected command %s", args[1])
			return nil, errors.New("unexpected synthetic command")
		}
	}
	if got, err := r.Current("policy-a"); err != nil || got != "node-a" || len(events) != 2 || events[1].Selected != next || old == next {
		t.Fatal("changed selected definition did not rotate the confirmed route")
	}
	if _, err := r.Current("policy-a"); err != nil || len(events) != 2 {
		t.Fatal("stable current generation reset DNS")
	}
}

func TestDNSCoreIdentityUsesProcessStartAndRejectsMalformedStat(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "17")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	fields := append([]string{"S"}, strings.Fields(strings.Repeat("0 ", 18))...)
	fields = append(fields, "123")
	valid := "17 (synthetic ) process) " + strings.Join(fields, " ")
	for _, test := range []struct {
		name, body string
		valid      bool
	}{{"valid", valid, true}, {"wrong-pid", strings.Replace(valid, "17 (", "18 (", 1), false}, {"zombie", strings.Replace(valid, ") S ", ") Z ", 1), false}, {"short", "17 (synthetic) S", false}, {"too-large", strings.Repeat("x", 4097), false}, {"bad-ticks", strings.TrimSuffix(valid, "123") + "bad", false}} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(test.body), 0600); err != nil {
				t.Fatal(err)
			}
			got, err := dnsCoreIdentity(root, 17)
			if test.valid {
				if err != nil || got.PID != 17 || got.StartTicks != 123 {
					t.Fatal("valid core start identity rejected")
				}
			} else if err == nil {
				t.Fatal("malformed core identity admitted")
			}
		})
	}
}
