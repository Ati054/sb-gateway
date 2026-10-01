package geoiprefresh

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func geoIPFixture(t *testing.T) Options {
	t.Helper()
	root := t.TempDir()
	rules := filepath.Join(root, "rules")
	if err := os.Mkdir(rules, 0o700); err != nil {
		t.Fatal(err)
	}
	options := Options{
		XrayConfig: filepath.Join(root, "xray.json"), RulesetDir: rules,
		ReadyFile: filepath.Join(root, "ready"), ApplyGuard: filepath.Join(root, "guard"),
		APIServer: "127.0.0.1:10085", XrayBinary: "xray",
	}
	write := func(path, body string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(options.ReadyFile, "123\n")
	write(options.XrayConfig, `{"routing":{"domainStrategy":"IPIfNonMatch","balancers":[{"tag":"policy-a","selector":["node-a"]}],"rules":[{"type":"field","inboundTag":["xray-api"],"outboundTag":"xray-api"},{"type":"field","ruleTag":"sb-geoip-geoip-cn-2-0","ip":["203.0.113.0/24"],"balancerTag":"policy-a"},{"type":"field","network":"tcp,udp","outboundTag":"block"}]}}`)
	write(filepath.Join(rules, "geoip-cn.json"), `{"rules":[{"ip_cidr":["198.51.100.0/24"]}]}`)
	return options
}

func proofForGeoIPFixture(t *testing.T, options *Options) {
	t.Helper()
	options.ProcRoot = filepath.Join(filepath.Dir(options.XrayConfig), "proc")
	process := filepath.Join(options.ProcRoot, "123")
	if err := os.MkdirAll(process, 0o700); err != nil {
		t.Fatal(err)
	}
	options.ValidatedFile = filepath.Join(filepath.Dir(options.XrayConfig), "proof")
	body, err := os.ReadFile(options.XrayConfig)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(body)
	fields := make([]string, 20)
	for i := range fields {
		fields[i] = "0"
	}
	fields[0], fields[19] = "S", "456"
	for path, body := range map[string]string{
		options.ValidatedFile:             "123 456 " + hex.EncodeToString(sum[:]),
		filepath.Join(process, "stat"):    "123 (xray) " + strings.Join(fields, " "),
		filepath.Join(process, "cmdline"): "/usr/local/bin/xray\x00run\x00-config\x00" + options.XrayConfig + "\x00",
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestActivateSkipsFreshStartupBaselineButNotUnknownOrMutatedCore(t *testing.T) {
	options := geoIPFixture(t)
	pack := filepath.Join(options.RulesetDir, "geoip-cn.json")
	baselinePack := []byte(`{"rules":[{"ip_cidr":["203.0.113.0/24"]}]}`)
	if err := os.WriteFile(pack, baselinePack, 0o600); err != nil {
		t.Fatal(err)
	}
	options.ValidatedFile = filepath.Join(filepath.Dir(options.XrayConfig), "proof")
	state := NewState(options)
	proofForGeoIPFixture(t, &options)
	var replacements int
	options.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[1] == "adrules" {
			replacements++
			return []byte("{}"), nil
		}
		return []byte(`{"rules":[{},{"ruleTag":"sb-geoip-geoip-cn-2-0"},{}]}`), nil
	}
	if changed, err := Activate(context.Background(), options, state); err != nil || changed || replacements != 0 {
		t.Fatalf("fresh baseline recompiled: changed=%t err=%v calls=%d", changed, err, replacements)
	}
	// Reusing the state across monitor restarts must retain confirmed routing.
	if changed, err := Activate(context.Background(), options, state); err != nil || changed || replacements != 0 {
		t.Fatalf("unchanged monitor refresh recompiled: %t %v calls=%d", changed, err, replacements)
	}
	if err := os.WriteFile(pack, []byte(`{"rules":[{"ip_cidr":["198.51.100.0/24"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := Activate(context.Background(), options, state); err != nil || !changed || replacements != 1 {
		t.Fatalf("updated pack not activated: %t %v calls=%d", changed, err, replacements)
	}
	configBefore, err := os.ReadFile(options.XrayConfig)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(options.XrayConfig, append(configBefore, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := Activate(context.Background(), options, state); err != nil || !changed || replacements != 2 {
		t.Fatalf("hot config change not reconciled: %t %v calls=%d", changed, err, replacements)
	}
	if err := os.WriteFile(options.XrayConfig, configBefore, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, baselinePack, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := Activate(context.Background(), options, state); err != nil || !changed || replacements != 3 {
		t.Fatalf("return to baseline incorrectly skipped: %t %v calls=%d", changed, err, replacements)
	}
	attached := NewState(options)
	if changed, err := Activate(context.Background(), options, attached); err != nil || !changed || replacements != 4 {
		t.Fatalf("new monitor trusted unknown prior routing: %t %v calls=%d", changed, err, replacements)
	}
	// Reused PID with new start ticks is a different core with fresh baseline.
	for _, path := range []string{options.ValidatedFile, filepath.Join(options.ProcRoot, "123", "stat")} {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(strings.Replace(string(body), " 456", " 457", 1)), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if changed, err := Activate(context.Background(), options, state); err != nil || changed || replacements != 4 {
		t.Fatalf("restarted baseline recompiled: %t %v calls=%d", changed, err, replacements)
	}
}

func TestActivateDefersThroughoutDurableApplyJournal(t *testing.T) {
	for _, body := range []string{`{"pending":true,"state":"runtime_activated"}`, `{"pending":true,"state":"recovery_pending"}`, `not-json`, `null`} {
		t.Run(body, func(t *testing.T) {
			options := geoIPFixture(t)
			options.ApplyOperationFile = filepath.Join(filepath.Dir(options.XrayConfig), "apply-operation.json")
			if err := os.WriteFile(options.ApplyOperationFile, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			options.Run = func(context.Context, string, ...string) ([]byte, error) {
				t.Fatal("hot reload raced pending Apply")
				return nil, nil
			}
			if changed, err := Activate(context.Background(), options, NewState(options)); changed || !errors.Is(err, ErrDeferred) {
				t.Fatalf("journal did not defer: %t %v", changed, err)
			}
			if err := os.WriteFile(options.ApplyOperationFile, []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			if activationGuarded(options) {
				t.Fatal("cleared Apply still deferred")
			}
		})
	}
}

func TestFailedHotUpdateInvalidatesPreviouslyConfirmedSignature(t *testing.T) {
	options := geoIPFixture(t)
	state := NewState(options)
	var replacements int
	fail := false
	options.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[1] == "adrules" {
			replacements++
			if fail {
				return nil, errors.New("ambiguous API failure")
			}
			return []byte("{}"), nil
		}
		return []byte(`{"rules":[{},{"ruleTag":"sb-geoip-geoip-cn-2-0"},{}]}`), nil
	}
	if _, err := Activate(context.Background(), options, state); err != nil {
		t.Fatal(err)
	}
	pack := filepath.Join(options.RulesetDir, "geoip-cn.json")
	if err := os.WriteFile(pack, []byte(`{"rules":[{"ip_cidr":["192.0.2.0/24"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	fail = true
	if _, err := Activate(context.Background(), options, state); err == nil {
		t.Fatal("expected failure")
	}
	fail = false
	if err := os.WriteFile(pack, []byte(`{"rules":[{"ip_cidr":["198.51.100.0/24"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := Activate(context.Background(), options, state); err != nil || !changed || replacements != 4 {
		t.Fatalf("old signature skipped after rollback: %t %v calls=%d", changed, err, replacements)
	}
}

func TestActivateReplacesOnlyGeoIPCIDRAndConfirmsOrder(t *testing.T) {
	options := geoIPFixture(t)
	var applied []map[string]any
	var calls int
	options.Run = func(_ context.Context, binary string, args ...string) ([]byte, error) {
		if binary != "xray" || len(args) < 3 || args[0] != "api" {
			t.Fatalf("unexpected Xray API call: %q %#v", binary, args)
		}
		switch args[1] {
		case "adrules":
			if args[3] != "-t=300" {
				t.Fatalf("GeoIP replacement timeout is too short for bounded country CIDRs: %#v", args)
			}
			calls++
			body, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Routing struct {
					Rules []map[string]any `json:"rules"`
				} `json:"routing"`
			}
			if err := json.Unmarshal(body, &config); err != nil {
				t.Fatal(err)
			}
			applied = config.Routing.Rules
			return []byte(`{}`), nil
		case "lsrules":
			response := struct {
				Rules []map[string]any `json:"rules"`
			}{}
			for _, rule := range applied {
				response.Rules = append(response.Rules, map[string]any{"ruleTag": rule["ruleTag"]})
			}
			return json.Marshal(response)
		}
		return nil, errors.New("unexpected command")
	}
	state := &State{}
	changed, err := Activate(context.Background(), options, state)
	if err != nil || !changed || calls != 1 {
		t.Fatalf("activation = %t, %v, calls=%d", changed, err, calls)
	}
	if applied[0]["outboundTag"] != "xray-api" || applied[1]["balancerTag"] != "policy-a" || applied[2]["outboundTag"] != "block" {
		t.Fatalf("unrelated routing changed: %#v", applied)
	}
	ip, _ := applied[1]["ip"].([]any)
	if len(ip) != 1 || ip[0] != "198.51.100.0/24" {
		t.Fatalf("GeoIP CIDR did not change: %#v", applied[1])
	}
	changed, err = Activate(context.Background(), options, state)
	if err != nil || changed || calls != 1 {
		t.Fatalf("unchanged update repeated: %t, %v, calls=%d", changed, err, calls)
	}
}

func TestActivateRestoresBaselineAfterPreviousHotUpdate(t *testing.T) {
	options := geoIPFixture(t)
	var applied []map[string]any
	var replacements int
	options.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		switch args[1] {
		case "adrules":
			body, err := os.ReadFile(args[len(args)-1])
			if err != nil {
				t.Fatal(err)
			}
			var config struct {
				Routing struct {
					Rules []map[string]any `json:"rules"`
				} `json:"routing"`
			}
			if err := json.Unmarshal(body, &config); err != nil {
				t.Fatal(err)
			}
			applied = config.Routing.Rules
			replacements++
			return []byte(`{}`), nil
		case "lsrules":
			response := struct {
				Rules []map[string]any `json:"rules"`
			}{}
			for _, rule := range applied {
				response.Rules = append(response.Rules, map[string]any{"ruleTag": rule["ruleTag"]})
			}
			return json.Marshal(response)
		}
		return nil, errors.New("unexpected command")
	}
	if changed, err := Activate(context.Background(), options, &State{}); err != nil || !changed {
		t.Fatalf("initial hot update = %t, %v", changed, err)
	}
	if err := os.WriteFile(filepath.Join(options.RulesetDir, "geoip-cn.json"), []byte(`{"rules":[{"ip_cidr":["203.0.113.0/24"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := Activate(context.Background(), options, &State{}); err != nil || !changed || replacements != 2 {
		t.Fatalf("baseline restore = %t, %v, replacements=%d", changed, err, replacements)
	}
	ip, _ := applied[1]["ip"].([]any)
	if len(ip) != 1 || ip[0] != "203.0.113.0/24" {
		t.Fatalf("baseline CIDR was not restored: %#v", applied[1])
	}
}

func TestActivateDefersDuringApplyAndRejectsInvalidCIDR(t *testing.T) {
	options := geoIPFixture(t)
	if err := os.WriteFile(options.ApplyGuard, []byte("1"), 0o600); err != nil {
		t.Fatal(err)
	}
	changed, err := Activate(context.Background(), options, &State{})
	if !errors.Is(err, ErrDeferred) || changed {
		t.Fatalf("activation raced Apply: %t, %v", changed, err)
	}
	if err := os.Remove(options.ApplyGuard); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(options.RulesetDir, "geoip-cn.json"), []byte(`{"rules":[{"ip_cidr":["198.51.100.7/24"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = Activate(context.Background(), options, &State{})
	if err == nil || !strings.Contains(err.Error(), "CIDR") {
		t.Fatalf("invalid GeoIP CIDR accepted: %v", err)
	}
}

func TestActivateRollsBackAfterReadbackFailure(t *testing.T) {
	options := geoIPFixture(t)
	var applied [][]byte
	options.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[1] == "lsrules" {
			return []byte(`{"rules":[]}`), nil
		}
		body, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			t.Fatal(err)
		}
		applied = append(applied, body)
		return []byte(`{}`), nil
	}
	changed, err := Activate(context.Background(), options, &State{})
	if err == nil || changed || len(applied) != 2 {
		t.Fatalf("unconfirmed activation was not rolled back: %t, %v, calls=%d", changed, err, len(applied))
	}
	if !strings.Contains(string(applied[0]), "198.51.100.0/24") || !strings.Contains(string(applied[1]), "203.0.113.0/24") {
		t.Fatalf("rollback did not restore old CIDRs")
	}
}

func TestActivateRollsBackAfterAmbiguousAPIError(t *testing.T) {
	options := geoIPFixture(t)
	var applied [][]byte
	options.Run = func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[1] != "adrules" {
			t.Fatalf("unexpected command after API failure: %#v", args)
		}
		body, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			t.Fatal(err)
		}
		applied = append(applied, body)
		if len(applied) == 1 {
			return nil, errors.New("transport timed out after server accepted routing")
		}
		return []byte(`{}`), nil
	}
	changed, err := Activate(context.Background(), options, &State{})
	if err == nil || changed || len(applied) != 2 {
		t.Fatalf("ambiguous API failure was not rolled back: %t, %v, calls=%d", changed, err, len(applied))
	}
	if !strings.Contains(string(applied[0]), "198.51.100.0/24") || !strings.Contains(string(applied[1]), "203.0.113.0/24") {
		t.Fatal("rollback did not restore the committed CIDRs")
	}
}
