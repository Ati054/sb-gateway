package main

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/memorybudget"
)

func TestXrayAliasDispatchNames(t *testing.T) {
	for _, name := range []string{"xray", filepath.Join("bin", "xray")} {
		if !isXrayAlias(name) {
			t.Fatalf("core alias not recognized: %q", name)
		}
	}
	for _, name := range []string{"sb-gateway", "sb-gateway-xray", "xray-old", "api", "appliance"} {
		if isXrayAlias(name) {
			t.Fatalf("gateway or unrelated executable routed to core: %q", name)
		}
	}
	if isXrayAlias("xray.exe") != (runtime.GOOS == "windows") {
		t.Fatal("executable suffix does not match platform")
	}
}

func TestXrayMemoryRoles(t *testing.T) {
	for _, tc := range []struct {
		args []string
		role memorybudget.Role
	}{
		{nil, memorybudget.Xray},
		{[]string{"run", "-config", "test.json"}, memorybudget.Xray},
		{[]string{"run", "-test", "-config", "test.json"}, memorybudget.Worker},
		{[]string{"run", "--test=true"}, memorybudget.Worker},
		{[]string{"api", "statsquery"}, memorybudget.Worker},
		{[]string{"version"}, memorybudget.Worker},
	} {
		if got := xrayMemoryRole(tc.args); got != tc.role {
			t.Fatalf("%v: role %d", tc.args, got)
		}
	}
}
