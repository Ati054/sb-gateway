package main

import (
	"path/filepath"
	"runtime"
	"testing"
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
