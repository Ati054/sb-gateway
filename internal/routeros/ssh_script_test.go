package routeros

import (
	"strings"
	"testing"
)

func TestManagedSSHScriptChecksOwnershipAndEmitsReceiptAfterRun(t *testing.T) {
	name := "SB-GATEWAY-apply-0123456789ab"
	command, receipt, err := managedScriptCommand(name)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{`[:len $target] != 1`, `comment] != "SB-GATEWAY managed script ` + name + `"`, `/system/script/run $target; :put "` + receipt + `"`, `on-error={ :put "ERROR:` + name + `" }`} {
		if !strings.Contains(command, required) {
			t.Fatalf("missing safety check %q", required)
		}
	}
	for _, unsafe := range []string{"watchdog", name + `"; /system/reboot`, "SB-GATEWAY-apply-"} {
		if _, _, err := managedScriptCommand(unsafe); err == nil {
			t.Fatalf("accepted unsafe name %q", unsafe)
		}
	}
}

func TestManagedSSHScriptReceiptIsBoundedAndRejectsSilentErrors(t *testing.T) {
	const receipt = "OK:SB-GATEWAY-apply-0123456789ab"
	for _, test := range []struct {
		output string
		want   bool
	}{
		{"", false},
		{"Script Error: failure\r\n", false},
		{`echo :put "` + receipt + `"`, false},
		{receipt + "\nERROR:SB-GATEWAY-apply-0123456789ab\n", false},
		{"Script file loaded\r\n" + receipt + "\r\n", true},
	} {
		var tail scriptReceiptTail
		_, _ = tail.Write([]byte(strings.Repeat("diagnostic", 10000)))
		_, _ = tail.Write([]byte("\n"))
		// SSH may split the completion line across writes.
		for _, b := range []byte(test.output) {
			_, _ = tail.Write([]byte{b})
		}
		if len(tail.data) > 4096 || tail.completed(receipt) != test.want {
			t.Fatalf("output %q: length=%d receipt=%t", test.output, len(tail.data), tail.completed(receipt))
		}
	}
}
