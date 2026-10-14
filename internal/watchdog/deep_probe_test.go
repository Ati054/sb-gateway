package watchdog

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDeepProbeDoesNotLaunchXrayValidation(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("live listener inventory requires Linux /proc")
	}
	root := t.TempDir()
	write := func(path, body string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tcp.Close() }()
	port := tcp.Addr().(*net.TCPAddr).Port
	udp, err := net.ListenPacket("udp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	write(filepath.Join(root, "ip"), `#!/bin/sh
case "$1 $2" in
"rule show") printf '1100: from all fwmark 0x1 lookup 1002\n' ;;
"route show") printf 'local default dev lo\n' ;;
*) exit 1 ;;
esac
`, 0700)
	nft := `{"nftables":[
{"chain":{"family":"inet","table":"sb_gateway_transparent","name":"prerouting","type":"filter","hook":"prerouting"}},
{"chain":{"family":"inet","table":"sb_gateway_transparent","name":"forward","type":"filter","hook":"forward"}},
{"rule":{"family":"inet","table":"sb_gateway_transparent","chain":"prerouting","expr":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"tcp"}},{"tproxy":{"port":12345}}]}},
{"rule":{"family":"inet","table":"sb_gateway_transparent","chain":"prerouting","expr":[{"match":{"op":"==","left":{"meta":{"key":"l4proto"}},"right":"udp"}},{"tproxy":{"port":12345}}]}},
{"rule":{"family":"inet","table":"sb_gateway_transparent","chain":"forward","comment":"sb-public-transit-reject","expr":[{"match":{"op":"==","left":{"meta":{"key":"iifname"}},"right":"veth-sb"}},{"reject":{"type":"icmpx","expr":"admin-prohibited"}}]}}
]}`
	write(filepath.Join(root, "nft"), "#!/bin/sh\nprintf '%s\\n' '"+nft+"'\n", 0700)
	marker := filepath.Join(root, "validator-called")
	write(filepath.Join(root, "xray"), "#!/bin/sh\n: > \"$WATCHDOG_TEST_VALIDATION_MARKER\"\nexit 23\n", 0700)
	t.Setenv("WATCHDOG_TEST_VALIDATION_MARKER", marker)
	t.Setenv("PATH", root+string(os.PathListSeparator)+os.Getenv("PATH"))
	config := filepath.Join(root, "xray.json")
	dns := filepath.Join(root, "dns.json")
	write(dns, fmt.Sprintf(`{"lanes":[{"port":%d}]}`, port), 0600)
	r := &runner{opts: Options{XrayConfig: config, PolicyDNSConfig: dns,
		RulePriority: "1100", RouteTable: "1002", TProxyMark: "1", TProxyPort: "12345"}}
	for n := range 3 {
		write(config, fmt.Sprintf(`{"inbounds":[{"protocol":"dokodemo-door","port":%d,"settings":{"network":"tcp,udp"}}],"routing":{"rules":[{"ip":["ext:missing-%d.dat:ru"]}]}}`, port, n), 0600)
		r.runDeepProbe(context.Background(), settings{deepInterval: time.Second}, time.Now())
		if !r.deepHealthy {
			t.Fatalf("routing-only change failed live readiness: %v", r.deepReasons)
		}
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("watchdog launched the configuration validator: %v", err)
	}
	_ = tcp.Close()
	r.runDeepProbe(context.Background(), settings{}, time.Now())
	if r.deepHealthy || !strings.Contains(strings.Join(r.deepReasons, ","), "tcp_listener") {
		t.Fatalf("missing TCP listener was ignored: %v", r.deepReasons)
	}
	tcp, err = net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	_ = udp.Close()
	r.runDeepProbe(context.Background(), settings{}, time.Now())
	if r.deepHealthy || !strings.Contains(strings.Join(r.deepReasons, ","), "udp_listener") {
		t.Fatalf("missing UDP listener was ignored: %v", r.deepReasons)
	}
}
