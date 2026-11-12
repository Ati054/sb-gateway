//go:build xray_multicall

package main

import (
	"encoding/json"
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/xtls/xray-core/infra/conf"
)

func TestHysteriaBandwidthReachesCompiledCore(t *testing.T) {
	for _, tc := range []struct {
		name     string
		up, down int
		obfs     bool
	}{
		{"both", 25, 100, false}, {"upload", 17, 0, false}, {"download-obfs", 0, 333, true}, {"automatic", 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			node := map[string]any{"type": "hysteria2", "tag": "hy-test", "server": "hy.example", "server_port": 443, "password": "local-control", "up_mbps": tc.up, "down_mbps": tc.down}
			if tc.obfs {
				node["obfs"] = map[string]any{"type": "salamander", "password": "local-mask"}
			}
			// Model the JSON storage boundary before conversion.
			saved, err := json.Marshal(node)
			if err != nil {
				t.Fatal(err)
			}
			if err = json.Unmarshal(saved, &node); err != nil {
				t.Fatal(err)
			}
			set, err := runtimeconfig.ConvertXrayOutbounds([]map[string]any{node}, "", nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(set.Outbounds[0]["streamSettings"])
			if err != nil {
				t.Fatal(err)
			}
			var stream conf.StreamConfig
			if err = json.Unmarshal(body, &stream); err != nil {
				t.Fatal(err)
			}
			built, err := stream.Build()
			if err != nil {
				t.Fatal(err)
			}
			if tc.up == 0 && tc.down == 0 {
				if built.QuicParams != nil {
					t.Fatal("automatic bandwidth gained QUIC options")
				}
			} else if built.QuicParams == nil || built.QuicParams.BrutalUp != uint64(tc.up)*1_000_000/8 || built.QuicParams.BrutalDown != uint64(tc.down)*1_000_000/8 {
				t.Fatalf("bandwidth lost or units changed: %+v", built.QuicParams)
			}
			if tc.obfs && len(built.Udpmasks) != 1 {
				t.Fatal("bandwidth replaced obfuscation")
			}
			if built.QuicParams != nil && (built.QuicParams.Congestion != "" || built.QuicParams.InitStreamReceiveWindow != 0 || built.QuicParams.MaxStreamReceiveWindow != 0) {
				t.Fatal("bandwidth forced unrelated QUIC settings")
			}
		})
	}
}
