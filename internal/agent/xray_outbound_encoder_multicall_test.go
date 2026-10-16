//go:build xray_multicall

package agent

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/core"
	"google.golang.org/protobuf/proto"
)

func TestMulticallOutboundEncoderUsesPinnedCompiler(t *testing.T) {
	for _, network := range []string{"raw", "ws", "grpc", "httpupgrade", "xhttp"} {
		t.Run(network, func(t *testing.T) {
			stream := map[string]any{"network": network, "security": "none", "sockopt": map[string]any{"tcpUserTimeout": 17, "tcpKeepAliveIdle": 11, "mark": 1024}}
			switch network {
			case "ws":
				stream["wsSettings"] = map[string]any{"path": "/encoder-fixture", "headers": map[string]any{"Host": "fixture.example"}}
			case "grpc":
				stream["grpcSettings"] = map[string]any{"serviceName": "encoder-fixture"}
			case "httpupgrade":
				stream["httpupgradeSettings"] = map[string]any{"path": "/encoder-fixture", "host": "fixture.example"}
			case "xhttp":
				stream["xhttpSettings"] = map[string]any{"path": "/encoder-fixture", "mode": "stream-up"}
			}
			outbound := map[string]any{
				"tag": "encoder-fixture", "protocol": "vless",
				"settings": map[string]any{"vnext": []any{map[string]any{
					"address": "127.0.0.1", "port": 443,
					"users": []any{map[string]any{"id": "11111111-1111-4111-8111-111111111111", "encryption": "none"}},
				}}},
				"streamSettings": stream,
			}
			encode := newXrayOutboundEncoder()
			body, err := encode(outbound)
			if err != nil {
				t.Fatal(err)
			}
			var compiled core.OutboundHandlerConfig
			if err := proto.Unmarshal(body, &compiled); err != nil {
				t.Fatal(err)
			}
			if compiled.Tag != "encoder-fixture" || compiled.ProxySettings == nil || compiled.ProxySettings.Type != "xray.proxy.vless.outbound.Config" || compiled.SenderSettings == nil {
				t.Fatalf("compiled transport lost typed settings: %v", &compiled)
			}
			client := controlRPCFixture(t, func(_ context.Context, _ string, payload []byte) ([]byte, error) {
				var upstream command.AddOutboundRequest
				if err := proto.Unmarshal(payload, &upstream); err != nil {
					return nil, err
				}
				if !proto.Equal(upstream.Outbound, &compiled) {
					return nil, errors.New("pinned HandlerService decoder lost transport settings")
				}
				return nil, nil
			})
			if err := client.add(context.Background(), body); err != nil {
				t.Fatal(err)
			}
			var group sync.WaitGroup
			for i := 0; i < 8; i++ {
				group.Add(1)
				go func() {
					defer group.Done()
					parallel, err := encode(outbound)
					if err != nil || !proto.Equal(mustDecodeOutbound(t, parallel), &compiled) {
						t.Errorf("parallel compiler changed immutable input: %v", err)
					}
				}()
			}
			group.Wait()
			if outbound["tag"] != "encoder-fixture" {
				t.Fatal("compiler mutated its input")
			}
		})
	}
	if _, err := newXrayOutboundEncoder()(map[string]any{"protocol": "invalid-protocol"}); err == nil {
		t.Fatal("invalid outbound was accepted")
	}
}

func mustDecodeOutbound(t *testing.T, body []byte) *core.OutboundHandlerConfig {
	t.Helper()
	var config core.OutboundHandlerConfig
	if err := proto.Unmarshal(body, &config); err != nil {
		t.Errorf("invalid protobuf: %v", err)
	}
	return &config
}
