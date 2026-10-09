package agent

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

func controlWireField(number protowire.Number, value []byte) []byte {
	return protowire.AppendBytes(protowire.AppendTag(nil, number, protowire.BytesType), value)
}

func controlRPCFixture(t *testing.T, handler func(context.Context, string, []byte) ([]byte, error)) *xrayControlClient {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	client, err := newXrayControlClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(stream)
		names := map[string][2]string{
			"/xray.app.router.command.RoutingService/GetBalancerInfo":        {"GetBalancerInfoRequest", "GetBalancerInfoResponse"},
			"/xray.app.router.command.RoutingService/OverrideBalancerTarget": {"OverrideBalancerTargetRequest", "OverrideBalancerTargetResponse"},
			"/xray.app.proxyman.command.HandlerService/ListOutbounds":        {"ListOutboundsRequest", "ListOutboundsResponse"},
			"/xray.app.proxyman.command.HandlerService/RemoveOutbound":       {"RemoveOutboundRequest", "RemoveOutboundResponse"},
			"/xray.app.stats.command.StatsService/GetStatsOnline":            {"GetStatsRequest", "GetStatsResponse"},
		}
		name, exists := names[method]
		if !exists {
			return errors.New("unexpected RPC")
		}
		request, response := client.message(name[0]), client.message(name[1])
		if err := stream.RecvMsg(request); err != nil {
			return err
		}
		body, err := (proto.MarshalOptions{Deterministic: true}).Marshal(request)
		if err != nil {
			return err
		}
		result, err := handler(stream.Context(), method, body)
		if err != nil {
			return err
		}
		if err := proto.Unmarshal(result, response); err != nil {
			return err
		}
		return stream.SendMsg(response)
	}))
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { client.close(); server.Stop(); _ = listener.Close() })
	return client
}

func TestXrayControlRPCOnlineUsesSharedConnection(t *testing.T) {
	name := "user>>>reverse-fixture>>>online"
	var mu sync.Mutex
	actual, count := name, uint64(1)
	client := controlRPCFixture(t, func(_ context.Context, method string, body []byte) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		if method != "/xray.app.stats.command.StatsService/GetStatsOnline" || !bytes.Equal(body, controlWireField(1, []byte(name))) {
			return nil, errors.New("incorrect online-statistic request")
		}
		stat := controlWireField(1, []byte(actual))
		stat = protowire.AppendVarint(protowire.AppendTag(stat, 2, protowire.VarintType), count)
		return controlWireField(1, stat), nil
	})
	runtime := newXraySelectorRuntime(Options{})
	runtime.control = client
	runtime.command = func(context.Context, time.Duration, string, ...string) ([]byte, error) {
		t.Error("reverse-online started an API subprocess")
		return nil, errors.New("unexpected subprocess")
	}
	if !runtime.reverseOnline("reverse-fixture") {
		t.Fatal("online reverse peer not recognized")
	}
	mu.Lock()
	count = 0
	mu.Unlock()
	if runtime.reverseOnline("reverse-fixture") {
		t.Fatal("zero online count accepted")
	}
	mu.Lock()
	count, actual = 1, "user>>>other>>>online"
	mu.Unlock()
	if runtime.reverseOnline("reverse-fixture") {
		t.Fatal("wrong statistic accepted")
	}
}

func TestXrayControlRPCWireContractAndReadback(t *testing.T) {
	var mu sync.Mutex
	selected := "old"
	ignoreOverride := false
	lostAcknowledgement := false
	tags := []string{"old", "new"}
	client := controlRPCFixture(t, func(_ context.Context, method string, body []byte) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case strings.HasSuffix(method, "/GetBalancerInfo"):
			if !bytes.Equal(body, controlWireField(1, []byte("sheet"))) {
				return nil, errors.New("incorrect selector request wire field")
			}
			return controlWireField(1, controlWireField(5, controlWireField(2, []byte(selected)))), nil
		case strings.HasSuffix(method, "/OverrideBalancerTarget"):
			wantNew := append(controlWireField(1, []byte("sheet")), controlWireField(2, []byte("new"))...)
			wantOld := append(controlWireField(1, []byte("sheet")), controlWireField(2, []byte("old"))...)
			if !bytes.Equal(body, wantNew) && !bytes.Equal(body, wantOld) {
				return nil, errors.New("incorrect override request wire fields")
			}
			if !ignoreOverride {
				selected = "new"
				if bytes.Equal(body, wantOld) {
					selected = "old"
				}
			}
			if lostAcknowledgement {
				return nil, errors.New("lost acknowledgement after applied override")
			}
			return nil, nil
		case strings.HasSuffix(method, "/ListOutbounds"):
			if len(body) != 0 {
				return nil, errors.New("inventory request should be empty")
			}
			var result []byte
			for _, tag := range tags {
				result = append(result, controlWireField(1, controlWireField(1, []byte(tag)))...)
			}
			return result, nil
		case strings.HasSuffix(method, "/RemoveOutbound"):
			if !bytes.Equal(body, controlWireField(1, []byte("old"))) {
				return nil, errors.New("incorrect removal request wire field")
			}
			tags = []string{"new"}
			return nil, errors.New("lost acknowledgement after applied removal")
		}
		return nil, errors.New("unexpected method")
	})
	runtime := newXraySelectorRuntime(Options{})
	runtime.control = client
	runtime.command = func(context.Context, time.Duration, string, ...string) ([]byte, error) {
		t.Error("hot RPC operation fell back to CLI")
		return nil, errors.New("unexpected CLI")
	}
	if current, err := runtime.Current("sheet"); err != nil || current != "old" {
		t.Fatalf("current=%q err=%v", current, err)
	}
	mu.Lock()
	ignoreOverride = true
	mu.Unlock()
	if err := runtime.Select("sheet", "new"); err == nil || runtime.selectorMembers["sheet"] == "new" {
		t.Fatal("unconfirmed override was accepted")
	}
	mu.Lock()
	ignoreOverride = false
	lostAcknowledgement = true
	mu.Unlock()
	if err := runtime.Select("sheet", "new"); err == nil || runtime.selectorMembers["sheet"] != "" {
		t.Fatal("ambiguous override retained stale cache")
	}
	mu.Lock()
	lostAcknowledgement = false
	mu.Unlock()
	if err := runtime.Select("sheet", "old"); err != nil {
		t.Fatal(err)
	}
	if current, err := runtime.Current("sheet"); err != nil || current != "old" {
		t.Fatalf("return after lost ack skipped live write/readback: current=%q err=%v", current, err)
	}
	if err := runtime.Select("sheet", "new"); err != nil {
		t.Fatal(err)
	}
	if current, err := runtime.Current("sheet"); err != nil || current != "new" {
		t.Fatalf("readback=%q err=%v", current, err)
	}
	if present, err := runtime.outboundPresent("old"); err != nil || !present {
		t.Fatalf("presence=%t err=%v", present, err)
	}
	runtime.loadedDynamic["old"] = true
	if err := runtime.removeOutbound("old"); err != nil {
		t.Fatal(err)
	}
	if present, err := runtime.outboundPresent("old"); err != nil || present {
		t.Fatalf("removed presence=%t err=%v", present, err)
	}
}

func TestXrayControlRPCRejectsMalformedOrAmbiguousEvidence(t *testing.T) {
	for _, scenario := range []string{"missing-balancer", "duplicate-tags", "empty-tag", "empty-inventory", "no-override"} {
		t.Run(scenario, func(t *testing.T) {
			client := controlRPCFixture(t, func(context.Context, string, []byte) ([]byte, error) {
				switch scenario {
				case "duplicate-tags":
					item := controlWireField(1, controlWireField(1, []byte("same")))
					return append(item, item...), nil
				case "empty-tag":
					return controlWireField(1, nil), nil
				case "no-override":
					return controlWireField(1, nil), nil
				}
				return nil, nil
			})
			if scenario == "missing-balancer" || scenario == "no-override" {
				member, err := client.selected(context.Background(), "sheet")
				if scenario == "missing-balancer" && err == nil {
					t.Fatal("missing balancer accepted")
				}
				if scenario == "no-override" && (err != nil || member != "") {
					t.Fatalf("valid absent override: member=%q err=%v", member, err)
				}
			} else {
				tags, err := client.outbounds(context.Background())
				if scenario == "empty-inventory" {
					if err != nil || len(tags) != 0 {
						t.Fatal("empty inventory invalid")
					}
				} else if err == nil {
					t.Fatal("ambiguous inventory accepted")
				}
			}
		})
	}
}

func TestXrayControlRPCCancellationAndIndependentSlots(t *testing.T) {
	entered := make(chan struct{}, 1)
	client := controlRPCFixture(t, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		entered <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	})
	for i := 0; i < cap(xrayProbeCommandSlots); i++ {
		xrayProbeCommandSlots <- struct{}{}
	}
	backgroundSlotsHeld := true
	t.Cleanup(func() {
		if backgroundSlotsHeld {
			for i := 0; i < cap(xrayProbeCommandSlots); i++ {
				<-xrayProbeCommandSlots
			}
		}
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := client.selected(ctx, "sheet"); done <- err }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("active RPC waited for background slots")
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("parent cancellation hidden: %v", err)
	}
	queued, stop := context.WithCancel(backgroundXrayCommandContext(context.Background()))
	stop()
	if _, err := client.selected(queued, "sheet"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled queued RPC: %v", err)
	}
	for i := 0; i < cap(xrayProbeCommandSlots); i++ {
		<-xrayProbeCommandSlots
	}
	backgroundSlotsHeld = false
	if len(xrayCommandSlot) != 0 || len(xrayProbeCommandSlots) != 0 {
		t.Fatal("API slots leaked")
	}
	client.close()
	if _, err := client.selected(context.Background(), "sheet"); err == nil {
		t.Fatal("closed monitor connection still used")
	}
}

func TestXrayControlRPCPreservesBoundedAPIDeadline(t *testing.T) {
	if xrayControlRPCTimeout != 3*time.Second {
		t.Fatal("RPC changed the pinned CLI's inner API timeout")
	}
	client := controlRPCFixture(t, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.selected(ctx, "sheet"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("parent deadline hidden: %v", err)
	}
	if len(xrayCommandSlot) != 0 {
		t.Fatal("deadline leaked active slot")
	}
}

func TestXrayControlRPCRecognizesRemoteDeadlineBeforeLocalTimer(t *testing.T) {
	client := controlRPCFixture(t, func(context.Context, string, []byte) ([]byte, error) {
		return nil, status.Error(codes.DeadlineExceeded, "remote deadline")
	})
	_, err := client.selected(context.Background(), "sheet")
	if !errors.Is(err, context.DeadlineExceeded) || status.Code(err) != codes.DeadlineExceeded {
		t.Fatalf("remote deadline lost its context classification or RPC status: %v", err)
	}
	if len(xrayCommandSlot) != 0 {
		t.Fatal("remote deadline leaked active slot")
	}
}
