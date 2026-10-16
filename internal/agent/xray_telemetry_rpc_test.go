package agent

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protowire"
)

func telemetryWireStat(name string, value int64) []byte {
	body := controlWireField(1, []byte(name))
	body = protowire.AppendTag(body, 2, protowire.VarintType)
	return protowire.AppendVarint(body, uint64(value))
}

func TestTelemetryRPCReadOnlySharedBackgroundConnection(t *testing.T) {
	var calls atomic.Int32
	client := controlRPCFixture(t, func(ctx context.Context, method string, body []byte) ([]byte, error) {
		calls.Add(1)
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) > 4*time.Second {
			return nil, errors.New("unbounded telemetry request")
		}
		if strings.HasSuffix(method, "/QueryStats") {
			if !bytes.Equal(body, controlWireField(1, []byte("user>>>"))) {
				return nil, errors.New("counter reset or pattern changed")
			}
			result := controlWireField(1, telemetryWireStat("user>>>alice>>>traffic>>>uplink", 1<<53+7))
			result = append(result, controlWireField(1, telemetryWireStat("user>>>alice>>>traffic>>>downlink", 99))...)
			result = append(result, controlWireField(1, telemetryWireStat("user>>>bob>>>traffic>>>uplink", -1))...)
			result = append(result, controlWireField(1, telemetryWireStat("outbound>>>proxy>>>traffic>>>uplink", 50))...)
			return result, nil
		}
		if strings.HasSuffix(method, "/GetAllOnlineUsers") {
			if len(body) != 0 {
				return nil, errors.New("unexpected online request fields")
			}
			result := controlWireField(1, []byte("alice"))
			for _, name := range []string{"user>>>reverse-vless-demo>>>online", "", "user>>>bad>>>traffic", "alice"} {
				result = append(result, controlWireField(1, []byte(name))...)
			}
			return result, nil
		}
		return nil, errors.New("unexpected telemetry method")
	})
	// Telemetry must progress even while the urgent health lane is occupied.
	xrayCommandSlot <- struct{}{}
	defer func() { <-xrayCommandSlot }()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	collector := newTelemetryCollector(Options{control: client, XrayBinary: "must-not-start-a-cli"})
	got := collector.remoteMeasurements(ctx)
	if got.statsErr != nil || got.onlineErr != nil || calls.Load() != 2 {
		t.Fatalf("native telemetry failed: stats=%v online=%v calls=%d", got.statsErr, got.onlineErr, calls.Load())
	}
	if got.measurements["alice"] != (counterPair{Uplink: 1<<53 + 7, Downlink: 99}) || got.measurements["bob"].Uplink != 0 || len(got.measurements) != 2 {
		t.Fatalf("counter decoding changed: %#v", got.measurements)
	}
	if _, ok := got.online["alice"]; !ok {
		t.Fatal("ordinary online user missing")
	}
	if _, ok := got.online["reverse-vless-demo"]; !ok || len(got.online) != 2 {
		t.Fatalf("online normalization changed: %#v", got.online)
	}
}

func TestTelemetryRPCPreservesIndependentSourceErrors(t *testing.T) {
	for _, failed := range []string{"QueryStats", "GetAllOnlineUsers", "both"} {
		t.Run(failed, func(t *testing.T) {
			var calls atomic.Int32
			client := controlRPCFixture(t, func(_ context.Context, method string, _ []byte) ([]byte, error) {
				calls.Add(1)
				if failed == "both" || strings.HasSuffix(method, "/"+failed) {
					return nil, status.Error(codes.Unavailable, "fixture unavailable")
				}
				return nil, nil
			})
			got := newTelemetryCollector(Options{control: client, XrayBinary: "must-not-fallback"}).remoteMeasurements(context.Background())
			if (got.statsErr != nil) != (failed != "GetAllOnlineUsers") || (got.onlineErr != nil) != (failed != "QueryStats") || calls.Load() != 2 {
				t.Fatalf("error/fallback mismatch: stats=%v online=%v calls=%d", got.statsErr, got.onlineErr, calls.Load())
			}
		})
	}
}

func TestTelemetryRPCWaitsForBothCanceledHandlers(t *testing.T) {
	var entered, exited atomic.Int32
	client := controlRPCFixture(t, func(ctx context.Context, _ string, _ []byte) ([]byte, error) {
		entered.Add(1)
		<-ctx.Done()
		exited.Add(1)
		return nil, ctx.Err()
	})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan remoteMeasurementResult, 1)
	go func() { done <- newTelemetryCollector(Options{control: client}).remoteMeasurements(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for entered.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case got := <-done:
		if !errors.Is(got.statsErr, context.Canceled) || !errors.Is(got.onlineErr, context.Canceled) {
			t.Fatalf("cancellation lost: %v %v", got.statsErr, got.onlineErr)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled telemetry did not return")
	}
	deadline = time.Now().Add(time.Second)
	for exited.Load() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if entered.Load() != 2 || exited.Load() != 2 {
		t.Fatal("canceled remote handlers leaked")
	}
}
