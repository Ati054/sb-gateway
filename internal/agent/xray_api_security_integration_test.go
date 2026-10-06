package agent

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// Opt-in against the image core; the test never contacts the live gateway API.
func TestXrayAPIRejectsMissingAuthority(t *testing.T) {
	binary := os.Getenv("SB_TEST_XRAY")
	if binary == "" {
		t.Skip("set SB_TEST_XRAY to run the real-core integration test")
	}
	command := func(ctx context.Context, args ...string) *exec.Cmd {
		if runner := os.Getenv("SB_TEST_XRAY_RUNNER"); runner != "" {
			return exec.CommandContext(ctx, runner, append([]string{binary}, args...)...)
		}
		return exec.CommandContext(ctx, binary, args...)
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	config := filepath.Join(root, "xray.json")
	if err := os.WriteFile(config, []byte(fmt.Sprintf(`{
  "log":{"loglevel":"warning"},
  "api":{"tag":"api","services":["RoutingService"]},
  "inbounds":[{"tag":"api-in","listen":"127.0.0.1","port":%d,"protocol":"dokodemo-door","settings":{"address":"127.0.0.1"}}],
  "outbounds":[{"tag":"first","protocol":"freedom"},{"tag":"second","protocol":"freedom"}],
  "routing":{"balancers":[{"tag":"security-probe","selector":["first","second"],"strategy":{"type":"random"}}],
    "rules":[{"type":"field","inboundTag":["api-in"],"outboundTag":"api"}]}
}`, port)), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	log, err := os.Create(filepath.Join(root, "xray.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	process := command(ctx, "run", "-config", config)
	process.Stdout, process.Stderr = log, log
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = process.Process.Kill()
		_ = process.Wait()
		if t.Failed() {
			body, _ := os.ReadFile(log.Name())
			t.Log(string(body))
		}
	}()
	ready := false
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); {
		conn, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("isolated Xray API did not start")
	}
	checkAPI := func() {
		t.Helper()
		callCtx, stop := context.WithTimeout(ctx, 10*time.Second)
		defer stop()
		output, err := command(callCtx, "api", "bo", "--server="+address, "-b", "security-probe", "first").CombinedOutput()
		if err != nil {
			t.Fatalf("normal selector command failed: %v: %s", err, output)
		}
	}
	checkAPI()
	for attempt := 0; attempt < 3; attempt++ {
		func() {
			conn, err := net.DialTimeout("tcp", address, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := conn.Write([]byte(http2.ClientPreface)); err != nil {
				t.Fatal(err)
			}
			framer := http2.NewFramer(conn, conn)
			framer.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
			if err := framer.WriteSettings(); err != nil {
				t.Fatal(err)
			}
			var block bytes.Buffer
			encoder := hpack.NewEncoder(&block)
			// Deliberately omit both :authority and Host; other fields are valid.
			for _, field := range []hpack.HeaderField{
				{Name: ":method", Value: "POST"},
				{Name: ":scheme", Value: "http"},
				{Name: ":path", Value: "/xray.app.router.command.RoutingService/GetBalancerInfo"},
				{Name: "content-type", Value: "application/grpc"},
				{Name: "te", Value: "trailers"},
			} {
				if err := encoder.WriteField(field); err != nil {
					t.Fatal(err)
				}
			}
			if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
				t.Fatal(err)
			}
			for {
				frame, err := framer.ReadFrame()
				if err != nil {
					t.Fatal(err)
				}
				switch f := frame.(type) {
				case *http2.SettingsFrame:
					if !f.IsAck() {
						if err := framer.WriteSettingsAck(); err != nil {
							t.Fatal(err)
						}
					}
				case *http2.MetaHeadersFrame:
					if f.StreamID != 1 {
						t.Fatalf("unexpected response stream %d", f.StreamID)
					}
					var httpStatus, grpcStatus string
					for _, header := range f.Fields {
						switch header.Name {
						case ":status":
							httpStatus = header.Value
						case "grpc-status":
							grpcStatus = header.Value
						}
					}
					if httpStatus != "400" || grpcStatus != "13" {
						t.Fatalf("request not rejected: HTTP=%q gRPC=%q", httpStatus, grpcStatus)
					}
					return
				}
			}
		}()
		checkAPI()
	}
	t.Log("three malformed requests rejected with HTTP 400/gRPC 13; selector API remains usable")
}
