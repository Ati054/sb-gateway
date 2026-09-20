package policydns

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestValidateFileCompilesWithoutOpeningListeners(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy-dns.json")
	body := `{"version":1,"servers":{},"lanes":[{"id":"lane","host":"127.0.0.1","port":30001,"final":"reject","rules":[]}],"timeout_seconds":5}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFile(path, Options{CacheEntries: 256, CacheBytes: 1 << 20}); err != nil {
		t.Fatal(err)
	}
}

func TestProbeListenersConnectsOnceToConfiguredLane(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	accepted := make(chan struct{}, 1)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			accepted <- struct{}{}
		}
	}()
	path := filepath.Join(t.TempDir(), "policy-dns.json")
	body := fmt.Sprintf(`{"version":1,"servers":{},"lanes":[{"id":"lane","host":"127.0.0.1","port":%d,"final":"reject","rules":[]}]}`, port)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := ProbeListeners(ctx, path); err != nil {
		t.Fatal(err)
	}
	select {
	case <-accepted:
	case <-ctx.Done():
		t.Fatal("policy DNS probe did not reach the configured lane")
	}
}
