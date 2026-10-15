package runtimeconfig

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type uploadTestService interface{ upload(grpc.ServerStream) error }
type uploadTestReceiver struct{}

func (uploadTestReceiver) upload(stream grpc.ServerStream) error {
	var total int64
	for {
		var message wrapperspb.BytesValue
		if err := stream.RecvMsg(&message); err != nil {
			if err == io.EOF {
				return stream.SendMsg(wrapperspb.Int64(total))
			}
			return err
		}
		total += int64(len(message.Value))
	}
}

// Run in an isolated Linux container: the generated upstreams use 11002/11004.
// SB_STREAMING_IDLE_SECONDS=65 also verifies an idle upload beyond the old 60s.
func TestNginxStreamingLargeBodies(t *testing.T) {
	if os.Getenv("SB_SHARED_LIVE_NGINX") != "1" {
		t.Skip("isolated Nginx integration disabled")
	}
	root := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"cert": pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "key": pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})} {
		if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	listener, err := net.Listen("tcp", "127.0.0.1:11002")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{ServiceName: "Tunnel", HandlerType: (*uploadTestService)(nil), Streams: []grpc.StreamDesc{{StreamName: "Upload", ClientStreams: true, Handler: func(receiver any, stream grpc.ServerStream) error { return receiver.(uploadTestService).upload(stream) }}}}, uploadTestReceiver{})
	go server.Serve(listener)
	defer server.Stop()
	webListener, err := net.Listen("tcp", "127.0.0.1:11004")
	if err != nil {
		t.Fatal(err)
	}
	web := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		count, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, "read failed", 400)
			return
		}
		fmt.Fprint(w, count)
	})}
	go web.Serve(webListener)
	defer web.Close()
	var locations strings.Builder
	for _, kind := range []string{"grpc", "xhttp"} {
		location, err := nginxTransportLocation(nginxDeployment{Kind: kind, Transport: map[string]any{}}, nil, func(string) (string, error) {
			if kind == "grpc" {
				return "Tunnel", nil
			}
			return "/stream", nil
		})
		if err != nil {
			t.Fatal(err)
		}
		locations.WriteString(location)
	}
	idleSeconds, _ := strconv.Atoi(os.Getenv("SB_STREAMING_IDLE_SECONDS"))
	if idleSeconds < 0 || idleSeconds > 120 {
		t.Fatal("idle test must be 0..120 seconds")
	}
	for _, legacy := range []bool{true, false} {
		name := "fixed"
		if legacy {
			name = "legacy"
		}
		t.Run(name, func(t *testing.T) {
			portListener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			address := portListener.Addr().String()
			portListener.Close()
			transportLocations := locations.String()
			if legacy {
				transportLocations = strings.ReplaceAll(transportLocations, nginxStreamingLimits, "")
			}
			config := fmt.Sprintf("pid %s/nginx.pid;\nerror_log %s/error.log warn;\nevents {}\nhttp { client_max_body_size 2m; access_log off; server { listen %s ssl; http2 on; ssl_certificate %s/cert; ssl_certificate_key %s/key; %s location /panel { proxy_pass http://127.0.0.1:11004; } } }", root, root, address, root, root, transportLocations)
			path := filepath.Join(root, "nginx.conf")
			if err := os.WriteFile(path, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command("nginx", "-c", path, "-g", "daemon off;")
			command.WaitDelay = 2 * time.Second
			var output bytes.Buffer
			command.Stdout, command.Stderr = &output, &output
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { command.Process.Signal(syscall.SIGTERM); command.Wait() }()
			deadline := time.Now().Add(3 * time.Second)
			for {
				c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
				if err == nil {
					c.Close()
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Nginx did not listen")
				}
				time.Sleep(20 * time.Millisecond)
			}
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(30+idleSeconds*2)*time.Second)
			defer cancel()
			roots := x509.NewCertPool()
			roots.AddCert(certFromDER(t, der))
			tlsConfig := &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS12}
			client, err := grpc.NewClient(address, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			stream, err := client.NewStream(ctx, &grpc.StreamDesc{ClientStreams: true}, "/Tunnel/Upload")
			if err != nil {
				t.Fatal(err)
			}
			chunk := make([]byte, 64<<10)
			var uploadErr error
			for n := 0; n < 320; n++ {
				if uploadErr = stream.SendMsg(wrapperspb.Bytes(chunk)); uploadErr != nil {
					break
				}
				if n == 0 && !legacy && idleSeconds > 0 {
					time.Sleep(time.Duration(idleSeconds) * time.Second)
				}
			}
			stream.CloseSend()
			var received wrapperspb.Int64Value
			if err := stream.RecvMsg(&received); uploadErr == nil {
				uploadErr = err
			}
			if legacy && uploadErr == nil {
				t.Fatal("legacy gRPC unexpectedly accepted >2 MiB")
			}
			if !legacy && (uploadErr != nil || received.Value != 20<<20) {
				t.Fatalf("gRPC upload: bytes=%d error=%v", received.Value, uploadErr)
			}
			transport := &http.Transport{TLSClientConfig: tlsConfig}
			defer transport.CloseIdleConnections()
			httpClient := &http.Client{Transport: transport}
			for _, target := range []string{"/stream/upload", "/panel"} {
				reader := io.Reader(bytes.NewReader(make([]byte, 20<<20)))
				if !legacy && target == "/stream/upload" && idleSeconds > 0 {
					pipeReader, writer := io.Pipe()
					defer pipeReader.Close()
					go func() {
						defer writer.Close()
						if _, err := writer.Write(chunk); err != nil {
							return
						}
						time.Sleep(time.Duration(idleSeconds) * time.Second)
						for n := 1; n < 320; n++ {
							if _, err := writer.Write(chunk); err != nil {
								return
							}
						}
					}()
					reader = pipeReader
				}
				request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+address+target, reader)
				if err != nil {
					t.Fatal(err)
				}
				response, err := httpClient.Do(request)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if legacy || target == "/panel" {
					if response.StatusCode != 413 {
						t.Fatalf("global limit bypass: %s %d", target, response.StatusCode)
					}
				} else if response.StatusCode != 200 || string(body) != "20971520" {
					t.Fatalf("XHTTP upstream: %d %s", response.StatusCode, body)
				}
			}
		})
	}
}

func certFromDER(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
