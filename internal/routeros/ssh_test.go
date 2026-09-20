package routeros

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestSSHTransportTrustsFirstKeyAndRejectsReplacement(t *testing.T) {
	knownHosts := filepath.Join(t.TempDir(), "ssh_known_hosts")
	transport, err := NewSSHTransport(SSHOptions{
		Host: "router.example", Port: 22, Username: "admin", Password: "secret", KnownHostsPath: knownHosts,
	})
	if err != nil {
		t.Fatal(err)
	}
	first := testSSHSigner(t)
	second := testSSHSigner(t)
	callback, err := transport.hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	host := "router.example:22"
	remote := &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 22}
	if err := callback(host, remote, first.PublicKey()); err != nil {
		t.Fatalf("trust first key: %v", err)
	}
	if err := callback(host, remote, first.PublicKey()); err != nil {
		t.Fatalf("verify retained key: %v", err)
	}
	if err := callback(host, remote, second.PublicKey()); err == nil {
		t.Fatal("changed RouterOS host key was accepted")
	}
	body, err := os.ReadFile(knownHosts)
	if err != nil || bytes.Count(body, []byte("\n")) != 1 {
		t.Fatalf("known_hosts was not written exactly once: %q / %v", body, err)
	}
}

func TestSSHTransportRejectsUnsafeInputsBeforeNetwork(t *testing.T) {
	base := SSHOptions{Host: "router.example", Port: 22, Username: "admin", Password: "secret", KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")}
	for _, host := range []string{"", "router/name", "user@router", "router name", "bad:host"} {
		options := base
		options.Host = host
		if _, err := NewSSHTransport(options); err == nil {
			t.Fatalf("unsafe SSH host %q was accepted", host)
		}
	}
	for _, test := range []struct {
		name string
		size int64
	}{
		{"apply.rsc", 1},
		{"SB-GATEWAY-apply-0123456789ab.rsc", 0},
		{"SB-GATEWAY-apply-0123456789ab.rsc", maxManagedImportBytes + 1},
	} {
		if err := validateManagedImport(test.name, test.size); err == nil {
			t.Fatalf("unsafe import %q/%d was accepted", test.name, test.size)
		}
	}
	if err := validateManagedImport("SB-GATEWAY-rollback-0123456789ab.rsc", 128); err != nil {
		t.Fatal(err)
	}
}

func TestValidateFullCandidateRequiresAllOrderedManagedSections(t *testing.T) {
	valid := managedCandidateHeader
	for _, section := range managedCandidateSections {
		valid += "# SB-GATEWAY section:" + section + "\n:put ok\n"
	}
	if err := validateFullCandidate(valid); err != nil {
		t.Fatal(err)
	}
	name, err := managedImportName("apply", valid)
	if err != nil || !managedImportNamePattern.MatchString(name) {
		t.Fatalf("name=%q err=%v", name, err)
	}
	if err := validateFullCandidate(managedCandidateHeader + "# SB-GATEWAY section:core\n"); err == nil {
		t.Fatal("incomplete full candidate was accepted")
	}
	if err := validateFullCandidate(valid + "/system reboot\n"); err == nil {
		t.Fatal("unsafe full candidate was accepted")
	}
}

func TestReadSCPAckDoesNotExposeRemoteMessage(t *testing.T) {
	if err := readSCPAck(bufio.NewReader(strings.NewReader("\x00"))); err != nil {
		t.Fatal(err)
	}
	err := readSCPAck(bufio.NewReader(strings.NewReader("\x01secret supplied by server\n")))
	if err == nil || strings.Contains(err.Error(), "secret") {
		t.Fatalf("SCP error was not safely classified: %v", err)
	}
}

func TestSendSCPFileStreamsExactLegacyProtocol(t *testing.T) {
	var destination bytes.Buffer
	ack := bufio.NewReader(bytes.NewReader([]byte{0, 0, 0}))
	name := "SB-GATEWAY-apply-0123456789ab.rsc"
	if err := sendSCPFile(ack, &destination, name, strings.NewReader("abc"), 3); err != nil {
		t.Fatal(err)
	}
	want := "C0600 3 " + name + "\nabc\x00"
	if destination.String() != want {
		t.Fatalf("SCP payload = %q, want %q", destination.String(), want)
	}
}

func testSSHSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return signer
}
