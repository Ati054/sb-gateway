package routeros

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

const maxManagedImportBytes = 2 << 20

var managedImportNamePattern = regexp.MustCompile(`^SB-GATEWAY-(?:apply|rollback)-[0-9a-f]{12}\.rsc$`)
var sshHostnamePattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

const managedCandidateHeader = "# SB-GATEWAY generated candidate; managed objects only\n"

var managedCandidateSections = []string{"core", "dns", "watchdog", "address-lists", "outage-exceptions", "wireguard-egress", "ipv6", "finalize"}

type SSHOptions struct {
	Host           string
	Port           int
	Username       string
	Password       string
	KnownHostsPath string
	Timeout        time.Duration
}

type SSHTransport struct {
	options SSHOptions
	mu      sync.Mutex
}

func NewSSHTransport(options SSHOptions) (*SSHTransport, error) {
	address := net.ParseIP(options.Host)
	if strings.TrimSpace(options.Host) == "" || (address == nil && !sshHostnamePattern.MatchString(options.Host)) {
		return nil, errors.New("RouterOS SSH host is invalid")
	}
	if options.Port < 1 || options.Port > 65535 {
		return nil, errors.New("RouterOS SSH port is invalid")
	}
	if options.Username == "" || options.Password == "" {
		return nil, errors.New("RouterOS SSH credentials are required")
	}
	if options.KnownHostsPath == "" {
		return nil, errors.New("RouterOS known_hosts path is required")
	}
	abs, err := filepath.Abs(options.KnownHostsPath)
	if err != nil {
		return nil, err
	}
	options.KnownHostsPath = abs
	if options.Timeout <= 0 {
		options.Timeout = 20 * time.Second
	}
	if options.Timeout > 2*time.Minute {
		return nil, errors.New("RouterOS SSH timeout exceeds two minutes")
	}
	return &SSHTransport{options: options}, nil
}

// UploadManagedImport uploads one generated RSC through the legacy SCP sink
// implemented by RouterOS. The body is streamed once and never retained as a
// second in-memory candidate.
func (transport *SSHTransport) UploadManagedImport(ctx context.Context, name string, source io.Reader, size int64) error {
	if err := validateManagedImport(name, size); err != nil {
		return err
	}
	client, connection, err := transport.dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	defer client.Close()
	_ = connection.SetDeadline(time.Now().Add(transport.options.Timeout))
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("open RouterOS SCP session: %w", err)
	}
	defer session.Close()
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	reader := bufio.NewReader(stdout)
	if err := session.Start("scp -t /"); err != nil {
		return errors.New("start RouterOS SCP sink failed")
	}
	if err := sendSCPFile(reader, stdin, name, source, size); err != nil {
		return err
	}
	if err := stdin.Close(); err != nil {
		return err
	}
	if err := session.Wait(); err != nil {
		return errors.New("RouterOS SCP upload did not complete")
	}
	return nil
}

func (transport *SSHTransport) uploadCandidate(ctx context.Context, role, source string) (string, error) {
	name, err := managedImportName(role, source)
	if err != nil {
		return "", err
	}
	if err := validateFullCandidate(source); err != nil {
		return "", err
	}
	if err := transport.UploadManagedImport(ctx, name, strings.NewReader(source), int64(len(source))); err != nil {
		return "", err
	}
	return name, nil
}

// RemoveManagedImports removes exact inert project files in one SSH round
// trip. File names are constrained before command construction.
func (transport *SSHTransport) RemoveManagedImports(ctx context.Context, names ...string) error {
	if len(names) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(names))
	commands := make([]string, 0, len(names)*3)
	for index, name := range names {
		if !managedImportNamePattern.MatchString(name) {
			return errors.New("managed RouterOS import name is invalid")
		}
		if _, exists := seen[name]; exists {
			continue
		}
		seen[name] = struct{}{}
		variable := "ids" + strconv.Itoa(index)
		commands = append(commands,
			`:local `+variable+` [/file find where name="`+name+`"]`,
			`:if ([:len $`+variable+`] > 1) do={ :error "ambiguous managed import" }`,
			`:if ([:len $`+variable+`] = 1) do={ /file remove $`+variable+` }`,
		)
	}
	client, connection, err := transport.dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	defer client.Close()
	_ = connection.SetDeadline(time.Now().Add(transport.options.Timeout))
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	if err := session.Run(strings.Join(commands, "; ")); err != nil {
		return errors.New("remove RouterOS managed imports failed")
	}
	return nil
}

func sendSCPFile(ack *bufio.Reader, destination io.Writer, name string, source io.Reader, size int64) error {
	if err := readSCPAck(ack); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(destination, "C0600 %d %s\n", size, name); err != nil {
		return err
	}
	if err := readSCPAck(ack); err != nil {
		return err
	}
	written, err := io.CopyN(destination, source, size)
	if err != nil || written != size {
		return errors.New("stream RouterOS managed import failed")
	}
	if _, err := destination.Write([]byte{0}); err != nil {
		return err
	}
	return readSCPAck(ack)
}

func validateManagedImport(name string, size int64) error {
	if !managedImportNamePattern.MatchString(name) {
		return errors.New("managed RouterOS import name is invalid")
	}
	if size < 1 || size > maxManagedImportBytes {
		return errors.New("managed RouterOS import must contain 1 byte to 2 MiB")
	}
	return nil
}

func managedImportName(role, source string) (string, error) {
	if !managedRolePattern.MatchString(role) {
		return "", errors.New("managed RouterOS import role is invalid")
	}
	digest := sha256.Sum256([]byte(source))
	return "SB-GATEWAY-" + role + "-" + hex.EncodeToString(digest[:])[:12] + ".rsc", nil
}

func validateFullCandidate(source string) error {
	if len(source) < len(managedCandidateHeader) || len(source) > maxManagedImportBytes {
		return errors.New("full RouterOS candidate must fit in 2 MiB")
	}
	if !strings.HasPrefix(source, managedCandidateHeader) || strings.IndexByte(source, 0) >= 0 {
		return errors.New("full RouterOS candidate has an invalid generated header")
	}
	position := len(managedCandidateHeader)
	for _, section := range managedCandidateSections {
		marker := "# SB-GATEWAY section:" + section + "\n"
		index := strings.Index(source[position:], marker)
		if index < 0 {
			return errors.New("full RouterOS candidate is missing a managed section")
		}
		position += index + len(marker)
	}
	for _, pattern := range prohibitedScriptPatterns {
		if pattern.MatchString(source) {
			return errors.New("full RouterOS candidate contains a prohibited command")
		}
	}
	return nil
}

func (transport *SSHTransport) dial(ctx context.Context) (*ssh.Client, net.Conn, error) {
	callback, err := transport.hostKeyCallback()
	if err != nil {
		return nil, nil, err
	}
	address := net.JoinHostPort(transport.options.Host, strconv.Itoa(transport.options.Port))
	dialer := net.Dialer{Timeout: min(transport.options.Timeout, 10*time.Second), KeepAlive: 30 * time.Second}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, nil, fmt.Errorf("connect RouterOS SSH: %w", err)
	}
	deadline := time.Now().Add(transport.options.Timeout)
	_ = connection.SetDeadline(deadline)
	config := &ssh.ClientConfig{
		User:            transport.options.Username,
		Auth:            []ssh.AuthMethod{ssh.Password(transport.options.Password)},
		HostKeyCallback: callback,
		Timeout:         transport.options.Timeout,
	}
	sshConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		connection.Close()
		return nil, nil, errors.New("authenticate RouterOS SSH failed")
	}
	_ = connection.SetDeadline(time.Time{})
	return ssh.NewClient(sshConnection, channels, requests), connection, nil
}

func (transport *SSHTransport) hostKeyCallback() (ssh.HostKeyCallback, error) {
	path := transport.options.KnownHostsPath
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
			return nil, errors.New("RouterOS known_hosts must be a private regular file")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		transport.mu.Lock()
		defer transport.mu.Unlock()
		if info, err := os.Stat(path); err == nil && info.Size() > 0 {
			verify, buildErr := knownhosts.New(path)
			if buildErr != nil {
				return errors.New("load RouterOS known_hosts failed")
			}
			if verifyErr := verify(hostname, remote, key); verifyErr == nil {
				return nil
			} else if keyErr, ok := verifyErr.(*knownhosts.KeyError); !ok || len(keyErr.Want) != 0 {
				return errors.New("RouterOS SSH host key changed")
			}
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		line := knownhosts.Line([]string{knownhosts.Normalize(hostname)}, key) + "\n"
		_, writeErr := io.WriteString(file, line)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if writeErr != nil {
			return writeErr
		}
		return closeErr
	}, nil
}

func readSCPAck(reader *bufio.Reader) error {
	code, err := reader.ReadByte()
	if err != nil {
		return errors.New("RouterOS SCP acknowledgement is unavailable")
	}
	if code == 0 {
		return nil
	}
	if code != 1 && code != 2 {
		return errors.New("RouterOS SCP returned an invalid acknowledgement")
	}
	message, _ := reader.ReadString('\n')
	if len(message) > 512 {
		message = message[:512]
	}
	return errors.New("RouterOS SCP rejected the managed import")
}
