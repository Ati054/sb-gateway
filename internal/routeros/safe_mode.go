package routeros

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxSafeModeOutputBytes = 256 << 10

type safeModeChannel interface {
	io.Reader
	io.Writer
	Close() error
	SetDeadline(time.Time) error
}

type SafeModeSession struct {
	channel      safeModeChannel
	active       bool
	autoReleased bool
	closed       bool
	pending      []byte
}

// BeginSafeMode opens one interactive RouterOS console, enters Safe Mode and
// runs an already installed content-addressed script. The returned session
// must be committed only after runtime health probes succeed; Close/Abort drops
// the owning console and lets RouterOS undo the floating transaction.
func (transport *SSHTransport) BeginSafeMode(ctx context.Context, scriptName string) (*SafeModeSession, error) {
	if !managedNamePattern.MatchString(scriptName) {
		return nil, errors.New("managed RouterOS script name is invalid")
	}
	client, connection, err := transport.dial(ctx)
	if err != nil {
		return nil, err
	}
	session, err := client.NewSession()
	if err != nil {
		connection.Close()
		client.Close()
		return nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		session.Close()
		connection.Close()
		client.Close()
		return nil, err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		session.Close()
		connection.Close()
		client.Close()
		return nil, err
	}
	session.Stderr = io.Discard
	modes := ssh.TerminalModes{ssh.ECHO: 0, ssh.TTY_OP_ISPEED: 14400, ssh.TTY_OP_OSPEED: 14400}
	if err := session.RequestPty("dumb", 24, 80, modes); err != nil {
		session.Close()
		connection.Close()
		client.Close()
		return nil, errors.New("RouterOS SSH did not provide an interactive console")
	}
	if err := session.Shell(); err != nil {
		session.Close()
		connection.Close()
		client.Close()
		return nil, errors.New("RouterOS SSH console did not start")
	}
	channel := &sshSafeModeChannel{
		Reader: stdout, Writer: stdin, connection: connection,
		close: func() error {
			_ = stdin.Close()
			_ = session.Close()
			_ = client.Close()
			return connection.Close()
		},
	}
	result := &SafeModeSession{channel: channel}
	if err := result.begin(ctx, scriptName, transport.options.Timeout); err != nil {
		_ = result.Abort()
		return nil, err
	}
	return result, nil
}

func (session *SafeModeSession) begin(ctx context.Context, scriptName string, timeout time.Duration) error {
	if _, err := session.waitFor(ctx, timeout, []byte("] >")); err != nil {
		return errors.New("RouterOS Safe Mode prompt was not available")
	}
	if _, err := session.channel.Write([]byte{0x18}); err != nil {
		return err
	}
	if _, err := session.waitFor(ctx, timeout, []byte("Taking Safe Mode session... Success!")); err != nil {
		return errors.New("RouterOS refused to enter Safe Mode")
	}
	session.active = true
	marker := "SB-GATEWAY-" + scriptName[len(scriptName)-12:]
	command := `:do { /system script run ` + scriptName + `; :put "OK:` + marker + `" } on-error={ :put "ERROR:` + marker + `" }` + "\r\n"
	if _, err := io.WriteString(session.channel, command); err != nil {
		return err
	}
	success := [][]byte{[]byte("\rOK:" + marker + "\r\n"), []byte("\nOK:" + marker + "\r\n")}
	failure := [][]byte{[]byte("\rERROR:" + marker + "\r\n"), []byte("\nERROR:" + marker + "\r\n")}
	output, found, err := session.waitForAny(ctx, max(timeout, 2*time.Minute), append(success, failure...))
	if err != nil {
		return errors.New("RouterOS managed candidate did not complete")
	}
	if bytes.Contains(found, []byte("ERROR:")) || safeModeCommandFailed(output) {
		return errors.New("RouterOS managed candidate failed")
	}
	_, prompt, err := session.waitForAny(ctx, 10*time.Second, [][]byte{[]byte("<SAFE>"), []byte("] >")})
	if err != nil {
		return errors.New("RouterOS prompt did not return after candidate")
	}
	if bytes.Equal(prompt, []byte("] >")) {
		// RouterOS automatically commits a Safe Mode transaction at its history
		// limit. The independently armed rollback scheduler remains the guard
		// until health checks succeed and the coordinator disarms it.
		session.active = false
		session.autoReleased = true
	}
	return nil
}

// Commit releases Safe Mode and closes the authenticated console only after
// RouterOS acknowledges that the floating transaction became permanent.
func (session *SafeModeSession) Commit(ctx context.Context, timeout time.Duration) error {
	if session.closed || (!session.active && !session.autoReleased) {
		return errors.New("RouterOS Safe Mode session is not active")
	}
	if session.autoReleased {
		session.closed = true
		return session.channel.Close()
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if _, err := session.channel.Write([]byte{0x18}); err != nil {
		_ = session.Abort()
		return err
	}
	output, err := session.waitFor(ctx, timeout, []byte("Safe Mode released"))
	if err != nil || bytes.Contains(output, []byte("Failure")) {
		_ = session.Abort()
		return errors.New("RouterOS did not commit the Safe Mode transaction")
	}
	session.active = false
	session.closed = true
	return session.channel.Close()
}

func (session *SafeModeSession) HistoryCapReached() bool {
	return session.autoReleased
}

// Abort closes the Safe Mode owner without releasing it. RouterOS therefore
// rolls back the transaction; sending Ctrl-D first gives an idle console the
// clean documented exit path, while connection close remains the fail-safe.
func (session *SafeModeSession) Abort() error {
	if session.closed {
		return nil
	}
	if session.active {
		_, _ = session.channel.Write([]byte{0x04})
	}
	session.active = false
	session.closed = true
	return session.channel.Close()
}

func (session *SafeModeSession) Close() error {
	return session.Abort()
}

func (session *SafeModeSession) waitFor(ctx context.Context, timeout time.Duration, token []byte) ([]byte, error) {
	result, _, err := session.waitForAny(ctx, timeout, [][]byte{token})
	return result, err
}

func (session *SafeModeSession) waitForAny(ctx context.Context, timeout time.Duration, tokens [][]byte) ([]byte, []byte, error) {
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := session.channel.SetDeadline(deadline); err != nil {
		return nil, nil, err
	}
	defer session.channel.SetDeadline(time.Time{})
	for {
		for _, token := range tokens {
			if index := bytes.Index(session.pending, token); index >= 0 {
				end := index + len(token)
				result := append([]byte(nil), session.pending[:end]...)
				session.pending = append(session.pending[:0], session.pending[end:]...)
				return result, token, nil
			}
		}
		if len(session.pending) >= maxSafeModeOutputBytes {
			return nil, nil, errors.New("RouterOS Safe Mode output exceeds 256 KiB")
		}
		if err := ctx.Err(); err != nil {
			return nil, nil, err
		}
		var buffer [4096]byte
		count, err := session.channel.Read(buffer[:])
		if count > 0 {
			session.pending = append(session.pending, buffer[:count]...)
		}
		if err != nil {
			return nil, nil, err
		}
	}
}

func safeModeCommandFailed(output []byte) bool {
	normalized := strings.ToLower(string(output))
	for _, marker := range []string{"syntax error", "failure:", "bad command name", "expected end of command", "no such item", "not allowed"} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

type sshSafeModeChannel struct {
	io.Reader
	io.Writer
	connection net.Conn
	close      func() error
}

func (channel *sshSafeModeChannel) Close() error {
	return channel.close()
}

func (channel *sshSafeModeChannel) SetDeadline(deadline time.Time) error {
	return channel.connection.SetDeadline(deadline)
}

func (session *SafeModeSession) String() string {
	return fmt.Sprintf("RouterOS Safe Mode(active=%t, autoReleased=%t, closed=%t)", session.active, session.autoReleased, session.closed)
}
