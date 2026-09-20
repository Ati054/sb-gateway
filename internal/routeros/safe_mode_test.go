package routeros

import (
	"bytes"
	"context"
	"io"
	"testing"
	"time"
)

func TestSafeModeSessionRunsMarkerAndCommitsAfterAcknowledgement(t *testing.T) {
	name := "SB-GATEWAY-apply-0123456789ab"
	channel := &fakeSafeModeChannel{input: bytes.NewReader([]byte(
		"RouterOS [admin@router] >Taking Safe Mode session... Success!\rOK:SB-GATEWAY-0123456789ab\r\n[admin@router] <SAFE>Safe Mode released",
	))}
	session := &SafeModeSession{channel: channel}
	if err := session.begin(context.Background(), name, time.Second); err != nil {
		t.Fatal(err)
	}
	if !session.active || session.closed {
		t.Fatalf("unexpected active state: %s", session)
	}
	if err := session.Commit(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	wantCommand := `:do { /system script run ` + name + `; :put "OK:SB-GATEWAY-0123456789ab" } on-error={ :put "ERROR:SB-GATEWAY-0123456789ab" }` + "\r\n"
	want := append([]byte{0x18}, []byte(wantCommand)...)
	want = append(want, 0x18)
	if !bytes.Equal(channel.output.Bytes(), want) {
		t.Fatalf("Safe Mode writes = %q, want %q", channel.output.Bytes(), want)
	}
	if !channel.closed || session.active || !session.closed {
		t.Fatalf("committed session was not closed: %s", session)
	}
}

func TestSafeModeSessionAbortsOnManagedScriptFailure(t *testing.T) {
	name := "SB-GATEWAY-rollback-0123456789ab"
	channel := &fakeSafeModeChannel{input: bytes.NewReader([]byte(
		"[admin@router] >Taking Safe Mode session... Success!\rERROR:SB-GATEWAY-0123456789ab\r\n[admin@router] <SAFE>",
	))}
	session := &SafeModeSession{channel: channel}
	if err := session.begin(context.Background(), name, time.Second); err == nil {
		t.Fatal("failed RouterOS script was accepted")
	}
	if err := session.Abort(); err != nil {
		t.Fatal(err)
	}
	written := channel.output.Bytes()
	if len(written) == 0 || written[len(written)-1] != 0x04 || !channel.closed {
		t.Fatalf("failed Safe Mode session was not aborted: %q", written)
	}
}

func TestSafeModeSessionAcceptsHistoryCapAutoRelease(t *testing.T) {
	name := "SB-GATEWAY-apply-0123456789ab"
	channel := &fakeSafeModeChannel{input: bytes.NewReader([]byte(
		"[admin@router] >Taking Safe Mode session... Success!\rOK:SB-GATEWAY-0123456789ab\r\n[admin@router] >",
	))}
	session := &SafeModeSession{channel: channel}
	if err := session.begin(context.Background(), name, time.Second); err != nil {
		t.Fatal(err)
	}
	if session.active || !session.HistoryCapReached() || session.closed {
		t.Fatalf("unexpected auto-release state: %s", session)
	}
	if err := session.Commit(context.Background(), time.Second); err != nil {
		t.Fatal(err)
	}
	if !channel.closed || !session.closed {
		t.Fatalf("auto-released session was not closed: %s", session)
	}
	if bytes.Count(channel.output.Bytes(), []byte{0x18}) != 1 {
		t.Fatalf("commit toggled a new empty Safe Mode: %q", channel.output.Bytes())
	}
}

func TestSafeModeOutputIsBounded(t *testing.T) {
	channel := &fakeSafeModeChannel{input: bytes.NewReader(bytes.Repeat([]byte("x"), maxSafeModeOutputBytes+4096))}
	session := &SafeModeSession{channel: channel}
	if _, err := session.waitFor(context.Background(), time.Second, []byte("never")); err == nil {
		t.Fatal("unbounded RouterOS console output was accepted")
	}
}

type fakeSafeModeChannel struct {
	input  io.Reader
	output bytes.Buffer
	closed bool
}

func (channel *fakeSafeModeChannel) Read(buffer []byte) (int, error) {
	return channel.input.Read(buffer)
}

func (channel *fakeSafeModeChannel) Write(buffer []byte) (int, error) {
	return channel.output.Write(buffer)
}

func (channel *fakeSafeModeChannel) Close() error {
	channel.closed = true
	return nil
}

func (channel *fakeSafeModeChannel) SetDeadline(time.Time) error {
	return nil
}
