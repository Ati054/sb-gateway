package routeros

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"
)

// RunManagedScript avoids RouterOS REST's fixed 60-second command timeout.
// The caller owns the already-armed rollback guard; no interactive Safe Mode
// is taken here. A zero SSH exit status alone is NOT a RouterOS success receipt.
func (transport *SSHTransport) RunManagedScript(ctx context.Context, name string) error {
	command, receipt, err := managedScriptCommand(name)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	client, connection, err := transport.dial(ctx)
	if err != nil {
		return err
	}
	defer connection.Close()
	defer client.Close()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := connection.SetDeadline(deadline); err != nil {
		return err
	}
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	var output scriptReceiptTail
	session.Stdout, session.Stderr = &output, &output
	if err := session.Run(command); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return errors.New("RouterOS SSH managed script execution failed")
	}
	if !output.completed(receipt) {
		// Do not expose arbitrary script output (which may contain secrets), or
		// accept a script error returned with RouterOS's successful SSH exit code.
		return errors.New("RouterOS managed script completion was not confirmed")
	}
	return nil
}

func managedScriptCommand(name string) (string, string, error) {
	if !managedNamePattern.MatchString(name) {
		return "", "", errors.New("managed RouterOS script name is invalid")
	}
	receipt := "OK:" + name
	command := `:do { :local target [/system/script/find where name="` + name + `"]; ` +
		`:if ([:len $target] != 1) do={ :error "managed script missing or ambiguous" }; ` +
		`:if ([/system/script/get $target comment] != "SB-GATEWAY managed script ` + name + `") do={ :error "unowned script" }; ` +
		`/system/script/run $target; :put "` + receipt + `" } on-error={ :put "ERROR:` + name + `" }`
	return command, receipt, nil
}

// Keep only a bounded tail, even when an import prints a large diagnostic.
type scriptReceiptTail struct {
	mu   sync.Mutex
	data []byte
}

func (tail *scriptReceiptTail) Write(p []byte) (int, error) {
	tail.mu.Lock()
	defer tail.mu.Unlock()
	n := len(p)
	const limit = 4096
	if len(p) >= limit {
		tail.data = append(tail.data[:0], p[len(p)-limit:]...)
	} else {
		if excess := len(tail.data) + len(p) - limit; excess > 0 {
			copy(tail.data, tail.data[excess:])
			tail.data = tail.data[:len(tail.data)-excess]
		}
		tail.data = append(tail.data, p...)
	}
	return n, nil
}

func (tail *scriptReceiptTail) completed(receipt string) bool {
	tail.mu.Lock()
	defer tail.mu.Unlock()
	lines := strings.Split(strings.TrimSpace(string(tail.data)), "\n")
	return strings.TrimSpace(lines[len(lines)-1]) == receipt
}
