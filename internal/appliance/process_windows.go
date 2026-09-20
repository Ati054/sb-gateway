//go:build windows

package appliance

import "os/exec"

func prepareCommand(_ *exec.Cmd) {}

func terminateCommand(command *exec.Cmd) error {
	return killCommand(command)
}

func killCommand(command *exec.Cmd) error {
	if command.Process == nil {
		return nil
	}
	return command.Process.Kill()
}
