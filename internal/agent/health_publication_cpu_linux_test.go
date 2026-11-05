package agent

import "syscall"

func benchmarkPublicationCPU() (int64, bool) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		return 0, false
	}
	return usage.Utime.Nano() + usage.Stime.Nano(), true
}
