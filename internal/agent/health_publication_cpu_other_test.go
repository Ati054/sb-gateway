//go:build !linux

package agent

func benchmarkPublicationCPU() (int64, bool) { return 0, false }
