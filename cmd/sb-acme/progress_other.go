//go:build !linux

package main

func newWorkerProgressReporter() *progressReporter { return &progressReporter{} }
