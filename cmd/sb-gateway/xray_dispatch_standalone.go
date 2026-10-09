//go:build !xray_multicall

package main

import (
	"fmt"
	"os"
)

func runXrayMain() {
	fmt.Fprintln(os.Stderr, "Xray alias requires a build with xray_multicall")
	os.Exit(2)
}
