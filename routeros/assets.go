// Package routerosassets shares the installer watchdog with native Apply.
package routerosassets

import (
	"embed"
	"strings"
)

//go:embed watchdog.rsc
var scripts embed.FS

// HealthWatchdogSource returns the same script body used by fresh installs.
func HealthWatchdogSource() string {
	source, err := scripts.ReadFile("watchdog.rsc")
	if err != nil {
		panic(err)
	}
	text := strings.ReplaceAll(string(source), "\r\n", "\n")
	_, body, ok := strings.Cut(text, `/system/script/add name="SB-GATEWAY-health-watchdog" policy=ftp,read,write,policy,test source={`)
	if !ok {
		panic("watchdog source marker missing")
	}
	body, _, ok = strings.Cut(body, `} comment="SB-GATEWAY health watchdog"`)
	if !ok {
		panic("watchdog end marker missing")
	}
	return strings.TrimSpace(body)
}
