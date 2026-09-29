// Package routerosassets shares the installer watchdog with native Apply.
package routerosassets

import (
	"embed"
	"strings"
)

//go:embed watchdog.rsc cloudflare-update.rsc
var scripts embed.FS

// HealthWatchdogSource returns the same script body used by fresh installs.
func HealthWatchdogSource() string {
	return scriptBody("watchdog.rsc", `/system/script/add name="SB-GATEWAY-health-watchdog" policy=ftp,read,write,policy,test source={`,
		`} comment="SB-GATEWAY health watchdog"`)
}

// StartupFailOpenSource returns the boot safety script without re-importing it.
func StartupFailOpenSource() string {
	return scriptBody("watchdog.rsc", `/system/script/add name="SB-GATEWAY-startup-fail-open" policy=read,write,test source={`,
		`} comment="SB-GATEWAY startup fail-open"`)
}

// CloudflareUpdateSource returns the optional RouterOS updater body.
func CloudflareUpdateSource() string {
	return scriptBody("cloudflare-update.rsc", `/system/script/add name="SB-GATEWAY-cloudflare-update" policy=read,write,test,ftp source={`,
		`} comment="SB-GATEWAY Cloudflare updater"`)
}

func scriptBody(filename, start, end string) string {
	source, err := scripts.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	text := strings.ReplaceAll(string(source), "\r\n", "\n")
	_, body, ok := strings.Cut(text, start)
	if !ok {
		panic(filename + " script source marker missing")
	}
	body, _, ok = strings.Cut(body, end)
	if !ok {
		panic(filename + " script end marker missing")
	}
	return strings.TrimSpace(body)
}
