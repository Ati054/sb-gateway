package appliance

import (
	"context"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/controlplane"
	"github.com/sb-gateway/sb-gateway/internal/monitor"
	"github.com/sb-gateway/sb-gateway/internal/policydns"
)

type Options struct {
	ControlPlane    controlplane.Options
	Monitor         monitor.Options
	PolicyDNS       policydns.Options
	PolicyDNSConfig string
	NginxBinary     string
	NginxConfig     string
	NginxReady      string
	ShellBinary     string
	XrayRunner      string
	XrayReady       string
}

func OptionsFromEnvironment() Options {
	controlPlane := controlplane.OptionsFromEnvironment()
	return Options{
		ControlPlane:    controlPlane,
		Monitor:         monitor.OptionsFromEnvironment(),
		PolicyDNS:       policydns.OptionsFromEnvironment(),
		PolicyDNSConfig: environment("SB_POLICY_DNS_CONFIG", "/config/generated/policy-dns.json"),
		NginxBinary:     environment("SB_NGINX_BINARY", "/usr/sbin/nginx"),
		NginxConfig:     environment("SB_NGINX_RUNTIME_CONFIG", "/run/sb-gateway/nginx.conf"),
		NginxReady:      environment("SB_NGINX_READY_ADDRESS", "127.0.0.1:9443"),
		ShellBinary:     environment("SB_SHELL_BINARY", "/bin/sh"),
		XrayRunner:      environment("SB_XRAY_RUNNER", "/opt/sb-gateway/scripts/run-xray.sh"),
		XrayReady:       environment("SB_XRAY_API_SERVER", "127.0.0.1:10085"),
	}
}

func Run(ctx context.Context, options Options) error {
	if migrated, err := controlplane.EnsureStartupNginxTrafficReadiness(options.NginxConfig); err != nil {
		return err
	} else if migrated {
		log.Printf("appliance: Nginx runtime migrated to route-aware traffic readiness")
	}
	if migrated, err := controlplane.EnforceStartupTrafficSafety(ctx, options.ControlPlane); err != nil {
		log.Printf("appliance: startup traffic safety could not be reconciled yet: %v", err)
	} else if migrated {
		log.Printf("appliance: RouterOS watchdog migrated to route-aware traffic readiness")
	}
	if migrated, err := controlplane.MigrateLegacyDynamicRuntime(ctx, options.ControlPlane); err != nil {
		log.Printf("appliance: legacy runtime migration skipped safely: %v", err)
	} else if migrated {
		log.Printf("appliance: subscription-backed startup outbounds migrated to on-demand loading")
	}
	var supervisor *Supervisor
	nginx, err := CommandProgram(
		"nginx", options.NginxBinary,
		[]string{"-c", options.NginxConfig, "-g", "daemon off;"},
		WaitProbe(TCPProbe(options.NginxReady, time.Second), 250*time.Millisecond),
	)
	if err != nil {
		return err
	}
	xray, err := CommandProgram(
		"xray", options.ShellBinary, []string{options.XrayRunner},
		WaitProbe(TCPProbe(options.XrayReady, time.Second), 250*time.Millisecond),
	)
	if err != nil {
		return err
	}
	apiAddress := net.JoinHostPort(options.ControlPlane.Host, strconv.Itoa(options.ControlPlane.Port))
	programs := []Program{
		{
			Name: "api",
			Run: func(child context.Context) error {
				controlOptions := options.ControlPlane
				controlOptions.Controller = supervisor
				return controlplane.Run(child, controlOptions)
			},
			Probe: WaitProbe(TCPProbe(apiAddress, time.Second), 250*time.Millisecond),
		},
		nginx,
		{
			Name: "dns",
			Run: func(child context.Context) error {
				return policydns.Serve(child, options.PolicyDNSConfig, options.PolicyDNS)
			},
			Probe: WaitProbe(func(probeContext context.Context) error {
				return policydns.ProbeListeners(probeContext, options.PolicyDNSConfig)
			}, 250*time.Millisecond),
		},
		xray,
		{
			Name: "monitor",
			Run:  func(child context.Context) error { return monitor.Run(child, options.Monitor) },
		},
	}
	supervisor, err = NewSupervisor(programs)
	if err != nil {
		return err
	}
	return supervisor.Run(ctx)
}

func environment(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
