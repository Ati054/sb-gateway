package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"github.com/sb-gateway/sb-gateway/internal/agent"
	"github.com/sb-gateway/sb-gateway/internal/appliance"
	"github.com/sb-gateway/sb-gateway/internal/controlplane"
	"github.com/sb-gateway/sb-gateway/internal/diagnosticlog"
	"github.com/sb-gateway/sb-gateway/internal/monitor"
	"github.com/sb-gateway/sb-gateway/internal/policydns"
	"github.com/sb-gateway/sb-gateway/internal/recovery"
	"github.com/sb-gateway/sb-gateway/internal/rulesets"
	"github.com/sb-gateway/sb-gateway/internal/runtimeconfig"
	"github.com/sb-gateway/sb-gateway/internal/watchdog"
)

var (
	version  = "dev"
	revision = "uncommitted"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC | log.Lmicroseconds)
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	closeDiagnosticLog := configureDiagnosticLog(os.Args[1])
	defer closeDiagnosticLog()

	switch os.Args[1] {
	case "appliance":
		if err := runAppliance(os.Args[2:]); err != nil {
			log.Fatalf("appliance: %v", err)
		}
	case "api":
		if err := runAPI(os.Args[2:]); err != nil {
			log.Fatalf("control-plane: %v", err)
		}
	case "agent":
		if err := runAgent(os.Args[2:]); err != nil {
			log.Fatalf("agent: %v", err)
		}
	case "monitor":
		if err := runMonitor(os.Args[2:]); err != nil {
			log.Fatalf("monitor: %v", err)
		}
	case "dns":
		if err := runDNS(os.Args[2:]); err != nil {
			log.Fatalf("policy-dns: %v", err)
		}
	case "dns-probe":
		if err := runDNSProbe(os.Args[2:]); err != nil {
			log.Fatalf("dns-probe: %v", err)
		}
	case "watchdog":
		if err := runWatchdog(os.Args[2:]); err != nil {
			log.Fatalf("watchdog: %v", err)
		}
	case "tcp-ready":
		if err := runTCPReady(os.Args[2:]); err != nil {
			log.Fatalf("tcp-ready: %v", err)
		}
	case "xray-balancers":
		if err := runXrayBalancers(os.Args[2:]); err != nil {
			log.Fatalf("xray-balancers: %v", err)
		}
	case "wireguard-egress-plan":
		if err := runWireGuardEgressPlan(os.Args[2:]); err != nil {
			log.Fatalf("wireguard-egress-plan: %v", err)
		}
	case "rulesets":
		if err := runRulesets(os.Args[2:]); err != nil {
			log.Fatalf("rulesets: %v", err)
		}
	case "recovery-apply-pending":
		if err := runRecoveryApplyPending(os.Args[2:]); err != nil {
			log.Fatalf("recovery: %v", err)
		}
	case "version", "--version", "-version":
		fmt.Printf("sb-gateway %s (%s)\n", version, revision)
	case "prune-update-backups":
		if len(os.Args) != 2 {
			log.Fatal("prune-update-backups accepts no arguments")
		}
		count, err := controlplane.PruneLocalUpdateBackups(controlplane.OptionsFromEnvironment())
		if err != nil {
			log.Fatalf("update backup retention: %v", err)
		}
		fmt.Printf("UPDATE_BACKUPS_REMOVED=%d\n", count)
	default:
		usage()
		os.Exit(2)
	}
}

func configureDiagnosticLog(command string) func() {
	if command != "appliance" && command != "api" {
		return func() {}
	}
	path := os.Getenv("SB_GATEWAY_CONTROL_PLANE_LOG")
	if path == "" {
		path = "/logs/control-plane.log"
	}
	writer, err := diagnosticlog.Open(path, 4<<20)
	if err != nil {
		log.Printf("diagnostic log unavailable: %v", err)
		return func() {}
	}
	log.SetOutput(io.MultiWriter(os.Stderr, writer))
	return func() { _ = writer.Close() }
}

func runAppliance(arguments []string) error {
	flags := flag.NewFlagSet("appliance", flag.ContinueOnError)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("appliance does not accept positional arguments")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Printf("appliance: starting version=%s revision=%s", version, revision)
	return appliance.Run(ctx, appliance.OptionsFromEnvironment())
}

func runRecoveryApplyPending(arguments []string) error {
	flags := flag.NewFlagSet("recovery-apply-pending", flag.ContinueOnError)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("recovery-apply-pending does not accept positional arguments")
	}
	result, err := recovery.ApplyPending(recovery.OptionsFromEnvironment())
	if err != nil {
		return err
	}
	fmt.Println(result.String())
	return nil
}

func runRulesets(arguments []string) error {
	flags := flag.NewFlagSet("rulesets", flag.ContinueOnError)
	prepare := flags.Bool("prepare", false, "create and validate offline seeds")
	once := flags.Bool("once", false, "run one online refresh")
	activeOnly := flags.Bool("active-only", false, "refresh only packs used by the active generation")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || (*prepare == *once) {
		return fmt.Errorf("select exactly one of --prepare or --once")
	}
	options := rulesets.OptionsFromEnvironment()
	catalog, err := rulesets.Catalog()
	if err != nil {
		return err
	}
	if *prepare {
		if _, err := rulesets.EnsureSeeds(options.RulesetDir, catalog); err != nil {
			return err
		}
		_, err = rulesets.ValidateLocal(options.RulesetDir)
		return err
	}
	packs := catalog
	if *activeOnly {
		packs, err = rulesets.ActivePacks(options.StateDir, catalog)
	} else {
		var custom []rulesets.ServicePack
		custom, err = rulesets.ConfiguredCustomPacks(options.StateDir, catalog)
		packs = append(packs, custom...)
	}
	if err != nil {
		return err
	}
	_, err = rulesets.RefreshAll(options, packs)
	return err
}

func runTCPReady(arguments []string) error {
	flags := flag.NewFlagSet("tcp-ready", flag.ContinueOnError)
	address := flags.String("address", "", "TCP host:port")
	timeout := flags.Duration("timeout", time.Second, "connection timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *address == "" || *timeout <= 0 || *timeout > 30*time.Second {
		return fmt.Errorf("provide --address host:port and a timeout up to 30s")
	}
	connection, err := net.DialTimeout("tcp", *address, *timeout)
	if err != nil {
		return err
	}
	return connection.Close()
}

func runXrayBalancers(arguments []string) error {
	flags, config := runtimeConfigFlags("xray-balancers")
	apply := flags.Bool("apply", false, "restore and confirm startup selectors through Xray API")
	timeout := flags.Duration("timeout", 5*time.Second, "overall selector restoration deadline")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *timeout <= 0 || *timeout > 30*time.Second {
		return fmt.Errorf("xray-balancers accepts no positional arguments and requires a timeout up to 30s")
	}
	opts := agent.OptionsFromEnvironment()
	if *apply {
		ctx, cancel := context.WithTimeout(context.Background(), *timeout)
		defer cancel()
		return agent.RestoreXraySelectors(ctx, *config, opts)
	}
	balancers, err := agent.XrayStartupSelections(*config, opts)
	if err != nil {
		return err
	}
	for _, item := range balancers {
		fmt.Printf("%s\t%s\n", item.Tag, item.Outbound)
	}
	return nil
}

func runWireGuardEgressPlan(arguments []string) error {
	config, err := runtimeConfigPath("wireguard-egress-plan", arguments)
	if err != nil {
		return err
	}
	_, egress, err := runtimeconfig.ReadXray(config)
	if err != nil {
		return err
	}
	for _, item := range egress {
		fmt.Printf("%s %d\n", item.Address, item.Priority)
	}
	return nil
}

func runtimeConfigFlags(name string) (*flag.FlagSet, *string) {
	flags := flag.NewFlagSet(name, flag.ContinueOnError)
	defaultConfig := os.Getenv("SB_XRAY_CONFIG")
	if defaultConfig == "" {
		defaultConfig = "/config/generated/xray.json"
	}
	config := flags.String("config", defaultConfig, "Xray JSON path")
	return flags, config
}

func runtimeConfigPath(name string, arguments []string) (string, error) {
	flags, config := runtimeConfigFlags(name)
	if err := flags.Parse(arguments); err != nil {
		return "", err
	}
	if flags.NArg() != 0 {
		return "", fmt.Errorf("%s does not accept positional arguments", name)
	}
	return filepath.Abs(*config)
}

func runAPI(arguments []string) error {
	flags := flag.NewFlagSet("api", flag.ContinueOnError)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("api does not accept positional arguments")
	}
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP,
	)
	defer stop()
	log.Printf("control-plane: starting version=%s revision=%s", version, revision)
	return controlplane.Run(ctx, controlplane.OptionsFromEnvironment())
}

func runAgent(arguments []string) error {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("agent does not accept positional arguments")
	}
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP,
	)
	defer stop()
	log.Printf("agent: starting version=%s revision=%s", version, revision)
	return agent.Run(ctx, agent.OptionsFromEnvironment())
}

func runMonitor(arguments []string) error {
	flags := flag.NewFlagSet("monitor", flag.ContinueOnError)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("monitor does not accept positional arguments")
	}
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP,
	)
	defer stop()
	log.Printf("monitor: starting version=%s revision=%s", version, revision)
	return monitor.Run(ctx, monitor.OptionsFromEnvironment())
}

func runWatchdog(arguments []string) error {
	flags := flag.NewFlagSet("watchdog", flag.ContinueOnError)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("watchdog does not accept positional arguments")
	}
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP,
	)
	defer stop()
	log.Printf("watchdog: starting version=%s revision=%s", version, revision)
	return watchdog.Run(ctx, watchdog.OptionsFromEnvironment())
}

func runDNS(arguments []string) error {
	flags := flag.NewFlagSet("dns", flag.ContinueOnError)
	defaultConfig := os.Getenv("SB_POLICY_DNS_CONFIG")
	if defaultConfig == "" {
		defaultConfig = "/config/generated/policy-dns.json"
	}
	configPath := flags.String("config", defaultConfig, "policy DNS JSON path")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	abs, err := filepath.Abs(*configPath)
	if err != nil {
		return fmt.Errorf("resolve config path: %w", err)
	}
	ctx, stop := signal.NotifyContext(
		context.Background(), syscall.SIGINT, syscall.SIGTERM,
	)
	defer stop()
	log.Printf("policy-dns: starting version=%s revision=%s config=%s", version, revision, abs)
	return policydns.Serve(ctx, abs, policydns.OptionsFromEnvironment())
}

func runDNSProbe(arguments []string) error {
	flags := flag.NewFlagSet("dns-probe", flag.ContinueOnError)
	address := flags.String("address", "", "DNS server host:port")
	name := flags.String("name", "example.com", "DNS name to resolve")
	network := flags.String("network", "udp", "DNS transport: udp or tcp")
	timeout := flags.Duration("timeout", 5*time.Second, "query timeout")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *address == "" || (*network != "udp" && *network != "tcp") || *timeout <= 0 || *timeout > 30*time.Second {
		return errors.New("provide --address host:port, --network udp|tcp and a timeout up to 30s")
	}
	if _, ok := dns.IsDomainName(*name); !ok {
		return fmt.Errorf("invalid DNS name %q", *name)
	}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(*name), dns.TypeA)
	client := &dns.Client{Net: *network, Timeout: *timeout}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	response, elapsed, err := client.ExchangeContext(ctx, query, *address)
	if err != nil {
		return err
	}
	if response == nil || !response.Response || response.Id != query.Id {
		return errors.New("invalid DNS response")
	}
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS response rcode=%s", dns.RcodeToString[response.Rcode])
	}
	fmt.Printf("DNS_PROBE=PASS network=%s address=%s name=%s answers=%d elapsed_ms=%d\n", *network, *address, dns.Fqdn(*name), len(response.Answer), elapsed.Milliseconds())
	return nil
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: sb-gateway <appliance|api|monitor|agent|dns|dns-probe|watchdog|rulesets|recovery-apply-pending|prune-update-backups|tcp-ready|xray-balancers|wireguard-egress-plan|version> [options]")
}
