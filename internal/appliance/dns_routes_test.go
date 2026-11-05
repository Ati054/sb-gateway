package appliance

import (
	"testing"

	"github.com/sb-gateway/sb-gateway/internal/dnsroute"
)

func TestApplianceSharesRouteRegistryAcrossComponentRestarts(t *testing.T) {
	var options Options
	wireDNSRouteEpochs(&options)
	if options.PolicyDNS.RouteEpochs == nil || options.Monitor.Agent.DNSRoutes != options.PolicyDNS.RouteEpochs {
		t.Fatal("agent and DNS did not receive the same instance-owned registry")
	}
	first := options.PolicyDNS.RouteEpochs
	wireDNSRouteEpochs(&options)
	if options.PolicyDNS.RouteEpochs != first {
		t.Fatal("component restart replaced registry state")
	}
	explicit := dnsroute.New()
	options.PolicyDNS.RouteEpochs = explicit
	wireDNSRouteEpochs(&options)
	if options.Monitor.Agent.DNSRoutes != explicit {
		t.Fatal("explicit appliance registry was not wired consistently")
	}
}
