package appliance

import "github.com/sb-gateway/sb-gateway/internal/dnsroute"

// The monitor agent and separately restartable DNS component share PID1. Bind
// exactly one registry here; validation and standalone commands never infer it.
func wireDNSRouteEpochs(options *Options) {
	if options.PolicyDNS.RouteEpochs == nil {
		options.PolicyDNS.RouteEpochs = dnsroute.New()
	}
	options.Monitor.Agent.DNSRoutes = options.PolicyDNS.RouteEpochs
}
