package acmejob

import "time"

const (
	PropagationPollingInterval = 10 * time.Second

	regRUDNSPropagationTimeout  = 4*time.Hour + 15*time.Minute
	publicDNSPropagationTimeout = 90 * time.Minute

	acmeWorkerSetupBudget        = 5 * time.Minute
	acmeWorkerPerSANBudget       = 10 * time.Minute
	acmeControllerOverheadBudget = time.Minute
)

// PropagationTimeout is the maximum DNS-01 wait budget used by both lego and
// the enclosing one-shot worker. It is deliberately a provider default rather
// than a promise that an operator's custom DNS TTL will fit inside it.
func PropagationTimeout(settings Settings) time.Duration {
	if settings.Provider == "acmedns" {
		if settings.PropagationTimeoutMinutes > 0 {
			return time.Duration(settings.PropagationTimeoutMinutes) * time.Minute
		}
		return regRUDNSPropagationTimeout
	}
	switch settings.Provider {
	case "regru":
		return regRUDNSPropagationTimeout
	case "cloudflare", "yandexcloud", "gcore":
		return publicDNSPropagationTimeout
	default:
		return publicDNSPropagationTimeout
	}
}

// WorkerTimeout caps one issuance as a whole. DNS propagation is one shared
// wait for the order; only setup/order work receives a bounded per-SAN margin.
func WorkerTimeout(settings Settings) time.Duration {
	sans := len(settings.Domains)
	if sans < 1 {
		sans = 1
	}
	if sans > 10 {
		sans = 10
	}
	return PropagationTimeout(settings) + acmeWorkerSetupBudget + time.Duration(sans)*acmeWorkerPerSANBudget
}

// ControllerTimeout leaves the control plane a short bounded margin to collect
// the worker result or install it locally after the worker deadline.
func ControllerTimeout(settings Settings) time.Duration {
	return WorkerTimeout(settings) + acmeControllerOverheadBudget
}
