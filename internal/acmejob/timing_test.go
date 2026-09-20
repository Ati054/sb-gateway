package acmejob

import (
	"testing"
	"time"
)

func TestACMEIssuanceTimingUsesProviderLimitsAndBoundedSANMargin(t *testing.T) {
	for name, test := range map[string]struct {
		settings    Settings
		propagation time.Duration
		worker      time.Duration
		controller  time.Duration
	}{
		"REG.RU": {
			settings:    Settings{Provider: "regru", Domains: []string{"api.example.com", "www.example.com"}},
			propagation: 4*time.Hour + 15*time.Minute,
			worker:      4*time.Hour + 40*time.Minute,
			controller:  4*time.Hour + 41*time.Minute,
		},
		"ACME-DNS legacy automatic": {
			settings:    Settings{Provider: "acmedns", Domains: []string{"api.example.com"}},
			propagation: 4*time.Hour + 15*time.Minute,
			worker:      4*time.Hour + 30*time.Minute,
			controller:  4*time.Hour + 31*time.Minute,
		},
		"ACME-DNS manual maximum and SAN cap": {
			settings:    Settings{Provider: "acmedns", PropagationTimeoutMinutes: 1440, Domains: []string{"1.example.com", "2.example.com", "3.example.com", "4.example.com", "5.example.com", "6.example.com", "7.example.com", "8.example.com", "9.example.com", "10.example.com", "ignored.example.com"}},
			propagation: 24 * time.Hour,
			worker:      25*time.Hour + 45*time.Minute,
			controller:  25*time.Hour + 46*time.Minute,
		},
		"Cloudflare limit": {
			settings:    Settings{Provider: "cloudflare", Domains: []string{"api.example.com"}},
			propagation: 90 * time.Minute,
			worker:      105 * time.Minute,
			controller:  106 * time.Minute,
		},
		"Yandex Cloud limit": {
			settings:    Settings{Provider: "yandexcloud", Domains: []string{"api.example.com"}},
			propagation: 90 * time.Minute,
			worker:      105 * time.Minute,
			controller:  106 * time.Minute,
		},
		"Gcore limit": {
			settings:    Settings{Provider: "gcore", Domains: []string{"api.example.com"}},
			propagation: 90 * time.Minute,
			worker:      105 * time.Minute,
			controller:  106 * time.Minute,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := PropagationTimeout(test.settings); got != test.propagation {
				t.Fatalf("propagation timeout: got %v want %v", got, test.propagation)
			}
			if got := WorkerTimeout(test.settings); got != test.worker {
				t.Fatalf("worker timeout: got %v want %v", got, test.worker)
			}
			if got := ControllerTimeout(test.settings); got != test.controller {
				t.Fatalf("controller timeout: got %v want %v", got, test.controller)
			}
		})
	}
	if PropagationPollingInterval != 10*time.Second {
		t.Fatalf("polling interval changed: %v", PropagationPollingInterval)
	}
}
