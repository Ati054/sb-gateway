package agent

import "testing"

func TestURLTestResponsivenessTradeoff(t *testing.T) {
	tests := []struct {
		name                string
		currentMS, nextMS   int
		currentBPS, nextBPS int64
		want                string
	}{
		{"screenshot", 560, 346, 14600000, 10100000, "reserve"},
		{"speed loss exceeds latency gain", 560, 500, 14600000, 10100000, ""},
		{"speed floor", 1000, 100, 1000, 649, ""},
		{"35 percent boundary", 1000, 500, 1000, 650, "reserve"},
		{"equal relative gain is insufficient", 1000, 900, 1000, 900, ""},
		{"below configured latency threshold", 1000, 951, 1000, 990, ""},
		{"unknown speed", 560, 346, 14600000, 0, ""},
		{"unchanged speed", 560, 346, 14600000, 14600000, "reserve"},
		{"slightly faster throughput", 560, 346, 14600000, 15000000, "reserve"},
		{"original path does not win back on throughput alone", 346, 560, 10100000, 14600000, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := meaningfullyBetter("active", []string{"reserve"},
				map[string]*int{"active": &test.currentMS, "reserve": &test.nextMS},
				map[string]*int64{"active": &test.currentBPS, "reserve": &test.nextBPS},
				effectivePolicySettings{speedEnabled: true, improvement: 50, speedImprovement: 25})
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}

func TestURLTestSpeedPriorityRemainsEffective(t *testing.T) {
	current, throughput, response := 560, 480, 346
	currentSpeed, throughputSpeed, responseSpeed := int64(14600000), int64(19000000), int64(10100000)
	delays := map[string]*int{"active": &current, "throughput": &throughput, "response": &response}
	speeds := map[string]*int64{"active": &currentSpeed, "throughput": &throughputSpeed, "response": &responseSpeed}
	settings := effectivePolicySettings{speedEnabled: true, improvement: 50, speedImprovement: 25}
	if got := meaningfullyBetter("active", []string{"response", "throughput"}, delays, speeds, settings); got != "throughput" {
		t.Fatal("candidate improving both configured thresholds lost priority")
	}
	settings.speedImprovement = 40
	if got := meaningfullyBetter("active", []string{"throughput", "response"}, delays, speeds, settings); got != "response" {
		t.Fatal("speed threshold is ineffective or fallback ignores responsiveness")
	}
}

func TestURLTestSpeedOnlySwitchBoundsLatencyAndPreventsReverse(t *testing.T) {
	tests := []struct {
		name                      string
		activeDelay, reserveDelay int
		activeSpeed, reserveSpeed int64
		want                      string
	}{
		{"reported slow active", 485, 445, 5_500_000, 18_400_000, "reserve"},
		{"equal latency and exactly 25 percent faster", 500, 500, 8_000_000, 10_000_000, "reserve"},
		{"50 ms worse", 500, 550, 8_000_000, 10_000_000, "reserve"},
		{"more than 50 ms worse", 500, 551, 8_000_000, 16_000_000, ""},
		{"insufficient speed gain", 500, 500, 8_000_000, 9_999_999, ""},
		{"speed gain loses responsive throughput", 100, 150, 8_000_000, 10_000_000, ""},
		{"reverse speed gain cannot undo latency tradeoff", 346, 560, 10_100_000, 14_600_000, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := meaningfullyBetter("active", []string{"reserve"},
				map[string]*int{"active": &test.activeDelay, "reserve": &test.reserveDelay},
				map[string]*int64{"active": &test.activeSpeed, "reserve": &test.reserveSpeed},
				effectivePolicySettings{speedEnabled: true, improvement: 50, speedImprovement: 25})
			if got != test.want {
				t.Fatalf("got %q, want %q", got, test.want)
			}
		})
	}
}
