package controlplane

import "testing"

func TestNormalizeXHTTPModeCompatibility(t *testing.T) {
	auto := map[string]any{
		"kind": "xhttp-reality", "mode": "auto",
		"uplink_data_placement": "header", "uplink_http_method": "GET",
	}
	packet := map[string]any{
		"kind": "xhttp", "mode": "packet-up",
		"uplink_data_placement": "header", "uplink_http_method": "GET",
	}
	config := map[string]any{"transports": []any{auto, packet}}

	normalizeXHTTPModeCompatibility(config)

	if auto["uplink_data_placement"] != "auto" || auto["uplink_http_method"] != "POST" {
		t.Fatalf("auto XHTTP settings were not normalized: %#v", auto)
	}
	if packet["uplink_data_placement"] != "header" || packet["uplink_http_method"] != "GET" {
		t.Fatalf("packet-up settings were unexpectedly changed: %#v", packet)
	}
}
