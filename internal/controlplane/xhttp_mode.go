package controlplane

import "strings"

// normalizeXHTTPModeCompatibility keeps persisted settings aligned with the
// parameters Xray can actually activate. Header/cookie uplink payloads and GET
// uploads are packet-up-only in Xray 26.9.9.
func normalizeXHTTPModeCompatibility(config map[string]any) {
	transports, _ := config["transports"].([]any)
	for _, raw := range transports {
		transport, _ := raw.(map[string]any)
		kind := text(transport["kind"])
		if kind != "xhttp" && kind != "xhttp-reality" {
			continue
		}
		mode := strings.ToLower(strings.TrimSpace(text(transport["mode"])))
		if mode == "" {
			if kind == "xhttp-reality" {
				mode = "auto"
			} else {
				mode = "packet-up"
			}
			transport["mode"] = mode
		}
		if mode == "packet-up" {
			continue
		}
		placement := strings.ToLower(strings.TrimSpace(text(transport["uplink_data_placement"])))
		if placement == "header" || placement == "cookie" {
			transport["uplink_data_placement"] = "auto"
		}
		if strings.EqualFold(strings.TrimSpace(text(transport["uplink_http_method"])), "GET") {
			transport["uplink_http_method"] = "POST"
		}
	}
}
