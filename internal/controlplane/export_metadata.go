package controlplane

import "net/http"

var transportExportFiles = map[string][]string{
	"ws":            {"xray-ws.json", "vless-ws.txt"},
	"grpc":          {"xray-grpc.json", "vless-grpc.txt"},
	"httpupgrade":   {"xray-httpupgrade.json", "vless-httpupgrade.txt"},
	"xhttp":         {"xray-xhttp.json", "vless-xhttp.txt"},
	"reality":       {"xray-direct-reality.json", "vless-direct-reality.txt"},
	"reality-grpc":  {"xray-grpc-reality.json", "vless-grpc-reality.txt"},
	"grpc-tls":      {"xray-grpc-tls-pin.json", "vless-grpc-tls-pin.txt"},
	"xhttp-reality": {"xray-xhttp-reality.json", "vless-xhttp-reality.txt"},
	"hysteria2":     {"xray-hysteria2.json", "hysteria2.txt"},
}

func (server *Server) remoteUserExportMetadata(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	userID := request.PathValue("user")
	var user map[string]any
	for _, item := range objects(config["remote_users"]) {
		if text(item["id"]) == userID {
			user = item
			break
		}
	}
	if user == nil {
		server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "The requested object does not exist.")
		return
	}
	excluded := make(map[string]bool)
	for _, id := range stringsOf(user["excluded_transports"]) {
		excluded[id] = true
	}
	profiles := make([]any, 0)
	for _, transport := range objects(config["transports"]) {
		id, kind := text(transport["id"]), text(transport["kind"])
		if !boolDefault(transport, "enabled", true) || excluded[id] {
			continue
		}
		files := append([]string(nil), transportExportFiles[kind]...)
		secretReference := text(user["uuid_secret_ref"])
		if kind == "hysteria2" {
			secretReference = text(user["hysteria2_password_secret_ref"])
		}
		profiles = append(profiles, map[string]any{
			"transport_id": id, "kind": kind, "role": "enabled",
			"files": stringAnySlice(files), "ready": secretReference != "" && server.secrets.exists(secretReference),
		})
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"user_id": userID, "directory": "client-exports/" + userID + "/", "profiles": profiles,
		"readme":           map[string]any{"requires_tun_vpn_mode": true, "transport_selection": "all-enabled", "automatic_updates": true},
		"contains_secrets": true, "download_requires_reauthentication": true,
	})
}
