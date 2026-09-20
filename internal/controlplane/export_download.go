package controlplane

import (
	"archive/zip"
	"bytes"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

const maxClientExportBytes = 8 << 20

func (server *Server) downloadRemoteUserExports(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	password, _ := body["password"].(string)
	encoded, err := server.secrets.read("admin-password-hash", false)
	if err != nil || encoded == "" || !verifyPassword(password, encoded) {
		server.writeErrorResponse(response, request, http.StatusForbidden, "reauthentication_failed", "Administrator password confirmation failed.")
		return
	}
	userID := request.PathValue("user")
	if !entityIDPattern.MatchString(userID) {
		server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "The requested object does not exist.")
		return
	}
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	config = server.withRouterOSLiveNetworks(config)
	user := entityFromConfig(config, "remote_users", userID, true)
	if user == nil {
		server.writeErrorResponse(response, request, http.StatusNotFound, "entity_not_found", "Enabled remote user was not found.")
		return
	}
	nodes, err := server.buildClientProfileNodes(config, user)
	if err != nil || len(nodes) == 0 {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "profile_export_failed", "Client profiles cannot be generated until all active transports are provisioned.")
		return
	}
	archive, files, err := buildClientExportArchive(config, user, nodes)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "profile_export_failed", "Client profiles could not be generated.")
		return
	}
	server.audit(request, fmt.Sprint(payload["sub"]), "remote_users.export", "ok", map[string]any{"id": userID, "files": stringAnySlice(files)})
	response.Header().Set("Content-Type", "application/zip")
	response.Header().Set("Content-Disposition", `attachment; filename="sb-gateway-`+userID+`-profiles.zip"`)
	response.Header().Set("Content-Length", fmt.Sprint(len(archive)))
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(archive)
}

func buildClientExportArchive(config, user map[string]any, nodes []clientProfileNode) ([]byte, []string, error) {
	files := map[string][]byte{}
	combinedXray, err := buildCombinedXrayProfile(config, user, nodes)
	if err != nil {
		return nil, nil, err
	}
	combinedMihomo, err := buildMihomoProfile(config, user, nodes)
	if err != nil {
		return nil, nil, err
	}
	files["client-xray.json"] = combinedXray
	files["client-mihomo.yaml"] = combinedMihomo
	links := make([]string, 0, len(nodes))
	for _, node := range nodes {
		individual, buildErr := buildCombinedXrayProfile(config, user, []clientProfileNode{node})
		if buildErr != nil {
			return nil, nil, buildErr
		}
		files[node.xrayFilename] = individual
		files[node.linkFilename] = []byte(node.link + "\n")
		links = append(links, node.link)
	}
	files["subscription-links.txt"] = []byte(strings.Join(links, "\n") + "\n")
	files["README.txt"] = []byte("SB Gateway client profiles for " + text(user["id"]) + "\n\nUse TUN/VPN mode. These files contain credentials; store them securely.\n")
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Store}
		header.SetMode(0o600)
		entry, createErr := writer.CreateHeader(header)
		if createErr != nil {
			_ = writer.Close()
			return nil, nil, createErr
		}
		if _, createErr = entry.Write(files[name]); createErr != nil {
			_ = writer.Close()
			return nil, nil, createErr
		}
		if output.Len() > maxClientExportBytes {
			_ = writer.Close()
			return nil, nil, fmt.Errorf("client export exceeds %d bytes", maxClientExportBytes)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, nil, err
	}
	if output.Len() > maxClientExportBytes {
		return nil, nil, fmt.Errorf("client export exceeds %d bytes", maxClientExportBytes)
	}
	return output.Bytes(), names, nil
}
