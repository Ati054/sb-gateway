package controlplane

import (
	"crypto/x509"
	"net/http"
	"strings"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

func (server *Server) provisionRouterOSCredentials(response http.ResponseWriter, request *http.Request) {
	payload, ok := server.requireCSRF(response, request)
	if !ok {
		return
	}
	body, ok := server.readObject(response, request, maxRequestBytes)
	if !ok {
		return
	}
	baseURL, username, password := strings.TrimSpace(text(body["base_url"])), text(body["username"]), text(body["password"])
	if username == "" || len(username) > 64 {
		server.writeErrorResponse(response, request, http.StatusBadRequest, "invalid_routeros_username", "RouterOS username is invalid.")
		return
	}
	if len(password) < 16 {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "weak_routeros_secret", "RouterOS REST password must be at least 16 characters.")
		return
	}
	if !server.secrets.exists("routeros/backup-password") {
		server.writeErrorResponse(response, request, http.StatusConflict, "panel_password_required", "Sign in again before provisioning RouterOS backup protection.")
		return
	}
	sshPort := 22
	if raw, exists := body["ssh_port"]; exists {
		var valid bool
		sshPort, valid = jsonInteger(raw)
		if !valid || sshPort < 1 || sshPort > 65535 {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_routeros_ssh_port", "RouterOS SSH port must be an integer from 1 to 65535.")
			return
		}
	}
	var caPool *x509.CertPool
	caCertificate, caSupplied := body["ca_certificate"].(string)
	if caSupplied {
		caPool = x509.NewCertPool()
		if !strings.Contains(caCertificate, "BEGIN CERTIFICATE") || !caPool.AppendCertsFromPEM([]byte(caCertificate)) {
			server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_routeros_ca", "RouterOS CA certificate is invalid.")
			return
		}
	}
	client, err := routeros.NewClient(routeros.Options{BaseURL: baseURL, Username: username, Password: password, RootCAs: caPool, Timeout: 15 * time.Second})
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_routeros_url", "RouterOS REST base URL must be a valid HTTPS origin with the explicit www-ssl port.")
		return
	}
	client.CloseIdleConnections()

	server.configMu.Lock()
	defer server.configMu.Unlock()
	config, err := server.getDraft()
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	router := objectAt(config, "routeros")
	router["base_url"] = strings.TrimSuffix(baseURL, "/")
	router["ssh_port"] = sshPort
	router["username_secret_ref"] = "routeros/username"
	router["password_secret_ref"] = "routeros/password"
	router["backup_password_secret_ref"] = "routeros/backup-password"
	objectAt(config, "system")["deployment_ready"] = false
	pending := []pendingEntitySecret{
		{reference: "routeros/username", value: username, overwrite: true},
		{reference: "routeros/password", value: password, overwrite: true},
	}
	if caSupplied {
		router["ca_certificate_secret_ref"] = "routeros/ca.pem"
		pending = append(pending, pendingEntitySecret{reference: "routeros/ca.pem", value: caCertificate, overwrite: true})
	}
	config["routeros"] = router
	validation := validateCurrentConfig(config)
	if !validation.Valid {
		server.writeValidationError(response, request, validation)
		return
	}
	undo, err := server.writeEntitySecrets(pending)
	if err != nil {
		server.writeErrorResponse(response, request, http.StatusInternalServerError, "secret_store_failed", "RouterOS credentials could not be stored.")
		return
	}
	revision, err := server.repository.saveDraft(config)
	if err != nil {
		_ = undo()
		server.internalStateError(response, request, err)
		return
	}
	server.rememberValidation(validation)
	server.audit(request, text(payload["sub"]), "routeros.credentials.provision", "ok", map[string]any{
		"base_url": strings.TrimSuffix(baseURL, "/"), "ssh_port": sshPort,
	})
	server.writeJSON(response, http.StatusOK, map[string]any{
		"ok": true, "base_url": strings.TrimSuffix(baseURL, "/"), "credentials_provisioned": true, "revision": revision,
	})
}
