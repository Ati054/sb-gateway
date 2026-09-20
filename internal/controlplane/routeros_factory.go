package controlplane

import (
	"crypto/x509"
	"errors"
	"net/url"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/routeros"
)

type routerOSStack struct {
	REST           *routeros.Client
	SSH            *routeros.SSHTransport
	BackupPassword string
}

func (server *Server) newRouterOSStack(config map[string]any) (routerOSStack, error) {
	rest, parsed, err := server.newRouterOSRESTClient(config)
	if err != nil {
		return routerOSStack{}, err
	}
	routerConfig, ok := config["routeros"].(map[string]any)
	if !ok {
		rest.CloseIdleConnections()
		return routerOSStack{}, errors.New("RouterOS configuration is missing")
	}
	backupPassword, err := server.readConfiguredSecret(routerConfig, "backup_password_secret_ref")
	if err != nil {
		rest.CloseIdleConnections()
		return routerOSStack{}, err
	}
	username, err := server.readConfiguredSecret(routerConfig, "username_secret_ref")
	if err != nil {
		rest.CloseIdleConnections()
		return routerOSStack{}, err
	}
	password, err := server.readConfiguredSecret(routerConfig, "password_secret_ref")
	if err != nil {
		rest.CloseIdleConnections()
		return routerOSStack{}, err
	}
	sshPort, ok := jsonInteger(routerConfig["ssh_port"])
	if !ok {
		rest.CloseIdleConnections()
		return routerOSStack{}, errors.New("RouterOS SSH port is invalid")
	}
	knownHosts, err := server.secrets.path("routeros/ssh_known_hosts")
	if err != nil {
		rest.CloseIdleConnections()
		return routerOSStack{}, err
	}
	sshTransport, err := routeros.NewSSHTransport(routeros.SSHOptions{
		Host: parsed.Hostname(), Port: sshPort, Username: username, Password: password,
		KnownHostsPath: knownHosts, Timeout: 30 * time.Second,
	})
	if err != nil {
		rest.CloseIdleConnections()
		return routerOSStack{}, err
	}
	return routerOSStack{REST: rest, SSH: sshTransport, BackupPassword: backupPassword}, nil
}

func (server *Server) newRouterOSRESTClient(config map[string]any) (*routeros.Client, *url.URL, error) {
	routerConfig, ok := config["routeros"].(map[string]any)
	if !ok {
		return nil, nil, errors.New("RouterOS configuration is missing")
	}
	baseURL, _ := routerConfig["base_url"].(string)
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Hostname() == "" {
		return nil, nil, errors.New("RouterOS HTTPS endpoint is unavailable")
	}
	username, err := server.readConfiguredSecret(routerConfig, "username_secret_ref")
	if err != nil {
		return nil, nil, err
	}
	password, err := server.readConfiguredSecret(routerConfig, "password_secret_ref")
	if err != nil {
		return nil, nil, err
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if reference, _ := routerConfig["ca_certificate_secret_ref"].(string); reference != "" {
		pem, readErr := server.secrets.read(reference, true)
		if readErr != nil {
			return nil, nil, errors.New("RouterOS CA certificate is unavailable")
		}
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, nil, errors.New("RouterOS CA certificate is invalid")
		}
	}
	rest, err := routeros.NewClient(routeros.Options{
		BaseURL: baseURL, Username: username, Password: password, RootCAs: pool,
		Timeout: 15 * time.Second, ActionTimeout: 2 * time.Minute,
	})
	if err != nil {
		return nil, nil, err
	}
	return rest, parsed, nil
}

func (server *Server) readConfiguredSecret(config map[string]any, field string) (string, error) {
	reference, _ := config[field].(string)
	if reference == "" {
		return "", errors.New("RouterOS secret reference is missing")
	}
	value, err := server.secrets.read(reference, true)
	if err != nil {
		return "", errors.New("RouterOS credential is unavailable")
	}
	return value, nil
}
