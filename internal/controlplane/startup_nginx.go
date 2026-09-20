package controlplane

import (
	"errors"
	"os"
	"strings"
)

const (
	nginxSchema2Header = "# sb-gateway-nginx-schema: 2"
	nginxSchema3Header = "# sb-gateway-nginx-schema: 3"
	nginxInternalStart = `    server {
        listen 9080;
        server_name _;
`
	nginxInternalTail = "        location / { return 404; }\n"
	nginxTrafficReady = `        location = /traffic-ready {
            proxy_http_version 1.1;
            proxy_set_header Host 127.0.0.1;
            proxy_pass_request_body off;
            proxy_set_header Content-Length "";
            proxy_pass http://127.0.0.1:8080/api/health/traffic-ready;
        }
`
)

// EnsureStartupNginxTrafficReadiness upgrades the exact schema-2 runtime that
// predates route-aware readiness. It preserves every public listener and only
// adds the private RouterOS probe before the internal server's deny-all tail.
func EnsureStartupNginxTrafficReadiness(path string) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("startup Nginx config is not a regular file")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	text := string(body)
	if strings.Count(text, nginxInternalStart) != 1 {
		return false, errors.New("startup Nginx internal server is missing or ambiguous")
	}
	internalStart := strings.Index(text, nginxInternalStart)
	internalTailOffset := strings.Index(text[internalStart:], nginxInternalTail)
	if internalTailOffset < 0 {
		return false, errors.New("startup Nginx internal server tail is missing")
	}
	internalTail := internalStart + internalTailOffset
	internal := text[internalStart:internalTail]
	if strings.HasPrefix(text, nginxSchema3Header+"\n") {
		if strings.Count(internal, "location = /traffic-ready") != 1 {
			return false, errors.New("schema-3 Nginx traffic readiness is missing or ambiguous")
		}
		return false, nil
	}
	if !strings.HasPrefix(text, nginxSchema2Header+"\n") {
		return false, errors.New("startup Nginx schema is unsupported")
	}
	if strings.Count(internal, "location = /traffic-ready") > 1 {
		return false, errors.New("schema-2 Nginx internal server is ambiguous")
	}
	text = strings.Replace(text, nginxSchema2Header, nginxSchema3Header, 1)
	if !strings.Contains(internal, "location = /traffic-ready") {
		text = text[:internalTail] + nginxTrafficReady + "\n" + text[internalTail:]
	}
	if err := writeAtomic(path, []byte(text), 0o600, false); err != nil {
		return false, err
	}
	return true, nil
}
