package controlplane

import (
	"context"
	"log"
	"time"

	"github.com/sb-gateway/sb-gateway/internal/diagnosticlog"
)

const externalLogMaximum = 4 << 20

func (server *Server) diagnosticLogRotator() *diagnosticlog.ExternalRotator {
	options := server.opts.Runtime
	return &diagnosticlog.ExternalRotator{
		Maximum: externalLogMaximum,
		AppendPaths: []string{
			diagnosticLogPath(options.XrayErrorLog, "/logs/xray-error.log"),
			diagnosticLogPath(options.XrayProcessLog, "/logs/xray-process.log"),
		},
		ReopenPaths: []string{
			diagnosticLogPath(options.NginxErrorLog, "/logs/nginx/error.log"),
			diagnosticLogPath(options.NginxPublicErrorLog, "/logs/nginx/public-error.log"),
		},
		Reopen: func(ctx context.Context) error {
			if native, ok := server.runtime.(*nativeRuntime); ok && native.nginxCommand != nil {
				return native.nginxCommand(ctx, "-s", "reopen", "-c", options.NginxConfig, "-p", "/")
			}
			return runValidationCommand(ctx, options.NginxBinary, "-s", "reopen", "-c", options.NginxConfig, "-p", "/")
		},
	}
}

func diagnosticLogPath(path, fallback string) string {
	if path == "" {
		return fallback
	}
	return path
}

func (server *Server) runDiagnosticLogMaintenance(ctx context.Context) {
	rotator := server.diagnosticLogRotator()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		check, cancel := context.WithTimeout(ctx, 5*time.Second)
		err := rotator.Check(check)
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("control-plane: diagnostic log maintenance: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
