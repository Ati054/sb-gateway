package controlplane

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultSystemLogLines = 200
	maximumSystemLogLines = 500
	maximumSystemLogBytes = 256 << 10
)

func (server *Server) systemLogs(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	source := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("source")))
	path := server.opts.Runtime.ControlPlaneLog
	filterLifecycle := false
	switch source {
	case "system":
	case "nginx":
		path = server.opts.Runtime.NginxErrorLog
	case "lifecycle":
		filterLifecycle = true
	default:
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_log_source", "Log source must be system, nginx or lifecycle.")
		return
	}
	lineLimit := defaultSystemLogLines
	if requested, err := strconv.Atoi(request.URL.Query().Get("lines")); err == nil && requested > 0 {
		lineLimit = min(requested, maximumSystemLogLines)
	}
	readLimit := lineLimit
	if filterLifecycle {
		readLimit = maximumSystemLogLines
	}
	lines, info, truncated, err := readLogTail(path, readLimit, maximumSystemLogBytes)
	if errors.Is(err, os.ErrNotExist) {
		server.writeJSON(response, http.StatusOK, map[string]any{
			"source": source, "available": false, "lines": []string{},
			"size_bytes": 0, "updated_at": nil, "truncated": false,
		})
		return
	}
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	if filterLifecycle {
		filtered := make([]string, 0, len(lines))
		for _, line := range lines {
			lower := strings.ToLower(line)
			if strings.Contains(lower, "image update") || strings.Contains(lower, "lifecycle") || strings.Contains(lower, "recovery archive") {
				filtered = append(filtered, line)
			}
		}
		if len(filtered) > lineLimit {
			filtered = filtered[len(filtered)-lineLimit:]
			truncated = true
		}
		lines = filtered
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"source": source, "available": true, "lines": lines,
		"size_bytes": info.Size(), "updated_at": info.ModTime().UTC().Format(time.RFC3339Nano),
		"truncated": truncated,
	})
}
