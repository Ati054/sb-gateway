package controlplane

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultXrayLogLines = 200
	maximumXrayLogLines = 500
	maximumXrayLogBytes = 256 << 10
)

func (server *Server) xrayLogs(response http.ResponseWriter, request *http.Request) {
	if _, ok := server.requireSession(response, request); !ok {
		return
	}
	source := strings.ToLower(strings.TrimSpace(request.URL.Query().Get("source")))
	path := server.opts.Runtime.XrayErrorLog
	if path == "" {
		path = "/logs/xray-error.log"
	}
	if source == "" {
		source = "error"
	}
	switch source {
	case "error":
	case "process":
		path = server.opts.Runtime.XrayProcessLog
		if path == "" {
			path = "/logs/xray-process.log"
		}
	default:
		server.writeErrorResponse(response, request, http.StatusUnprocessableEntity, "invalid_log_source", "Log source must be error or process.")
		return
	}
	lineLimit := defaultXrayLogLines
	if requested, err := strconv.Atoi(request.URL.Query().Get("lines")); err == nil && requested > 0 {
		lineLimit = requested
	}
	if lineLimit > maximumXrayLogLines {
		lineLimit = maximumXrayLogLines
	}
	lines, info, truncated, err := readLogTail(path, lineLimit, maximumXrayLogBytes)
	logging := server.xrayLoggingStatus()
	if errors.Is(err, os.ErrNotExist) {
		server.writeJSON(response, http.StatusOK, map[string]any{
			"source": source, "available": false, "lines": []string{},
			"size_bytes": 0, "updated_at": nil, "truncated": false,
			"logging": logging,
		})
		return
	}
	if err != nil {
		server.internalStateError(response, request, err)
		return
	}
	server.writeJSON(response, http.StatusOK, map[string]any{
		"source": source, "available": true, "lines": lines,
		"size_bytes": info.Size(), "updated_at": info.ModTime().UTC().Format(time.RFC3339Nano),
		"truncated": truncated, "logging": logging,
	})
}

func (server *Server) xrayLoggingStatus() map[string]any {
	status := map[string]any{"configured_level": "warning", "effective_level": "warning"}
	if draft, err := server.getDraft(); err == nil {
		status["configured_level"] = configuredXrayLogLevel(draft)
	}
	if active, err := server.repository.loadActive(); err == nil {
		status["effective_level"] = configuredXrayLogLevel(active)
	}
	if state, err := server.repository.auxiliary(xrayLoggingStateName); err == nil {
		if expires := subscriptionText(state["debug_expires_at"]); expires != "" && status["effective_level"] == "debug" {
			status["debug_expires_at"] = expires
		}
	}
	return status
}

func readLogTail(path string, lineLimit, byteLimit int) ([]string, os.FileInfo, bool, error) {
	linkInfo, err := os.Lstat(path)
	if err != nil {
		return nil, nil, false, err
	}
	if !linkInfo.Mode().IsRegular() || linkInfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, false, errors.New("log path must be a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, nil, false, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(linkInfo, info) {
		return nil, nil, false, errors.New("log path must be a regular file")
	}
	if lineLimit < 1 {
		lineLimit = 1
	}
	if byteLimit < 1 {
		byteLimit = maximumXrayLogBytes
	}
	start := info.Size() - int64(byteLimit)
	truncated := start > 0
	if start < 0 {
		start = 0
	}
	if _, err := file.Seek(start, io.SeekStart); err != nil {
		return nil, nil, false, err
	}
	body, err := io.ReadAll(io.LimitReader(file, int64(byteLimit)))
	if err != nil {
		return nil, nil, false, err
	}
	if start > 0 {
		if newline := bytes.IndexByte(body, '\n'); newline >= 0 {
			body = body[newline+1:]
		} else {
			body = nil
		}
	}
	text := strings.TrimRight(string(body), "\r\n")
	if text == "" {
		return []string{}, info, truncated, nil
	}
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	if len(lines) > lineLimit {
		lines = lines[len(lines)-lineLimit:]
		truncated = true
	}
	return lines, info, truncated, nil
}
