package diagnosticlog

import (
	"bytes"
	"io"
)

// ConsoleWriter leaves repetitive route probes in the persistent diagnostic
// log while keeping actual switches and other failures visible in RouterOS.
// The caller must also write the original line to the persistent log.
type ConsoleWriter struct {
	Output io.Writer
}

func (writer ConsoleWriter) Write(body []byte) (int, error) {
	if bytes.Contains(body, []byte("agent: route-health ")) &&
		(bytes.Contains(body, []byte(`"event":"probe-failed"`)) ||
			bytes.Contains(body, []byte(`"event":"probe-recovered"`)) ||
			bytes.Contains(body, []byte(`"event":"probe-suppressed"`))) {
		return len(body), nil
	}
	return writer.Output.Write(body)
}
