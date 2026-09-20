package diagnosticlog

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
)

// Writer keeps one bounded current diagnostic log and one previous segment.
// Rotation is intentionally local and dependency-free so logging can never
// become a reason for the appliance to stop.
type Writer struct {
	mu      sync.Mutex
	path    string
	maximum int64
	file    *os.File
	written int64
}

func Open(path string, maximum int64) (*Writer, error) {
	if path == "" || maximum < 1024 {
		return nil, errors.New("diagnostic log path or limit is invalid")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	return &Writer{path: path, maximum: maximum, file: file, written: info.Size()}, nil
}

func (writer *Writer) Write(body []byte) (int, error) {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.file == nil {
		return 0, os.ErrClosed
	}
	if writer.written > 0 && writer.written+int64(len(body)) > writer.maximum {
		if err := writer.rotateLocked(); err != nil {
			return 0, err
		}
	}
	written, err := writer.file.Write(body)
	writer.written += int64(written)
	return written, err
}

func (writer *Writer) Close() error {
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.file == nil {
		return nil
	}
	err := writer.file.Close()
	writer.file = nil
	return err
}

func (writer *Writer) rotateLocked() error {
	if err := writer.file.Close(); err != nil {
		return err
	}
	previous := writer.path + ".1"
	if err := os.Remove(previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Rename(writer.path, previous); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(writer.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	writer.file = file
	writer.written = 0
	return nil
}
