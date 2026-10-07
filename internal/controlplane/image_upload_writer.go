package controlplane

import (
	"log"
	"os"
)

const imageUploadCacheWindow = int64(8 << 20)

type imageUploadWriter struct {
	file       *os.File
	written    int64
	flushed    int64
	flushRange func(int64, int64) error
}

// A streamed archive must not retain its entire dirty page cache alongside
// Xray and the API in the same small RouterOS memory cgroup.
func newImageUploadWriter(file *os.File) *imageUploadWriter {
	adviceLogged := false
	return &imageUploadWriter{file: file, flushRange: func(offset, length int64) error {
		if err := file.Sync(); err != nil {
			return err
		}
		if err := discardImageUploadCache(file, offset, length); err != nil && !adviceLogged {
			log.Printf("lifecycle image upload page-cache advice unavailable: %v", err)
			adviceLogged = true
		}
		return nil
	}}
}

func (writer *imageUploadWriter) Write(body []byte) (int, error) {
	count, err := writer.file.Write(body)
	writer.written += int64(count)
	if err != nil {
		return count, err
	}
	if writer.written-writer.flushed >= imageUploadCacheWindow {
		return count, writer.Flush()
	}
	return count, nil
}

func (writer *imageUploadWriter) Flush() error {
	if writer.written == writer.flushed {
		return nil
	}
	if err := writer.flushRange(writer.flushed, writer.written-writer.flushed); err != nil {
		return err
	}
	writer.flushed = writer.written
	return nil
}
