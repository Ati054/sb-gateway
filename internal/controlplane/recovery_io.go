package controlplane

import (
	"io"
	"os"

	"github.com/sb-gateway/sb-gateway/internal/storagebudget"
)

const recoveryFileWindow = 8 << 20
const recoverySpaceQuantum = 1 << 20

// Bound dirty-page accumulation as well as Go buffers. Sync errors propagate;
// cache eviction is a best-effort hint on platforms that support it.
type recoveryFileWriter struct {
	file        *os.File
	output      io.Writer
	root        string
	spaceCredit int
	pending     int
}

func newRecoveryFileWriter(file *os.File, root string, extra io.Writer) *recoveryFileWriter {
	var output io.Writer = file
	if extra != nil {
		output = io.MultiWriter(file, extra)
	}
	return &recoveryFileWriter{file: file, root: root, output: output}
}

func (writer *recoveryFileWriter) Write(body []byte) (int, error) {
	if len(body) > writer.spaceCredit {
		credit := max(recoverySpaceQuantum, len(body))
		if err := storagebudget.Check(writer.root, uint64(recoveryStorageHeadroom+credit)); err != nil {
			return 0, err
		}
		writer.spaceCredit = credit
	}
	written := 0
	for len(body) > 0 {
		length := min(len(body), recoveryFileWindow-writer.pending)
		n, err := writer.output.Write(body[:length])
		written += n
		writer.spaceCredit -= n
		writer.pending += n
		if err != nil {
			return written, err
		}
		if n != length {
			return written, io.ErrShortWrite
		}
		body = body[n:]
		if writer.pending == recoveryFileWindow {
			if err = writer.file.Sync(); err != nil {
				return written, err
			}
			dropRecoveryFileCache(writer.file)
			writer.pending = 0
		}
	}
	return written, nil
}

type recoveryFileReader struct {
	file              *os.File
	position, advised int64
	large             bool
}

func newRecoveryFileReader(file *os.File) *recoveryFileReader {
	reader := &recoveryFileReader{file: file}
	info, err := file.Stat()
	reader.large = err == nil && info.Size() >= recoveryFileWindow
	if position, err := file.Seek(0, io.SeekCurrent); err == nil {
		reader.position = position
		page := int64(os.Getpagesize())
		reader.advised = ((position + page - 1) / page) * page
	}
	return reader
}
func (reader *recoveryFileReader) Read(body []byte) (int, error) {
	n, err := reader.file.Read(body)
	reader.position += int64(n)
	if reader.large && reader.position-reader.advised >= recoveryFileWindow {
		page := int64(os.Getpagesize())
		end := (reader.position / page) * page
		dropRecoveryFileRange(reader.file, reader.advised, end-reader.advised)
		reader.advised = end
	}
	return n, err
}
