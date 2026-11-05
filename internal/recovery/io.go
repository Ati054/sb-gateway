package recovery

import (
	"io"
	"os"

	"github.com/sb-gateway/sb-gateway/internal/storagebudget"
)

const restoreCopyBuffer = 64 << 10
const restoreFileWindow = 8 << 20
const restoreSpaceQuantum = 1 << 20

// A copy owns its temporary output. Sync/drop only consumed complete windows;
// no global cache flush or shared input eviction is performed.
type restoreFileWriter struct {
	file            *os.File
	output          io.Writer
	root            string
	credit, pending int
	offset          int64
	checkSpace      func(string, uint64) error
	syncFile        func() error
	dropRange       func(*os.File, int64, int64)
}

func newRestoreFileWriter(file *os.File, root string, digest io.Writer) *restoreFileWriter {
	var output io.Writer = file
	if digest != nil {
		output = io.MultiWriter(file, digest)
	}
	return &restoreFileWriter{file: file, root: root, output: output, checkSpace: storagebudget.Check, syncFile: file.Sync, dropRange: dropRestoreFileRange}
}
func (writer *restoreFileWriter) Write(body []byte) (int, error) {
	written := 0
	for len(body) > 0 {
		if writer.credit == 0 {
			if err := writer.checkSpace(writer.root, restoreStorageHeadroom+restoreStorageOverhead+restoreSpaceQuantum); err != nil {
				return written, err
			}
			writer.credit = restoreSpaceQuantum
		}
		length := min(len(body), writer.credit, restoreFileWindow-writer.pending)
		n, err := writer.output.Write(body[:length])
		written += n
		writer.credit -= n
		writer.pending += n
		if err != nil {
			return written, err
		}
		if n != length {
			return written, io.ErrShortWrite
		}
		body = body[n:]
		if writer.pending == restoreFileWindow {
			if err := writer.syncFile(); err != nil {
				return written, err
			}
			writer.dropRange(writer.file, writer.offset, restoreFileWindow)
			writer.offset += restoreFileWindow
			writer.pending = 0
		}
	}
	return written, nil
}

type restoreFileReader struct {
	file              *os.File
	position, advised int64
	large             bool
	dropRange         func(*os.File, int64, int64)
}

func newRestoreFileReader(file *os.File) *restoreFileReader {
	reader := &restoreFileReader{file: file, dropRange: dropRestoreFileRange}
	info, err := file.Stat()
	reader.large = err == nil && info.Size() >= restoreFileWindow
	if position, err := file.Seek(0, io.SeekCurrent); err == nil {
		reader.position = position
		page := int64(os.Getpagesize())
		reader.advised = ((position + page - 1) / page) * page
	}
	return reader
}
func (reader *restoreFileReader) Read(body []byte) (int, error) {
	n, err := reader.file.Read(body)
	reader.position += int64(n)
	if reader.large && reader.position-reader.advised >= restoreFileWindow {
		page := int64(os.Getpagesize())
		end := (reader.position / page) * page
		reader.dropRange(reader.file, reader.advised, end-reader.advised)
		reader.advised = end
	}
	return n, err
}
