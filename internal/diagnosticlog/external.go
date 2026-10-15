package diagnosticlog

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"os"
	"path/filepath"
)

// ExternalRotator is owned by one maintenance goroutine. Append writers retain
// their inode; reopen writers keep writing the renamed file until signalled.
type ExternalRotator struct {
	AppendPaths, ReopenPaths []string
	Maximum                  int64
	Reopen                   func(context.Context) error
	pending, initialized     bool
}

func (r *ExternalRotator) Check(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.Maximum < 1024 {
		return errors.New("external log limit is invalid")
	}
	var result error
	for _, path := range r.AppendPaths {
		_, err := rotateAppend(ctx, path, r.Maximum)
		result = errors.Join(result, err, compactLog(ctx, path+".1", r.Maximum))
	}
	if !r.initialized {
		r.initialized = true
		for _, path := range r.ReopenPaths {
			if _, err := os.Lstat(path + ".1"); err == nil {
				// A controller restart must retry an interrupted reopen, even if
				// Nginx still holds the only descriptor to the renamed log.
				r.pending = true
			}
		}
	}
	if !r.pending {
		for _, path := range r.ReopenPaths {
			if err := ctx.Err(); err != nil {
				return errors.Join(result, err)
			}
			changed, err := rotateRename(path, r.Maximum)
			r.pending = r.pending || changed
			result = errors.Join(result, err)
		}
	}
	if r.pending {
		if r.Reopen == nil {
			return errors.Join(result, errors.New("log reopen callback is missing"))
		}
		if err := r.Reopen(ctx); err != nil {
			return errors.Join(result, err)
		}
		r.pending = false
	}
	for _, path := range r.ReopenPaths {
		result = errors.Join(result, compactLog(ctx, path+".1", r.Maximum))
	}
	return result
}

func openRegularLog(path string, flags int) (*os.Root, *os.File, os.FileInfo, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, nil, nil, err
	}
	fail := func(err error) (*os.Root, *os.File, os.FileInfo, error) {
		root.Close()
		return nil, nil, nil, err
	}
	name := filepath.Base(path)
	info, err := root.Lstat(name)
	if err != nil {
		return fail(err)
	}
	if !info.Mode().IsRegular() {
		return fail(errors.New("log target is not a regular file"))
	}
	file, err := root.OpenFile(name, flags, 0)
	if err != nil {
		return fail(err)
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		file.Close()
		return fail(errors.Join(err, errors.New("log target changed while opening")))
	}
	return root, file, opened, nil
}

func regularOrMissing(root *os.Root, name string) error {
	info, err := root.Lstat(name)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("log archive is not a regular file")
	}
	return nil
}

func rotateAppend(ctx context.Context, path string, maximum int64) (bool, error) {
	root, file, info, err := openRegularLog(path, os.O_RDWR)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer root.Close()
	defer file.Close()
	if info.Size() <= maximum {
		return false, nil
	}
	if err := saveLogTail(ctx, root, file, info.Size(), maximum, filepath.Base(path)+".1"); err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := file.Truncate(0); err != nil {
		return false, err
	}
	return true, file.Sync()
}

func rotateRename(path string, maximum int64) (bool, error) {
	root, file, info, err := openRegularLog(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer root.Close()
	defer file.Close()
	if info.Size() <= maximum {
		return false, nil
	}
	name := filepath.Base(path)
	if err := regularOrMissing(root, name+".1"); err != nil {
		return false, err
	}
	if err := root.Rename(name, name+".1"); err != nil {
		return false, err
	}
	return true, nil
}

func compactLog(ctx context.Context, path string, maximum int64) error {
	root, file, info, err := openRegularLog(path, os.O_RDONLY)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer root.Close()
	defer file.Close()
	if info.Size() <= maximum {
		return nil
	}
	return saveLogTail(ctx, root, file, info.Size(), maximum, filepath.Base(path))
}

func saveLogTail(ctx context.Context, root *os.Root, source *os.File, size, maximum int64, destination string) error {
	if err := regularOrMissing(root, destination); err != nil {
		return err
	}
	name := ".log-tail-" + rand.Text()
	temporary, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	reader := logContextReader{ctx: ctx, reader: io.NewSectionReader(source, max(0, size-maximum), min(size, maximum))}
	_, copyErr := io.CopyBuffer(struct{ io.Writer }{temporary}, reader, make([]byte, 32<<10))
	if err := errors.Join(copyErr, temporary.Sync(), temporary.Close(), ctx.Err()); err != nil {
		return err
	}
	return root.Rename(name, destination)
}

type logContextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r logContextReader) Read(body []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(body)
}
