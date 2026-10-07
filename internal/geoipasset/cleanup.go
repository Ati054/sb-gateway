package geoipasset

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Prune removes only our obsolete assets, never portable packs or user files.
// Configs include active/LKG routing and the bounded candidate/rollback store.
// A ten-minute publication lease covers render before candidate persistence.
func Prune(root string, configs, candidateRoots []string, live []byte, now time.Time) (int, error) {
	publication.Lock()
	defer publication.Unlock()
	keep := make(map[string]bool)
	if len(live) != 0 {
		if err := collectReferences(bytes.NewReader(live), keep); err != nil {
			return 0, err
		}
	}
	readConfig := func(path string) error {
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() || info.Size() > 32<<20 {
			return errors.New("unsafe GeoIP retention input")
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		opened, err := file.Stat()
		if err != nil || !os.SameFile(info, opened) {
			return errors.New("GeoIP retention input changed during open")
		}
		reader := &io.LimitedReader{R: file, N: (32 << 20) + 1}
		if err := collectReferences(reader, keep); err != nil {
			return err
		}
		if reader.N == 0 {
			return errors.New("GeoIP retention input exceeds the limit")
		}
		return nil
	}
	for _, path := range configs {
		if path != "" {
			if err := readConfig(path); err != nil {
				return 0, err
			}
		}
	}
	for _, path := range candidateRoots {
		if path == "" {
			continue
		}
		if err := filepath.WalkDir(path, func(path string, entry os.DirEntry, err error) error {
			if errors.Is(err, os.ErrNotExist) {
				return nil
			}
			if err != nil {
				return err
			}
			if entry.Type()&os.ModeSymlink != 0 {
				return errors.New("unsafe GeoIP retention input")
			}
			if !entry.IsDir() && entry.Name() == "xray.json" {
				return readConfig(path)
			}
			return nil
		}); err != nil {
			return 0, err
		}
	}
	entries, err := os.ReadDir(root)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, entry := range entries {
		if !namePattern.MatchString(entry.Name()) || keep[entry.Name()] {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return removed, err
		}
		if !info.Mode().IsRegular() || now.Sub(info.ModTime()) < 10*time.Minute {
			continue
		}
		if err := os.Remove(filepath.Join(root, entry.Name())); err != nil {
			return removed, err
		}
		removed++
	}
	if removed != 0 {
		err = syncDirectory(root)
	}
	return removed, err
}

func collectReferences(reader io.Reader, keep map[string]bool) error {
	decoder := json.NewDecoder(reader)
	depth, roots := 0, 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			if depth == 0 && roots == 1 {
				return nil
			}
			return io.ErrUnexpectedEOF
		}
		if err != nil {
			return err
		}
		if depth == 0 {
			if roots != 0 || token != json.Delim('{') {
				return errors.New("GeoIP retention input must be one complete JSON object")
			}
			roots++
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{', '[':
				depth++
			case '}', ']':
				depth--
			}
		}
		if reference, ok := token.(string); ok {
			if name, valid := ReferenceName(reference); valid {
				keep[name] = true
			}
		}
	}
}
