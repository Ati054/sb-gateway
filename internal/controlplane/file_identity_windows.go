package controlplane

import "os"

func statFileIdentity(path string) (os.FileInfo, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	// Path-based Stat resolves Windows file IDs lazily, after a cached path may
	// already refer to a replacement. Handle-based Stat captures the ID now.
	return file.Stat()
}
