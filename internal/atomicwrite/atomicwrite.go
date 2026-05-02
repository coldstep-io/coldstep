// Package atomicwrite persists whole-file payloads using temp file + fsync + rename (POSIX).
package atomicwrite

import (
	"errors"
	"os"
	"path/filepath"
)

// Bytes writes data to path atomically (replace). perm is applied with Chmod when non-zero.
func Bytes(path string, data []byte, perm os.FileMode) error {
	if path == "" {
		return errors.New("atomicwrite: path is empty")
	}
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".coldstep-atomic.*.tmp")
	if err != nil {
		return err
	}
	tmpPath := f.Name()
	keepTmp := true
	defer func() {
		if keepTmp {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return err
	}
	keepTmp = false
	if perm != 0 {
		if err := os.Chmod(path, perm); err != nil {
			return err
		}
	}
	return nil
}
