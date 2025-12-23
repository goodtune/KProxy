package storage

import "os"

// EnsureDir ensures a directory exists with default permissions.
func EnsureDir(path string) error {
	return os.MkdirAll(path, 0755)
}
