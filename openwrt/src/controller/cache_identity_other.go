//go:build !linux && !windows

package main

import (
	"fmt"
	"os"
)

func cacheFileIdentity(file *os.File, info os.FileInfo) (string, error) {
	if _, err := file.Stat(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%s:%d:%d", info.Name(), info.Size(), info.ModTime().UnixNano()), nil
}

func validateCacheStateDirectory(path string, info os.FileInfo) error {
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache state directory is not a regular directory")
	}
	return nil
}

func validateCacheStateFile(info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("cache state path is not a regular file")
	}
	return nil
}
