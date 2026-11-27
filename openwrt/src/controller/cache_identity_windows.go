//go:build windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func cacheFileIdentity(file *os.File, info os.FileInfo) (string, error) {
	var data syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(syscall.Handle(file.Fd()), &data); err != nil {
		return "", err
	}
	return fmt.Sprintf("%08x:%08x%08x", data.VolumeSerialNumber, data.FileIndexHigh, data.FileIndexLow), nil
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
