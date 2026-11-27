//go:build linux

package main

import (
	"fmt"
	"os"
	"syscall"
)

func cacheFileIdentity(file *os.File, info os.FileInfo) (string, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("journal file identity is unavailable")
	}
	if stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return "", fmt.Errorf("journal is not a single-link file owned by the controller user")
	}
	if _, err := file.Stat(); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x:%x", uint64(stat.Dev), uint64(stat.Ino)), nil
}

func validateCacheStateDirectory(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("cache state directory identity is unavailable")
	}
	if stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm() != 0700 {
		return fmt.Errorf("cache state directory is not private and controller-owned")
	}
	return nil
}

func validateCacheStateFile(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.Mode().IsRegular() {
		return fmt.Errorf("cache state file identity is unavailable")
	}
	if stat.Uid != uint32(os.Geteuid()) || stat.Nlink != 1 || info.Mode().Perm() != 0600 {
		return fmt.Errorf("cache state file is not a private single-link controller-owned file")
	}
	return nil
}
