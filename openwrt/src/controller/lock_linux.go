package main

import (
	"fmt"
	"path/filepath"
	"syscall"
)

func lockFile(path string) (func(), error) {
	file, err := openOwnedLock(filepath.Dir(path), filepath.Base(path))
	if err != nil {
		return nil, err
	}
	// The supervisor owns this lock for its whole lifecycle. Another action
	// must fail without waiting for that service to exit or changing its state.
	if err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		file.Close()
		return nil, fmt.Errorf("controller lock unavailable; retain current lifecycle: %w", err)
	}
	return func() { syscall.Flock(int(file.Fd()), syscall.LOCK_UN); file.Close() }, nil
}
