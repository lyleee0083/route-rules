package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

func openServiceLock(state string) (*os.File, error) {
	return openOwnedLock(state, "service.lock")
}

func openOwnedLock(state, name string) (*os.File, error) {
	if name != "service.lock" && name != "controller.lock" {
		return nil, errors.New("unknown owned lock name")
	}
	info, err := os.Lstat(state)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || st.Uid != 0 {
		return nil, errors.New("service state must be a root-owned private directory")
	}
	// Use a verified directory fd, not a path through a replaceable directory link.
	dirFD, err := syscall.Open(state, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer syscall.Close(dirFD)
	var ds syscall.Stat_t
	if err = syscall.Fstat(dirFD, &ds); err != nil {
		return nil, err
	}
	if ds.Uid != 0 || ds.Mode&07777 != 0700 || ds.Ino != st.Ino || ds.Dev != st.Dev {
		return nil, errors.New("service state directory changed")
	}
	// O_NONBLOCK avoids blocking on a pre-existing FIFO before fstat rejects it.
	fd, err := syscall.Openat(dirFD, name, syscall.O_CREAT|syscall.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), filepath.Join(state, name))
	var fs syscall.Stat_t
	if err = syscall.Fstat(fd, &fs); err != nil {
		file.Close()
		return nil, err
	}
	if fs.Mode&syscall.S_IFMT != syscall.S_IFREG || fs.Nlink != 1 || fs.Uid != 0 || fs.Mode&07777 != 0600 {
		file.Close()
		return nil, errors.New("service lock must be a private regular file without aliases")
	}
	return file, nil
}

func (c *controller) serviceLockAction(action string) error {
	if err := c.validateServiceState(); err != nil {
		return err
	}
	if action == "service-status" {
		if _, err := os.Lstat(filepath.Join(c.state, "service.lock")); os.IsNotExist(err) {
			return nil // A never-started service has no lock; stop must not create one.
		} else if err != nil {
			return err
		}
	}
	file, err := openServiceLock(c.state)
	if err != nil {
		return err
	}
	defer file.Close()
	deadline := time.Now().Add(65 * time.Second)
	for {
		err = syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			break
		}
		if err != syscall.EWOULDBLOCK && err != syscall.EAGAIN {
			return err
		}
		if action == "service-start" || !time.Now().Before(deadline) {
			return fmt.Errorf("service lock unavailable: %w", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err = c.validateServiceState(); err != nil {
		return err
	}
	if action == "service-status" {
		return c.restorationStatus()
	}
	if action == "service-start" {
		// Defense in depth for callers that bypass activate.sh. The read-only
		// gate runs while the service lock is held and before the wrapper starts.
		if err = c.cacheBootCheck(); err != nil {
			var recoveryOnly recoveryOnlyError
			if !errors.As(err, &recoveryOnly) {
				return err
			}
			fmt.Fprintln(os.Stderr, err)
		}
	}
	var args []string
	switch action {
	case "service-start":
		args = []string{"/bin/sh", filepath.Join(c.root, "sing-box-service.sh"), "--service-lock-held"}
	case "service-rollback":
		args = []string{"/bin/sh", filepath.Join(c.root, "rollback.sh"), "--rollback-authorized", "--service-lock-held"}
	default:
		return errors.New("unknown service lock action")
	}
	// Replace the helper: no extra supervisor remains. Inherited fd 8 holds the
	// same flock throughout exec, supervision and exit restoration.
	if int(file.Fd()) == 8 {
		_, _, errno := syscall.Syscall(syscall.SYS_FCNTL, file.Fd(), syscall.F_SETFD, 0)
		if errno != 0 {
			return errno
		}
	} else if err = syscall.Dup3(int(file.Fd()), 8, 0); err != nil {
		return err
	}
	return syscall.Exec("/bin/sh", args, os.Environ())
}
