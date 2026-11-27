package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// These syscall tests execute only on Linux; cross-compilation is not execution.
func TestLinuxServiceLockNoTruncationOrAliases(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production lock ownership requires root")
	}
	for _, kind := range []string{"regular", "symlink", "hardlink", "fifo", "directory"} {
		t.Run(kind, func(t *testing.T) {
			state := t.TempDir()
			if err := os.Chmod(state, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "unrelated")
			const text = "keep existing content\n"
			if err := os.WriteFile(target, []byte(text), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(state, "service.lock")
			var err error
			switch kind {
			case "regular":
				err = os.WriteFile(path, []byte(text), 0600)
			case "symlink":
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(target, path)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			file, err := openServiceLock(state)
			if kind == "regular" {
				if err != nil {
					t.Fatal(err)
				}
				file.Close()
				data, e := os.ReadFile(path)
				if e != nil || string(data) != text {
					t.Fatal("existing lock truncated")
				}
			} else if err == nil {
				file.Close()
				t.Fatal("unsafe lock accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != text {
				t.Fatal("unrelated target changed")
			}
		})
	}
}

func TestLinuxControllerLockRejectsUnsafeFilesAndContention(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("production lock ownership requires root")
	}
	for _, kind := range []string{"regular", "symlink", "hardlink", "fifo", "directory", "public"} {
		t.Run(kind, func(t *testing.T) {
			state := t.TempDir()
			if err := os.Chmod(state, 0700); err != nil {
				t.Fatal(err)
			}
			target := filepath.Join(t.TempDir(), "unrelated")
			const content = "keep lock and unrelated bytes\n"
			if err := os.WriteFile(target, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(state, "controller.lock")
			var err error
			switch kind {
			case "regular", "public":
				err = os.WriteFile(path, []byte(content), 0600)
				if err == nil && kind == "public" {
					err = os.Chmod(path, 0644)
				}
			case "symlink":
				err = os.Symlink(target, path)
			case "hardlink":
				err = os.Link(target, path)
			case "fifo":
				err = syscall.Mkfifo(path, 0600)
			case "directory":
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			unlock, err := lockFile(path)
			if kind == "regular" {
				if err != nil {
					t.Fatal(err)
				}
				defer unlock()
				if second, err := lockFile(path); err == nil {
					second()
					t.Fatal("contending controller action acquired the lifecycle lock")
				}
				data, err := os.ReadFile(path)
				if err != nil || string(data) != content {
					t.Fatal("existing controller lock was truncated")
				}
			} else if err == nil {
				unlock()
				t.Fatal("unsafe controller lock accepted")
			}
			data, err := os.ReadFile(target)
			if err != nil || string(data) != content {
				t.Fatal("unrelated target was changed")
			}
		})
	}
}
