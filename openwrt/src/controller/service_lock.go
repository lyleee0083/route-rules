package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Validate before opening a lock or stopping anything. The Linux opener also
// checks the opened inode atomically without following links or truncating it.
func (c *controller) validateServiceState() error {
	if err := directory(c.state); err != nil {
		return err
	}
	owner := filepath.Join(c.state, "owner")
	if err := regular(owner); err != nil {
		return err
	}
	data, err := os.ReadFile(owner)
	if err != nil {
		return err
	}
	if string(data) != "sing-box-native-v1\n" {
		return errors.New("unknown integration owner")
	}
	for _, name := range []string{"service.lock", "restoration-status", "service-exit", "mosdns.pid", "sing-box.pid", "core.pid"} {
		path := filepath.Join(c.state, name)
		if _, err := os.Lstat(path); os.IsNotExist(err) {
			continue
		} else if err != nil {
			return err
		}
		if err := regular(path); err != nil {
			return err
		}
	}
	return nil
}

func (c *controller) restorationStatus() error {
	path := filepath.Join(c.state, "restoration-status")
	if err := regular(path); err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if string(data) != "restored\n" && string(data) != "not-started\n" {
		return fmt.Errorf("service restoration did not complete: %q", data)
	}
	return nil
}
