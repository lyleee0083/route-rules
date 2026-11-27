//go:build !linux

package main

import "os/exec"

func configureCommandCancellation(cmd *exec.Cmd) {
	// CommandContext kills the child; WaitDelay bounds inherited-pipe waits.
	// Production OpenWrt uses the Linux process-group cancellation above.
}
