package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

const (
	executeContextHelperEnv       = "SING_BOX_CONTROLLER_EXECUTE_HELPER"
	executeContextHelperMarkerEnv = "SING_BOX_CONTROLLER_EXECUTE_HELPER_MARKER"
)

func TestExecuteContextReturnsInputAndOutput(t *testing.T) {
	t.Setenv(executeContextHelperEnv, "1")

	const input = "controller input payload"
	const argument = "expected argument"
	got, err := executeContext(context.Background(), input, os.Args[0], executeContextHelperArgs("echo", argument)...)
	if err != nil {
		t.Fatalf("executeContext returned an error: %v", err)
	}
	if want := "input=" + input + ";arg=" + argument; string(got) != want {
		t.Fatalf("executeContext output = %q, want %q", got, want)
	}
}

func TestExecuteContextNonzeroExitDoesNotLeakSecrets(t *testing.T) {
	t.Setenv(executeContextHelperEnv, "1")

	const (
		inputSecret  = "input-credential-4c80"
		argument     = "argument-credential-77a1"
		stdoutSecret = "stdout-credential-813d"
		stderrSecret = "stderr-credential-91be"
	)
	_, err := executeContext(context.Background(), inputSecret, os.Args[0], executeContextHelperArgs("fail", argument, stdoutSecret, stderrSecret)...)
	if err == nil {
		t.Fatal("executeContext succeeded for a helper that exits nonzero")
	}
	assertErrorOmits(t, err, inputSecret, argument, stdoutSecret, stderrSecret)
}

func TestExecuteContextDeadlineStopsProcessAndHidesSecrets(t *testing.T) {
	t.Setenv(executeContextHelperEnv, "1")

	const (
		inputSecret  = "deadline-input-credential"
		argument     = "deadline-argument-credential"
		stdoutSecret = "deadline-stdout-credential"
		stderrSecret = "deadline-stderr-credential"
	)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	started := time.Now()
	_, err := executeContext(ctx, inputSecret, os.Args[0], executeContextHelperArgs("hang-secret", argument, stdoutSecret, stderrSecret)...)
	elapsed := time.Since(started)
	if !errors.Is(err, ctx.Err()) {
		t.Fatalf("executeContext error = %v, want context error %v", err, ctx.Err())
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("executeContext took %s after a 200ms deadline", elapsed)
	}
	assertErrorOmits(t, err, inputSecret, argument, stdoutSecret, stderrSecret)
}

func TestExecuteContextCancellationStopsStartedProcess(t *testing.T) {
	t.Setenv(executeContextHelperEnv, "1")
	marker := t.TempDir() + string(os.PathSeparator) + "started"
	t.Setenv(executeContextHelperMarkerEnv, marker)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() {
		_, err := executeContext(ctx, "", os.Args[0], executeContextHelperArgs("hang")...)
		finished <- err
	}()

	waitForExecuteContextHelper(t, marker, finished)
	cancel()
	select {
	case err := <-finished:
		if !errors.Is(err, ctx.Err()) {
			t.Fatalf("executeContext error = %v, want context error %v", err, ctx.Err())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("executeContext did not return after cancellation")
	}
}

func TestExecuteContextCanceledBeforeStartDoesNotLaunchHelper(t *testing.T) {
	t.Setenv(executeContextHelperEnv, "1")
	marker := t.TempDir() + string(os.PathSeparator) + "started"
	t.Setenv(executeContextHelperMarkerEnv, marker)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := executeContext(ctx, "", os.Args[0], executeContextHelperArgs("echo", "unused")...)
	if !errors.Is(err, ctx.Err()) {
		t.Fatalf("executeContext error = %v, want context error %v", err, ctx.Err())
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("helper started with a canceled context; marker stat error = %v", statErr)
	}
}

func TestExecuteContextReportsDeadlineAfterSuccessfulCommandExit(t *testing.T) {
	t.Setenv(executeContextHelperEnv, "1")

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err := executeContext(ctx, "", os.Args[0], executeContextHelperArgs("pipe-parent")...)
	if !errors.Is(err, ctx.Err()) {
		t.Fatalf("executeContext error = %v, want context error %v after the command exited", err, ctx.Err())
	}
}

func TestExecuteContextHelper(t *testing.T) {
	if os.Getenv(executeContextHelperEnv) != "1" {
		return
	}

	args, ok := executeContextHelperArguments()
	if !ok || len(args) == 0 {
		os.Exit(90)
	}
	if marker := os.Getenv(executeContextHelperMarkerEnv); marker != "" {
		if err := os.WriteFile(marker, []byte("started"), 0600); err != nil {
			os.Exit(91)
		}
	}

	switch args[0] {
	case "echo":
		input, err := io.ReadAll(os.Stdin)
		if err != nil || len(args) < 2 {
			os.Exit(92)
		}
		_, _ = fmt.Fprintf(os.Stdout, "input=%s;arg=%s", input, args[1])
		os.Exit(0)
	case "fail":
		_, _ = io.Copy(io.Discard, os.Stdin)
		if len(args) < 4 {
			os.Exit(93)
		}
		_, _ = fmt.Fprint(os.Stdout, args[2])
		_, _ = fmt.Fprint(os.Stderr, args[3])
		os.Exit(23)
	case "hang":
		time.Sleep(2 * time.Second)
		os.Exit(0)
	case "hang-secret":
		if len(args) < 4 {
			os.Exit(94)
		}
		_, _ = fmt.Fprint(os.Stdout, args[2])
		_, _ = fmt.Fprint(os.Stderr, args[3])
		time.Sleep(2 * time.Second)
		os.Exit(0)
	case "pipe-parent":
		child := exec.Command(os.Args[0], executeContextHelperArgs("pipe-holder")...)
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			os.Exit(95)
		}
		os.Exit(0)
	case "pipe-holder":
		time.Sleep(350 * time.Millisecond)
		os.Exit(0)
	default:
		os.Exit(96)
	}
}

func executeContextHelperArgs(mode string, extra ...string) []string {
	args := []string{"-test.run=^TestExecuteContextHelper$", "--", mode}
	return append(args, extra...)
}

func executeContextHelperArguments() ([]string, bool) {
	for index, arg := range os.Args {
		if arg == "--" && index+1 < len(os.Args) {
			return os.Args[index+1:], true
		}
	}
	return nil, false
}

func waitForExecuteContextHelper(t *testing.T, marker string, finished <-chan error) {
	t.Helper()
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := os.Stat(marker); err == nil {
			return
		} else if !os.IsNotExist(err) {
			t.Fatalf("stat helper marker: %v", err)
		}
		select {
		case err := <-finished:
			t.Fatalf("executeContext returned before helper started: %v", err)
		case <-timer.C:
			t.Fatal("timed out waiting for helper process to start")
		case <-ticker.C:
		}
	}
}

func assertErrorOmits(t *testing.T, err error, values ...string) {
	t.Helper()
	message := err.Error()
	for _, value := range values {
		if strings.Contains(message, value) {
			t.Errorf("error exposed sensitive value %q: %s", value, message)
		}
	}
}
