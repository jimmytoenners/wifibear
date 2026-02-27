package tools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// Process wraps an exec.Cmd with context-aware lifecycle management.
type Process struct {
	cmd    *exec.Cmd
	ctx    context.Context
	cancel context.CancelFunc
	stdout io.ReadCloser
	stderr io.ReadCloser
	mu     sync.Mutex
}

// StartProcess launches a command with context cancellation support.
func StartProcess(ctx context.Context, name string, args ...string) (*Process, error) {
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, name, args...)

	// Use process groups so we can kill the entire tree
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("stdout pipe: %w", err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		cancel()
		return nil, fmt.Errorf("start %s: %w", name, err)
	}

	return &Process{
		cmd:    cmd,
		ctx:    ctx,
		cancel: cancel,
		stdout: stdout,
		stderr: stderr,
	}, nil
}

// RunCapture executes a command and returns its combined output.
func RunCapture(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// RunSilent executes a command and discards output.
func RunSilent(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	return cmd.Run()
}

// Stdout returns a scanner over the process stdout.
func (p *Process) StdoutScanner() *bufio.Scanner {
	return bufio.NewScanner(p.stdout)
}

// StderrScanner returns a scanner over the process stderr.
func (p *Process) StderrScanner() *bufio.Scanner {
	return bufio.NewScanner(p.stderr)
}

// StdoutReader returns the raw stdout reader.
func (p *Process) StdoutReader() io.ReadCloser {
	return p.stdout
}

// Wait waits for the process to exit.
func (p *Process) Wait() error {
	return p.cmd.Wait()
}

// Stop sends SIGTERM to the process group, then cleans up.
func (p *Process) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.cancel()

	if p.cmd.Process != nil {
		// Kill the entire process group
		pgid, err := syscall.Getpgid(p.cmd.Process.Pid)
		if err == nil {
			_ = syscall.Kill(-pgid, syscall.SIGTERM)
		}
	}

	return p.cmd.Wait()
}

// Pid returns the process ID.
func (p *Process) Pid() int {
	if p.cmd.Process != nil {
		return p.cmd.Process.Pid
	}
	return 0
}

// Running returns true if the process has not exited.
func (p *Process) Running() bool {
	return p.cmd.ProcessState == nil
}
