package zfsstorage

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
)

const maxCommandOutput = 1 << 20

// Runner is the fixed OpenZFS command surface used by Backend. Implementations
// receive arguments only; no shell command or tenant-controlled executable is
// ever accepted.
type Runner interface {
	Run(context.Context, ...string) ([]byte, error)
}

// CommandError retains bounded, locale-stable stderr for conservative error
// classification without exposing it over the storage protocol.
type CommandError struct {
	Args   []string
	Stderr string
	Err    error
}

func (err *CommandError) Error() string {
	return fmt.Sprintf("zfs %s failed: %v", strings.Join(err.Args, " "), err.Err)
}

func (err *CommandError) Unwrap() error { return err.Err }

// ExecRunner invokes one absolute zfs binary with a closed environment and
// bounded output. It never invokes a shell.
type ExecRunner struct{ Path string }

func (runner ExecRunner) Validate() error {
	if runner.Path == "" || !filepath.IsAbs(runner.Path) || filepath.Clean(runner.Path) != runner.Path ||
		filepath.Base(runner.Path) != "zfs" {
		return errors.New("zfs runner requires a clean absolute zfs binary path")
	}
	return nil
}

func (runner ExecRunner) Run(ctx context.Context, args ...string) ([]byte, error) {
	if err := runner.Validate(); err != nil {
		return nil, err
	}
	if ctx == nil {
		return nil, errors.New("zfs runner requires a context")
	}
	command := exec.CommandContext(ctx, runner.Path, args...)
	command.Env = []string{"LANG=C", "LC_ALL=C", "PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	stdout := &boundedBuffer{remaining: maxCommandOutput}
	stderr := &boundedBuffer{remaining: maxCommandOutput}
	command.Stdout, command.Stderr = stdout, stderr
	if err := command.Run(); err != nil {
		return nil, &CommandError{Args: append([]string(nil), args...), Stderr: stderr.String(), Err: err}
	}
	if stdout.overflow || stderr.overflow {
		return nil, errors.New("zfs command output exceeded 1 MiB")
	}
	return stdout.Bytes(), nil
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	remaining int
	overflow  bool
}

func (buffer *boundedBuffer) Write(value []byte) (int, error) {
	length := len(value)
	available := buffer.remaining
	if buffer.remaining > 0 {
		written := len(value)
		if written > buffer.remaining {
			written = buffer.remaining
		}
		_, _ = buffer.buffer.Write(value[:written])
		buffer.remaining -= written
	}
	if length > available {
		buffer.overflow = true
	}
	return length, nil
}

func (buffer *boundedBuffer) Bytes() []byte {
	return buffer.buffer.Bytes()
}

func (buffer *boundedBuffer) String() string { return buffer.buffer.String() }
