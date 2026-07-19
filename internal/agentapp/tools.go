package agentapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const externalToolTimeout = 30 * time.Second

// LoadDefinition accepts concrete JSON directly. CUE remains an operator-side
// compiler: its output crosses the same strict, bounded JSON boundary as any
// other untrusted definition and CUE is never loaded into an enforcement process.
func LoadDefinition(ctx context.Context, path, cueBinary string) (Definition, error) {
	if strings.EqualFold(filepath.Ext(path), ".cue") {
		if cueBinary == "" {
			cueBinary = "cue"
		}
		raw, _, err := runTool(ctx, cueBinary, nil, "export", path, "--out", "json")
		if err != nil {
			return Definition{}, fmt.Errorf("compile CUE agent definition: %w", err)
		}
		return DecodeDefinition(raw)
	}
	raw, err := readBoundedRegular(path, MaxArtifactBytes)
	if err != nil {
		return Definition{}, err
	}
	return DecodeDefinition(raw)
}

// EvaluateOPA evaluates one explicit data query against one offline OPA bundle.
// Only an exact raw `true` permits the build; undefined, malformed, oversized,
// timed-out, or denied decisions all fail closed.
func EvaluateOPA(ctx context.Context, opaBinary, bundlePath, query string, input []byte) (PolicyEvidence, error) {
	if opaBinary == "" {
		opaBinary = "opa"
	}
	if !validQuery(query) {
		return PolicyEvidence{}, errors.New("OPA query must be a bounded data.* query")
	}
	if len(input) == 0 || len(input) > MaxArtifactBytes {
		return PolicyEvidence{}, errors.New("OPA input must be between 1 byte and 1 MiB")
	}
	digest, err := digestRegular(bundlePath, MaxArtifactBytes)
	if err != nil {
		return PolicyEvidence{}, fmt.Errorf("read OPA bundle: %w", err)
	}
	stdout, _, err := runTool(ctx, opaBinary, input, "eval", "--format", "raw", "--bundle", bundlePath, "--stdin-input", query)
	if err != nil {
		return PolicyEvidence{}, fmt.Errorf("evaluate OPA policy: %w", err)
	}
	allowed := string(bytes.TrimSpace(stdout)) == "true"
	if !allowed {
		return PolicyEvidence{}, errors.New("OPA policy denied or did not return the boolean true")
	}
	return PolicyEvidence{BundleDigest: digest, Query: query, Allowed: true}, nil
}

func runTool(parent context.Context, binary string, stdin []byte, arguments ...string) ([]byte, []byte, error) {
	resolved, err := exec.LookPath(binary)
	if err != nil {
		return nil, nil, fmt.Errorf("find %s: %w", binary, err)
	}
	workspace, err := os.MkdirTemp("", "steward-tool-")
	if err != nil {
		return nil, nil, err
	}
	defer os.RemoveAll(workspace)
	ctx, cancel := context.WithTimeout(parent, externalToolTimeout)
	defer cancel()
	command := exec.CommandContext(ctx, resolved, arguments...)
	command.Env = []string{"HOME=" + workspace, "TMPDIR=" + workspace, "NO_COLOR=1"}
	command.Stdin = bytes.NewReader(stdin)
	stdout := &limitedBuffer{maximum: MaxArtifactBytes}
	stderr := &limitedBuffer{maximum: 64 << 10}
	command.Stdout, command.Stderr = stdout, stderr
	err = command.Run()
	if ctx.Err() != nil {
		return nil, stderr.Bytes(), errors.New("external tool exceeded 30 second timeout")
	}
	if stdout.overflow || stderr.overflow {
		return nil, stderr.Bytes(), errors.New("external tool output exceeded its bound")
	}
	if err != nil {
		detail := strings.TrimSpace(string(stderr.Bytes()))
		if len(detail) > 512 {
			detail = detail[:512]
		}
		if detail != "" {
			return nil, stderr.Bytes(), fmt.Errorf("external tool failed: %s", detail)
		}
		return nil, stderr.Bytes(), fmt.Errorf("external tool failed: %w", err)
	}
	return stdout.Bytes(), stderr.Bytes(), nil
}

type limitedBuffer struct {
	buffer   bytes.Buffer
	maximum  int
	overflow bool
}

func (writer *limitedBuffer) Write(value []byte) (int, error) {
	if writer.buffer.Len()+len(value) > writer.maximum {
		remaining := writer.maximum - writer.buffer.Len()
		if remaining > 0 {
			_, _ = writer.buffer.Write(value[:remaining])
		}
		writer.overflow = true
		return len(value), errors.New("bounded output exceeded")
	}
	return writer.buffer.Write(value)
}

func (writer *limitedBuffer) Bytes() []byte { return writer.buffer.Bytes() }

func readBoundedRegular(path string, maximum int64) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() || before.Size() < 0 || before.Size() > maximum {
		return nil, errors.New("artifact must be a bounded regular file, not a link or special file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	named, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maximum || !os.SameFile(before, after) || !os.SameFile(after, named) || int64(len(raw)) != after.Size() {
		return nil, errors.New("artifact changed while it was read or exceeds its bound")
	}
	return raw, nil
}

func digestRegular(path string, maximum int64) (string, error) {
	raw, err := readBoundedRegular(path, maximum)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
