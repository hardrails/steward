package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestCompletionScriptsUseOnlyTheLocalStewardctlCandidateSource(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			var output bytes.Buffer
			if err := completionCommand([]string{shell}, &output); err != nil {
				t.Fatal(err)
			}
			script := output.String()
			if !strings.Contains(script, "stewardctl __complete") || strings.Contains(script, "http://") || strings.Contains(script, "https://") {
				t.Fatalf("completion script is not local or bounded: %s", script)
			}
		})
	}
	if err := completionCommand([]string{"powershell"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unsupported completion shell was accepted")
	}
}

func TestCompletionCandidatesCoverCommandsFlagsAndContextNames(t *testing.T) {
	if candidates := stewardctlCompletionCandidates([]string{"co"}); !slices.Contains(candidates, "control") || !slices.Contains(candidates, "context") {
		t.Fatalf("top-level candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"control", "command", ""}); !slices.Equal(candidates, []string{"list", "status", "submit"}) {
		t.Fatalf("control command candidates=%v", candidates)
	}
	flags := stewardctlCompletionCandidates([]string{"control", "command", "submit", "-"})
	for _, expected := range []string{"-command", "-control-url", "-node-id", "-tenant-id", "-token-file"} {
		if !slices.Contains(flags, expected) {
			t.Fatalf("command flags %v missing %s", flags, expected)
		}
	}
	if candidates := stewardctlCompletionCandidates([]string{"control", "tenant", "list", "-token-file", ""}); len(candidates) != 0 {
		t.Fatalf("file argument candidates=%v; shell file completion should handle the value", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"gateway", "service", ""}); !slices.Equal(candidates, []string{"list", "set", "trust"}) {
		t.Fatalf("gateway service candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"gateway", "service", "set", "-agent", "o"}); !slices.Equal(candidates, []string{"openclaw"}) {
		t.Fatalf("agent preset candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"permit", "con"}); !slices.Equal(candidates, []string{"context"}) {
		t.Fatalf("permit context candidates=%v", candidates)
	}
	permitFlags := stewardctlCompletionCandidates([]string{"permit", "issue", "-con"})
	if !slices.Equal(permitFlags, []string{"-connector-id", "-context"}) {
		t.Fatalf("permit issue flags=%v", permitFlags)
	}

	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	if err := contextCommand([]string{"set", "production", "-token-file", tokenPath}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if candidates := stewardctlCompletionCandidates([]string{"context", "use", "pro"}); !slices.Equal(candidates, []string{"production"}) {
		t.Fatalf("context candidates=%v", candidates)
	}
}

func TestCompletionDispatchWritesCandidatesForExecutablePaths(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"__complete", "/usr/local/bin/stewardctl", "control", "tenant", ""}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if output.String() != "create\nlist\n" {
		t.Fatalf("completion output=%q", output.String())
	}
	if err := completionCommand(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("completion without a shell succeeded")
	}
}
