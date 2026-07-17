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
