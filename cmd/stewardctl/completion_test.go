package main

import (
	"bytes"
	"encoding/json"
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
	if candidates := stewardctlCompletionCandidates([]string{"control", "freeze", ""}); !slices.Equal(candidates, []string{"clear", "set", "status"}) {
		t.Fatalf("control freeze candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"control", "quota", ""}); !slices.Equal(candidates, []string{"clear", "set", "status"}) {
		t.Fatalf("control quota candidates=%v", candidates)
	}
	supportFlags := stewardctlCompletionCandidates([]string{"control", "support-bundle", "verify", "-expected"})
	if !slices.Equal(supportFlags, []string{"-expected-sha256"}) {
		t.Fatalf("support bundle verification flags=%v", supportFlags)
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
	if candidates := stewardctlCompletionCandidates([]string{"gateway", "service", "set", "-agent", "h"}); !slices.Equal(candidates, []string{"hermes"}) {
		t.Fatalf("agent preset candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"gateway", "connector", "set", "-preset", "g"}); !slices.Equal(candidates, []string{"github-issues"}) {
		t.Fatalf("connector preset candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"gateway", "connector", "set", "-preset", "research-"}); !slices.Equal(candidates, []string{"research-extract", "research-search"}) {
		t.Fatalf("research connector preset candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"gateway", "inference", "set", "-provider", "v"}); !slices.Equal(candidates, []string{"vllm"}) {
		t.Fatalf("inference provider candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"gateway", "inference", "set", "-credential-mode", "x"}); !slices.Equal(candidates, []string{"x-api-key"}) {
		t.Fatalf("inference credential candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"site", "init", "new-site", "-authorized-effects", "r"}); !slices.Equal(candidates, []string{"required"}) {
		t.Fatalf("site effects candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"site", "node", ""}); !slices.Equal(candidates, []string{"activate", "prepare", "verify"}) {
		t.Fatalf("site node candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"site", ""}); !slices.Equal(candidates, []string{"connect", "init", "node", "task", "verify"}) {
		t.Fatalf("site candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"site", "task", ""}); !slices.Equal(candidates, []string{"connect"}) {
		t.Fatalf("site task candidates=%v", candidates)
	}
	taskConnectFlags := stewardctlCompletionCandidates([]string{"site", "task", "connect", "steward-site", "-"})
	for _, expected := range []string{"-context", "-gateway-token-file", "-trust", "-site-root-public-key", "-task-key"} {
		if !slices.Contains(taskConnectFlags, expected) {
			t.Fatalf("site task connect flags %v missing %s", taskConnectFlags, expected)
		}
	}
	siteConnectFlags := stewardctlCompletionCandidates([]string{"site", "connect", "steward-site", "-"})
	for _, expected := range []string{"-context", "-control-url", "-no-context", "-operator-token-out", "-site-root-public-key", "-token-file"} {
		if !slices.Contains(siteConnectFlags, expected) {
			t.Fatalf("site connect flags %v missing %s", siteConnectFlags, expected)
		}
	}
	siteNodeFlags := stewardctlCompletionCandidates([]string{"site", "node", "prepare", "-"})
	for _, expected := range []string{"-control-url", "-no-context", "-out", "-site-root-public-key", "-token-file"} {
		if !slices.Contains(siteNodeFlags, expected) {
			t.Fatalf("site node prepare flags %v missing %s", siteNodeFlags, expected)
		}
	}
	if candidates := stewardctlCompletionCandidates([]string{"agent", "init", "-runtime", ""}); !slices.Equal(candidates, []string{"hermes"}) {
		t.Fatalf("agent runtime candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"agent", "create", "auditor", "-runtime", ""}); !slices.Equal(candidates, []string{"hermes"}) {
		t.Fatalf("agent create runtime candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"agent", "deployment", ""}); !slices.Equal(candidates, []string{"apply", "list", "pause", "remove", "resume", "status", "wait"}) {
		t.Fatalf("agent deployment candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"agent", "service", ""}); !slices.Equal(candidates, []string{"activate"}) {
		t.Fatalf("agent service candidates=%v", candidates)
	}
	for command, expected := range map[string]string{
		"publish": "-archive", "authorize": "-controller-public-key", "service activate": "-trust-out",
	} {
		arguments := append([]string{"agent"}, strings.Fields(command)...)
		arguments = append(arguments, "-")
		if flags := stewardctlCompletionCandidates(arguments); !slices.Contains(flags, expected) {
			t.Fatalf("agent %s flags %v missing %s", command, flags, expected)
		}
	}
	deploymentFlags := stewardctlCompletionCandidates([]string{"agent", "deployment", "apply", "-"})
	for _, expected := range []string{"-bundle", "-capsule", "-delegation", "-revision", "-tenant"} {
		if !slices.Contains(deploymentFlags, expected) {
			t.Fatalf("deployment flags %v missing %s", deploymentFlags, expected)
		}
	}
	namedApplyFlags := stewardctlCompletionCandidates([]string{"agent", "apply", "auditor", "-"})
	for _, expected := range []string{"-delegation", "-max-unavailable", "-tenant-id", "-revision", "-control-url", "-ca-file"} {
		if !slices.Contains(namedApplyFlags, expected) {
			t.Fatalf("named apply flags %v missing %s", namedApplyFlags, expected)
		}
	}
	if candidates := stewardctlCompletionCandidates([]string{"permit", "con"}); !slices.Equal(candidates, []string{"context"}) {
		t.Fatalf("permit context candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"node", "maintenance", ""}); !slices.Equal(candidates, []string{"drain", "enter", "exit", "status"}) {
		t.Fatalf("node maintenance candidates=%v", candidates)
	}
	if candidates := stewardctlCompletionCandidates([]string{"executor-command", "delegation", ""}); !slices.Equal(candidates, []string{"issue", "verify"}) {
		t.Fatalf("executor delegation candidates=%v", candidates)
	}
	delegationFlags := stewardctlCompletionCandidates([]string{"executor-command", "delegation", "issue", "-controller"})
	if !slices.Equal(delegationFlags, []string{"-controller-key-id", "-controller-public-key"}) {
		t.Fatalf("executor delegation flags=%v", delegationFlags)
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

func TestCompletionInstallDetectsActivatesAndUpdatesIdempotently(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, "config")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("SHELL", "/bin/zsh")
	var output bytes.Buffer
	if err := completionCommand([]string{"install"}, &output); err != nil {
		t.Fatal(err)
	}
	var installed completionInstallResult
	if err := json.Unmarshal(output.Bytes(), &installed); err != nil {
		t.Fatal(err)
	}
	if installed.Shell != "zsh" || !installed.Changed || installed.StartupFile != filepath.Join(home, ".zshrc") {
		t.Fatalf("install result=%+v", installed)
	}
	script, err := os.ReadFile(installed.CompletionFile)
	if err != nil || string(script) != zshCompletionScript {
		t.Fatalf("script=%q error=%v", script, err)
	}
	startup, err := os.ReadFile(installed.StartupFile)
	if err != nil || !strings.Contains(string(startup), "compinit") || !strings.Contains(string(startup), installed.CompletionFile) {
		t.Fatalf("startup=%q error=%v", startup, err)
	}

	output.Reset()
	if err := completionCommand([]string{"install"}, &output); err != nil {
		t.Fatal(err)
	}
	installed = completionInstallResult{}
	if err := json.Unmarshal(output.Bytes(), &installed); err != nil || installed.Changed {
		t.Fatalf("idempotent result=%+v error=%v", installed, err)
	}
	if err := os.WriteFile(installed.CompletionFile, []byte("user content\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := completionCommand([]string{"install"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "-force") {
		t.Fatalf("conflicting completion error=%v", err)
	}
	if err := completionCommand([]string{"install", "-force"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}

func TestCompletionInstallUsesFishAutoloadWithoutStartupMutation(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("SHELL", "/usr/bin/unknown")
	var output bytes.Buffer
	if err := completionCommand([]string{"install", "-shell", "fish"}, &output); err != nil {
		t.Fatal(err)
	}
	var installed completionInstallResult
	if err := json.Unmarshal(output.Bytes(), &installed); err != nil {
		t.Fatal(err)
	}
	if installed.StartupFile != "" || !strings.HasSuffix(installed.CompletionFile, filepath.Join("fish", "completions", "stewardctl.fish")) {
		t.Fatalf("fish install=%+v", installed)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "fish", "config.fish")); !os.IsNotExist(err) {
		t.Fatalf("fish startup file was unexpectedly created: %v", err)
	}
	if err := completionCommand([]string{"install"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "could not detect") {
		t.Fatalf("unknown shell error=%v", err)
	}
}

func TestCompletionInstallActivatesBashAndPreservesStartupContent(t *testing.T) {
	home := t.TempDir()
	config := filepath.Join(home, ".config")
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", config)
	t.Setenv("SHELL", "/bin/bash")
	startupPath := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(startupPath, []byte("export EXISTING=value"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := completionCommand([]string{"install"}, &output); err != nil {
		t.Fatal(err)
	}
	var installed completionInstallResult
	if err := json.Unmarshal(output.Bytes(), &installed); err != nil {
		t.Fatal(err)
	}
	startup, err := os.ReadFile(startupPath)
	if err != nil || !strings.HasPrefix(string(startup), "export EXISTING=value\n") ||
		!strings.Contains(string(startup), "source '") || installed.Shell != "bash" {
		t.Fatalf("install=%+v startup=%q error=%v", installed, startup, err)
	}
	if script, err := os.ReadFile(installed.CompletionFile); err != nil || !strings.Contains(string(script), "compgen") || strings.Contains(string(script), "mapfile") {
		t.Fatalf("bash script=%q error=%v", script, err)
	}
}

func TestCompletionInstallRejectsAmbiguousConfiguration(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")
	if err := completionCommand([]string{"install", "positional"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "named flags") {
		t.Fatalf("positional install error=%v", err)
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	if err := completionCommand([]string{"install"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative XDG error=%v", err)
	}
	startup := filepath.Join(home, ".zshrc")
	if err := os.WriteFile(startup, []byte("# >>> Steward stewardctl completion >>>\nuser managed\n# <<< Steward stewardctl completion <<<\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := installCompletionStartupBlock(startup, "source '/expected'"); err == nil || !strings.Contains(err.Error(), "conflicting") {
		t.Fatalf("conflicting startup block error=%v", err)
	}
	if err := completionCommand([]string{"install", "-shell", "powershell"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "detect") {
		t.Fatalf("unsupported install shell error=%v", err)
	}
	target := filepath.Join(home, "completion")
	if err := os.Symlink(startup, target); err != nil {
		t.Fatal(err)
	}
	if _, err := installCompletionFile(target, []byte("generated"), false); err == nil || !strings.Contains(err.Error(), "not a link") {
		t.Fatalf("symlink completion target error=%v", err)
	}
}
