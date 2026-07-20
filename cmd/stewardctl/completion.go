package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

var completionTree = map[string][]string{
	"":                            {"help", "site", "agent", "context", "completion", "keygen", "key", "capsule", "policy", "permit", "task", "executor-command", "control", "evidence", "node", "gateway", "secret", "image", "upgrade", "version"},
	"help":                        {"site", "agent", "context", "completion", "keygen", "key", "capsule", "policy", "permit", "task", "executor-command", "control", "evidence", "node", "gateway", "secret", "image", "upgrade"},
	"site":                        {"init", "verify", "node"},
	"site node":                   {"prepare", "activate", "verify"},
	"agent":                       {"create", "init", "validate", "build", "plan", "apply", "deploy", "deployment", "fork", "doctor"},
	"agent deployment":            {"apply", "wait", "status", "list", "remove"},
	"context":                     {"set", "use", "show", "list", "delete"},
	"completion":                  {"install", "bash", "zsh", "fish"},
	"key":                         {"match"},
	"capsule":                     {"sign", "verify"},
	"policy":                      {"sign", "verify"},
	"permit":                      {"context", "issue", "approve", "verify", "audit", "bundle"},
	"permit bundle":               {"issue", "approve", "verify", "audit"},
	"task":                        {"run", "issue", "verify", "audit", "submit", "status", "observe", "wait"},
	"executor-command":            {"delegation", "issue", "verify"},
	"executor-command delegation": {"issue", "verify"},
	"control":                     {"pki", "tenant", "operator", "enrollment", "node", "node-credential", "snapshot", "operations", "quota", "freeze", "attention", "incident", "agent", "command", "credential", "evidence", "evidence-capture", "support-bundle"},
	"control pki":                 {"create"},
	"control tenant":              {"create", "list"},
	"control operator":            {"issue", "revoke"},
	"control enrollment": {
		"create", "exchange",
	},
	"control node":             {"list", "status", "cordon", "uncordon", "quarantine", "unquarantine", "drain", "cancel-drain", "revoke"},
	"control node-credential":  {"revoke"},
	"control snapshot":         {"status", "quarantine", "unquarantine"},
	"control operations":       {"status"},
	"control quota":            {"status", "set", "clear"},
	"control freeze":           {"status", "set", "clear"},
	"control attention":        {"list"},
	"control incident":         {"timeline"},
	"control agent":            {"list"},
	"control command":          {"submit", "status", "list"},
	"control credential":       {"list"},
	"control evidence":         {"status", "export", "verify"},
	"control evidence-capture": {"arm", "status", "seal", "export", "verify", "delete"},
	"control support-bundle":   {"create", "verify"},
	"evidence":                 {"verify", "export"},
	"node":                     {"whoami", "admit", "status", "logs", "egress", "start", "stop", "destroy", "snapshot-state", "clone-state", "delete-snapshot", "purge-state", "maintenance"},
	"node maintenance":         {"status", "enter", "drain", "exit"},
	"gateway":                  {"validate", "route", "connector", "service", "effects"},
	"gateway route":            {"add", "remove", "list"},
	"gateway connector":        {"set", "list", "trust"},
	"gateway service":          {"set", "list", "trust"},
	"gateway effects":          {"check"},
	"secret":                   {"materialization"},
	"secret materialization":   {"check", "prepare"},
	"image":                    {"inspect", "import"},
	"upgrade":                  {"check-drained", "inspect-formats"},
}

var completionFlags = map[string][]string{
	"site init":                         {"-site-id", "-tenant-id", "-repository", "-service-id", "-connector-id", "-control-server-names", "-authorized-effects", "-dry-run"},
	"site verify":                       {"-site-root-public-key"},
	"site node prepare":                 {"-out", "-request-id", "-valid-for", "-site-root-public-key", "-control-url", "-token-file", "-ca-file", "-no-context"},
	"site node activate":                {"-out", "-site-root-public-key"},
	"site node verify":                  {"-site-root-public-key"},
	"agent init":                        {"-runtime", "-name", "-force"},
	"agent create":                      {"-runtime", "-force"},
	"agent validate":                    {"-file", "-cue"},
	"agent build":                       {"-file", "-out", "-cue", "-opa", "-policy-bundle", "-policy-query"},
	"agent plan":                        {"-bundle", "-nodes", "-tenant", "-out"},
	"agent apply":                       {"-bundle", "-capsule", "-policy", "-site-root-public-key", "-site-root-key-id", "-nodes", "-tenant", "-node-id", "-instance-id", "-lineage-id", "-generation", "-node-url", "-token-file", "-timeout", "-plan-only", "-no-context", "-delegation", "-tenant-id", "-revision", "-max-unavailable", "-control-url", "-ca-file"},
	"agent deploy":                      {"-bundle", "-capsule", "-policy", "-site-root-public-key", "-site-root-key-id", "-nodes", "-tenant", "-node-id", "-instance-id", "-lineage-id", "-generation", "-claim-generation", "-command-key", "-command-key-id", "-control-url", "-token-file", "-ca-file", "-timeout", "-plan-only", "-no-context"},
	"agent deployment apply":            {"-bundle", "-capsule", "-delegation", "-tenant", "-tenant-id", "-generation", "-revision", "-max-unavailable", "-fork-plan", "-source-node", "-control-url", "-token-file", "-ca-file", "-no-context"},
	"agent deployment wait":             {"-tenant", "-tenant-id", "-instance-id", "-out", "-timeout", "-control-url", "-token-file", "-ca-file", "-no-context"},
	"agent deployment status":           {"-tenant", "-tenant-id", "-control-url", "-token-file", "-ca-file", "-no-context"},
	"agent deployment list":             {"-tenant", "-tenant-id", "-after", "-limit", "-control-url", "-token-file", "-ca-file", "-no-context"},
	"agent deployment remove":           {"-tenant", "-tenant-id", "-revision", "-control-url", "-token-file", "-ca-file", "-no-context"},
	"agent fork":                        {"-bundle", "-snapshot", "-instance-id", "-lineage-id", "-ttl", "-on-expiry", "-out"},
	"task issue":                        {"-deployment", "-admission", "-intent", "-trust", "-request", "-operation-id", "-task-id", "-valid-for", "-clock-skew", "-key", "-key-id", "-out"},
	"task run":                          {"-deployment", "-instance-id", "-trust", "-request", "-operation-id", "-task-id", "-valid-for", "-clock-skew", "-key", "-key-id", "-bundle-out", "-result-out", "-discard-result", "-run-dir", "-gateway-url", "-gateway-token-file", "-wait-timeout", "-deployment-timeout", "-tenant", "-tenant-id", "-control-url", "-control-token-file", "-ca-file", "-no-context"},
	"context set":                       {"-control-url", "-token-file", "-ca-file", "-node-url", "-node-token-file", "-gateway-url", "-gateway-token-file", "-service-trust", "-task-key", "-task-key-id", "-tenant-id", "-node-id"},
	"completion install":                {"-shell", "-force"},
	"control":                           {"-control-url", "-token-file", "-ca-file", "-no-context"},
	"control node":                      {"-tenant-id", "-node-id", "-request-id", "-reason", "-after", "-limit"},
	"control snapshot":                  {"-tenant-id", "-node-id", "-snapshot-id", "-reason", "-revision"},
	"control operations status":         {"-tenant-id"},
	"control quota":                     {"-tenant-id", "-revision", "-memory-mib", "-cpu-millis", "-pids", "-workloads"},
	"control freeze":                    {"-tenant-id", "-site", "-reason", "-revision"},
	"control attention list":            {"-tenant-id", "-reason", "-cursor", "-limit"},
	"control incident timeline":         {"-tenant-id", "-node-id", "-kind", "-severity", "-cursor", "-limit"},
	"control agent list":                {"-tenant-id", "-node-id", "-status", "-cursor", "-limit"},
	"control command submit":            {"-tenant-id", "-node-id", "-command"},
	"control command status":            {"-tenant-id", "-node-id", "-command-id"},
	"control command list":              {"-tenant-id", "-node-id", "-state", "-terminal-status", "-cursor", "-limit"},
	"control credential list":           {"-tenant-id", "-kind", "-role", "-node-id", "-revoked", "-cursor", "-limit"},
	"control evidence":                  {"-node-id", "-out", "-in", "-witness-public-key"},
	"control evidence-capture":          {"-tenant-id", "-node-id", "-capture-id", "-request-id", "-runtime-ref", "-out", "-in"},
	"control support-bundle":            {"-tenant-id", "-out", "-in", "-expected-sha256"},
	"executor-command issue":            {"-command-id", "-tenant-id", "-node-id", "-instance-id", "-kind", "-claim-generation", "-instance-generation", "-sequence", "-valid-for", "-payload", "-delegation", "-key", "-key-id", "-out"},
	"executor-command delegation issue": {"-delegation-id", "-tenant-id", "-controller-public-key", "-controller-key-id", "-operations", "-node-ids", "-instances", "-claim-generation", "-admission-template", "-valid-for", "-key", "-key-id", "-out"},
	"permit context":                    {"-admission", "-intent", "-receipts", "-receipt-public-key", "-receipt-node-id", "-receipt-epoch", "-expected-sequence", "-expected-chain-hash", "-out"},
	"permit issue":                      {"-admission", "-intent", "-context", "-trust", "-request", "-connector-id", "-operation-id", "-task-id", "-valid-for", "-clock-skew", "-key", "-key-id", "-out", "-header-out"},
	"permit approve":                    {"-in", "-admission", "-intent", "-trust", "-request", "-key", "-key-id", "-out", "-header-out"},
	"permit verify":                     {"-in", "-public-key", "-key-id", "-authority", "-request", "-max-validity", "-at"},
	"permit audit":                      {"-in", "-public-key", "-key-id", "-authority", "-receipts", "-receipt-public-key", "-receipt-node-id", "-receipt-epoch", "-request", "-max-validity", "-expected-sequence", "-expected-chain-hash"},
	"permit bundle issue":               {"-admission", "-intent", "-trust", "-plan", "-valid-for", "-clock-skew", "-key", "-key-id", "-out", "-header-out"},
	"permit bundle approve":             {"-in", "-admission", "-intent", "-trust", "-plan", "-key", "-key-id", "-out", "-header-out"},
	"permit bundle verify":              {"-in", "-plan", "-trust", "-authority", "-max-validity", "-at"},
	"permit bundle audit":               {"-in", "-plan", "-trust", "-authority", "-receipts", "-receipt-public-key", "-receipt-node-id", "-receipt-epoch", "-max-validity", "-expected-sequence", "-expected-chain-hash"},
	"node":                              {"-node-url", "-token-file", "-no-context", "-runtime-ref", "-capsule", "-intent", "-tenant-id", "-node-id", "-lineage-id", "-generation", "-reason", "-apply"},
	"gateway":                           {"-config", "-agent", "-tenant-id", "-node-id", "-receipt-file", "-receipt-key-file", "-receipt-node-id", "-receipt-epoch"},
	"gateway connector set":             {"-preset", "-repository", "-id", "-base-url", "-credential-file", "-credential-mode", "-credential-epoch", "-allow-cidr", "-operation", "-tenant-budget", "-action-authority", "-action-authority-tenant", "-action-node-id", "-max-action-permit-seconds", "-max-concurrent", "-max-request-bytes", "-max-response-bytes", "-max-seconds", "-max-calls-per-grant"},
}

func completionCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) > 0 && arguments[0] == "install" {
		return completionInstall(arguments[1:], stdout)
	}
	if len(arguments) != 1 {
		return errors.New("completion requires install, bash, zsh, or fish")
	}
	var script string
	switch arguments[0] {
	case "bash":
		script = bashCompletionScript
	case "zsh":
		script = zshCompletionScript
	case "fish":
		script = fishCompletionScript
	default:
		return errors.New("completion requires install, bash, zsh, or fish")
	}
	_, err := io.WriteString(stdout, script)
	return err
}

type completionInstallResult struct {
	Shell          string `json:"shell"`
	CompletionFile string `json:"completion_file"`
	StartupFile    string `json:"startup_file,omitempty"`
	Changed        bool   `json:"changed"`
}

func completionInstall(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("completion install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	shell := flags.String("shell", "", "bash, zsh, or fish")
	force := flags.Bool("force", false, "replace a conflicting generated completion file")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("completion install accepts only named flags")
	}
	selected := strings.ToLower(strings.TrimSpace(*shell))
	if selected == "" {
		selected = filepath.Base(os.Getenv("SHELL"))
	}
	if selected != "bash" && selected != "zsh" && selected != "fish" {
		return errors.New("could not detect bash, zsh, or fish; use -shell")
	}
	home, err := os.UserHomeDir()
	if err != nil || !filepath.IsAbs(home) {
		return errors.New("locate an absolute home directory for completion installation")
	}
	configRoot := os.Getenv("XDG_CONFIG_HOME")
	if configRoot == "" {
		configRoot = filepath.Join(home, ".config")
	} else if !filepath.IsAbs(configRoot) {
		return errors.New("XDG_CONFIG_HOME must be an absolute path")
	}

	var script, completionPath, startupPath, startupBlock string
	switch selected {
	case "bash":
		script = bashCompletionScript
		completionPath = filepath.Join(configRoot, "steward", "completions", "stewardctl.bash")
		startupPath = filepath.Join(home, ".bashrc")
		if runtime.GOOS == "darwin" {
			if _, statErr := os.Stat(filepath.Join(home, ".bashrc")); errors.Is(statErr, os.ErrNotExist) {
				startupPath = filepath.Join(home, ".bash_profile")
			}
		}
		startupBlock = "source " + shellQuote(completionPath)
	case "zsh":
		script = zshCompletionScript
		completionPath = filepath.Join(configRoot, "steward", "completions", "_stewardctl")
		startupPath = filepath.Join(home, ".zshrc")
		startupBlock = "autoload -Uz compinit\nif ! (( $+functions[compdef] )); then compinit; fi\nsource " + shellQuote(completionPath)
	case "fish":
		script = fishCompletionScript
		completionPath = filepath.Join(configRoot, "fish", "completions", "stewardctl.fish")
	}
	changed, err := installCompletionFile(completionPath, []byte(script), *force)
	if err != nil {
		return err
	}
	if startupPath != "" {
		startupChanged, err := installCompletionStartupBlock(startupPath, startupBlock)
		if err != nil {
			return err
		}
		changed = startupChanged || changed
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(completionInstallResult{
		Shell: selected, CompletionFile: completionPath, StartupFile: startupPath, Changed: changed,
	})
}

func installCompletionFile(path string, content []byte, force bool) (bool, error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return false, fmt.Errorf("create completion directory: %w", err)
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return false, errors.New("completion target must be a regular file, not a link")
		}
		existing, readErr := os.ReadFile(path)
		if readErr != nil {
			return false, fmt.Errorf("read existing completion file: %w", readErr)
		}
		if string(existing) == string(content) {
			return false, nil
		}
		if !force {
			return false, errors.New("completion file already contains different content; inspect it or retry with -force")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect completion target: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".stewardctl-completion-*")
	if err != nil {
		return false, fmt.Errorf("create temporary completion file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func(cause error) error {
		return errors.Join(cause, temporary.Close(), os.Remove(temporaryPath))
	}
	if err := temporary.Chmod(0o644); err != nil {
		return false, cleanup(err)
	}
	if _, err := temporary.Write(content); err != nil {
		return false, cleanup(err)
	}
	if err := temporary.Sync(); err != nil {
		return false, cleanup(err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return false, err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return false, fmt.Errorf("replace completion file: %w", err)
	}
	if err := syncOutputDirectory(path); err != nil {
		return false, err
	}
	return true, nil
}

func installCompletionStartupBlock(path, command string) (bool, error) {
	const begin = "# >>> Steward stewardctl completion >>>"
	const end = "# <<< Steward stewardctl completion <<<"
	var existing []byte
	info, err := os.Stat(path)
	if err == nil {
		if !info.Mode().IsRegular() || info.Size() > 1<<20 {
			return false, errors.New("shell startup file must be a regular file no larger than 1 MiB")
		}
		existing, err = os.ReadFile(path)
		if err != nil {
			return false, fmt.Errorf("read shell startup file: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("inspect shell startup file: %w", err)
	}
	text := string(existing)
	if strings.Contains(text, begin) || strings.Contains(text, end) {
		if strings.Contains(text, begin+"\n"+command+"\n"+end) {
			return false, nil
		}
		return false, errors.New("shell startup file contains a conflicting Steward completion block")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return false, fmt.Errorf("open shell startup file: %w", err)
	}
	prefix := ""
	if len(existing) > 0 && existing[len(existing)-1] != '\n' {
		prefix = "\n"
	}
	_, writeErr := io.WriteString(file, prefix+begin+"\n"+command+"\n"+end+"\n")
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if err := errors.Join(writeErr, file.Close()); err != nil {
		return false, err
	}
	return true, nil
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func writeCompletionCandidates(arguments []string, stdout io.Writer) error {
	for _, candidate := range stewardctlCompletionCandidates(arguments) {
		if _, err := fmt.Fprintln(stdout, candidate); err != nil {
			return err
		}
	}
	return nil
}

func stewardctlCompletionCandidates(arguments []string) []string {
	if len(arguments) > 0 && filepathBase(arguments[0]) == "stewardctl" {
		arguments = arguments[1:]
	}
	current := ""
	if len(arguments) > 0 {
		current = arguments[len(arguments)-1]
	}
	if len(arguments) > 1 {
		previous := arguments[len(arguments)-2]
		leaf := completionLeafPath(arguments[:len(arguments)-2])
		if previous == "-agent" || previous == "-runtime" &&
			(leaf == "agent init" || leaf == "agent create" || strings.HasPrefix(leaf, "agent create ")) {
			return matchingCandidates([]string{"hermes", "openclaw"}, current)
		}
		if previous == "-preset" && leaf == "gateway connector set" {
			return matchingCandidates([]string{"github-issues"}, current)
		}
		if previous == "-authorized-effects" && (leaf == "site init" || strings.HasPrefix(leaf, "site init ")) {
			return matchingCandidates([]string{"optional", "required"}, current)
		}
	}
	if strings.HasPrefix(current, "-") {
		return matchingCandidates(completionFlagsFor(arguments[:len(arguments)-1]), current)
	}
	if len(arguments) > 1 && current == "" && strings.HasPrefix(arguments[len(arguments)-2], "-") {
		return nil
	}
	words := arguments
	if current == "" && len(words) > 0 {
		words = words[:len(words)-1]
	} else if len(words) > 0 {
		words = words[:len(words)-1]
	}
	path := commandWordPath(words)
	if path == "context use" || path == "context delete" {
		config, _, err := loadCLIContextConfig()
		if err == nil {
			names := make([]string, 0, len(config.Contexts))
			for _, context := range config.Contexts {
				names = append(names, context.Name)
			}
			return matchingCandidates(names, current)
		}
	}
	return matchingCandidates(completionTree[path], current)
}

func completionFlagsFor(arguments []string) []string {
	path := completionLeafPath(arguments)
	result := []string{"-h", "-help"}
	for key, flags := range completionFlags {
		if path == key || strings.HasPrefix(path, key+" ") {
			result = append(result, flags...)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func completionLeafPath(arguments []string) string {
	words := make([]string, 0, 3)
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-") || len(words) == 3 {
			break
		}
		words = append(words, argument)
	}
	return strings.Join(words, " ")
}

func commandWordPath(arguments []string) string {
	words := make([]string, 0, 3)
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-") || len(words) == 3 {
			break
		}
		words = append(words, argument)
	}
	for len(words) > 0 {
		path := strings.Join(words, " ")
		if _, found := completionTree[path]; found || path == "context use" || path == "context delete" {
			return path
		}
		words = words[:len(words)-1]
	}
	return ""
}

func matchingCandidates(candidates []string, prefix string) []string {
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		if strings.HasPrefix(candidate, prefix) {
			result = append(result, candidate)
		}
	}
	slices.Sort(result)
	return slices.Compact(result)
}

func filepathBase(value string) string {
	if index := strings.LastIndexAny(value, "/\\"); index >= 0 {
		return value[index+1:]
	}
	return value
}

const bashCompletionScript = `# Steward command completion. Generated by: stewardctl completion bash
_stewardctl_complete() {
	local candidates
	candidates="$(command stewardctl __complete "${COMP_WORDS[@]:1}")"
	COMPREPLY=( $(compgen -W "$candidates" -- "${COMP_WORDS[COMP_CWORD]}") )
}
complete -o default -F _stewardctl_complete stewardctl
`

const zshCompletionScript = `#compdef stewardctl
# Steward command completion. Generated by: stewardctl completion zsh
_stewardctl() {
  local -a candidates
  candidates=("${(@f)$(command stewardctl __complete "${words[@]:1}")}")
  if (( ${#candidates} )); then
    _describe 'stewardctl' candidates
  else
    _files
  fi
}
compdef _stewardctl stewardctl
`

const fishCompletionScript = `# Steward command completion. Generated by: stewardctl completion fish
function __stewardctl_complete
    command stewardctl __complete (commandline -opc)[2..-1] (commandline -ct)
end
complete -c stewardctl -a '(__stewardctl_complete)'
`
