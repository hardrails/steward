package main

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
)

var completionTree = map[string][]string{
	"":                 {"context", "completion", "keygen", "key", "capsule", "policy", "permit", "task", "executor-command", "control", "evidence", "node", "gateway", "secret", "image", "agent-release", "agent-catalog", "activation", "rollout", "upgrade", "version"},
	"context":          {"set", "use", "show", "list", "delete"},
	"completion":       {"bash", "zsh", "fish"},
	"key":              {"match"},
	"capsule":          {"sign", "verify"},
	"policy":           {"sign", "verify"},
	"permit":           {"issue", "approve", "verify", "audit", "bundle"},
	"permit bundle":    {"issue", "approve", "verify", "audit"},
	"task":             {"issue", "verify", "audit", "submit", "status", "observe", "wait"},
	"executor-command": {"issue", "verify"},
	"control":          {"pki", "tenant", "operator", "enrollment", "node", "node-credential", "operations", "attention", "command", "credential", "evidence", "evidence-capture"},
	"control pki":      {"create"},
	"control tenant":   {"create", "list"},
	"control operator": {"issue", "revoke"},
	"control enrollment": {
		"create", "exchange",
	},
	"control node":             {"list", "status", "revoke"},
	"control node-credential":  {"revoke"},
	"control operations":       {"status"},
	"control attention":        {"list"},
	"control command":          {"submit", "status", "list"},
	"control credential":       {"list"},
	"control evidence":         {"status", "export", "verify"},
	"control evidence-capture": {"arm", "status", "seal", "export", "verify", "delete"},
	"evidence":                 {"verify", "export"},
	"node":                     {"admit", "status", "logs", "egress", "start", "stop", "destroy", "purge-state"},
	"gateway":                  {"validate", "route", "connector", "service", "effects"},
	"gateway route":            {"add", "remove", "list"},
	"gateway connector":        {"add", "remove", "list", "trust"},
	"gateway service":          {"add", "remove", "list", "trust"},
	"gateway effects":          {"check"},
	"secret":                   {"materialization", "openbao"},
	"secret materialization":   {"check", "prepare"},
	"secret openbao":           {"compile"},
	"image":                    {"inspect", "import"},
	"agent-release":            {"issue", "verify"},
	"agent-catalog":            {"issue", "verify", "list", "search", "show", "compare"},
	"activation":               {"create", "attach", "run", "status", "verify"},
	"rollout":                  {"create", "run", "status", "verify"},
	"upgrade":                  {"check-drained", "inspect-formats"},
}

var completionFlags = map[string][]string{
	"context set":               {"-control-url", "-token-file", "-ca-file", "-tenant-id", "-node-id"},
	"control":                   {"-control-url", "-token-file", "-ca-file", "-no-context"},
	"control node":              {"-tenant-id", "-node-id", "-after", "-limit"},
	"control operations status": {"-tenant-id"},
	"control attention list":    {"-tenant-id", "-reason", "-cursor", "-limit"},
	"control command submit":    {"-tenant-id", "-node-id", "-command"},
	"control command status":    {"-tenant-id", "-node-id", "-command-id"},
	"control command list":      {"-tenant-id", "-node-id", "-state", "-terminal-status", "-cursor", "-limit"},
	"control credential list":   {"-tenant-id", "-kind", "-role", "-node-id", "-revoked", "-cursor", "-limit"},
	"control evidence":          {"-node-id", "-out", "-in", "-witness-public-key"},
	"control evidence-capture":  {"-tenant-id", "-node-id", "-capture-id", "-request-id", "-runtime-ref", "-out", "-in"},
	"executor-command issue":    {"-command-id", "-tenant-id", "-node-id", "-instance-id", "-runtime-ref", "-kind", "-claim-generation", "-instance-generation", "-sequence", "-payload", "-key", "-key-id", "-out"},
	"node":                      {"-node-url", "-token-file", "-runtime-ref", "-capsule", "-intent", "-tenant-id", "-node-id", "-lineage-id", "-generation"},
	"gateway":                   {"-config", "-tenant-id", "-node-id", "-receipt-file", "-receipt-key-file", "-receipt-node-id", "-receipt-epoch"},
	"activation":                {"-workspace", "-control-url", "-token-file", "-ca-file", "-tenant-id", "-node-id"},
	"rollout":                   {"-workspace", "-control-url", "-token-file", "-ca-file", "-tenant-id"},
}

func completionCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) != 1 {
		return errors.New("completion requires bash, zsh, or fish")
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
		return errors.New("completion requires bash, zsh, or fish")
	}
	_, err := io.WriteString(stdout, script)
	return err
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
	if strings.HasPrefix(current, "-") {
		return matchingCandidates(completionFlagsFor(arguments[:len(arguments)-1]), current)
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
  local -a candidates
  mapfile -t candidates < <(command stewardctl __complete "${COMP_WORDS[@]:1}")
  COMPREPLY=( $(compgen -W "${candidates[*]}" -- "${COMP_WORDS[COMP_CWORD]}") )
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
