package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gatewayclient"
	"github.com/hardrails/steward/internal/nodeclient"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	legacyCLIContextSchema = "steward.cli-context.v1"
	priorCLIContextSchema  = "steward.cli-context.v2"
	cliContextSchema       = "steward.cli-context.v3"
	maxCLIContextFileBytes = 64 << 10
	maxCLIContexts         = 32
)

type cliContext struct {
	Name             string `json:"name"`
	ControlURL       string `json:"control_url,omitempty"`
	TokenFile        string `json:"token_file,omitempty"`
	CAFile           string `json:"ca_file,omitempty"`
	NodeURL          string `json:"node_url,omitempty"`
	NodeTokenFile    string `json:"node_token_file,omitempty"`
	GatewayURL       string `json:"gateway_url,omitempty"`
	GatewayTokenFile string `json:"gateway_token_file,omitempty"`
	ServiceTrustFile string `json:"service_trust_file,omitempty"`
	TaskKeyFile      string `json:"task_key_file,omitempty"`
	TaskKeyID        string `json:"task_key_id,omitempty"`
	TenantID         string `json:"tenant_id,omitempty"`
	NodeID           string `json:"node_id,omitempty"`
}

type cliContextConfig struct {
	SchemaVersion string       `json:"schema_version"`
	Current       string       `json:"current,omitempty"`
	Contexts      []cliContext `json:"contexts"`
}

type controlContextCommandSpec struct {
	network bool
	token   bool
	tenant  bool
	node    bool
}

var controlContextCommands = map[string]controlContextCommandSpec{
	"tenant create":           {network: true, token: true},
	"tenant list":             {network: true, token: true},
	"operator issue":          {network: true, token: true},
	"operator revoke":         {network: true, token: true},
	"enrollment create":       {network: true, token: true},
	"enrollment exchange":     {network: true},
	"node list":               {network: true, token: true, tenant: true},
	"node status":             {network: true, token: true, tenant: true, node: true},
	"node revoke":             {network: true, token: true},
	"node-credential revoke":  {network: true, token: true},
	"operations status":       {network: true, token: true, tenant: true},
	"attention list":          {network: true, token: true, tenant: true},
	"agent list":              {network: true, token: true, tenant: true, node: true},
	"command submit":          {network: true, token: true, tenant: true, node: true},
	"command status":          {network: true, token: true, tenant: true, node: true},
	"command list":            {network: true, token: true, tenant: true, node: true},
	"credential list":         {network: true, token: true, tenant: true},
	"evidence status":         {network: true, token: true, node: true},
	"evidence export":         {network: true, token: true, node: true},
	"evidence-capture arm":    {network: true, token: true, tenant: true, node: true},
	"evidence-capture status": {network: true, token: true, node: true},
	"evidence-capture seal":   {network: true, token: true, node: true},
	"evidence-capture export": {network: true, token: true, node: true},
	"evidence-capture delete": {network: true, token: true, node: true},
}

func contextCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("context requires set, use, show, list, or delete")
	}
	switch arguments[0] {
	case "set":
		return contextSet(arguments[1:], stdout)
	case "use":
		return contextUse(arguments[1:], stdout)
	case "show":
		return contextShow(arguments[1:], stdout)
	case "list":
		return contextList(arguments[1:], stdout)
	case "delete":
		return contextDelete(arguments[1:], stdout)
	default:
		return errors.New("context requires set, use, show, list, or delete")
	}
}

func contextSet(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return errors.New("context set requires a context name before its flags")
	}
	name := arguments[0]
	if !validCLIContextName(name) {
		return errors.New("context name is invalid")
	}
	return withCLIContextConfigMutation(func(config *cliContextConfig, path string) error {
		existing, _ := findCLIContext(*config, name)
		if existing.Name == "" {
			existing = cliContext{Name: name}
		}
		flags := flag.NewFlagSet("context set", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		controlURL := flags.String("control-url", existing.ControlURL, "Steward Control origin")
		tokenFile := flags.String("token-file", existing.TokenFile, "operator token file path")
		caFile := flags.String("ca-file", existing.CAFile, "private CA PEM bundle path")
		nodeURL := flags.String("node-url", existing.NodeURL, "loopback Executor origin")
		nodeTokenFile := flags.String("node-token-file", existing.NodeTokenFile, "owner-only Executor token file path")
		gatewayURL := flags.String("gateway-url", existing.GatewayURL, "loopback Gateway service origin")
		gatewayTokenFile := flags.String("gateway-token-file", existing.GatewayTokenFile, "owner-only Gateway service token path")
		serviceTrustFile := flags.String("service-trust", existing.ServiceTrustFile, "Gateway service-trust inventory path")
		taskKeyFile := flags.String("task-key", existing.TaskKeyFile, "owner-only task-authority private key path")
		taskKeyID := flags.String("task-key-id", existing.TaskKeyID, "admitted task-authority key ID")
		tenantID := flags.String("tenant-id", existing.TenantID, "default tenant for scoped operations")
		nodeID := flags.String("node-id", existing.NodeID, "default node for scoped operations")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("context set accepts one name followed by named flags")
		}
		if !validOptionalControlIdentifier(*tenantID, 128) || !validOptionalControlIdentifier(*nodeID, 128) {
			return errors.New("context tenant or node is invalid")
		}
		if *tokenFile != "" && *controlURL == "" {
			*controlURL = "http://127.0.0.1:8443"
		}
		if *nodeTokenFile != "" && *nodeURL == "" {
			*nodeURL = "http://127.0.0.1:8090"
		}
		if *gatewayTokenFile != "" && *gatewayURL == "" {
			*gatewayURL = "http://127.0.0.1:8091"
		}
		if (*controlURL == "") != (*tokenFile == "") || (*nodeURL == "") != (*nodeTokenFile == "") ||
			(*gatewayURL == "") != (*gatewayTokenFile == "") ||
			*tokenFile == "" && *nodeTokenFile == "" && *gatewayTokenFile == "" {
			return errors.New("context requires a complete control, node, or Gateway connection")
		}
		resolvedToken, err := absoluteContextPath(*tokenFile, false)
		if err != nil {
			return fmt.Errorf("resolve context token file: %w", err)
		}
		resolvedCA, err := absoluteContextPath(*caFile, false)
		if err != nil {
			return fmt.Errorf("resolve context CA file: %w", err)
		}
		resolvedNodeToken, err := absoluteContextPath(*nodeTokenFile, false)
		if err != nil {
			return fmt.Errorf("resolve context node token file: %w", err)
		}
		resolvedGatewayToken, err := absoluteContextPath(*gatewayTokenFile, false)
		if err != nil {
			return fmt.Errorf("resolve context Gateway token file: %w", err)
		}
		resolvedServiceTrust, err := absoluteContextPath(*serviceTrustFile, false)
		if err != nil {
			return fmt.Errorf("resolve context service trust file: %w", err)
		}
		resolvedTaskKey, err := absoluteContextPath(*taskKeyFile, false)
		if err != nil {
			return fmt.Errorf("resolve context task key file: %w", err)
		}
		if resolvedToken != "" {
			if _, err := controlclient.NewFromFiles(*controlURL, resolvedToken, resolvedCA); err != nil {
				return fmt.Errorf("validate context control connection: %w", err)
			}
		} else if resolvedCA != "" {
			return errors.New("context CA file requires a control connection")
		}
		if resolvedNodeToken != "" {
			if _, err := nodeclient.NewFromTokenFile(*nodeURL, resolvedNodeToken); err != nil {
				return fmt.Errorf("validate context node connection: %w", err)
			}
		}
		if resolvedGatewayToken != "" {
			token, err := nodeclient.ReadToken(resolvedGatewayToken)
			if err != nil {
				return fmt.Errorf("validate context Gateway token: %w", err)
			}
			if _, err := gatewayclient.New(*gatewayURL, token); err != nil {
				return fmt.Errorf("validate context Gateway connection: %w", err)
			}
		}
		taskDefaults := resolvedServiceTrust != "" || resolvedTaskKey != "" || *taskKeyID != ""
		if taskDefaults && (resolvedServiceTrust == "" || resolvedTaskKey == "" || !taskIdentifier(*taskKeyID) || resolvedGatewayToken == "") {
			return errors.New("task defaults require Gateway, service trust, task key, and a valid task key ID")
		}
		if resolvedServiceTrust != "" {
			if _, err := securefile.Read(resolvedServiceTrust, maxServiceTrustBytes, securefile.TrustFile); err != nil {
				return fmt.Errorf("validate context service trust: %w", err)
			}
			if _, err := readPrivateKey(resolvedTaskKey); err != nil {
				return fmt.Errorf("validate context task key: %w", err)
			}
		}
		next := cliContext{
			Name: name, ControlURL: *controlURL, TokenFile: resolvedToken, CAFile: resolvedCA,
			NodeURL: *nodeURL, NodeTokenFile: resolvedNodeToken,
			GatewayURL: *gatewayURL, GatewayTokenFile: resolvedGatewayToken,
			ServiceTrustFile: resolvedServiceTrust, TaskKeyFile: resolvedTaskKey, TaskKeyID: *taskKeyID,
			TenantID: *tenantID, NodeID: *nodeID,
		}
		upsertCLIContext(config, next)
		config.Current = name
		if err := writeCLIContextConfig(path, *config); err != nil {
			return err
		}
		return writeContextJSON(stdout, struct {
			Current bool       `json:"current"`
			Context cliContext `json:"context"`
		}{Current: true, Context: next})
	})
}

func contextUse(arguments []string, stdout io.Writer) error {
	if len(arguments) != 1 || !validCLIContextName(arguments[0]) {
		return errors.New("context use requires one context name")
	}
	return withCLIContextConfigMutation(func(config *cliContextConfig, path string) error {
		selected, found := findCLIContext(*config, arguments[0])
		if !found {
			return fmt.Errorf("context %q does not exist", arguments[0])
		}
		config.Current = selected.Name
		if err := writeCLIContextConfig(path, *config); err != nil {
			return err
		}
		return writeContextJSON(stdout, struct {
			Current string `json:"current"`
		}{Current: selected.Name})
	})
}

func contextShow(arguments []string, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("context show accepts no arguments")
	}
	config, path, err := loadCLIContextConfig()
	if err != nil {
		return err
	}
	selected, err := selectedCLIContext(config)
	if err != nil {
		return err
	}
	return writeContextJSON(stdout, struct {
		ContextFile string     `json:"context_file"`
		Context     cliContext `json:"context"`
	}{ContextFile: path, Context: selected})
}

func contextList(arguments []string, stdout io.Writer) error {
	if len(arguments) != 0 {
		return errors.New("context list accepts no arguments")
	}
	config, _, err := loadCLIContextConfig()
	if err != nil {
		return err
	}
	return writeContextJSON(stdout, struct {
		Current  string       `json:"current,omitempty"`
		Contexts []cliContext `json:"contexts"`
	}{Current: config.Current, Contexts: config.Contexts})
}

func contextDelete(arguments []string, stdout io.Writer) error {
	if len(arguments) != 1 || !validCLIContextName(arguments[0]) {
		return errors.New("context delete requires one context name")
	}
	return withCLIContextConfigMutation(func(config *cliContextConfig, path string) error {
		index := slices.IndexFunc(config.Contexts, func(context cliContext) bool { return context.Name == arguments[0] })
		if index < 0 {
			return fmt.Errorf("context %q does not exist", arguments[0])
		}
		config.Contexts = slices.Delete(config.Contexts, index, index+1)
		if config.Current == arguments[0] {
			config.Current = ""
		}
		if err := writeCLIContextConfig(path, *config); err != nil {
			return err
		}
		return writeContextJSON(stdout, struct {
			Deleted string `json:"deleted"`
		}{Deleted: arguments[0]})
	})
}

func withCLIContextConfigMutation(update func(*cliContextConfig, string) error) (err error) {
	path, err := cliContextFilePath()
	if err != nil {
		return err
	}
	unlock, err := lockCLIContextConfig(path)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, unlock()) }()
	config, loadedPath, err := loadCLIContextConfig()
	if err != nil {
		return err
	}
	if loadedPath != path {
		return errors.New("CLI context file changed while acquiring its write lock")
	}
	return update(&config, path)
}

func applyCLIContext(arguments []string) ([]string, error) {
	if len(arguments) < 2 {
		return arguments, nil
	}
	arguments, disabled, err := stripNoContextFlag(arguments)
	if err != nil || disabled {
		return arguments, err
	}
	spec, found := controlContextCommands[arguments[0]+" "+arguments[1]]
	if !found || !spec.network {
		return arguments, nil
	}
	config, _, err := loadCLIContextConfig()
	if err != nil {
		return nil, err
	}
	if config.Current == "" && os.Getenv("STEWARD_CONTEXT") == "" {
		return arguments, nil
	}
	selected, err := selectedCLIContext(config)
	if err != nil {
		return nil, err
	}
	result := append([]string(nil), arguments...)
	result = injectContextFlag(result, "control-url", selected.ControlURL)
	result = injectContextFlag(result, "ca-file", selected.CAFile)
	if spec.token {
		result = injectContextFlag(result, "token-file", selected.TokenFile)
	}
	if spec.tenant {
		result = injectContextFlag(result, "tenant-id", selected.TenantID)
	}
	if spec.node {
		result = injectContextFlag(result, "node-id", selected.NodeID)
	}
	return result, nil
}

func applyNodeCLIContext(arguments []string) ([]string, error) {
	arguments, disabled, err := stripNoContextFlag(arguments)
	if err != nil || disabled {
		return arguments, err
	}
	config, _, err := loadCLIContextConfig()
	if err != nil {
		return nil, err
	}
	if config.Current == "" && os.Getenv("STEWARD_CONTEXT") == "" {
		return arguments, nil
	}
	selected, err := selectedCLIContext(config)
	if err != nil {
		return nil, err
	}
	if selected.NodeURL == "" || selected.NodeTokenFile == "" {
		return arguments, nil
	}
	result := append([]string(nil), arguments...)
	if !hasNamedFlag(result, "node-url") {
		result = append(result, "-node-url", selected.NodeURL)
	}
	if !hasNamedFlag(result, "token-file") {
		result = append(result, "-token-file", selected.NodeTokenFile)
	}
	return result, nil
}

func stripNoContextFlag(arguments []string) ([]string, bool, error) {
	result := make([]string, 0, len(arguments))
	found := false
	for _, argument := range arguments {
		if argument == "-no-context" || argument == "--no-context" {
			if found {
				return nil, false, errors.New("-no-context may be supplied only once")
			}
			found = true
			continue
		}
		result = append(result, argument)
	}
	return result, found, nil
}

func injectContextFlag(arguments []string, name, value string) []string {
	if value == "" || hasNamedFlag(arguments[2:], name) {
		return arguments
	}
	return append(arguments, "-"+name, value)
}

func hasNamedFlag(arguments []string, name string) bool {
	short, long := "-"+name, "--"+name
	for _, argument := range arguments {
		if argument == short || argument == long || strings.HasPrefix(argument, short+"=") ||
			strings.HasPrefix(argument, long+"=") {
			return true
		}
	}
	return false
}

func loadCLIContextConfig() (cliContextConfig, string, error) {
	path, err := cliContextFilePath()
	if err != nil {
		return cliContextConfig{}, "", err
	}
	raw, err := securefile.Read(path, maxCLIContextFileBytes, securefile.OwnerOnly)
	if errors.Is(err, os.ErrNotExist) {
		return cliContextConfig{SchemaVersion: cliContextSchema, Contexts: []cliContext{}}, path, nil
	}
	if err != nil {
		return cliContextConfig{}, path, fmt.Errorf("CLI context file must be a bounded owner-only regular file: %w", err)
	}
	var config cliContextConfig
	if err := dsse.DecodeStrictInto(raw, maxCLIContextFileBytes, &config); err != nil {
		return cliContextConfig{}, path, fmt.Errorf("decode CLI context file: %w", err)
	}
	if err := validateCLIContextConfig(config); err != nil {
		return cliContextConfig{}, path, err
	}
	return config, path, nil
}

func validateCLIContextConfig(config cliContextConfig) error {
	if (config.SchemaVersion != cliContextSchema && config.SchemaVersion != priorCLIContextSchema && config.SchemaVersion != legacyCLIContextSchema) || len(config.Contexts) > maxCLIContexts {
		return errors.New("CLI context file has an unsupported schema or too many contexts")
	}
	seen := make(map[string]struct{}, len(config.Contexts))
	for _, context := range config.Contexts {
		controlComplete := context.ControlURL != "" && context.TokenFile != "" && filepath.IsAbs(context.TokenFile)
		nodeComplete := context.NodeURL != "" && context.NodeTokenFile != "" && filepath.IsAbs(context.NodeTokenFile)
		gatewayComplete := context.GatewayURL != "" && context.GatewayTokenFile != "" && filepath.IsAbs(context.GatewayTokenFile)
		taskDefaults := context.ServiceTrustFile != "" || context.TaskKeyFile != "" || context.TaskKeyID != ""
		if !validCLIContextName(context.Name) || !controlComplete && !nodeComplete && !gatewayComplete ||
			(context.ControlURL == "") != (context.TokenFile == "") ||
			(context.NodeURL == "") != (context.NodeTokenFile == "") ||
			(context.GatewayURL == "") != (context.GatewayTokenFile == "") ||
			context.CAFile != "" && (!controlComplete || !filepath.IsAbs(context.CAFile)) ||
			config.SchemaVersion == legacyCLIContextSchema && (nodeComplete || gatewayComplete || taskDefaults) ||
			config.SchemaVersion == priorCLIContextSchema && (gatewayComplete || taskDefaults) ||
			taskDefaults && (!gatewayComplete || !filepath.IsAbs(context.ServiceTrustFile) ||
				!filepath.IsAbs(context.TaskKeyFile) || !taskIdentifier(context.TaskKeyID)) ||
			!validOptionalControlIdentifier(context.TenantID, 128) || !validOptionalControlIdentifier(context.NodeID, 128) {
			return errors.New("CLI context file contains an invalid context")
		}
		if nodeComplete {
			if _, err := nodeclient.New(context.NodeURL, "context-validation"); err != nil {
				return errors.New("CLI context file contains an invalid node connection")
			}
		}
		if gatewayComplete {
			if _, err := gatewayclient.New(context.GatewayURL, "context-validation"); err != nil {
				return errors.New("CLI context file contains an invalid Gateway connection")
			}
		}
		if _, duplicate := seen[context.Name]; duplicate {
			return errors.New("CLI context file contains duplicate context names")
		}
		seen[context.Name] = struct{}{}
	}
	if config.Current != "" {
		if _, found := seen[config.Current]; !found {
			return errors.New("CLI context file selects an unknown current context")
		}
	}
	return nil
}

func writeCLIContextConfig(path string, config cliContextConfig) error {
	config.SchemaVersion = cliContextSchema
	slices.SortFunc(config.Contexts, func(left, right cliContext) int { return strings.Compare(left.Name, right.Name) })
	if err := validateCLIContextConfig(config); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	if len(raw) > maxCLIContextFileBytes {
		return errors.New("CLI context file exceeds its size limit")
	}
	directory := filepath.Dir(path)
	if err := ensureCLIContextDirectory(directory); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".contexts-*")
	if err != nil {
		return fmt.Errorf("create temporary CLI context file: %w", err)
	}
	temporaryPath := temporary.Name()
	cleanup := func(cause error) error {
		return errors.Join(cause, temporary.Close(), os.Remove(temporaryPath))
	}
	if err := temporary.Chmod(0o600); err != nil {
		return cleanup(err)
	}
	if _, err := temporary.Write(raw); err != nil {
		return cleanup(err)
	}
	if err := temporary.Sync(); err != nil {
		return cleanup(err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return fmt.Errorf("replace CLI context file: %w", err)
	}
	return syncOutputDirectory(path)
}

func ensureCLIContextDirectory(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("create CLI context directory: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("CLI context directory must be an owner-only real directory")
	}
	return nil
}

func cliContextFilePath() (string, error) {
	if override := os.Getenv("STEWARD_CONTEXT_FILE"); override != "" {
		if !filepath.IsAbs(override) {
			return "", errors.New("STEWARD_CONTEXT_FILE must be an absolute path")
		}
		return filepath.Clean(override), nil
	}
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("locate user configuration directory: %w", err)
	}
	return filepath.Join(root, "steward", "contexts.json"), nil
}

func selectedCLIContext(config cliContextConfig) (cliContext, error) {
	name := os.Getenv("STEWARD_CONTEXT")
	if name == "" {
		name = config.Current
	}
	if name == "" {
		return cliContext{}, errors.New("no Steward CLI context is selected; run 'stewardctl context set NAME ...'")
	}
	context, found := findCLIContext(config, name)
	if !found {
		return cliContext{}, fmt.Errorf("selected Steward CLI context %q does not exist", name)
	}
	return context, nil
}

func findCLIContext(config cliContextConfig, name string) (cliContext, bool) {
	for _, context := range config.Contexts {
		if context.Name == name {
			return context, true
		}
	}
	return cliContext{}, false
}

func upsertCLIContext(config *cliContextConfig, next cliContext) {
	for index := range config.Contexts {
		if config.Contexts[index].Name == next.Name {
			config.Contexts[index] = next
			return
		}
	}
	config.Contexts = append(config.Contexts, next)
}

func absoluteContextPath(value string, required bool) (string, error) {
	if value == "" {
		if required {
			return "", errors.New("path is required")
		}
		return "", nil
	}
	resolved, err := filepath.Abs(value)
	if err != nil {
		return "", err
	}
	return filepath.Clean(resolved), nil
}

func validCLIContextName(value string) bool {
	if len(value) == 0 || len(value) > 64 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func writeContextJSON(stdout io.Writer, value any) error {
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
