package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/agentapp"
)

func agentCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("agent requires create, init, template, validate, build, publish, authorize, service, plan, apply, deploy, deployment, fork, or doctor")
	}
	switch arguments[0] {
	case "create":
		return agentCreate(arguments[1:], stdout)
	case "init":
		return agentInit(arguments[1:], stdout)
	case "template":
		return agentTemplateCommand(arguments[1:], stdout)
	case "validate":
		return agentValidate(arguments[1:], stdout)
	case "build":
		return agentBuild(arguments[1:], stdout)
	case "publish":
		return agentPublish(arguments[1:], stdout)
	case "authorize":
		return agentAuthorize(arguments[1:], stdout)
	case "service":
		return agentServiceCommand(arguments[1:], stdout)
	case "plan":
		return agentPlan(arguments[1:], stdout)
	case "apply":
		if len(arguments) > 1 && !strings.HasPrefix(arguments[1], "-") {
			return agentDeploymentApply(arguments[1:], stdout)
		}
		return agentApply(arguments[1:], stdout)
	case "deploy":
		return agentDeploy(arguments[1:], stdout)
	case "deployment":
		return agentDeployment(arguments[1:], stdout)
	case "fork":
		return agentFork(arguments[1:], stdout)
	case "doctor":
		return agentDoctor(arguments[1:], stdout)
	default:
		return fmt.Errorf("unknown agent command %q; expected create, init, template, validate, build, publish, authorize, service, plan, apply, deploy, deployment, fork, or doctor", arguments[0])
	}
}

// agentCreate is the task-led alias for agent init. Keeping the implementation
// in agentInitWithDefault ensures the concise and expert surfaces produce
// byte-identical application definitions while letting the concise form create a
// same-named project directory by default.
func agentCreate(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || strings.HasPrefix(arguments[0], "-") {
		return errors.New("agent create requires an agent name before its flags")
	}
	name := arguments[0]
	for _, argument := range arguments[1:] {
		if argument == "-name" || strings.HasPrefix(argument, "-name=") {
			return errors.New("agent create takes the agent name positionally; do not also pass -name")
		}
	}
	forwarded := append([]string{"-name", name}, arguments[1:]...)
	return agentInitWithDefault(forwarded, stdout, name)
}

func agentInit(arguments []string, stdout io.Writer) error {
	return agentInitWithDefault(arguments, stdout, ".")
}

func agentInitWithDefault(arguments []string, stdout io.Writer, defaultDirectory string) error {
	flags := flag.NewFlagSet("agent init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	engine := flags.String("runtime", "hermes", "agent runtime; currently hermes")
	templateID := flags.String("template", "workspace", "workspace, research, or developer capability preset")
	name := flags.String("name", "my-agent", "agent name")
	force := flags.Bool("force", false, "replace an existing Stewardfile.cue")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *engine != "hermes" {
		return errors.New("agent runtime must be hermes")
	}
	if err := agentapp.ValidateName(*name); err != nil {
		return err
	}
	if flags.NArg() > 1 {
		return errors.New("agent init accepts at most one project directory")
	}
	directory := defaultDirectory
	if flags.NArg() == 1 {
		directory = flags.Arg(0)
	}
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("create agent project: %w", err)
	}
	path := filepath.Join(directory, "Stewardfile.cue")
	if info, err := os.Lstat(path); err == nil && (!*force || !info.Mode().IsRegular()) {
		return errors.New("Stewardfile.cue already exists; inspect it or use -force for a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	definition, err := agentapp.DefinitionFromTemplate(
		*templateID, *name, "replace.invalid/agent@sha256:"+strings.Repeat("0", 64),
	)
	if err != nil {
		return err
	}
	content := renderAgentCUE(definition)
	if *force {
		if err := replaceAgentFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	} else if err := writeNewFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	return writeAgentJSON(stdout, map[string]any{
		"file": path, "runtime": *engine, "template": *templateID,
		"next": "replace the placeholder image, then run stewardctl agent build -file " + path + " -out agent.bundle.json",
	})
}

func agentTemplateCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || len(arguments) > 2 {
		return errors.New("agent template requires list or show TEMPLATE")
	}
	if arguments[0] == "list" && len(arguments) == 1 {
		return writeAgentJSON(stdout, map[string]any{"templates": agentapp.BuiltinTemplates()})
	}
	templateID := arguments[0]
	if arguments[0] == "show" && len(arguments) == 2 {
		templateID = arguments[1]
	} else if len(arguments) != 1 {
		return errors.New("agent template show requires one template ID")
	}
	template, err := agentapp.GetTemplate(templateID)
	if err != nil {
		return err
	}
	return writeAgentJSON(stdout, template)
}

func renderAgentCUE(definition agentapp.Definition) string {
	var content strings.Builder
	content.WriteString("// Steward agent application. CUE validates and exports this concrete value.\n{\n")
	fmt.Fprintf(&content, "  schema: %s\n  name: %s\n", strconv.Quote(definition.Schema), strconv.Quote(definition.Name))
	fmt.Fprintf(&content, "  tool_profile: %s\n", strconv.Quote(definition.ToolProfile))
	content.WriteString("  runtime: {\n")
	fmt.Fprintf(&content, "    engine: %s\n    image: %s\n    adapter_contract: %s\n",
		strconv.Quote(definition.Runtime.Engine), strconv.Quote(definition.Runtime.Image),
		strconv.Quote(definition.Runtime.AdapterContract))
	content.WriteString("  }\n")
	fmt.Fprintf(&content, "  model: route: %s\n", strconv.Quote(definition.Model.Route))
	fmt.Fprintf(&content, "  skills: %s\n", cueStringList(definition.Skills))
	content.WriteString("  capabilities: {\n")
	if len(definition.Capabilities.ConnectorIDs) > 0 {
		fmt.Fprintf(&content, "    connector_ids: %s\n", cueStringList(definition.Capabilities.ConnectorIDs))
	}
	if definition.Capabilities.ControllerEvents {
		content.WriteString("    controller_events: true\n")
	}
	content.WriteString("  }\n")
	fmt.Fprintf(&content, "  resources: {\n    cpu_millis: %d\n    memory_mib: %d\n    disk_mib: %d\n    pids: %d\n  }\n",
		definition.Resources.CPUMillis, definition.Resources.MemoryMiB,
		definition.Resources.DiskMiB, definition.Resources.PIDs)
	fmt.Fprintf(&content, "  placement: {\n    architectures: %s\n    isolation: %s\n  }\n",
		cueStringList(definition.Placement.Architectures), strconv.Quote(definition.Placement.Isolation))
	fmt.Fprintf(&content, "  state: persistent: %t\n  lifetime: mode: %s\n}\n",
		definition.State.Persistent, strconv.Quote(definition.Lifetime.Mode))
	return content.String()
}

func cueStringList(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = strconv.Quote(value)
	}
	return "[" + strings.Join(quoted, ", ") + "]"
}

func agentValidate(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent validate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	file := flags.String("file", "Stewardfile.cue", "agent JSON or CUE definition")
	cue := flags.String("cue", "cue", "CUE executable")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("agent validate accepts only named flags")
	}
	definition, err := agentapp.LoadDefinition(context.Background(), *file, *cue)
	if err != nil {
		return err
	}
	digest, err := agentapp.DigestJSON(definition)
	if err != nil {
		return err
	}
	return writeAgentJSON(stdout, map[string]any{"valid": true, "name": definition.Name, "runtime": definition.Runtime.Engine, "source_digest": digest})
}

func agentBuild(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent build", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	file := flags.String("file", "Stewardfile.cue", "agent JSON or CUE definition")
	output := flags.String("out", "agent.bundle.json", "new bundle output")
	cue := flags.String("cue", "cue", "CUE executable")
	opa := flags.String("opa", "opa", "OPA executable")
	policyBundle := flags.String("policy-bundle", "", "optional offline OPA bundle file")
	policyQuery := flags.String("policy-query", "data.steward.agent.allow", "OPA allow query")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("agent build accepts only named flags")
	}
	definition, err := agentapp.LoadDefinition(context.Background(), *file, *cue)
	if err != nil {
		return err
	}
	var policy *agentapp.PolicyEvidence
	if *policyBundle != "" {
		input, err := agentapp.MarshalCanonical(definition)
		if err != nil {
			return err
		}
		decision, err := agentapp.EvaluateOPA(context.Background(), *opa, *policyBundle, *policyQuery, input)
		if err != nil {
			return err
		}
		policy = &decision
	}
	bundle, err := agentapp.Build(definition, policy)
	if err != nil {
		return err
	}
	raw, err := agentapp.MarshalCanonical(bundle)
	if err != nil {
		return err
	}
	digest, err := agentapp.DigestJSON(bundle)
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, raw, 0o644); err != nil {
		return err
	}
	return writeAgentJSON(stdout, map[string]any{"bundle": *output, "digest": digest, "runtime": definition.Runtime.Engine, "policy_evaluated": policy != nil})
}

func agentPlan(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent plan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "agent.bundle.json", "agent bundle")
	nodesPath := flags.String("nodes", "nodes.json", "bounded node inventory")
	tenant := flags.String("tenant", "default", "tenant placement scope")
	output := flags.String("out", "", "optional new placement output")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("agent plan accepts only named flags")
	}
	bundleRaw, err := readCLIArtifact(*bundlePath)
	if err != nil {
		return err
	}
	bundle, err := agentapp.DecodeBundle(bundleRaw)
	if err != nil {
		return err
	}
	nodesRaw, err := readCLIArtifact(*nodesPath)
	if err != nil {
		return err
	}
	inventory, err := agentapp.DecodeInventory(nodesRaw)
	if err != nil {
		return err
	}
	decision, scheduleErr := agentapp.Schedule(bundle, *tenant, inventory)
	raw, marshalErr := agentapp.MarshalCanonical(decision)
	if marshalErr != nil {
		return marshalErr
	}
	if *output != "" {
		if err := writeNewFile(*output, raw, 0o644); err != nil {
			return err
		}
	} else if _, err := stdout.Write(raw); err != nil {
		return err
	}
	return scheduleErr
}

func agentFork(arguments []string, stdout io.Writer) error {
	leadingDeployment, arguments := deploymentLeadingName(arguments)
	flags := flag.NewFlagSet("agent fork", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "agent.bundle.json", "agent bundle")
	snapshotPath := flags.String("snapshot", "", "snapshot metadata")
	instanceID := flags.String("instance-id", "", "new instance identity; generated when omitted")
	lineageID := flags.String("lineage-id", "", "new lineage identity; generated when omitted")
	ttl := flags.Duration("ttl", 0, "optional fork lifetime, from 1m to 720h")
	onExpiry := flags.String("on-expiry", "", "destroy when TTL expires")
	output := flags.String("out", "fork.json", "new fork plan")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *snapshotPath == "" || flags.NArg() != 0 {
		return errors.New("agent fork requires -snapshot and accepts one optional leading deployment name")
	}
	if *ttl != 0 && *onExpiry == "" {
		*onExpiry = "destroy"
	}
	if *instanceID == "" {
		generated, err := randomAgentID("agent")
		if err != nil {
			return err
		}
		*instanceID = generated
	}
	if *lineageID == "" {
		generated, err := randomAgentID("lineage")
		if err != nil {
			return err
		}
		*lineageID = generated
	}
	bundleRaw, err := readCLIArtifact(*bundlePath)
	if err != nil {
		return err
	}
	bundle, err := agentapp.DecodeBundle(bundleRaw)
	if err != nil {
		return err
	}
	snapshotRaw, err := readCLIArtifact(*snapshotPath)
	if err != nil {
		return err
	}
	snapshot, err := agentapp.DecodeSnapshot(snapshotRaw)
	if err != nil {
		return err
	}
	deploymentID := bundle.Definition.Name + "-fork"
	if leadingDeployment != "" {
		deploymentID = leadingDeployment
	}
	plan, err := agentapp.Fork(bundle, snapshot, deploymentID, *instanceID, *lineageID, *ttl, *onExpiry, time.Now().UTC())
	if err != nil {
		return err
	}
	raw, err := agentapp.MarshalCanonical(plan)
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, raw, 0o644); err != nil {
		return err
	}
	return writeAgentJSON(stdout, map[string]any{
		"fork": *output, "deployment": plan.DeploymentID, "instance_id": plan.InstanceID,
		"lineage_id": plan.LineageID, "source_node_id": plan.SourceNodeID,
		"expires_at": plan.ExpiresAt,
		"next":       "stewardctl agent authorize SITE_DIRECTORY -fork-plan " + *output,
	})
}

func agentDoctor(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("agent doctor accepts no arguments")
	}
	tools := map[string]bool{}
	for _, name := range []string{"docker", "cue", "opa", "limactl", "runsc"} {
		_, err := exec.LookPath(name)
		tools[name] = err == nil
	}
	profile := "development"
	limitations := []string{}
	if runtime.GOOS == "linux" && tools["docker"] && tools["runsc"] {
		profile = "hardened"
	}
	if runtime.GOOS == "darwin" {
		limitations = append(limitations, "Docker Desktop is a development profile; hardened workloads belong in a managed Linux VM with gVisor")
	}
	if runtime.GOARCH == "arm64" {
		limitations = append(limitations, "the bundled Hermes qualification evidence currently covers linux/amd64 only")
	}
	return writeAgentJSON(stdout, map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "profile": profile, "tools": tools, "limitations": limitations})
}

func readCLIArtifact(path string) ([]byte, error) {
	return readBounded(path)
}

func replaceAgentFile(path string, contents []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".steward-agent-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	cleanup := func(cause error) error {
		return errors.Join(cause, temporary.Close(), os.Remove(temporaryPath))
	}
	if err := temporary.Chmod(mode); err != nil {
		return cleanup(err)
	}
	if _, err := temporary.Write(contents); err != nil {
		return cleanup(err)
	}
	if err := temporary.Sync(); err != nil {
		return cleanup(err)
	}
	if err := temporary.Close(); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		_ = os.Remove(temporaryPath)
		return errors.New("Stewardfile.cue replacement target must be a regular file")
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		_ = os.Remove(temporaryPath)
		return err
	}
	if err := os.Rename(temporaryPath, path); err != nil {
		_ = os.Remove(temporaryPath)
		return err
	}
	return syncOutputDirectory(path)
}

func randomAgentID(prefix string) (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("generate %s identity: %w", prefix, err)
	}
	return prefix + "-" + hex.EncodeToString(value), nil
}

func writeAgentJSON(writer io.Writer, value any) error {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
