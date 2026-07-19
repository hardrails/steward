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
	"strings"
	"time"

	"github.com/hardrails/steward/internal/agentapp"
)

func agentCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("agent requires init, validate, build, plan, fork, or doctor")
	}
	switch arguments[0] {
	case "init":
		return agentInit(arguments[1:], stdout)
	case "validate":
		return agentValidate(arguments[1:], stdout)
	case "build":
		return agentBuild(arguments[1:], stdout)
	case "plan":
		return agentPlan(arguments[1:], stdout)
	case "fork":
		return agentFork(arguments[1:], stdout)
	case "doctor":
		return agentDoctor(arguments[1:], stdout)
	default:
		return fmt.Errorf("unknown agent command %q; expected init, validate, build, plan, fork, or doctor", arguments[0])
	}
}

func agentInit(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("agent init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	engine := flags.String("runtime", "hermes", "hermes or openclaw")
	name := flags.String("name", "my-agent", "agent name")
	force := flags.Bool("force", false, "replace an existing Stewardfile.cue")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *engine != "hermes" && *engine != "openclaw" {
		return errors.New("agent runtime must be hermes or openclaw")
	}
	if flags.NArg() > 1 {
		return errors.New("agent init accepts at most one project directory")
	}
	directory := "."
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
	contract := "steward.hermes-agent.v1"
	if *engine == "openclaw" {
		contract = "steward.openclaw.v1"
	}
	content := fmt.Sprintf(agentCUETemplate, *name, *engine, strings.Repeat("0", 64), contract)
	if *force {
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			return err
		}
	} else if err := writeNewFile(path, []byte(content), 0o644); err != nil {
		return err
	}
	return writeAgentJSON(stdout, map[string]any{"file": path, "runtime": *engine, "next": "replace the placeholder image, then run stewardctl agent build -file " + path + " -out agent.bundle.json"})
}

const agentCUETemplate = `// Steward agent application. CUE validates and exports this concrete value.
{
  schema: "steward.agent.v1"
  name: %q
  runtime: {
    engine: %q
    image: "replace.invalid/agent@sha256:%s"
    adapter_contract: %q
  }
  model: route: "local/default"
  skills: ["workspace-audit"]
  resources: {
    cpu_millis: 1000
    memory_mib: 1024
    disk_mib: 2048
    pids: 256
  }
  placement: {
    architectures: ["amd64"]
    isolation: "hardened"
  }
  state: persistent: true
  lifetime: mode: "service"
}
`

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
	if err := writeNewFile(*output, raw, 0o644); err != nil {
		return err
	}
	digest, _ := agentapp.DigestJSON(bundle)
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
	flags := flag.NewFlagSet("agent fork", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	bundlePath := flags.String("bundle", "agent.bundle.json", "agent bundle")
	snapshotPath := flags.String("snapshot", "", "snapshot metadata")
	instanceID := flags.String("instance-id", "", "new instance identity; generated when omitted")
	lineageID := flags.String("lineage-id", "", "new lineage identity; generated when omitted")
	ttl := flags.Duration("ttl", 0, "optional fork lifetime, from 1m to 720h")
	onExpiry := flags.String("on-expiry", "", "destroy or hibernate when TTL expires")
	output := flags.String("out", "fork.json", "new fork plan")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *snapshotPath == "" || flags.NArg() != 0 {
		return errors.New("agent fork requires -snapshot and accepts only named flags")
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
	plan, err := agentapp.Fork(bundle, snapshot, *instanceID, *lineageID, *ttl, *onExpiry, time.Now().UTC())
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
	return writeAgentJSON(stdout, map[string]any{"fork": *output, "instance_id": plan.InstanceID, "lineage_id": plan.LineageID, "expires_at": plan.ExpiresAt})
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
		limitations = append(limitations, "the bundled Hermes and OpenClaw qualification evidence currently covers linux/amd64 only")
	}
	return writeAgentJSON(stdout, map[string]any{"os": runtime.GOOS, "architecture": runtime.GOARCH, "profile": profile, "tools": tools, "limitations": limitations})
}

func readCLIArtifact(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > agentapp.MaxArtifactBytes {
		return nil, errors.New("agent artifact must be a regular file no larger than 1 MiB")
	}
	return io.ReadAll(io.LimitReader(file, agentapp.MaxArtifactBytes+1))
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
