package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/hardrails/steward/internal/buildinfo"
)

const supportMatrixSchemaV1 = "steward.support-matrix.v1"

type supportMatrix struct {
	SchemaVersion  string                `json:"schema_version"`
	StewardVersion string                `json:"steward_version"`
	ReleaseChannel string                `json:"release_channel"`
	Platforms      []supportPlatform     `json:"platforms"`
	AgentRuntimes  []supportAgentRuntime `json:"agent_runtimes"`
	Isolation      supportIsolation      `json:"isolation"`
	Interfaces     []string              `json:"interfaces"`
	AuthorityModes []string              `json:"authority_modes"`
	Disconnected   []string              `json:"disconnected_capabilities"`
	Compatibility  supportCompatibility  `json:"compatibility"`
	KnownLimits    []string              `json:"known_limits"`
}

type supportPlatform struct {
	Role          string   `json:"role"`
	HostFamily    string   `json:"host_family"`
	Architectures []string `json:"architectures"`
	Status        string   `json:"status"`
	Requirements  []string `json:"requirements"`
}

type supportAgentRuntime struct {
	Name               string   `json:"name"`
	Status             string   `json:"status"`
	Contract           string   `json:"contract,omitempty"`
	QualifiedPlatforms []string `json:"qualified_platforms,omitempty"`
	SourceMetadata     string   `json:"source_metadata,omitempty"`
	Capabilities       []string `json:"capabilities,omitempty"`
	Reason             string   `json:"reason,omitempty"`
}

type supportIsolation struct {
	ProductionSandbox       string `json:"production_sandbox"`
	ContainerEngine         string `json:"container_engine"`
	MinimumDockerMajor      int    `json:"minimum_docker_major"`
	TenantBoundary          string `json:"tenant_boundary"`
	ControlAuthorityOnNodes bool   `json:"control_authority_on_nodes"`
}

type supportCompatibility struct {
	NodeManifest          string `json:"node_manifest"`
	FormatInspection      string `json:"format_inspection"`
	BackupSchema          string `json:"backup_schema"`
	SupportSchema         string `json:"support_schema"`
	BackwardCompatibility string `json:"backward_compatibility"`
}

func supportCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "matrix" {
		return errors.New("support command requires matrix")
	}
	flags := flag.NewFlagSet("support matrix", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	output := flags.String("output", "human", "human or json")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("support matrix accepts no positional arguments")
	}
	matrix := currentSupportMatrix()
	switch *output {
	case "human":
		return writeSupportMatrixHuman(stdout, matrix)
	case "json":
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		return encoder.Encode(matrix)
	default:
		return errors.New("-output must be human or json")
	}
}

func currentSupportMatrix() supportMatrix {
	version := buildinfo.Resolve()
	channel := "stable"
	if strings.Contains(version, "-") || !strings.HasPrefix(version, "v") {
		channel = "development_or_prerelease"
	}
	return supportMatrix{
		SchemaVersion: supportMatrixSchemaV1, StewardVersion: version, ReleaseChannel: channel,
		Platforms: []supportPlatform{
			{
				Role: "control", HostFamily: "systemd-linux", Architectures: []string{"amd64", "arm64"}, Status: "production",
				Requirements: []string{"local durable storage", "TLS for non-loopback listeners", "no container runtime required"},
			},
			{
				Role: "executor", HostFamily: "systemd-linux", Architectures: []string{"amd64", "arm64"}, Status: "production",
				Requirements: []string{"systemd 235 or newer", "Docker Engine 28 or newer", "gVisor registered as runsc"},
			},
			{
				Role: "operator_and_development", HostFamily: "macos", Architectures: []string{"amd64", "arm64"}, Status: "supported_non_executor",
				Requirements: []string{"native archive or installer", "Linux Executor for production workloads"},
			},
		},
		AgentRuntimes: []supportAgentRuntime{
			{
				Name: "hermes-agent", Status: "qualified", Contract: "steward.hermes-agent.v1",
				QualifiedPlatforms: []string{"linux/amd64"}, SourceMetadata: "adapters/hermes-agent/adapter.json",
				Capabilities: []string{"bounded tasks", "custom skills", "web research", "Codex worker", "Claude Code worker", "controller events"},
			},
			{Name: "openclaw", Status: "not_supported", Reason: "active support is retired pending a separately qualified runtime contract"},
		},
		Isolation: supportIsolation{
			ProductionSandbox: "gvisor-runsc", ContainerEngine: "docker", MinimumDockerMajor: 28,
			TenantBoundary:          "separate sandbox, lifecycle identity, resource reservation, state lineage, and capability network per workload",
			ControlAuthorityOnNodes: false,
		},
		Interfaces:     []string{"CLI", "HTTP API", "MCP stdio", "air-gapped React console"},
		AuthorityModes: []string{"strict-sovereign", "bounded-autonomous"},
		Disconnected: []string{
			"offline installation and OCI import", "local OpenAI-compatible inference gateway", "offline policy evaluation",
			"offline receipt and evidence verification", "stopped-Control backup verification and restore",
		},
		Compatibility: supportCompatibility{
			NodeManifest: "release.json", FormatInspection: "stewardctl upgrade inspect-formats",
			BackupSchema: "steward.control-backup.v1", SupportSchema: supportMatrixSchemaV1,
			BackwardCompatibility: "supported only when the target release manifest accepts every retained format reported by inspect-formats",
		},
		KnownLimits: []string{
			"Executor is not supported on macOS or Windows",
			"the packaged Hermes adapter builder is qualified only on linux/amd64",
			"distribution-specific boot acceptance is not run for every Linux family",
			"the exact production kernel, systemd, Docker, and gVisor combination requires pre-production workload acceptance",
			"Control backup requires a stopped controller and is not an online high-availability protocol",
		},
	}
}

func writeSupportMatrixHuman(writer io.Writer, matrix supportMatrix) error {
	if _, err := fmt.Fprintf(writer, "Steward %s support matrix (%s)\n\n", matrix.StewardVersion, matrix.ReleaseChannel); err != nil {
		return err
	}
	for _, platform := range matrix.Platforms {
		if _, err := fmt.Fprintf(writer, "%s: %s on %s/%s\n", platform.Role, platform.Status, platform.HostFamily, strings.Join(platform.Architectures, ",")); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(writer, "\nAgent runtime: Hermes (%s; %s)\n", matrix.AgentRuntimes[0].Status, strings.Join(matrix.AgentRuntimes[0].QualifiedPlatforms, ",")); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "Production isolation: %s with Docker %d+\n", matrix.Isolation.ProductionSandbox, matrix.Isolation.MinimumDockerMajor); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(writer, "\nKnown limits:"); err != nil {
		return err
	}
	for _, limitation := range matrix.KnownLimits {
		if _, err := fmt.Fprintf(writer, "- %s\n", limitation); err != nil {
			return err
		}
	}
	_, err := fmt.Fprintln(writer, "\nUse -output json for the stable machine-readable contract.")
	return err
}
