// Package agentapp defines Steward's portable, runtime-neutral agent application
// artifact. It deliberately contains no credential material or executable host
// command: the existing admission and Executor boundaries remain authoritative.
package agentapp

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	DefinitionSchema = "steward.agent.v1"
	BundleSchema     = "steward.agent.bundle.v1"
	InventorySchema  = "steward.nodes.v1"
	SnapshotSchema   = "steward.agent.snapshot.v1"
	ForkSchema       = "steward.agent.fork.v1"
	MaxArtifactBytes = 1 << 20
)

type Definition struct {
	Schema       string             `json:"schema"`
	Name         string             `json:"name"`
	Runtime      Runtime            `json:"runtime"`
	Model        Model              `json:"model"`
	Skills       []string           `json:"skills,omitempty"`
	MCP          []string           `json:"mcp_servers,omitempty"`
	Capabilities CapabilityRequests `json:"capabilities,omitempty"`
	Resources    Resources          `json:"resources"`
	Placement    Placement          `json:"placement"`
	State        State              `json:"state"`
	Lifetime     Lifetime           `json:"lifetime"`
}

type Runtime struct {
	Engine          string `json:"engine"`
	Image           string `json:"image"`
	AdapterContract string `json:"adapter_contract"`
}

type Model struct {
	Route string `json:"route"`
}

// CapabilityRequests names positive network capabilities. Inference and the
// runtime's bounded task service are implied by every agent application; raw
// credentials and upstream origins never belong here.
type CapabilityRequests struct {
	EgressRouteIDs   []string `json:"egress_route_ids,omitempty"`
	ConnectorIDs     []string `json:"connector_ids,omitempty"`
	ControllerEvents bool     `json:"controller_events,omitempty"`
}

type Resources struct {
	CPUMillis int64 `json:"cpu_millis"`
	MemoryMiB int64 `json:"memory_mib"`
	DiskMiB   int64 `json:"disk_mib"`
	PIDs      int64 `json:"pids"`
}

type Placement struct {
	Architectures   []string `json:"architectures"`
	Isolation       string   `json:"isolation"`
	RequiredLabels  []Label  `json:"required_labels,omitempty"`
	PreferredLabels []Label  `json:"preferred_labels,omitempty"`
	Tolerations     []string `json:"tolerations,omitempty"`
	SpreadBy        string   `json:"spread_by,omitempty"`
}

type Label struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type State struct {
	Persistent bool   `json:"persistent"`
	SnapshotID string `json:"snapshot_id,omitempty"`
}

type Lifetime struct {
	Mode       string `json:"mode"`
	TTLSeconds int64  `json:"ttl_seconds,omitempty"`
	OnExpiry   string `json:"on_expiry,omitempty"`
}

type PolicyEvidence struct {
	BundleDigest string `json:"bundle_digest"`
	Query        string `json:"query"`
	Allowed      bool   `json:"allowed"`
}

type Bundle struct {
	Schema       string          `json:"schema"`
	SourceDigest string          `json:"source_digest"`
	Definition   Definition      `json:"definition"`
	Policy       *PolicyEvidence `json:"policy,omitempty"`
}

func DecodeDefinition(raw []byte) (Definition, error) {
	var value Definition
	if err := dsse.DecodeStrictInto(raw, MaxArtifactBytes, &value); err != nil {
		return Definition{}, fmt.Errorf("decode agent definition: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Definition{}, err
	}
	return value, nil
}

func DecodeBundle(raw []byte) (Bundle, error) {
	var value Bundle
	if err := dsse.DecodeStrictInto(raw, MaxArtifactBytes, &value); err != nil {
		return Bundle{}, fmt.Errorf("decode agent bundle: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Bundle{}, err
	}
	return value, nil
}

func (value Bundle) Validate() error {
	if value.Schema != BundleSchema {
		return errors.New("agent bundle schema must be " + BundleSchema)
	}
	if err := value.Definition.Validate(); err != nil {
		return err
	}
	expected, err := DigestJSON(value.Definition)
	if err != nil {
		return err
	}
	if value.SourceDigest != expected {
		return errors.New("agent bundle source_digest does not match its definition")
	}
	if value.Policy != nil {
		if !validDigest(value.Policy.BundleDigest) || !validQuery(value.Policy.Query) || !value.Policy.Allowed {
			return errors.New("agent bundle policy evidence is invalid or denied")
		}
	}
	return nil
}

func Build(definition Definition, policy *PolicyEvidence) (Bundle, error) {
	if err := definition.Validate(); err != nil {
		return Bundle{}, err
	}
	digest, err := DigestJSON(definition)
	if err != nil {
		return Bundle{}, err
	}
	bundle := Bundle{Schema: BundleSchema, SourceDigest: digest, Definition: definition, Policy: policy}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return Bundle{}, err
	}
	return DecodeBundle(raw)
}

func MarshalCanonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxArtifactBytes {
		return nil, errors.New("agent artifact exceeds 1 MiB")
	}
	return append(raw, '\n'), nil
}

func DigestJSON(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func (value Definition) Validate() error {
	if value.Schema != DefinitionSchema {
		return errors.New("agent definition schema must be " + DefinitionSchema)
	}
	if err := ValidateName(value.Name); err != nil {
		return err
	}
	wantContract := map[string]string{"hermes": "steward.hermes-agent.v1"}
	contract, ok := wantContract[value.Runtime.Engine]
	if !ok || value.Runtime.AdapterContract != contract {
		return errors.New("runtime must select hermes with its exact Steward adapter contract")
	}
	if !validImage(value.Runtime.Image) {
		return errors.New("runtime image must be a bounded OCI reference pinned by sha256 digest")
	}
	if _, _, err := ParseModelRoute(value.Model.Route); err != nil {
		return err
	}
	if value.Resources.CPUMillis < 10 || value.Resources.CPUMillis > 128000 ||
		value.Resources.MemoryMiB < 64 || value.Resources.MemoryMiB > 1048576 ||
		value.Resources.DiskMiB < 64 || value.Resources.DiskMiB > 10485760 ||
		value.Resources.PIDs < 16 || value.Resources.PIDs > 1048576 {
		return errors.New("resources are outside Steward's bounded CPU, memory, disk, or PID range")
	}
	if len(value.Placement.Architectures) == 0 || len(value.Placement.Architectures) > 4 {
		return errors.New("placement must contain 1-4 architectures")
	}
	seen := map[string]bool{}
	for _, architecture := range value.Placement.Architectures {
		if architecture != "amd64" && architecture != "arm64" {
			return errors.New("placement architectures support amd64 and arm64")
		}
		if seen[architecture] {
			return errors.New("placement architectures must be unique")
		}
		seen[architecture] = true
	}
	if value.Placement.Isolation != "development" && value.Placement.Isolation != "hardened" {
		return errors.New("placement isolation must be development or hardened")
	}
	if err := validateLabels(value.Placement.RequiredLabels, 32); err != nil {
		return fmt.Errorf("required labels: %w", err)
	}
	if err := validateLabels(value.Placement.PreferredLabels, 32); err != nil {
		return fmt.Errorf("preferred labels: %w", err)
	}
	if value.Placement.SpreadBy != "" && !validToken(value.Placement.SpreadBy, 63) {
		return errors.New("spread_by must be a valid label name")
	}
	for _, list := range []struct {
		name   string
		values []string
	}{{"skills", value.Skills}, {"MCP servers", value.MCP}, {"tolerations", value.Placement.Tolerations}} {
		if len(list.values) > 64 {
			return fmt.Errorf("%s exceed the 64-entry limit", list.name)
		}
		copyValues := append([]string(nil), list.values...)
		slices.Sort(copyValues)
		for index, item := range copyValues {
			if !validToken(item, 128) || (index > 0 && copyValues[index-1] == item) {
				return fmt.Errorf("%s must contain unique bounded identifiers", list.name)
			}
		}
	}
	for _, list := range []struct {
		name   string
		values []string
	}{{"egress routes", value.Capabilities.EgressRouteIDs}, {"connector IDs", value.Capabilities.ConnectorIDs}} {
		if len(list.values) > 32 {
			return fmt.Errorf("%s exceed the 32-entry admission limit", list.name)
		}
		copyValues := append([]string(nil), list.values...)
		slices.Sort(copyValues)
		for index, item := range copyValues {
			if !validRouteIdentifier(item, 128) || (index > 0 && copyValues[index-1] == item) {
				return fmt.Errorf("%s must contain unique route identifiers", list.name)
			}
		}
	}
	if value.State.SnapshotID != "" && (!value.State.Persistent || !validToken(value.State.SnapshotID, 128)) {
		return errors.New("snapshot_id requires persistent state and a bounded identifier")
	}
	switch value.Lifetime.Mode {
	case "task", "service":
		if value.Lifetime.TTLSeconds != 0 || value.Lifetime.OnExpiry != "" {
			return errors.New("task and service lifetimes cannot set expiry fields")
		}
	case "temporary":
		if value.Lifetime.TTLSeconds < 60 || value.Lifetime.TTLSeconds > int64((30*24*time.Hour)/time.Second) ||
			(value.Lifetime.OnExpiry != "destroy" && value.Lifetime.OnExpiry != "hibernate") {
			return errors.New("temporary lifetime requires a 60s-30d TTL and destroy or hibernate expiry")
		}
	default:
		return errors.New("lifetime mode must be task, service, or temporary")
	}
	return nil
}

// ParseModelRoute converts the portable route/alias shorthand into the two
// logical identifiers used by Executor admission and Gateway. It rejects URLs,
// credentials, and ambiguous extra path segments.
func ParseModelRoute(value string) (string, string, error) {
	parts := strings.Split(value, "/")
	if len(parts) != 2 || !validRouteIdentifier(parts[0], 128) || !validRouteIdentifier(parts[1], 256) {
		return "", "", errors.New("model route must be route-id/model-alias using bounded logical identifiers")
	}
	return parts[0], parts[1], nil
}

func ValidateName(value string) error {
	if !validName(value) {
		return errors.New("agent name must be 1-63 lowercase letters, digits, or hyphens")
	}
	return nil
}

func validName(value string) bool {
	if len(value) < 1 || len(value) > 63 || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, character := range value {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '-' {
			return false
		}
	}
	return true
}

func validToken(value string, maximum int) bool {
	if value == "" || len(value) > maximum || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == '\\' || character == '"' {
			return false
		}
	}
	return true
}

func validRouteIdentifier(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for index, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func validImage(value string) bool {
	parts := strings.Split(value, "@sha256:")
	return len(value) <= 512 && len(parts) == 2 && parts[0] != "" && len(parts[1]) == 64 && isHex(parts[1])
}

func validDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == 71 && isHex(strings.TrimPrefix(value, "sha256:"))
}

func validQuery(value string) bool {
	return len(value) >= len("data.a") && len(value) <= 256 && strings.HasPrefix(value, "data.") && validToken(value, 256)
}

func isHex(value string) bool {
	_, err := hex.DecodeString(value)
	return err == nil
}

func validateLabels(values []Label, maximum int) error {
	if len(values) > maximum {
		return fmt.Errorf("exceeds %d entries", maximum)
	}
	seen := map[string]bool{}
	for _, label := range values {
		if !validToken(label.Key, 63) || !validToken(label.Value, 128) || seen[label.Key] {
			return errors.New("keys and values must be bounded printable identifiers")
		}
		seen[label.Key] = true
	}
	return nil
}
