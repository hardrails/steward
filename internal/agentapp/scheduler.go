package agentapp

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

type NodeInventory struct {
	Schema string `json:"schema"`
	Nodes  []Node `json:"nodes"`
}

type Node struct {
	ID           string    `json:"id"`
	Ready        bool      `json:"ready"`
	Tenants      []string  `json:"tenants"`
	Architecture string    `json:"architecture"`
	Isolation    string    `json:"isolation"`
	Labels       []Label   `json:"labels,omitempty"`
	Taints       []string  `json:"taints,omitempty"`
	Capacity     Resources `json:"capacity"`
	Allocated    Resources `json:"allocated"`
	Images       []string  `json:"images,omitempty"`
	Snapshots    []string  `json:"snapshots,omitempty"`
	ActiveAgents int64     `json:"active_agents"`
}

type Candidate struct {
	NodeID   string   `json:"node_id"`
	Eligible bool     `json:"eligible"`
	Score    int64    `json:"score"`
	Reasons  []string `json:"reasons"`
}

type PlacementDecision struct {
	Schema       string      `json:"schema"`
	BundleDigest string      `json:"bundle_digest"`
	SelectedNode string      `json:"selected_node,omitempty"`
	Candidates   []Candidate `json:"candidates"`
}

func DecodeInventory(raw []byte) (NodeInventory, error) {
	var inventory NodeInventory
	if err := dsse.DecodeStrictInto(raw, MaxArtifactBytes, &inventory); err != nil {
		return NodeInventory{}, fmt.Errorf("decode node inventory: %w", err)
	}
	if err := inventory.Validate(); err != nil {
		return NodeInventory{}, err
	}
	return inventory, nil
}

func (inventory NodeInventory) Validate() error {
	if inventory.Schema != InventorySchema || len(inventory.Nodes) == 0 || len(inventory.Nodes) > 4096 {
		return errors.New("node inventory requires schema steward.nodes.v1 and 1-4096 nodes")
	}
	seen := map[string]bool{}
	for _, node := range inventory.Nodes {
		if !validToken(node.ID, 128) || seen[node.ID] {
			return errors.New("node IDs must be unique bounded identifiers")
		}
		seen[node.ID] = true
		if node.Architecture != "amd64" && node.Architecture != "arm64" {
			return errors.New("node architecture must be amd64 or arm64")
		}
		if node.Isolation != "development" && node.Isolation != "hardened" {
			return errors.New("node isolation must be development or hardened")
		}
		if err := validateLabels(node.Labels, 64); err != nil {
			return fmt.Errorf("node %s labels: %w", node.ID, err)
		}
		for _, values := range [][]string{node.Tenants, node.Taints, node.Images, node.Snapshots} {
			if len(values) > 256 {
				return errors.New("node inventory list exceeds 256 entries")
			}
			for _, value := range values {
				if !validToken(value, 512) {
					return errors.New("node inventory contains an invalid identifier")
				}
			}
		}
		if !resourceNonNegative(node.Capacity) || !resourceNonNegative(node.Allocated) || !resourceFits(node.Allocated, node.Capacity) || node.ActiveAgents < 0 {
			return errors.New("node capacity or allocation is invalid")
		}
	}
	return nil
}

func Schedule(bundle Bundle, tenant string, inventory NodeInventory) (PlacementDecision, error) {
	if err := bundle.Validate(); err != nil {
		return PlacementDecision{}, err
	}
	if err := inventory.Validate(); err != nil {
		return PlacementDecision{}, err
	}
	if !validToken(tenant, 128) {
		return PlacementDecision{}, errors.New("tenant must be a bounded identifier")
	}
	bundleDigest, err := DigestJSON(bundle)
	if err != nil {
		return PlacementDecision{}, err
	}
	nodes := append([]Node(nil), inventory.Nodes...)
	slices.SortFunc(nodes, func(left, right Node) int { return strings.Compare(left.ID, right.ID) })
	decision := PlacementDecision{Schema: "steward.placement.v1", BundleDigest: bundleDigest, Candidates: make([]Candidate, 0, len(nodes))}
	bestScore := int64(-1 << 62)
	for _, node := range nodes {
		candidate := evaluateNode(bundle.Definition, tenant, node)
		decision.Candidates = append(decision.Candidates, candidate)
		if candidate.Eligible && (decision.SelectedNode == "" || candidate.Score > bestScore) {
			decision.SelectedNode, bestScore = node.ID, candidate.Score
		}
	}
	if decision.SelectedNode == "" {
		return decision, errors.New("no eligible node; inspect placement candidates for exact rejection reasons")
	}
	return decision, nil
}

func evaluateNode(definition Definition, tenant string, node Node) Candidate {
	result := Candidate{NodeID: node.ID, Eligible: true, Reasons: []string{}}
	reject := func(reason string) { result.Eligible = false; result.Reasons = append(result.Reasons, reason) }
	if !node.Ready {
		reject("node_not_ready")
	}
	if !slices.Contains(node.Tenants, tenant) {
		reject("tenant_not_allowed")
	}
	if !slices.Contains(definition.Placement.Architectures, node.Architecture) {
		reject("architecture_mismatch")
	}
	if definition.Placement.Isolation == "hardened" && node.Isolation != "hardened" {
		reject("hardened_isolation_required")
	}
	for _, label := range definition.Placement.RequiredLabels {
		if labelValue(node.Labels, label.Key) != label.Value {
			reject("required_label_mismatch:" + label.Key)
		}
	}
	for _, taint := range node.Taints {
		if !slices.Contains(definition.Placement.Tolerations, taint) {
			reject("untolerated_taint:" + taint)
		}
	}
	available := subtractResources(node.Capacity, node.Allocated)
	if !resourceFits(definition.Resources, available) {
		reject("insufficient_resources")
	}
	if !result.Eligible {
		return result
	}
	result.Score = 1000 - node.ActiveAgents
	result.Reasons = append(result.Reasons, "eligible")
	if slices.Contains(node.Images, definition.Runtime.Image) {
		result.Score += 200
		result.Reasons = append(result.Reasons, "image_local:+200")
	}
	if definition.State.SnapshotID != "" && slices.Contains(node.Snapshots, definition.State.SnapshotID) {
		result.Score += 200
		result.Reasons = append(result.Reasons, "snapshot_local:+200")
	}
	for _, label := range definition.Placement.PreferredLabels {
		if labelValue(node.Labels, label.Key) == label.Value {
			result.Score += 25
			result.Reasons = append(result.Reasons, "preferred_label:"+label.Key+":+25")
		}
	}
	return result
}

func labelValue(labels []Label, key string) string {
	for _, label := range labels {
		if label.Key == key {
			return label.Value
		}
	}
	return ""
}

type Snapshot struct {
	Schema        string `json:"schema"`
	ID            string `json:"id"`
	BundleDigest  string `json:"bundle_digest"`
	RuntimeEngine string `json:"runtime_engine"`
	StateDigest   string `json:"state_digest"`
	SourceNodeID  string `json:"source_node_id"`
	SourceLineage string `json:"source_lineage"`
	CreatedAt     string `json:"created_at"`
}

type ForkPlan struct {
	Schema          string `json:"schema"`
	DeploymentID    string `json:"deployment_id"`
	SnapshotID      string `json:"snapshot_id"`
	BundleDigest    string `json:"bundle_digest"`
	InstanceID      string `json:"instance_id"`
	LineageID       string `json:"lineage_id"`
	Generation      uint64 `json:"generation"`
	SourceNodeID    string `json:"source_node_id"`
	SourceLineageID string `json:"source_lineage_id"`
	ExpiresAt       string `json:"expires_at,omitempty"`
	OnExpiry        string `json:"on_expiry,omitempty"`
}

func DecodeForkPlan(raw []byte) (ForkPlan, error) {
	var value ForkPlan
	if err := dsse.DecodeStrictInto(raw, MaxArtifactBytes, &value); err != nil {
		return ForkPlan{}, fmt.Errorf("decode fork plan: %w", err)
	}
	if err := value.Validate(); err != nil {
		return ForkPlan{}, err
	}
	return value, nil
}

func (value ForkPlan) Validate() error {
	if value.Schema != ForkSchema || !validToken(value.DeploymentID, 128) ||
		!validToken(value.SnapshotID, 128) || !validDigest(value.BundleDigest) ||
		!validToken(value.InstanceID, 128) || !validToken(value.LineageID, 128) ||
		!validToken(value.SourceNodeID, 128) || !validToken(value.SourceLineageID, 128) ||
		value.LineageID == value.SourceLineageID || value.Generation == 0 {
		return errors.New("fork plan is invalid")
	}
	if value.ExpiresAt == "" {
		if value.OnExpiry != "" {
			return errors.New("fork plan expiry action requires expires_at")
		}
		return nil
	}
	expires, err := time.Parse(time.RFC3339Nano, value.ExpiresAt)
	if err != nil || value.ExpiresAt != expires.UTC().Format(time.RFC3339Nano) || value.OnExpiry != "destroy" {
		return errors.New("temporary fork plan requires a canonical expiry and destroy action")
	}
	return nil
}

func DecodeSnapshot(raw []byte) (Snapshot, error) {
	var value Snapshot
	if err := dsse.DecodeStrictInto(raw, MaxArtifactBytes, &value); err != nil {
		return Snapshot{}, fmt.Errorf("decode snapshot: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Snapshot{}, err
	}
	return value, nil
}

func (value Snapshot) Validate() error {
	if value.Schema != SnapshotSchema || !validToken(value.ID, 128) || !validDigest(value.BundleDigest) ||
		!validDigest(value.StateDigest) || !validToken(value.SourceLineage, 128) ||
		!validToken(value.SourceNodeID, 128) || value.RuntimeEngine != "hermes" {
		return errors.New("snapshot metadata is invalid")
	}
	if _, err := time.Parse(time.RFC3339Nano, value.CreatedAt); err != nil {
		return errors.New("snapshot created_at must be RFC3339Nano")
	}
	return nil
}

func Fork(bundle Bundle, snapshot Snapshot, deploymentID, instanceID, lineageID string, ttl time.Duration, onExpiry string, now time.Time) (ForkPlan, error) {
	if err := bundle.Validate(); err != nil {
		return ForkPlan{}, err
	}
	if err := snapshot.Validate(); err != nil {
		return ForkPlan{}, err
	}
	bundleDigest, err := DigestJSON(bundle)
	if err != nil {
		return ForkPlan{}, err
	}
	if snapshot.BundleDigest != bundleDigest || snapshot.RuntimeEngine != bundle.Definition.Runtime.Engine {
		return ForkPlan{}, errors.New("snapshot is not compatible with the selected agent bundle")
	}
	if !validToken(deploymentID, 128) || !validToken(instanceID, 128) ||
		!validToken(lineageID, 128) || lineageID == snapshot.SourceLineage {
		return ForkPlan{}, errors.New("fork requires new bounded instance and lineage identities")
	}
	plan := ForkPlan{
		Schema: ForkSchema, DeploymentID: deploymentID, SnapshotID: snapshot.ID,
		BundleDigest: bundleDigest, InstanceID: instanceID, LineageID: lineageID,
		SourceNodeID: snapshot.SourceNodeID, SourceLineageID: snapshot.SourceLineage, Generation: 1,
	}
	if ttl != 0 {
		if ttl < time.Minute || ttl > 30*24*time.Hour || onExpiry != "destroy" {
			return ForkPlan{}, errors.New("fork TTL must be 1 minute-30 days with destroy expiry")
		}
		plan.ExpiresAt = now.UTC().Add(ttl).Format(time.RFC3339Nano)
		plan.OnExpiry = onExpiry
	} else if onExpiry != "" {
		return ForkPlan{}, errors.New("on-expiry requires a fork TTL")
	}
	return plan, nil
}

func resourceNonNegative(value Resources) bool {
	return value.CPUMillis >= 0 && value.MemoryMiB >= 0 && value.DiskMiB >= 0 && value.PIDs >= 0
}

func resourceFits(request, available Resources) bool {
	return request.CPUMillis <= available.CPUMillis && request.MemoryMiB <= available.MemoryMiB && request.DiskMiB <= available.DiskMiB && request.PIDs <= available.PIDs
}

func subtractResources(left, right Resources) Resources {
	return Resources{CPUMillis: left.CPUMillis - right.CPUMillis, MemoryMiB: left.MemoryMiB - right.MemoryMiB, DiskMiB: left.DiskMiB - right.DiskMiB, PIDs: left.PIDs - right.PIDs}
}
