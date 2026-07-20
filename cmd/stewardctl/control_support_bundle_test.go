package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

type supportBundleClientFixture struct {
	attentionCalls int
	timelineCalls  int
}

func (fixture *supportBundleClientFixture) ListIncidentTimeline(
	context.Context, string, string, string, string, string, int,
) (controlstore.IncidentTimelinePage, error) {
	fixture.timelineCalls++
	if fixture.timelineCalls == 1 {
		return controlstore.IncidentTimelinePage{
			Events: []controlstore.IncidentEvent{{
				ID:         "incident-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				OccurredAt: "2026-07-20T12:02:00Z", Kind: controlstore.IncidentContainment,
				Action: "node_quarantined", Severity: controlstore.IncidentCritical,
				Scope: "tenant", TenantID: "tenant-a", NodeID: "node-a",
				Reason: "evidence mismatch",
			}},
			NextCursor: "next",
		}, nil
	}
	return controlstore.IncidentTimelinePage{Events: []controlstore.IncidentEvent{}}, nil
}

func (fixture *supportBundleClientFixture) ListTenants(context.Context, string, int) (controlclient.TenantList, error) {
	return controlclient.TenantList{Tenants: []controlclient.Tenant{{
		TenantID: "tenant-a", State: "active", Created: "2026-07-20T12:00:00Z",
	}}}, nil
}

func (fixture *supportBundleClientFixture) ListNodes(context.Context, string, string, int) (controlclient.NodeList, error) {
	return controlclient.NodeList{Nodes: []controlclient.Node{{
		NodeID: "node-a", TenantIDs: []string{"tenant-a"}, Capabilities: []string{"executor-v4"},
		State: "active", CreatedAt: "2026-07-20T12:00:00Z",
	}}}, nil
}

func (fixture *supportBundleClientFixture) ListDeployments(context.Context, string, string, int) (controlclient.DeploymentList, error) {
	return controlclient.DeploymentList{Deployments: []controlclient.Deployment{}}, nil
}

func (fixture *supportBundleClientFixture) GetTenantResourceQuota(context.Context, string) (controlstore.TenantResourceQuotaStatus, error) {
	return controlstore.TenantResourceQuotaStatus{TenantID: "tenant-a"}, nil
}

func (fixture *supportBundleClientFixture) GetOperationalFreeze(_ context.Context, tenantID string) (controlstore.OperationalFreezeStatus, error) {
	status := controlstore.OperationalFreezeStatus{}
	if tenantID == "tenant-a" {
		status.Tenant = &controlstore.OperationalFreeze{
			Scope: controlstore.OperationalFreezeTenant, TenantID: tenantID,
			Revision: 1, ChangedAt: "2026-07-20T12:00:00Z",
		}
	}
	return status, nil
}

func (fixture *supportBundleClientFixture) GetOperationsSummary(context.Context, string) (controlstore.OperationsSummary, error) {
	return controlstore.OperationsSummary{
		GeneratedAt: "2026-07-20T12:01:00Z", TenantID: "tenant-a",
		Capacity: []controlstore.CapacityUsage{}, Attention: controlstore.AttentionSummary{Counts: []controlstore.AttentionCount{}},
	}, nil
}

func (fixture *supportBundleClientFixture) ListAttention(context.Context, string, string, string, int) (controlstore.AttentionPage, error) {
	fixture.attentionCalls++
	if fixture.attentionCalls == 1 {
		return controlstore.AttentionPage{
			Items: []controlstore.AttentionItem{{
				ID: "finding-a", Reason: controlstore.AttentionNodeStale,
				Severity: controlstore.AttentionWarning, Resource: controlstore.AttentionResourceNode,
				TenantID: "tenant-a", NodeID: "node-a", Since: "2026-07-20T12:00:00Z",
			}},
			NextCursor: "next",
		}, nil
	}
	return controlstore.AttentionPage{Items: []controlstore.AttentionItem{}}, nil
}

func (fixture *supportBundleClientFixture) ListAgentInventory(context.Context, string, string, string, string, int) (controlstore.AgentInventoryPage, error) {
	return controlstore.AgentInventoryPage{Agents: []controlstore.AgentMetadata{{
		TenantID: "tenant-a", NodeID: "node-a", RuntimeRef: "executor-runtime",
		InstanceGeneration: 1, ObservedStatus: "running", LatestCommandID: "command-a",
		LatestCommandKind: "start", LatestCommandState: "terminal",
		CreatedAt: "2026-07-20T12:00:00Z", UpdatedAt: "2026-07-20T12:01:00Z",
	}}}, nil
}

func (fixture *supportBundleClientFixture) ListCommandInventory(context.Context, string, string, string, string, string, int) (controlstore.CommandInventoryPage, error) {
	return controlstore.CommandInventoryPage{Commands: []controlstore.CommandMetadata{{
		TenantID: "tenant-a", NodeID: "node-a", ID: "command-a", DeliveryID: "delivery-a",
		Digest: "sha256:" + strings.Repeat("a", 64), State: controlstore.CommandTerminal,
		CreatedAt: "2026-07-20T12:00:00Z", TerminalStatus: "done",
	}}}, nil
}

func (fixture *supportBundleClientFixture) ListCredentialInventory(context.Context, string, string, string, string, *bool, string, int) (controlstore.CredentialInventoryPage, error) {
	return controlstore.CredentialInventoryPage{Credentials: []controlstore.CredentialMetadata{{
		ID: "credential-a", Kind: "operator", Role: "tenant_operator", TenantID: "tenant-a",
		CreatedAt: "2026-07-20T12:00:00Z",
	}}}, nil
}

func (fixture *supportBundleClientFixture) InspectExecutorEvidence(context.Context, string) (controlprotocol.ExecutorEvidenceInspectionV1, error) {
	return controlprotocol.ExecutorEvidenceInspectionV1{
		ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
		ControllerInstanceID: "controller-a", ControlNodeID: "node-a",
		Status: controlprotocol.ExecutorEvidenceStatusV1{State: controlprotocol.ExecutorEvidenceStatusUnwitnessed},
	}, nil
}

func TestControlSupportBundleCollectsCanonicalMetadataOnly(t *testing.T) {
	fixture := &supportBundleClientFixture{}
	bundle, err := collectControlSupportBundle(
		context.Background(), fixture, "tenant-a", time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if fixture.attentionCalls != 2 || fixture.timelineCalls != 2 || len(bundle.Tenants) != 1 || len(bundle.Nodes) != 1 ||
		len(bundle.Attention) != 1 || len(bundle.Commands) != 1 || len(bundle.Credentials) != 1 ||
		len(bundle.Timeline) != 1 || bundle.Timeline[0].Action != "node_quarantined" ||
		len(bundle.Evidence) != 1 || bundle.Evidence[0].NodeID != "node-a" {
		t.Fatalf("support bundle = %#v", bundle)
	}
	raw, err := encodeControlSupportBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		`"token"`, `"credential"`, `"command_dsse"`, `"result"`, `"prompt"`,
		`"request_body"`, `"response_body"`, `"private_key"`,
	} {
		if bytes.Contains(raw, []byte(forbidden+`:`)) {
			t.Fatalf("support bundle contains forbidden field %s: %s", forbidden, raw)
		}
	}
	decoded, err := decodeControlSupportBundle(raw)
	if err != nil || decoded.GeneratedAt != bundle.GeneratedAt {
		t.Fatalf("decoded support bundle = (%#v, %v)", decoded, err)
	}
}

func TestControlSupportBundleRejectsAmbiguousOrIncompleteFiles(t *testing.T) {
	fixture := &supportBundleClientFixture{}
	bundle, err := collectControlSupportBundle(
		context.Background(), fixture, "tenant-a", time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeControlSupportBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string][]byte{
		"non canonical":     append([]byte(" "), raw...),
		"unknown field":     bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":1,"unknown":true`), 1),
		"wrong version":     bytes.Replace(raw, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1),
		"missing exclusion": bytes.Replace(raw, []byte(`"agent_result_text",`), nil, 1),
	} {
		if _, err := decodeControlSupportBundle(candidate); err == nil {
			t.Fatalf("%s support bundle was accepted", name)
		}
	}
}

func TestControlSupportBundleVerifyRequiresOwnerOnlyCanonicalInput(t *testing.T) {
	fixture := &supportBundleClientFixture{}
	bundle, err := collectControlSupportBundle(
		context.Background(), fixture, "tenant-a", time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := encodeControlSupportBundle(bundle)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "support.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := controlSupportBundleVerify([]string{"-in", path}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"verified":true`) ||
		!strings.Contains(output.String(), `"tenant_id":"tenant-a"`) {
		t.Fatalf("verification output = %s", output.String())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := controlSupportBundleVerify([]string{"-in", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("world-readable support bundle was accepted")
	}
}

func TestControlSupportBundleCommandAndCompletionAreDiscoverable(t *testing.T) {
	if err := controlSupportBundleCommand([]string{"unknown"}, &bytes.Buffer{}); err == nil ||
		!strings.Contains(err.Error(), "create or verify") {
		t.Fatalf("support bundle usage error = %v", err)
	}
	if got := stewardctlCompletionCandidates([]string{"stewardctl", "control", "support-bundle", ""}); !slicesEqual(got, []string{"create", "verify"}) {
		t.Fatalf("support bundle completion = %v", got)
	}
}

func slicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
