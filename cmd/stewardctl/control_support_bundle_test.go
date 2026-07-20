package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
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
	attentionCalls    int
	evidenceCalls     int
	siteFreezeCalls   int
	tenantFreezeCalls int
	timelineCalls     int
	failAt            string
}

func (fixture *supportBundleClientFixture) failure(stage string) error {
	if fixture.failAt == stage {
		return errors.New("injected " + stage + " failure")
	}
	return nil
}

func (fixture *supportBundleClientFixture) ListIncidentTimeline(
	context.Context, string, string, string, string, string, int,
) (controlstore.IncidentTimelinePage, error) {
	if err := fixture.failure("timeline"); err != nil {
		return controlstore.IncidentTimelinePage{}, err
	}
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
	if err := fixture.failure("tenants"); err != nil {
		return controlclient.TenantList{}, err
	}
	return controlclient.TenantList{Tenants: []controlclient.Tenant{{
		TenantID: "tenant-a", State: "active", Created: "2026-07-20T12:00:00Z",
	}}}, nil
}

func (fixture *supportBundleClientFixture) ListNodes(context.Context, string, string, int) (controlclient.NodeList, error) {
	if err := fixture.failure("nodes"); err != nil {
		return controlclient.NodeList{}, err
	}
	return controlclient.NodeList{Nodes: []controlclient.Node{{
		NodeID: "node-a", TenantIDs: []string{"tenant-a"}, Capabilities: []string{"executor-v4"},
		State: "active", CreatedAt: "2026-07-20T12:00:00Z",
	}}}, nil
}

func (fixture *supportBundleClientFixture) ListDeployments(context.Context, string, string, int) (controlclient.DeploymentList, error) {
	if err := fixture.failure("deployments"); err != nil {
		return controlclient.DeploymentList{}, err
	}
	return controlclient.DeploymentList{Deployments: []controlclient.Deployment{}}, nil
}

func (fixture *supportBundleClientFixture) GetTenantResourceQuota(context.Context, string) (controlstore.TenantResourceQuotaStatus, error) {
	if err := fixture.failure("quota"); err != nil {
		return controlstore.TenantResourceQuotaStatus{}, err
	}
	return controlstore.TenantResourceQuotaStatus{TenantID: "tenant-a"}, nil
}

func (fixture *supportBundleClientFixture) GetOperationalFreeze(_ context.Context, tenantID string) (controlstore.OperationalFreezeStatus, error) {
	stage := "tenant freeze"
	if tenantID == "" {
		stage = "site freeze"
		fixture.siteFreezeCalls++
	} else {
		fixture.tenantFreezeCalls++
	}
	if err := fixture.failure(stage); err != nil {
		return controlstore.OperationalFreezeStatus{}, err
	}
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
	if err := fixture.failure("operations"); err != nil {
		return controlstore.OperationsSummary{}, err
	}
	return controlstore.OperationsSummary{
		GeneratedAt: "2026-07-20T12:01:00Z", TenantID: "tenant-a",
		Capacity: []controlstore.CapacityUsage{}, Attention: controlstore.AttentionSummary{Counts: []controlstore.AttentionCount{}},
	}, nil
}

func (fixture *supportBundleClientFixture) ListAttention(context.Context, string, string, string, int) (controlstore.AttentionPage, error) {
	if err := fixture.failure("attention"); err != nil {
		return controlstore.AttentionPage{}, err
	}
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
	if err := fixture.failure("agents"); err != nil {
		return controlstore.AgentInventoryPage{}, err
	}
	return controlstore.AgentInventoryPage{Agents: []controlstore.AgentMetadata{{
		TenantID: "tenant-a", NodeID: "node-a", RuntimeRef: "executor-runtime",
		InstanceGeneration: 1, ObservedStatus: "running", LatestCommandID: "command-a",
		LatestCommandKind: "start", LatestCommandState: "terminal",
		CreatedAt: "2026-07-20T12:00:00Z", UpdatedAt: "2026-07-20T12:01:00Z",
	}}}, nil
}

func (fixture *supportBundleClientFixture) ListCommandInventory(context.Context, string, string, string, string, string, int) (controlstore.CommandInventoryPage, error) {
	if err := fixture.failure("commands"); err != nil {
		return controlstore.CommandInventoryPage{}, err
	}
	return controlstore.CommandInventoryPage{Commands: []controlstore.CommandMetadata{{
		TenantID: "tenant-a", NodeID: "node-a", ID: "command-a", DeliveryID: "delivery-a",
		Digest: "sha256:" + strings.Repeat("a", 64), State: controlstore.CommandTerminal,
		CreatedAt: "2026-07-20T12:00:00Z", TerminalStatus: "done",
	}}}, nil
}

func (fixture *supportBundleClientFixture) ListCredentialInventory(context.Context, string, string, string, string, *bool, string, int) (controlstore.CredentialInventoryPage, error) {
	if err := fixture.failure("credentials"); err != nil {
		return controlstore.CredentialInventoryPage{}, err
	}
	return controlstore.CredentialInventoryPage{Credentials: []controlstore.CredentialMetadata{{
		ID: "credential-a", Kind: "operator", Role: "tenant_operator", TenantID: "tenant-a",
		CreatedAt: "2026-07-20T12:00:00Z",
	}}}, nil
}

func (fixture *supportBundleClientFixture) InspectExecutorEvidence(context.Context, string) (controlprotocol.ExecutorEvidenceInspectionV1, error) {
	fixture.evidenceCalls++
	if err := fixture.failure("evidence"); err != nil {
		return controlprotocol.ExecutorEvidenceInspectionV1{}, err
	}
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
		bundle.SiteFreeze != nil || len(bundle.Evidence) != 0 || fixture.evidenceCalls != 0 ||
		fixture.siteFreezeCalls != 0 || fixture.tenantFreezeCalls != 1 {
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

func TestControlSupportBundleCollectionFailsClosedAtEveryStage(t *testing.T) {
	for _, stage := range []string{
		"tenants", "operations", "site freeze", "tenant freeze", "quota", "deployments",
		"nodes", "attention", "timeline", "agents", "commands", "credentials", "evidence",
	} {
		t.Run(stage, func(t *testing.T) {
			fixture := &supportBundleClientFixture{failAt: stage}
			tenantID := "tenant-a"
			if stage == "evidence" || stage == "site freeze" {
				tenantID = ""
			}
			if _, err := collectControlSupportBundle(
				context.Background(), fixture, tenantID,
				time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
			); err == nil || !strings.Contains(err.Error(), "injected "+stage+" failure") {
				t.Fatalf("collection stage %q error = %v", stage, err)
			}
		})
	}
	if _, err := collectControlSupportBundle(context.Background(), nil, "tenant-a", time.Now()); err == nil {
		t.Fatal("nil support bundle client was accepted")
	}
}

func TestControlSupportBundleTenantScopeSkipsSiteAdminReads(t *testing.T) {
	fixture := &supportBundleClientFixture{failAt: "site freeze"}
	bundle, err := collectControlSupportBundle(
		context.Background(), fixture, "tenant-a",
		time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	if bundle.SiteFreeze != nil || len(bundle.Evidence) != 0 ||
		fixture.siteFreezeCalls != 0 || fixture.evidenceCalls != 0 {
		t.Fatalf("tenant support bundle crossed site-admin boundary: bundle=%#v fixture=%#v", bundle, fixture)
	}
}

func TestControlSupportBundleCreateWritesVerifiedOwnerOnlyFile(t *testing.T) {
	requests := make(map[string]int)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer operator-secret" {
			t.Fatalf("support bundle request = %s %s authorization=%q", request.Method, request.URL.String(), request.Header.Get("Authorization"))
		}
		requests[request.URL.Path]++
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/tenants":
			if request.URL.Query().Get("limit") != "500" {
				t.Fatalf("tenant inventory query = %s", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`{"tenants":[]}`))
		case "/v1/operations/summary":
			if request.URL.RawQuery != "" {
				t.Fatalf("site summary query = %s", request.URL.RawQuery)
			}
			_, _ = writer.Write([]byte(`{"capacity":[]}`))
		case "/v1/operations/freeze":
			_, _ = writer.Write([]byte(`{}`))
		case "/v1/operations/attention":
			_, _ = writer.Write([]byte(`{"items":[]}`))
		case "/v1/operations/timeline":
			_, _ = writer.Write([]byte(`{"events":[]}`))
		case "/v1/operations/agents":
			_, _ = writer.Write([]byte(`{"agents":[]}`))
		case "/v1/operations/commands":
			_, _ = writer.Write([]byte(`{"commands":[]}`))
		case "/v1/operations/credentials":
			_, _ = writer.Write([]byte(`{"credentials":[]}`))
		default:
			t.Fatalf("unexpected support bundle request path %q", request.URL.Path)
		}
	}))
	defer server.Close()

	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "operator.token")
	outputPath := filepath.Join(directory, "support.json")
	if err := os.WriteFile(tokenPath, []byte("operator-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := controlSupportBundleCommand([]string{
		"create", "-control-url", server.URL, "-token-file", tokenPath, "-out", outputPath,
	}, &output); err != nil {
		t.Fatal(err)
	}
	if requests["/v1/tenants"] != 1 || requests["/v1/operations/summary"] != 1 ||
		requests["/v1/operations/freeze"] != 1 || requests["/v1/operations/attention"] != 1 ||
		requests["/v1/operations/timeline"] != 1 || requests["/v1/operations/agents"] != 1 ||
		requests["/v1/operations/commands"] != 1 || requests["/v1/operations/credentials"] != 1 ||
		len(requests) != 8 {
		t.Fatalf("support bundle requests = %v", requests)
	}
	if !strings.Contains(output.String(), `"output":"`+outputPath+`"`) ||
		!strings.Contains(output.String(), `"node_count":0`) ||
		!strings.Contains(output.String(), `"finding_count":0`) {
		t.Fatalf("support bundle create output = %s", output.String())
	}
	raw, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	expectedSHA256 := "sha256:" + hex.EncodeToString(digest[:])
	if !strings.Contains(output.String(), `"sha256":"`+expectedSHA256+`"`) {
		t.Fatalf("support bundle create omitted its digest: %s", output.String())
	}
	info, err := os.Stat(outputPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("support bundle mode = %v error=%v", info, err)
	}
	var verified bytes.Buffer
	if err := controlSupportBundleCommand([]string{
		"verify", "-in", outputPath, "-expected-sha256", expectedSHA256,
	}, &verified); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(verified.String(), `"verified":true`) ||
		!strings.Contains(verified.String(), `"node_count":0`) {
		t.Fatalf("support bundle verification output = %s", verified.String())
	}
	if err := controlSupportBundleCommand([]string{
		"create", "-control-url", server.URL, "-token-file", tokenPath, "-out", outputPath,
	}, &bytes.Buffer{}); err == nil {
		t.Fatal("support bundle create overwrote an existing output")
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

func TestControlSupportBundleRejectsBrokenInventoryRelationships(t *testing.T) {
	fixture := &supportBundleClientFixture{}
	bundle, err := collectControlSupportBundle(
		context.Background(), fixture, "", time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*controlSupportBundleV1)
	}{
		{"noncanonical generated time", func(value *controlSupportBundleV1) { value.GeneratedAt = "2026-07-20T13:00:00+00:00" }},
		{"unbounded tenant inventory", func(value *controlSupportBundleV1) {
			value.Tenants = make([]controlSupportBundleTenant, maxControlSupportBundleItems+1)
		}},
		{"node without evidence", func(value *controlSupportBundleV1) { value.Evidence = nil }},
		{"site bundle without site freeze", func(value *controlSupportBundleV1) { value.SiteFreeze = nil }},
		{"deployment with unknown tenant", func(value *controlSupportBundleV1) {
			value.Deployments = []controlclient.Deployment{{TenantID: "tenant-b"}}
		}},
		{"invalid evidence inspection", func(value *controlSupportBundleV1) {
			value.Evidence[0].Inspection.ProtocolVersion = 0
		}},
		{"inconsistent tenant scope", func(value *controlSupportBundleV1) { value.Scope.TenantID = "tenant-b" }},
		{"noncanonical incident time", func(value *controlSupportBundleV1) {
			value.Timeline[0].OccurredAt = "2026-07-20T12:02:00+00:00"
		}},
		{"incident order", func(value *controlSupportBundleV1) {
			second := value.Timeline[0]
			second.ID = "incident-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			second.OccurredAt = "2026-07-20T12:03:00Z"
			value.Timeline = append(value.Timeline, second)
		}},
		{"short incident ID", func(value *controlSupportBundleV1) { value.Timeline[0].ID = "incident-short" }},
		{"invalid incident digest", func(value *controlSupportBundleV1) {
			value.Timeline[0].ID = "incident-gggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggggg"
		}},
		{"duplicate incident", func(value *controlSupportBundleV1) {
			second := value.Timeline[0]
			second.OccurredAt = "2026-07-20T12:01:00Z"
			value.Timeline = append(value.Timeline, second)
		}},
		{"site event with tenant", func(value *controlSupportBundleV1) {
			value.Timeline[0].Scope = "site"
		}},
		{"unknown incident tenant", func(value *controlSupportBundleV1) {
			value.Timeline[0].TenantID = "tenant-b"
		}},
		{"event with untrusted classification", func(value *controlSupportBundleV1) {
			value.Timeline[0].Kind = "prompt"
		}},
		{"event with malformed action", func(value *controlSupportBundleV1) {
			value.Timeline[0].Action = "node-quarantined"
		}},
		{"event with empty action", func(value *controlSupportBundleV1) { value.Timeline[0].Action = "" }},
		{"event with multiline reason", func(value *controlSupportBundleV1) {
			value.Timeline[0].Reason = "line one\nline two"
		}},
	}
	tenantFixture := &supportBundleClientFixture{}
	tenantBundle, err := collectControlSupportBundle(
		context.Background(), tenantFixture, "tenant-a", time.Date(2026, 7, 20, 13, 0, 0, 0, time.UTC),
	)
	if err != nil {
		t.Fatal(err)
	}
	tenantBundle.SiteFreeze = &controlstore.OperationalFreezeStatus{}
	if _, err := encodeControlSupportBundle(tenantBundle); err == nil {
		t.Fatal("tenant support bundle with site freeze data was accepted")
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := bundle
			candidate.Tenants = append([]controlSupportBundleTenant(nil), bundle.Tenants...)
			candidate.Nodes = append([]controlclient.Node(nil), bundle.Nodes...)
			candidate.Deployments = append([]controlclient.Deployment(nil), bundle.Deployments...)
			candidate.Timeline = append([]controlstore.IncidentEvent(nil), bundle.Timeline...)
			candidate.Evidence = append([]controlSupportBundleEvidence(nil), bundle.Evidence...)
			test.mutate(&candidate)
			if _, err := encodeControlSupportBundle(candidate); err == nil {
				t.Fatal("invalid support bundle relationship was accepted")
			}
		})
	}
	if !supportBundleNodesEqual(bundle.Nodes[0], bundle.Nodes[0]) {
		t.Fatal("identical support bundle nodes did not compare equal")
	}
	changedNode := bundle.Nodes[0]
	changedNode.State = "revoked"
	if supportBundleNodesEqual(bundle.Nodes[0], changedNode) {
		t.Fatal("different support bundle nodes compared equal")
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
	digest := sha256.Sum256(raw)
	expectedSHA256 := "sha256:" + hex.EncodeToString(digest[:])
	var output bytes.Buffer
	if err := controlSupportBundleVerify([]string{"-in", path, "-expected-sha256", expectedSHA256}, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"verified":true`) ||
		!strings.Contains(output.String(), `"tenant_id":"tenant-a"`) {
		t.Fatalf("verification output = %s", output.String())
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := controlSupportBundleVerify([]string{"-in", path, "-expected-sha256", expectedSHA256}, &bytes.Buffer{}); err == nil {
		t.Fatal("world-readable support bundle was accepted")
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := controlSupportBundleVerify([]string{
		"-in", path, "-expected-sha256", "sha256:" + strings.Repeat("0", 64),
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("wrong trusted support bundle digest error = %v", err)
	}
	if err := controlSupportBundleVerify([]string{"-in", path}, &bytes.Buffer{}); err == nil {
		t.Fatal("support bundle verification accepted no trusted digest")
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
