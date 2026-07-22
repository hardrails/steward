package main

import (
	"bytes"
	"encoding/json"
	"io"
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

func TestControlNodePoolCommandsExposeCapacityWithoutCloudCredentials(t *testing.T) {
	status := stewardctlNodePoolStatus("pool-a")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("node pool authorization=%q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/node-pools":
			if request.URL.Query().Get("after") != "pool-before" || request.URL.Query().Get("limit") != "1" {
				t.Fatalf("node pool list query=%s", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(controlclient.NodePoolList{NodePools: []controlstore.NodePoolStatus{status}})
		case "GET /v1/node-pools/pool-a":
			_ = json.NewEncoder(writer).Encode(status)
		case "PUT /v1/node-pools/pool-a":
			var input struct {
				ExpectedRevision uint64   `json:"expected_revision"`
				TenantIDs        []string `json:"tenant_ids"`
				DesiredNodes     int      `json:"desired_nodes"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.ExpectedRevision != 1 ||
				strings.Join(input.TenantIDs, ",") != "tenant-a,tenant-b" || input.DesiredNodes != 2 {
				t.Fatalf("node pool apply=%+v err=%v", input, err)
			}
			_ = json.NewEncoder(writer).Encode(status)
		case "DELETE /v1/node-pools/pool-a":
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected node pool request %s %s", request.Method, request.URL)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	common := []string{"-control-url", server.URL, "-token-file", tokenPath, "-no-context"}
	commands := [][]string{
		append([]string{"control", "node-pool", "list", "-after", "pool-before", "-limit", "1"}, common...),
		append([]string{"control", "node-pool", "status", "-pool-id", "pool-a"}, common...),
		append([]string{"control", "node-pool", "apply", "-pool-id", "pool-a", "-tenant-ids", "tenant-b,tenant-a", "-architecture", "amd64", "-min-nodes", "1", "-desired-nodes", "2", "-max-nodes", "4", "-revision", "1"}, common...),
		append([]string{"control", "node-pool", "delete", "-pool-id", "pool-a", "-revision", "1"}, common...),
	}
	for _, command := range commands {
		var output bytes.Buffer
		if err := run(command, &output, &bytes.Buffer{}); err != nil {
			t.Fatalf("%v failed: %v", command, err)
		}
		if output.Len() == 0 {
			t.Fatalf("%v returned no output", command)
		}
	}
}

func TestControlNodePoolMembershipIssueAndVerify(t *testing.T) {
	directory := t.TempDir()
	privatePath, publicPath := generateTestKeyPair(t, directory, "pool")
	output := filepath.Join(directory, "membership.dsse.json")
	originalNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = originalNow })
	var digest bytes.Buffer
	err := run([]string{
		"control", "node-pool", "membership-issue", "-private-key", privatePath, "-key-id", "pool-authority-1",
		"-controller-id", "control-a", "-pool-id", "pool-a", "-pool-membership-generation", "3", "-node-id", "node-a",
		"-pool-created-at", "2026-07-22T11:00:00Z",
		"-tenant-ids", "tenant-b,tenant-a", "-architecture", "amd64",
		"-boot-identity-sha256", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"-scheduling-policy-sha256", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"-runtime-assurance-sha256", "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"-valid-for", "1h", "-out", output, "-no-context",
	}, &digest, &bytes.Buffer{})
	if err != nil || !strings.HasPrefix(strings.TrimSpace(digest.String()), "sha256:") {
		t.Fatalf("issue output=%q err=%v", digest.String(), err)
	}
	var verified bytes.Buffer
	if err := run([]string{
		"control", "node-pool", "membership-verify", "-in", output, "-public-key", publicPath,
		"-key-id", "pool-authority-1", "-no-context",
	}, &verified, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var statement struct {
		PoolID    string   `json:"pool_id"`
		TenantIDs []string `json:"tenant_ids"`
	}
	if err := json.Unmarshal(verified.Bytes(), &statement); err != nil || statement.PoolID != "pool-a" ||
		strings.Join(statement.TenantIDs, ",") != "tenant-a,tenant-b" {
		t.Fatalf("verified=%s err=%v", verified.String(), err)
	}
}

func TestNodeAssuranceReportFeedsOfflineMembershipIssue(t *testing.T) {
	now := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
	assurance := controlprotocol.RuntimeAssuranceV1{
		SchemaVersion: controlprotocol.RuntimeAssuranceSchemaV1,
		Profile:       controlprotocol.RuntimeAssuranceSharedHost, Runtime: "docker",
		Isolation: controlprotocol.ExecutorSchedulingIsolationGVisor, Network: "isolated-bridge",
		StateIsolation: controlprotocol.RuntimeAssuranceStateQuota, CredentialBoundary: "gateway-only",
	}
	assuranceDigest, err := controlprotocol.RuntimeAssuranceDigest(assurance)
	if err != nil {
		t.Fatal(err)
	}
	policy := controlprotocol.ExecutorSchedulingPolicyV1{
		PerWorkload:     controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 1, CPUMillis: 1, PIDs: 1, Workloads: 1},
		Host:            controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 2, CPUMillis: 2, PIDs: 2, Workloads: 2},
		Tenant:          controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 2, CPUMillis: 2, PIDs: 2, Workloads: 2},
		RuntimeOverhead: controlprotocol.ExecutorSchedulingResourcesV1{MemoryBytes: 1, CPUMillis: 1, PIDs: 1},
	}
	policyDigest, err := controlprotocol.SchedulingPolicyDigest(policy)
	if err != nil {
		t.Fatal(err)
	}
	node := controlclient.Node{
		NodeID: "node-a", TenantIDs: []string{"tenant-a"}, Capabilities: []string{}, State: "active",
		CreatedAt: now.Add(-time.Hour).Format(time.RFC3339Nano),
		Scheduling: &controlstore.NodeScheduling{
			ObservedAt: now.Add(-time.Minute).Format(time.RFC3339Nano),
			Observation: controlprotocol.ExecutorSchedulingObservationV1{
				SchemaVersion: controlprotocol.ExecutorSchedulingSchemaV1,
				NodeID:        "node-a", CredentialScope: "node", OS: "linux", Architecture: "amd64",
				Isolation:          controlprotocol.ExecutorSchedulingIsolationGVisor,
				BootIdentitySHA256: "sha256:" + strings.Repeat("a", 64), SchedulingPolicySHA256: policyDigest,
				RuntimeAssurance: &assurance, RuntimeAssuranceSHA256: assuranceDigest,
				Labels: []controlprotocol.ExecutorSchedulingLabelV1{}, Taints: []string{},
				CachedImageConfigDigests: []string{}, Policy: policy,
			},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" || request.URL.Path != "/v1/tenants/tenant-a/nodes/node-a" {
			t.Fatalf("unexpected assurance request %s auth=%q", request.URL, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(node)
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	originalNow := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = originalNow })
	var report bytes.Buffer
	if err := run([]string{
		"control", "node", "assurance", "-tenant-id", "tenant-a", "-node-id", "node-a",
		"-control-url", server.URL, "-token-file", tokenPath, "-no-context",
	}, &report, io.Discard); err != nil {
		t.Fatal(err)
	}
	var decoded nodeAssuranceReport
	if err := json.Unmarshal(report.Bytes(), &decoded); err != nil || decoded.Status != "pass" || decoded.RuntimeAssuranceSHA256 != assuranceDigest {
		t.Fatalf("assurance report=%s err=%v", report.String(), err)
	}
	reportPath := filepath.Join(directory, "node-assurance.json")
	if err := os.WriteFile(reportPath, report.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	privatePath, _ := generateTestKeyPair(t, directory, "assurance-membership")
	membershipPath := filepath.Join(directory, "membership.json")
	if err := controlNodePoolMembershipIssue([]string{
		"-private-key", privatePath, "-key-id", "pool-authority-1", "-controller-id", "control-a",
		"-pool-id", "pool-a", "-pool-membership-generation", "1", "-pool-created-at", now.Add(-time.Hour).Format(time.RFC3339Nano),
		"-tenant-ids", "tenant-a", "-node-assurance", reportPath, "-out", membershipPath,
	}, io.Discard); err != nil {
		t.Fatal(err)
	}
}

func stewardctlNodePoolStatus(poolID string) controlstore.NodePoolStatus {
	return controlstore.NodePoolStatus{
		Pool: controlstore.NodePool{
			ID: poolID, Revision: 1, MembershipGeneration: 1, TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
			MinNodes: 1, DesiredNodes: 2, MaxNodes: 4,
			CreatedAt: "2026-07-21T01:00:00Z", UpdatedAt: "2026-07-21T01:00:00Z",
		},
		Nodes: []controlstore.NodePoolNode{}, RegisteredNodes: 0, ReadyNodes: 0, ScaleOutNeeded: 2,
		ScaleInCandidates: []string{}, Conditions: []string{controlstore.NodePoolConditionCapacityShortfall},
		ObservedAt: "2026-07-21T01:00:01Z",
	}
}

func TestControlNodePoolCommandsRejectIncompleteIntent(t *testing.T) {
	tests := []struct {
		name string
		call func([]string, io.Writer) error
		args []string
	}{
		{name: "list limit", call: controlNodePoolList, args: []string{"-limit", "0"}},
		{name: "status identity", call: controlNodePoolStatus, args: nil},
		{name: "apply tenants", call: controlNodePoolApply, args: []string{"-pool-id", "pool-a", "-max-nodes", "2"}},
		{name: "apply order", call: controlNodePoolApply, args: []string{"-pool-id", "pool-a", "-tenant-ids", "tenant-a", "-min-nodes", "2", "-desired-nodes", "1", "-max-nodes", "3"}},
		{name: "apply authority pair", call: controlNodePoolApply, args: []string{"-pool-id", "pool-a", "-tenant-ids", "tenant-a", "-max-nodes", "2", "-membership-key-id", "authority-a"}},
		{name: "delete revision", call: controlNodePoolDelete, args: []string{"-pool-id", "pool-a"}},
		{name: "issue flags", call: controlNodePoolMembershipIssue, args: []string{"-unknown"}},
		{name: "issue tenants", call: controlNodePoolMembershipIssue, args: []string{"-tenant-ids", "tenant-a,"}},
		{name: "issue required", call: controlNodePoolMembershipIssue, args: nil},
		{name: "verify flags", call: controlNodePoolMembershipVerify, args: []string{"-unknown"}},
		{name: "verify required", call: controlNodePoolMembershipVerify, args: nil},
		{name: "bind flags", call: controlNodePoolMembershipBind, args: []string{"-unknown"}},
		{name: "bind required", call: controlNodePoolMembershipBind, args: nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(test.args, &bytes.Buffer{}); err == nil {
				t.Fatalf("invalid node pool arguments accepted: %v", test.args)
			}
		})
	}
}

func TestControlNodePoolMembershipCommandsReportArtifactFailures(t *testing.T) {
	directory := t.TempDir()
	originalNow := timeNow
	timeNow = func() time.Time { return time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { timeNow = originalNow })
	privatePath, publicPath := generateTestKeyPair(t, directory, "membership-errors")
	missing := filepath.Join(directory, "missing")
	output := filepath.Join(directory, "membership.json")
	issue := []string{
		"-private-key", privatePath, "-key-id", "authority-a", "-controller-id", "control-a",
		"-pool-id", "pool-a", "-pool-membership-generation", "1", "-pool-created-at", "2026-07-22T11:00:00Z",
		"-node-id", "node-a", "-tenant-ids", "tenant-a",
		"-boot-identity-sha256", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"-scheduling-policy-sha256", "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"-runtime-assurance-sha256", "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"-valid-for", "1h", "-out", output,
	}
	badKey := append([]string(nil), issue...)
	badKey[1] = missing
	if err := controlNodePoolMembershipIssue(badKey, &bytes.Buffer{}); err == nil {
		t.Fatal("missing membership private key was accepted")
	}
	badDigest := append([]string(nil), issue...)
	badDigest[19] = "invalid"
	if err := controlNodePoolMembershipIssue(badDigest, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid signed claim was accepted")
	}
	if err := os.WriteFile(output, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := controlNodePoolMembershipIssue(issue, &bytes.Buffer{}); err == nil {
		t.Fatal("membership issue overwrote an existing artifact")
	}

	if err := controlNodePoolMembershipVerify([]string{"-in", missing, "-public-key", publicPath, "-key-id", "authority-a"}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing membership envelope was accepted")
	}
	if err := controlNodePoolMembershipVerify([]string{"-in", output, "-public-key", missing, "-key-id", "authority-a"}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing membership public key was accepted")
	}
	if err := controlNodePoolMembershipVerify([]string{"-in", output, "-public-key", publicPath, "-key-id", "authority-a"}, &bytes.Buffer{}); err == nil {
		t.Fatal("malformed membership envelope was accepted")
	}

	credential := filepath.Join(directory, "credential.json")
	if err := controlNodePoolMembershipBind([]string{"-in", missing, "-credential", credential}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing bind envelope was accepted")
	}
	if err := os.WriteFile(output, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := controlNodePoolMembershipBind([]string{"-in", output, "-credential", missing}, &bytes.Buffer{}); err == nil {
		t.Fatal("missing node credential was accepted")
	}
	if err := os.WriteFile(credential, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := controlNodePoolMembershipBind([]string{"-in", output, "-credential", credential}, &bytes.Buffer{}); err == nil {
		t.Fatal("invalid node credential was accepted")
	}
}
