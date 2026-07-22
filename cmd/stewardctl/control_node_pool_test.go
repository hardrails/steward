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
		{name: "delete revision", call: controlNodePoolDelete, args: []string{"-pool-id", "pool-a"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(test.args, &bytes.Buffer{}); err == nil {
				t.Fatalf("invalid node pool arguments accepted: %v", test.args)
			}
		})
	}
}
