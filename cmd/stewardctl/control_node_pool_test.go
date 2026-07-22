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

func stewardctlNodePoolStatus(poolID string) controlstore.NodePoolStatus {
	return controlstore.NodePoolStatus{
		Pool: controlstore.NodePool{
			ID: poolID, Revision: 1, TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
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
