package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestNodePoolClientUsesBoundedPublicContract(t *testing.T) {
	status := controlClientNodePoolStatus("pool-a")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("node pool auth=%q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.Method + " " + request.URL.Path {
		case "GET /v1/node-pools":
			if request.URL.Query().Get("after") != "pool-before" || request.URL.Query().Get("limit") != "1" {
				t.Fatalf("node pool list query=%s", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(NodePoolList{NodePools: []controlstore.NodePoolStatus{status}, NextAfter: status.Pool.ID})
		case "GET /v1/node-pools/pool-a":
			_ = json.NewEncoder(writer).Encode(status)
		case "PUT /v1/node-pools/pool-a":
			var input struct {
				ExpectedRevision uint64   `json:"expected_revision"`
				TenantIDs        []string `json:"tenant_ids"`
				DesiredNodes     int      `json:"desired_nodes"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.ExpectedRevision != 1 ||
				len(input.TenantIDs) != 1 || input.TenantIDs[0] != "tenant-a" || input.DesiredNodes != 2 {
				t.Fatalf("node pool apply=%+v err=%v", input, err)
			}
			_ = json.NewEncoder(writer).Encode(status)
		case "DELETE /v1/node-pools/pool-a":
			var input struct {
				ExpectedRevision uint64 `json:"expected_revision"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.ExpectedRevision != 1 {
				t.Fatalf("node pool delete=%+v err=%v", input, err)
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %s %s", request.Method, request.URL)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListNodePools(context.Background(), "pool-before", 1)
	if err != nil || len(page.NodePools) != 1 || page.NextAfter != "pool-a" {
		t.Fatalf("node pool page=(%+v, %v)", page, err)
	}
	got, err := client.GetNodePool(context.Background(), "pool-a")
	if err != nil || got.Pool.ID != "pool-a" {
		t.Fatalf("node pool get=(%+v, %v)", got, err)
	}
	got, err = client.ApplyNodePool(context.Background(), "pool-a", NodePoolApply{
		ExpectedRevision: 1, TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		MinNodes: 1, DesiredNodes: 2, MaxNodes: 4,
	})
	if err != nil || got.ScaleOutNeeded != 2 {
		t.Fatalf("node pool apply=(%+v, %v)", got, err)
	}
	if err := client.DeleteNodePool(context.Background(), "pool-a", 1); err != nil {
		t.Fatal(err)
	}
}

func TestNodePoolClientRejectsInvalidRequestsAndResponses(t *testing.T) {
	valid := controlClientNodePoolStatus("pool-a")
	invalid := []NodePoolList{
		{},
		{NodePools: []controlstore.NodePoolStatus{{}}},
		{NodePools: []controlstore.NodePoolStatus{valid}, NextAfter: "pool-wrong"},
		{NodePools: []controlstore.NodePoolStatus{controlClientNodePoolStatus("pool-b"), valid}},
	}
	for index, page := range invalid {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(writer).Encode(page)
		}))
		client, err := New(server.URL, "operator", nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := client.ListNodePools(context.Background(), "", 2); err == nil {
			t.Fatalf("invalid node pool page %d accepted: %+v", index, page)
		}
		server.Close()
	}
	client, err := New("http://127.0.0.1:1", "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ListNodePools(context.Background(), "", 0); err == nil {
		t.Fatal("zero node pool limit accepted")
	}
	if _, err := client.ListNodePools(context.Background(), strings.Repeat("a", 4097), 1); err == nil {
		t.Fatal("oversized node pool cursor accepted")
	}
	if _, err := client.GetNodePool(context.Background(), "bad pool"); err == nil {
		t.Fatal("invalid node pool identity accepted")
	}
	if err := client.DeleteNodePool(context.Background(), "pool-a", 0); err == nil {
		t.Fatal("zero node pool delete revision accepted")
	}
}

func controlClientNodePoolStatus(poolID string) controlstore.NodePoolStatus {
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
