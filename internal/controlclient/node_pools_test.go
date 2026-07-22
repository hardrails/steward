package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/poolmembership"
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

func TestNodePoolMembershipClientUsesExactExecutorUplink(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)
	statement := poolmembership.Statement{
		SchemaVersion: 1, ControllerInstanceID: "control-a", PoolID: "pool-a", PoolMembershipGeneration: 2,
		PoolCreatedAt: "2026-07-22T09:00:00Z", NodeID: "node-a", TenantIDs: []string{"tenant-a"}, Architecture: "amd64",
		BootIdentitySHA256:     "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		SchedulingPolicySHA256: "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		IssuedAt:               now.Format(time.RFC3339Nano), NotAfter: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	raw, err := poolmembership.Sign(statement, "authority-a", private)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodPut || request.URL.Path != "/executor-uplink/pool-membership" ||
			request.Header.Get("Authorization") != "Bearer node-bearer" {
			t.Fatalf("membership request=%s %s auth=%q", request.Method, request.URL.Path, request.Header.Get("Authorization"))
		}
		var body struct {
			Membership json.RawMessage `json:"membership"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil || string(body.Membership) != string(raw) {
			t.Fatalf("membership body=%s err=%v", body.Membership, err)
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(NodePoolMembershipBinding{NodeID: statement.NodeID, Membership: &controlstore.NodePoolMembership{
			PoolID: statement.PoolID, PoolMembershipGeneration: statement.PoolMembershipGeneration,
			PoolCreatedAt: statement.PoolCreatedAt, Digest: dsse.Digest(raw), KeyID: "authority-a",
			EnvelopeBase64: base64.StdEncoding.EncodeToString(raw), Architecture: statement.Architecture,
			BootIdentitySHA256: statement.BootIdentitySHA256, SchedulingPolicySHA256: statement.SchedulingPolicySHA256,
			IssuedAt: statement.IssuedAt, NotAfter: statement.NotAfter,
		}})
	}))
	defer server.Close()
	client, err := New(server.URL, "node-bearer", nil)
	if err != nil {
		t.Fatal(err)
	}
	binding, err := client.BindNodePoolMembership(context.Background(), raw)
	if err != nil || binding.NodeID != statement.NodeID || binding.Membership == nil || binding.Membership.Digest != dsse.Digest(raw) {
		t.Fatalf("membership binding=%+v err=%v", binding, err)
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
