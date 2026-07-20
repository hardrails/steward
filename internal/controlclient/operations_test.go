package controlclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestOperationsClientForwardsBoundedFiltersAndDecodesStoreTypes(t *testing.T) {
	attentionCursor := base64.RawURLEncoding.EncodeToString([]byte("attention-cursor"))
	agentCursor := base64.RawURLEncoding.EncodeToString([]byte("agent-cursor"))
	commandCursor := base64.RawURLEncoding.EncodeToString([]byte("command-cursor"))
	credentialCursor := base64.RawURLEncoding.EncodeToString([]byte("credential-cursor"))
	timelineCursor := base64.RawURLEncoding.EncodeToString([]byte("timeline-cursor"))
	expected := []struct {
		path  string
		query url.Values
		body  string
	}{
		{
			path: "/v1/operations/summary", query: url.Values{"tenant_id": {"tenant-a"}},
			body: `{"generated_at":"2026-07-16T12:00:00Z","tenant_id":"tenant-a","capacity":[],"commands":{"total":0,"pending":0,"leased":0,"terminal":0,"done":0,"failed":0,"rejected":0,"outcome_unknown":0},"evidence":{"nodes":0,"active_nodes":0,"witnessed":0,"unwitnessed":0,"current":0,"stale":0,"rollback_detected":0,"equivocation_detected":0},"attention":{"total":0,"warnings":0,"critical":0,"counts":[]}}`,
		},
		{
			path: "/v1/operations/attention",
			query: url.Values{
				"tenant_id": {"tenant-a"}, "reason": {"node_stale"},
				"cursor": {attentionCursor}, "limit": {"25"},
			},
			body: `{"items":[]}`,
		},
		{
			path: "/v1/operations/timeline",
			query: url.Values{
				"tenant_id": {"tenant-a"}, "node_id": {"node-1"}, "kind": {"containment"},
				"severity": {"critical"}, "cursor": {timelineCursor}, "limit": {"20"},
			},
			body: `{"events":[{"id":"incident-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","occurred_at":"2026-07-16T12:00:00Z","kind":"containment","action":"node_quarantined","severity":"critical","scope":"tenant","tenant_id":"tenant-a","node_id":"node-1","reason":"evidence mismatch"}]}`,
		},
		{
			path: "/v1/operations/agents",
			query: url.Values{
				"tenant_id": {"tenant-a"}, "node_id": {"node-1"}, "status": {"running"},
				"cursor": {agentCursor}, "limit": {"40"},
			},
			body: `{"agents":[]}`,
		},
		{
			path: "/v1/operations/commands",
			query: url.Values{
				"tenant_id": {"tenant-a"}, "node_id": {"node-1"}, "state": {"terminal"},
				"terminal_status": {"failed"}, "cursor": {commandCursor}, "limit": {"50"},
			},
			body: `{"commands":[]}`,
		},
		{
			path: "/v1/operations/credentials",
			query: url.Values{
				"tenant_id": {"tenant-a"}, "kind": {"node"}, "node_id": {"node-1"},
				"revoked": {"false"}, "cursor": {credentialCursor}, "limit": {"10"},
			},
			body: `{"credentials":[]}`,
		},
	}
	index := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if index >= len(expected) {
			t.Fatalf("unexpected operations request %s", request.URL)
		}
		want := expected[index]
		index++
		if request.Method != http.MethodGet || request.URL.Path != want.path ||
			request.Header.Get("Authorization") != "Bearer operator" ||
			request.URL.Query().Encode() != want.query.Encode() {
			t.Fatalf("operations request = %s %s auth=%q query=%q, want %s query=%q",
				request.Method, request.URL.Path, request.Header.Get("Authorization"),
				request.URL.Query().Encode(), want.path, want.query.Encode())
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(want.body))
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if summary, err := client.GetOperationsSummary(ctx, "tenant-a"); err != nil || summary.TenantID != "tenant-a" {
		t.Fatalf("operations summary = (%+v, %v)", summary, err)
	}
	if page, err := client.ListAttention(ctx, "tenant-a", "node_stale", attentionCursor, 25); err != nil || page.Items == nil {
		t.Fatalf("attention page = (%+v, %v)", page, err)
	}
	if page, err := client.ListIncidentTimeline(
		ctx, "tenant-a", "node-1", "containment", "critical", timelineCursor, 20,
	); err != nil || len(page.Events) != 1 || page.Events[0].Action != "node_quarantined" {
		t.Fatalf("incident timeline page = (%+v, %v)", page, err)
	}
	if page, err := client.ListAgentInventory(
		ctx, "tenant-a", "node-1", "running", agentCursor, 40,
	); err != nil || page.Agents == nil {
		t.Fatalf("agent inventory = (%+v, %v)", page, err)
	}
	if page, err := client.ListCommandInventory(
		ctx, "tenant-a", "node-1", "terminal", "failed", commandCursor, 50,
	); err != nil || page.Commands == nil {
		t.Fatalf("command inventory = (%+v, %v)", page, err)
	}
	revoked := false
	if page, err := client.ListCredentialInventory(
		ctx, "tenant-a", "node", "", "node-1", &revoked, credentialCursor, 10,
	); err != nil || page.Credentials == nil {
		t.Fatalf("credential inventory = (%+v, %v)", page, err)
	}
	if index != len(expected) {
		t.Fatalf("operations request count = %d, want %d", index, len(expected))
	}
}

func TestOperationsClientRejectsUnboundedOrAmbiguousFilters(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("invalid operations input reached the network")
	}))
	defer target.Close()
	client, err := New(target.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.GetOperationsSummary(ctx, strings.Repeat("t", 129)); err == nil {
		t.Fatal("oversized tenant filter was accepted")
	}
	if _, err := client.ListAttention(ctx, "", " node_stale", "", 1); err == nil {
		t.Fatal("whitespace-bearing attention reason was accepted")
	}
	if _, err := client.ListCommandInventory(ctx, "", "", "", "", strings.Repeat("x", 8193), 1); err == nil {
		t.Fatal("oversized operations cursor was accepted")
	}
	for _, cursor := range []string{"Zh", "Zg==", "Zg\n"} {
		if _, err := client.ListAttention(ctx, "", "", cursor, 1); err == nil {
			t.Fatalf("non-canonical operations cursor %q was accepted", cursor)
		}
	}
	if _, err := client.ListCommandInventory(ctx, "", "", "", "failed", "", 1); err == nil {
		t.Fatal("terminal status without terminal state was accepted")
	}
	if _, err := client.ListCommandInventory(ctx, "", "", "pending", "failed", "", 1); err == nil {
		t.Fatal("terminal status with non-terminal state was accepted")
	}
	if _, err := client.ListIncidentTimeline(ctx, "", "", "unknown", "", "", 1); err == nil {
		t.Fatal("unknown incident kind was accepted")
	}
	if _, err := client.ListIncidentTimeline(ctx, "", "", "", "urgent", "", 1); err == nil {
		t.Fatal("unknown incident severity was accepted")
	}
	for name, input := range map[string]struct {
		kind   string
		role   string
		nodeID string
	}{
		"role with node":      {role: "tenant_operator", nodeID: "node-1"},
		"node kind with role": {kind: "node", role: "tenant_operator"},
		"operator with node":  {kind: "operator", nodeID: "node-1"},
	} {
		if _, err := client.ListCredentialInventory(
			ctx, "", input.kind, input.role, input.nodeID, nil, "", 1,
		); err == nil {
			t.Fatalf("%s credential filters were accepted", name)
		}
	}
	if _, err := client.ListCredentialInventory(ctx, "", "", "", "", nil, "", controlstore.MaxInventoryPageLimit+1); err == nil {
		t.Fatal("oversized operations page was accepted")
	}
	noToken, err := New(target.URL, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noToken.GetOperationsSummary(ctx, ""); err == nil {
		t.Fatal("operations request without an operator token was accepted")
	}
}

func TestOperationsClientSurfacesScopeAndFilterBoundCursorRejection(t *testing.T) {
	cursor := base64.RawURLEncoding.EncodeToString([]byte("opaque-cursor"))
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Query().Get("cursor") != cursor {
			t.Fatalf("cursor was not forwarded: %s", request.URL.RawQuery)
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = writer.Write([]byte(`{"error":"invalid_request","message":"operations cursor is invalid"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"changed filter": func() error {
			_, err := client.ListAttention(context.Background(), "tenant-a", "node_stale", cursor, 1)
			return err
		},
		"cross tenant": func() error {
			_, err := client.ListCommandInventory(context.Background(), "tenant-b", "", "pending", "", cursor, 1)
			return err
		},
	} {
		err := call()
		var apiError *APIError
		if !errors.As(err, &apiError) || apiError.Status != http.StatusBadRequest ||
			apiError.Code != "invalid_request" {
			t.Fatalf("%s cursor rejection = %v", name, err)
		}
	}
}

func TestIncidentTimelineClientRejectsUntrustedResponseShape(t *testing.T) {
	valid := controlstore.IncidentEvent{
		ID:         "incident-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		OccurredAt: "2026-07-16T12:00:00Z", Kind: controlstore.IncidentContainment,
		Action: "node_quarantined", Severity: controlstore.IncidentCritical,
		Scope: "tenant", TenantID: "tenant-a", NodeID: "node-a",
	}
	tests := map[string]controlstore.IncidentTimelinePage{
		"nil events": {},
		"bad id": {
			Events: []controlstore.IncidentEvent{func() controlstore.IncidentEvent {
				value := valid
				value.ID = "incident-not-a-digest"
				return value
			}()},
		},
		"noncanonical time": {
			Events: []controlstore.IncidentEvent{func() controlstore.IncidentEvent {
				value := valid
				value.OccurredAt = "2026-07-16T12:00:00+00:00"
				return value
			}()},
		},
		"tenant leak": {
			Events: []controlstore.IncidentEvent{func() controlstore.IncidentEvent {
				value := valid
				value.TenantID = "tenant-b"
				return value
			}()},
		},
		"invalid classification": {
			Events: []controlstore.IncidentEvent{func() controlstore.IncidentEvent {
				value := valid
				value.Severity = "urgent"
				return value
			}()},
		},
		"duplicate event": {Events: []controlstore.IncidentEvent{valid, valid}},
		"oldest first": {
			Events: []controlstore.IncidentEvent{
				func() controlstore.IncidentEvent {
					value := valid
					value.OccurredAt = "2026-07-16T11:00:00Z"
					return value
				}(),
				func() controlstore.IncidentEvent {
					value := valid
					value.ID = "incident-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
					return value
				}(),
			},
		},
	}
	for name, page := range tests {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(writer).Encode(page); err != nil {
					t.Fatal(err)
				}
			}))
			defer server.Close()
			client, err := New(server.URL, "operator", nil)
			if err != nil {
				t.Fatal(err)
			}
			if result, err := client.ListIncidentTimeline(
				context.Background(), "tenant-a", "", "", "", "", 100,
			); err == nil {
				t.Fatalf("untrusted page was accepted: %+v", result)
			}
		})
	}
}
