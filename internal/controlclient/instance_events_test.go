package controlclient

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestListInstanceEventsValidatesTheCompletePage(t *testing.T) {
	event := controlClientEvent("tenant-a", "finding-1")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/tenants/tenant-a/instance-events" ||
			request.URL.Query().Get("after") != "event-before" || request.URL.Query().Get("limit") != "1" ||
			request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("instance event request=%s %s auth=%q", request.Method, request.URL, request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(InstanceEventList{
			Events: []controlstore.InstanceEvent{event}, NextAfter: event.Event.EventID,
		})
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.ListInstanceEvents(context.Background(), "tenant-a", "event-before", 1)
	if err != nil || len(page.Events) != 1 || page.NextAfter != event.Event.EventID {
		t.Fatalf("instance event page=(%+v, %v)", page, err)
	}
}

func TestListInstanceEventsRejectsInvalidRequestsAndResponses(t *testing.T) {
	event := controlClientEvent("tenant-a", "finding-1")
	responses := []struct {
		name string
		page InstanceEventList
	}{
		{name: "omitted collection", page: InstanceEventList{}},
		{name: "over limit", page: InstanceEventList{Events: []controlstore.InstanceEvent{event, event}}},
		{name: "wrong tenant", page: InstanceEventList{Events: []controlstore.InstanceEvent{controlClientEvent("tenant-b", "finding-2")}}},
		{name: "invalid received time", page: InstanceEventList{Events: []controlstore.InstanceEvent{{Event: event.Event, ReceivedAt: "2026-07-21T01:00:02+00:00"}}}},
		{name: "empty cursor page", page: InstanceEventList{Events: []controlstore.InstanceEvent{}, NextAfter: event.Event.EventID}},
		{name: "wrong cursor", page: InstanceEventList{Events: []controlstore.InstanceEvent{event}, NextAfter: "event-" + strings.Repeat("f", 64)}},
	}
	for _, test := range responses {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(writer).Encode(test.page)
			}))
			defer server.Close()
			client, err := New(server.URL, "operator", nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := client.ListInstanceEvents(context.Background(), "tenant-a", "", 1); err == nil {
				t.Fatalf("invalid instance event page accepted: %+v", test.page)
			}
		})
	}
	client, err := New("http://127.0.0.1:1", "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		tenant string
		limit  int
	}{{tenant: "-tenant", limit: 1}, {tenant: "tenant-a", limit: 0}, {tenant: "tenant-a", limit: 101}} {
		if _, err := client.ListInstanceEvents(context.Background(), input.tenant, "", input.limit); err == nil {
			t.Fatalf("invalid request accepted: %+v", input)
		}
	}
	if _, err := client.ListInstanceEvents(context.Background(), "tenant-a", "", 1); err == nil {
		t.Fatal("instance event transport failure accepted")
	}
	if _, err := client.ListInstanceEvents(context.Background(), "tenant-a", strings.Repeat("a", 4097), 1); err == nil {
		t.Fatal("oversized instance event cursor accepted")
	}
}

func controlClientEvent(tenantID, key string) controlstore.InstanceEvent {
	grantID := "grant-" + strings.Repeat("d", 64)
	digest := sha256.Sum256([]byte("steward-instance-event-v1\x00" + grantID + "\x00" + key))
	return controlstore.InstanceEvent{
		Event: controlprotocol.InstanceEventV1{
			SchemaVersion: controlprotocol.InstanceEventSchemaV1,
			EventID:       "event-" + hex.EncodeToString(digest[:]), IdempotencyKey: key,
			Source: "agent", TenantID: tenantID, NodeID: "node-1", InstanceID: "researcher-a", Generation: 1,
			RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: grantID,
			CapsuleDigest: "sha256:" + strings.Repeat("b", 64), PolicyDigest: "sha256:" + strings.Repeat("c", 64),
			Kind: "finding", Code: "source-confirmed", Severity: "info", Summary: "Primary source confirmed.",
			ObservedAt: "2026-07-21T01:00:00Z", AcceptedAt: "2026-07-21T01:00:01Z",
		},
		ReceivedAt: "2026-07-21T01:00:02Z",
	}
}
