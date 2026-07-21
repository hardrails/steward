package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestExecutorEventUplinkAndOperatorTimelineAreAuthenticatedAndPaginated(t *testing.T) {
	fixture := newServerFixture(t)
	requireStatus(t, fixture.request(t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`), http.StatusCreated)
	response := fixture.request(t, http.MethodPost, "/v1/enrollments", fixture.adminToken,
		`{"request_id":"events-enrollment","node_id":"node-1","tenant_ids":["tenant-a"],"ttl_seconds":900}`)
	requireStatus(t, response, http.StatusCreated)
	var enrollment testEnrollmentCapability
	decodeResponse(t, response, &enrollment)
	proof := fixture.evidenceIdentityProof(t, enrollment)
	response = fixture.request(t, http.MethodPost, "/v1/enroll", "",
		enrollmentExchangeBody(t, enrollment, "events-exchange", proof))
	requireStatus(t, response, http.StatusCreated)
	var credential controlauth.NodeCredentialFile
	decodeResponse(t, response, &credential)

	event := controlplaneEvent("tenant-a", "node-1", "finding-1", fixture.now)
	batch := controlprotocol.InstanceEventBatchRequestV1{
		SchemaVersion: controlprotocol.InstanceEventBatchV1, NodeID: "node-1",
		Events: []controlprotocol.InstanceEventV1{event},
	}
	requireError(t, fixture.request(t, http.MethodPost, "/executor-uplink/events", fixture.adminToken, mustJSON(t, batch)),
		http.StatusUnauthorized, "unauthorized")
	response = fixture.request(t, http.MethodPost, "/executor-uplink/events", credential.Credential, mustJSON(t, batch))
	requireStatus(t, response, http.StatusOK)
	response = fixture.request(t, http.MethodPost, "/executor-uplink/events", credential.Credential, mustJSON(t, batch))
	requireStatus(t, response, http.StatusOK)

	response = fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/instance-events?limit=1", fixture.adminToken, "")
	requireStatus(t, response, http.StatusOK)
	var timeline struct {
		Events    []controlstore.InstanceEvent `json:"events"`
		NextAfter string                       `json:"next_after"`
	}
	decodeResponse(t, response, &timeline)
	if len(timeline.Events) != 1 || timeline.Events[0].Event.EventID != event.EventID || timeline.NextAfter != "" {
		t.Fatalf("timeline=%+v", timeline)
	}
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/instance-events?limit=101", fixture.adminToken, ""),
		http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(t, http.MethodGet, "/v1/tenants/tenant-a/instance-events?after=event-missing", fixture.adminToken, ""),
		http.StatusBadRequest, "invalid_request")
}

func controlplaneEvent(tenantID, nodeID, key string, accepted time.Time) controlprotocol.InstanceEventV1 {
	grantID := "grant-" + strings.Repeat("d", 64)
	digest := sha256.Sum256([]byte("steward-instance-event-v1\x00" + grantID + "\x00" + key))
	return controlprotocol.InstanceEventV1{
		SchemaVersion: controlprotocol.InstanceEventSchemaV1,
		EventID:       "event-" + hex.EncodeToString(digest[:]), IdempotencyKey: key,
		Source: "agent", TenantID: tenantID, NodeID: nodeID, InstanceID: "researcher-a", Generation: 1,
		RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: grantID,
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64), PolicyDigest: "sha256:" + strings.Repeat("c", 64),
		Kind: "finding", Code: "source-confirmed", Severity: "info", Summary: "Primary source confirmed.",
		ObservedAt: accepted.Format(time.RFC3339Nano), AcceptedAt: accepted.Format(time.RFC3339Nano),
	}
}
