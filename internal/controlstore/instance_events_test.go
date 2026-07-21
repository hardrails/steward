package controlstore

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

func testControllerEvent(tenantID, nodeID, key string, accepted time.Time) controlprotocol.InstanceEventV1 {
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

func TestInstanceEventsAreNodeBoundIdempotentDurableAndTenantScoped(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	event := testControllerEvent("tenant-a", node.NodeID, "finding-1", fixture.now.Add(2*time.Minute))
	batch := controlprotocol.InstanceEventBatchRequestV1{
		SchemaVersion: controlprotocol.InstanceEventBatchV1, NodeID: node.NodeID,
		Events: []controlprotocol.InstanceEventV1{event},
	}
	if applied, err := fixture.store.RetainInstanceEvents(node, batch, fixture.now.Add(3*time.Minute)); err != nil || applied != 1 {
		t.Fatalf("retain = (%d, %v)", applied, err)
	}
	if applied, err := fixture.store.RetainInstanceEvents(node, batch, fixture.now.Add(4*time.Minute)); err != nil || applied != 0 {
		t.Fatalf("retry = (%d, %v)", applied, err)
	}
	changed := batch
	changed.Events = append([]controlprotocol.InstanceEventV1(nil), batch.Events...)
	changed.Events[0].Summary = "Conflicting retry."
	if _, err := fixture.store.RetainInstanceEvents(node, changed, fixture.now.Add(5*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting retry err=%v", err)
	}

	events, err := fixture.store.ListInstanceEvents(fixture.admin, "tenant-a")
	if err != nil || len(events) != 1 || events[0].Event.EventID != event.EventID || events[0].ReceivedAt != fixture.now.Add(3*time.Minute).Format(time.RFC3339Nano) {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	unauthorized := controlauth.Identity{Role: controlauth.RoleTenantOperator, TenantID: "tenant-b"}
	if _, err := fixture.store.ListInstanceEvents(unauthorized, "tenant-a"); !errors.Is(err, controlauth.ErrUnauthorized) {
		t.Fatalf("unauthorized list err=%v", err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	events, err = reopened.ListInstanceEvents(fixture.admin, "tenant-a")
	if err != nil || len(events) != 1 || events[0].Event.EventID != event.EventID {
		t.Fatalf("reopened events=%+v err=%v", events, err)
	}
}

func TestInstanceEventRetentionSelectsOldestPerTenant(t *testing.T) {
	events := make(map[string]InstanceEvent, MaxInstanceEventsPerTenant+1)
	base := time.Date(2026, 7, 21, 1, 0, 0, 0, time.UTC)
	var oldest string
	for index := 0; index <= MaxInstanceEventsPerTenant; index++ {
		event := testControllerEvent("tenant-a", "node-1", fmt.Sprintf("event-%d", index), base.Add(time.Duration(index)*time.Second))
		stored := InstanceEvent{Event: event, ReceivedAt: event.AcceptedAt}
		events[event.EventID] = stored
		if index == 0 {
			oldest = event.EventID
		}
	}
	evicted := retentionEvictions(events)
	if len(evicted) != 1 || evicted[0] != oldest {
		t.Fatalf("evicted=%v want=%s", evicted, oldest)
	}
}

func TestInstanceEventReceiptOrderSurvivesControllerClockRollback(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	first := testControllerEvent("tenant-a", node.NodeID, "finding-first", fixture.now.Add(time.Minute))
	second := testControllerEvent("tenant-a", node.NodeID, "finding-second", fixture.now.Add(2*time.Minute))
	for _, retained := range []struct {
		event controlprotocol.InstanceEventV1
		now   time.Time
	}{
		{event: first, now: fixture.now.Add(10 * time.Minute)},
		{event: second, now: fixture.now.Add(5 * time.Minute)},
	} {
		batch := controlprotocol.InstanceEventBatchRequestV1{
			SchemaVersion: controlprotocol.InstanceEventBatchV1,
			NodeID:        node.NodeID,
			Events:        []controlprotocol.InstanceEventV1{retained.event},
		}
		if applied, err := fixture.store.RetainInstanceEvents(node, batch, retained.now); err != nil || applied != 1 {
			t.Fatalf("retain = (%d, %v)", applied, err)
		}
	}
	events, err := fixture.store.ListInstanceEvents(fixture.admin, "tenant-a")
	if err != nil || len(events) != 2 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	firstReceived, _ := parseTimestamp(events[0].ReceivedAt)
	secondReceived, _ := parseTimestamp(events[1].ReceivedAt)
	if !firstReceived.After(secondReceived) {
		t.Fatalf("new receipt %s was not ordered after existing receipt %s", events[0].ReceivedAt, events[1].ReceivedAt)
	}
}
