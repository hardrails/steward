package controlprotocol

import (
	"strings"
	"testing"
)

func TestInstanceEventValidationBindsIdentityAndBoundsAgentData(t *testing.T) {
	event := validProtocolInstanceEvent("finding-1")
	if err := event.Validate(); err != nil {
		t.Fatal(err)
	}
	batch := InstanceEventBatchRequestV1{
		SchemaVersion: InstanceEventBatchV1, NodeID: event.NodeID, Events: []InstanceEventV1{event},
	}
	if err := batch.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*InstanceEventV1){
		"event identity": func(value *InstanceEventV1) { value.EventID = "event-" + strings.Repeat("f", 64) },
		"attribute key":  func(value *InstanceEventV1) { value.Attributes = map[string]string{"bad key": "value"} },
		"attribute value": func(value *InstanceEventV1) {
			value.Attributes = map[string]string{"key": strings.Repeat("x", 1025)}
		},
		"attribute total": func(value *InstanceEventV1) {
			value.Attributes = map[string]string{
				"key-a": strings.Repeat("a", 1024), "key-b": strings.Repeat("b", 1024),
				"key-c": strings.Repeat("c", 1024), "key-d": strings.Repeat("d", 1024),
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := event
			mutate(&candidate)
			if candidate.Validate() == nil {
				t.Fatalf("invalid event accepted: %+v", candidate)
			}
		})
	}
	if (InstanceEventBatchRequestV1{}).Validate() == nil {
		t.Fatal("empty event batch accepted")
	}
	wrongNode := batch
	wrongNode.NodeID = "node-other"
	if wrongNode.Validate() == nil {
		t.Fatal("cross-node event batch accepted")
	}
	duplicate := batch
	duplicate.Events = append(duplicate.Events, event)
	if duplicate.Validate() == nil {
		t.Fatal("duplicate event batch accepted")
	}
	if recordID("-invalid", 128) || text("unsafe\ntext", 128) || timestamp("2026-07-21T01:00:00+00:00") {
		t.Fatal("noncanonical event primitives accepted")
	}
}

func validProtocolInstanceEvent(key string) InstanceEventV1 {
	grantID := "grant-" + strings.Repeat("d", 64)
	return InstanceEventV1{
		SchemaVersion: InstanceEventSchemaV1, EventID: instanceEventID(grantID, key), IdempotencyKey: key,
		Source: "agent", TenantID: "tenant-a", NodeID: "node-1", InstanceID: "researcher-a", Generation: 1,
		RuntimeRef: "executor-" + strings.Repeat("a", 64), GrantID: grantID,
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64), PolicyDigest: "sha256:" + strings.Repeat("c", 64),
		Kind: "finding", Code: "source-confirmed", Severity: "info", Summary: "Primary source confirmed.",
		Attributes: map[string]string{"source": "primary"},
		ObservedAt: "2026-07-21T01:00:00Z", AcceptedAt: "2026-07-21T01:00:01Z",
	}
}
