package rollout

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/ocibundle"
)

func TestPlanV1RoundTripAndBatches(t *testing.T) {
	plan := rolloutPlanFixture(5)
	raw, err := MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParsePlanV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.RolloutID != plan.RolloutID ||
		len(parsed.Targets) != 5 ||
		dsse.Digest(raw) == "" {
		t.Fatalf("round trip=%#v", parsed)
	}
	batches, err := parsed.Batches()
	if err != nil {
		t.Fatal(err)
	}
	want := []BatchV1{
		{Number: 0, Start: 0, End: 1},
		{Number: 1, Start: 1, End: 3},
		{Number: 2, Start: 3, End: 5},
	}
	if len(batches) != len(want) {
		t.Fatalf("batches=%#v", batches)
	}
	for index := range want {
		if batches[index] != want[index] {
			t.Fatalf("batch %d=%#v want %#v", index, batches[index], want[index])
		}
	}
}

func TestPlanV1RejectsInvalidShapeAndAmbiguity(t *testing.T) {
	valid := rolloutPlanFixture(2)
	for name, mutate := range map[string]func(*PlanV1){
		"schema":          func(value *PlanV1) { value.SchemaVersion = "other" },
		"rollout":         func(value *PlanV1) { value.RolloutID = "-bad" },
		"tenant":          func(value *PlanV1) { value.TenantID = " tenant" },
		"release":         func(value *PlanV1) { value.ReleaseDigest = "" },
		"policy":          func(value *PlanV1) { value.PolicyDigest = digest("A") },
		"archive digest":  func(value *PlanV1) { value.Archive.Digest = "bad" },
		"archive bytes":   func(value *PlanV1) { value.Archive.Bytes = 0 },
		"canary":          func(value *PlanV1) { value.Canary.Kind = "shell" },
		"batch zero":      func(value *PlanV1) { value.BatchSize = 0 },
		"batch excessive": func(value *PlanV1) { value.BatchSize = MaxBatchSize + 1 },
		"created":         func(value *PlanV1) { value.CreatedAt = "not-time" },
		"deadline before": func(value *PlanV1) { value.Deadline = value.CreatedAt },
		"deadline long": func(value *PlanV1) {
			value.Deadline = planTime(25 * time.Hour)
		},
		"targets empty": func(value *PlanV1) { value.Targets = nil },
		"duplicate node": func(value *PlanV1) {
			value.Targets[1].NodeID = value.Targets[0].NodeID
		},
		"duplicate activation": func(value *PlanV1) {
			value.Targets[1].ActivationID = value.Targets[0].ActivationID
		},
		"duplicate command": func(value *PlanV1) {
			value.Targets[1].StartCommandID = value.Targets[0].AdmitCommandID
		},
		"zero claim": func(value *PlanV1) {
			value.Targets[0].ClaimGeneration = 0
		},
		"zero generation": func(value *PlanV1) {
			value.Targets[0].InstanceGeneration = 0
		},
		"zero Gateway receipt epoch": func(value *PlanV1) {
			value.Targets[0].GatewayReceiptEpoch = 0
		},
		"target digest": func(value *PlanV1) {
			value.Targets[0].ActivationPlanDigest = ""
		},
		"Gateway receipt key digest": func(value *PlanV1) {
			value.Targets[0].GatewayReceiptPublicKeySHA256 = "sha256:invalid"
		},
		"operation policy digest": func(value *PlanV1) {
			value.Targets[0].OperationPolicyDigest = "sha256:invalid"
		},
		"same target commands": func(value *PlanV1) {
			value.Targets[0].StartCommandID = value.Targets[0].AdmitCommandID
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := clonePlan(t, valid)
			mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatalf("invalid plan accepted: %#v", candidate)
			}
		})
	}

	raw, err := MarshalPlanV1(valid)
	if err != nil {
		t.Fatal(err)
	}
	for name, ambiguous := range map[string][]byte{
		"unknown": append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"unknown":true}`)...),
		"duplicate": []byte(strings.Replace(
			string(raw),
			`"schema_version":"`+PlanSchemaV1+`"`,
			`"schema_version":"`+PlanSchemaV1+`","schema_version":"`+PlanSchemaV1+`"`,
			1,
		)),
		"trailing": append(append([]byte(nil), raw...), []byte(` {}`)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParsePlanV1(ambiguous); err == nil {
				t.Fatal("ambiguous plan accepted")
			}
		})
	}
}

func rolloutPlanFixture(targets int) PlanV1 {
	plan := PlanV1{
		SchemaVersion: PlanSchemaV1,
		RolloutID:     "rollout-1",
		TenantID:      "tenant-a",
		ReleaseDigest: digest("a"),
		PolicyDigest:  digest("b"),
		Archive: ocibundle.ArchiveIdentity{
			Digest: digest("c"),
			Bytes:  4096,
		},
		Canary:    activation.CanaryV1{Kind: activation.CanaryHermesWorkspaceAuditV1},
		BatchSize: 2,
		CreatedAt: planTime(0),
		Deadline:  planTime(time.Hour),
		Targets:   make([]TargetV1, targets),
	}
	for index := range plan.Targets {
		suffix := string(rune('a' + index))
		plan.Targets[index] = TargetV1{
			NodeID:                        "node-" + suffix,
			InstanceID:                    "agent-" + suffix,
			ActivationID:                  "activation-" + suffix,
			IntentDigest:                  digest(suffix),
			ActivationPlanDigest:          digest(string(rune('f' - index))),
			GatewayReceiptEpoch:           uint64(index + 1),
			GatewayReceiptPublicKeySHA256: digest("d"),
			OperationPolicyDigest:         digest("e"),
			ClaimGeneration:               uint64(index + 1),
			InstanceGeneration:            uint64(index + 2),
		}
		plan.Targets[index].AdmitCommandID,
			plan.Targets[index].StartCommandID,
			plan.Targets[index].CanaryCommandID = TargetCommandIDsV1(
			plan.RolloutID, index, plan.Targets[index].NodeID,
		)
	}
	return plan
}

func clonePlan(t *testing.T, plan PlanV1) PlanV1 {
	t.Helper()
	raw, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	var cloned PlanV1
	if err := json.Unmarshal(raw, &cloned); err != nil {
		t.Fatal(err)
	}
	return cloned
}

func digest(fill string) string {
	return "sha256:" + strings.Repeat(fill, 64)
}

func planTime(offset time.Duration) string {
	return time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC).
		Add(offset).
		Format(time.RFC3339Nano)
}
