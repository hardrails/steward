package schedulepermit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/taskpermit"
)

func TestScheduleRunPermitBindsEveryDeterministicField(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	statement := fixtureStatement(start)
	signed, err := Sign(statement, "tenant-task", private)
	if err != nil {
		t.Fatal(err)
	}
	run, err := BuildRunPermit(signed, 2)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyRun(
		run, map[string]ed25519.PublicKey{"tenant-task": public},
		start.Add(5*time.Minute+30*time.Second),
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Statement != statement || verified.Ordinal != 2 ||
		verified.TaskID != "daily-research-2" ||
		verified.DueAt != start.Add(5*time.Minute) ||
		verified.EnvelopeDigest == "" || verified.RunPermitDigest == "" {
		t.Fatalf("verified run = %+v", verified)
	}
}

func TestScheduleRunPermitRejectsRebindingExpiryAndUnknownAuthority(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	start := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	signed, _ := Sign(fixtureStatement(start), "tenant-task", private)
	run, _ := BuildRunPermit(signed, 1)
	var wrapper map[string]any
	if err := json.Unmarshal(run, &wrapper); err != nil {
		t.Fatal(err)
	}
	wrapper["task_id"] = "daily-research-2"
	changed, _ := json.Marshal(wrapper)
	for name, test := range map[string]struct {
		raw  []byte
		keys map[string]ed25519.PublicKey
		now  time.Time
	}{
		"rebound task":  {changed, map[string]ed25519.PublicKey{"tenant-task": public}, start},
		"before window": {run, map[string]ed25519.PublicKey{"tenant-task": public}, start.Add(-time.Second)},
		"after window":  {run, map[string]ed25519.PublicKey{"tenant-task": public}, start.Add(2 * time.Minute)},
		"unknown key":   {run, map[string]ed25519.PublicKey{"other": other}, start},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRun(test.raw, test.keys, test.now); err == nil {
				t.Fatal("invalid schedule run was accepted")
			}
		})
	}
}

func TestScheduleStatementBoundsFiniteAuthority(t *testing.T) {
	start := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	for name, mutate := range map[string]func(*Statement){
		"unbounded runs":     func(value *Statement) { value.RunCount = MaxRuns + 1 },
		"short interval":     func(value *Statement) { value.IntervalSeconds = 59 },
		"wide window":        func(value *Statement) { value.WindowSeconds = int64(MaxWindow/time.Second) + 1 },
		"ambiguous workroom": func(value *Statement) { value.SessionID = "" },
		"invalid overlap":    func(value *Statement) { value.OverlapPolicy = "parallel" },
		"illusory catch-up":  func(value *Statement) { value.MissedRunPolicy = "catch_up_one" },
		"one-time repeats":   func(value *Statement) { value.IntervalSeconds, value.RunCount = 0, 2 },
	} {
		t.Run(name, func(t *testing.T) {
			value := fixtureStatement(start)
			mutate(&value)
			if err := value.Validate(); err == nil {
				t.Fatal("invalid finite schedule was accepted")
			}
		})
	}
}

func TestSchedulePermitRejectsMalformedSigningAndRunWrappers(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	start := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	statement := fixtureStatement(start)
	if _, err := Sign(statement, "bad key", private); err == nil {
		t.Fatal("invalid key ID was accepted")
	}
	if _, err := Sign(statement, "tenant-task", ed25519.PrivateKey("short")); err == nil {
		t.Fatal("invalid private key was accepted")
	}
	signed, err := Sign(statement, "tenant-task", private)
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]func() error{
		"empty inspect": func() error {
			_, err := InspectUnverified(nil)
			return err
		},
		"empty run": func() error {
			_, err := BuildRunPermit(nil, 1)
			return err
		},
		"zero ordinal": func() error {
			_, err := BuildRunPermit(signed, 0)
			return err
		},
		"high ordinal": func() error {
			_, err := BuildRunPermit(signed, statement.RunCount+1)
			return err
		},
		"empty run inspect": func() error {
			_, err := InspectRunUnverified(nil)
			return err
		},
		"zero verify time": func() error {
			run, _ := BuildRunPermit(signed, 1)
			_, err := VerifyRun(run, map[string]ed25519.PublicKey{"tenant-task": public}, time.Time{})
			return err
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := call(); err == nil {
				t.Fatal("malformed schedule input was accepted")
			}
		})
	}
	run, err := BuildRunPermit(signed, 1)
	if err != nil {
		t.Fatal(err)
	}
	inspected, err := InspectRunUnverified(run)
	if err != nil || inspected.TaskID != "daily-research-1" || inspected.Ordinal != 1 ||
		inspected.RunPermitDigest == "" {
		t.Fatalf("inspected run=(%+v, %v)", inspected, err)
	}
	var wrapper map[string]any
	if err := json.Unmarshal(run, &wrapper); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(map[string]any){
		"schema":   func(value map[string]any) { value["schema_version"] = "other" },
		"base64":   func(value map[string]any) { value["schedule_base64"] = "!!!!" },
		"omitted":  func(value map[string]any) { delete(value, "due_at") },
		"unknown":  func(value map[string]any) { value["unknown"] = true },
		"due time": func(value map[string]any) { value["due_at"] = start.Add(time.Second).Format(time.RFC3339) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := make(map[string]any, len(wrapper))
			for key, value := range wrapper {
				candidate[key] = value
			}
			mutate(candidate)
			raw, _ := json.Marshal(candidate)
			if _, err := InspectRunUnverified(raw); err == nil {
				t.Fatal("malformed run wrapper was accepted")
			}
		})
	}
}

func TestScheduleRunHandlesOneTimeAndDerivedIdentityBounds(t *testing.T) {
	start := time.Date(2026, 7, 24, 10, 0, 0, 0, time.UTC)
	one := fixtureStatement(start)
	one.IntervalSeconds, one.RunCount = 0, 1
	due, taskID, err := one.Run(1)
	if err != nil || due != start || taskID != "daily-research-1" || one.Validate() != nil {
		t.Fatalf("one-time run=(%s, %q, %v)", due, taskID, err)
	}
	invalidTime := one
	invalidTime.StartsAt = "not-a-time"
	if _, _, err := invalidTime.Run(1); err == nil {
		t.Fatal("invalid run time was accepted")
	}
	invalidID := one
	invalidID.ScheduleID = strings.Repeat("a", 128)
	if _, _, err := invalidID.Run(1); err == nil {
		t.Fatal("oversized derived task ID was accepted")
	}
	overflow := fixtureStatement(start)
	overflow.IntervalSeconds = int64(MaxValidity/time.Second) + 1
	overflow.RunCount = 2
	if _, _, err := overflow.Run(2); err == nil {
		t.Fatal("overflowing due time was accepted")
	}
}

func fixtureStatement(start time.Time) Statement {
	request := []byte(`{"input":"research exact topic"}`)
	return Statement{
		SchemaVersion: SchemaV1, ScheduleID: "daily-research",
		NodeID: "node-a", TenantID: "tenant-a", InstanceID: "researcher-a",
		RuntimeRef: "executor-" + strings.Repeat("a", 64),
		GrantID:    "grant-" + strings.Repeat("b", 64), Generation: 1,
		CapsuleDigest:     "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:      "sha256:" + strings.Repeat("d", 64),
		RoutePolicyDigest: "sha256:" + strings.Repeat("e", 64),
		ServiceID:         "hermes-api", OperationID: "hermes.run",
		OperationPolicyDigest: "sha256:" + strings.Repeat("f", 64),
		RequestDigest:         taskpermit.RequestDigest(request), RequestBytes: int64(len(request)),
		ContentType: "application/json", StartsAt: start.Format(time.RFC3339),
		IntervalSeconds: 300, RunCount: 3, WindowSeconds: 60,
		MaxConcurrency: 1, OverlapPolicy: "skip", MissedRunPolicy: "skip",
		ProjectID: "research-project", SessionID: "scheduled-session",
	}
}
