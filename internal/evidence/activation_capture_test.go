package evidence

import (
	"strings"
	"testing"
)

func TestObserveActivationCaptureRequiresOneOrderedPair(t *testing.T) {
	target := activationCaptureTestTarget()
	begin := activationCaptureTestReceipt(ActivationBegin, 1)
	checkpoint := activationCaptureTestReceipt(ActivationCheckpoint, 3)

	state, err := ObserveActivationCapture(target, ActivationCaptureState{}, begin)
	if err != nil || state.ActivationBeginSequence != 1 ||
		state.CapsuleDigest != begin.CapsuleDigest || state.PolicyDigest != begin.PolicyDigest {
		t.Fatalf("observe begin = (%+v, %v)", state, err)
	}
	started := activationCaptureTestReceipt(LifecycleStart, 2)
	started.GrantID = "workload"
	started.Outcome = Committed
	state, err = ObserveActivationCapture(target, state, started)
	if err != nil || state.LatestLifecycleStartSequence != 2 {
		t.Fatalf("observe lifecycle start = (%+v, %v)", state, err)
	}
	state, err = ObserveActivationCapture(target, state, checkpoint)
	if err != nil || state.ActivationCheckpointSequence != 3 ||
		state.ActivationCheckpointDigest != checkpoint.MetadataHash {
		t.Fatalf("observe checkpoint = (%+v, %v)", state, err)
	}

	for name, receipts := range map[string][]Receipt{
		"checkpoint only":       {checkpoint},
		"duplicate begin":       {begin, begin},
		"checkpoint then begin": {checkpoint, begin},
		"duplicate checkpoint":  {begin, checkpoint, checkpoint},
	} {
		t.Run(name, func(t *testing.T) {
			var candidate ActivationCaptureState
			var observeErr error
			for _, receipt := range receipts {
				candidate, observeErr = ObserveActivationCapture(target, candidate, receipt)
				if observeErr != nil {
					break
				}
			}
			if observeErr == nil {
				t.Fatal("invalid activation marker sequence was accepted")
			}
		})
	}
}

func TestObserveActivationCaptureRejectsRelatedSubstitution(t *testing.T) {
	target := activationCaptureTestTarget()
	valid := activationCaptureTestReceipt(ActivationBegin, 1)
	for name, mutate := range map[string]func(*Receipt){
		"wrong begin digest": func(value *Receipt) { value.MetadataHash = activationCaptureTestDigest("9") },
		"wrong outcome":      func(value *Receipt) { value.Outcome = Committed },
		"same coordinate different activation": func(value *Receipt) {
			value.GrantID = "activation-other"
		},
		"same activation different runtime": func(value *Receipt) {
			value.RuntimeRef = "executor-" + strings.Repeat("b", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if _, err := ObserveActivationCapture(target, ActivationCaptureState{}, candidate); err == nil {
				t.Fatal("related target substitution was accepted")
			}
		})
	}
}

func TestObserveActivationCaptureRejectsLifecycleInvalidationThroughFinalHead(t *testing.T) {
	target := activationCaptureTestTarget()
	begin := activationCaptureTestReceipt(ActivationBegin, 1)
	checkpoint := activationCaptureTestReceipt(ActivationCheckpoint, 3)
	base, err := ObserveActivationCapture(target, ActivationCaptureState{}, begin)
	if err != nil {
		t.Fatal(err)
	}
	completed, err := ObserveActivationCapture(target, base, checkpoint)
	if err != nil {
		t.Fatal(err)
	}

	for _, kind := range []EventType{LifecycleStop, LifecycleDestroy, Drift, Revocation} {
		t.Run(EventName(kind), func(t *testing.T) {
			invalidating := activationCaptureTestReceipt(kind, 4)
			invalidating.Outcome = Committed
			if _, err := ObserveActivationCapture(target, completed, invalidating); err == nil {
				t.Fatal("post-checkpoint lifecycle invalidation was accepted")
			}
		})
	}

	started := activationCaptureTestReceipt(LifecycleStart, 2)
	started.GrantID = "workload"
	started.Outcome = Committed
	startedState, err := ObserveActivationCapture(target, base, started)
	if err != nil {
		t.Fatal(err)
	}
	compensated := activationCaptureTestReceipt(JournalCompensate, 3)
	compensated.GrantID = "workload"
	compensated.Outcome = Compensated
	if _, err := ObserveActivationCapture(target, startedState, compensated); err == nil {
		t.Fatal("post-start workload compensation was accepted")
	}

	purged := activationCaptureTestReceipt(StatePurge, 2)
	purged.RuntimeRef = "steward-state-" + strings.Repeat("c", 64)
	purged.GrantID = "state"
	purged.Outcome = Committed
	if _, err := ObserveActivationCapture(target, base, purged); err == nil {
		t.Fatal("matching closed-scope state purge was accepted")
	}

	unrelated := activationCaptureTestReceipt(LifecycleDestroy, 4)
	unrelated.RuntimeRef = "executor-" + strings.Repeat("d", 64)
	unrelated.Outcome = Committed
	if got, err := ObserveActivationCapture(target, completed, unrelated); err != nil || got != completed {
		t.Fatalf("unrelated lifecycle evidence = (%+v, %v)", got, err)
	}
}

func activationCaptureTestTarget() ActivationCaptureTarget {
	return ActivationCaptureTarget{
		TenantID: "tenant-a", RuntimeRef: "executor-" + strings.Repeat("a", 64),
		Generation: 7, ActivationID: "activation-a",
		ActivationBeginDigest: activationCaptureTestDigest("6"),
	}
}

func activationCaptureTestReceipt(kind EventType, sequence uint64) Receipt {
	outcome := Committed
	metadata := activationCaptureTestDigest("7")
	if kind == ActivationBegin {
		outcome = Allowed
		metadata = activationCaptureTestDigest("6")
	}
	return Receipt{
		Sequence: sequence,
		Event: Event{
			Type: kind, TenantID: "tenant-a",
			RuntimeRef:    "executor-" + strings.Repeat("a", 64),
			CapsuleDigest: activationCaptureTestDigest("4"),
			PolicyDigest:  activationCaptureTestDigest("5"),
			Generation:    7, GrantID: "activation-a", Outcome: outcome,
			MetadataHash: metadata,
		},
	}
}

func activationCaptureTestDigest(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}
