package activation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

type executorEvidenceFixture struct {
	request        ExecutorEvidenceRequestV1
	path           string
	receiptPrivate ed25519.PrivateKey
	witnessPrivate ed25519.PrivateKey
	identityProof  controlprotocol.ExecutorEvidenceIdentityProofV1
}

func TestCollectAndVerifyExecutorEvidenceV1(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t)
	collected, err := CollectExecutorEvidenceV1(fixture.request, fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	if len(collected.Delta) == 0 ||
		collected.Coordinate.ReceiptNodeID != fixture.request.Binding.NodeID ||
		collected.Coordinate.Sequence != collected.Witness.Sequence ||
		collected.Coordinate.ChainHash != collected.Witness.ChainHash {
		t.Fatalf("collected executor evidence = %#v", collected)
	}
	verified, err := VerifyExecutorEvidenceDeltaV1(fixture.request, collected.Delta)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Coordinate != collected.Coordinate ||
		verified.Witness != collected.Witness ||
		string(verified.Delta) != string(collected.Delta) {
		t.Fatalf("verified executor evidence = %#v, want %#v", verified, collected)
	}
}

func TestExecutorEvidenceV1RejectsSubstitutionAndIncompleteProof(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t)
	collected, err := CollectExecutorEvidenceV1(fixture.request, fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	tests := map[string]func(*ExecutorEvidenceRequestV1, *[]byte){
		"wrong runtime": func(request *ExecutorEvidenceRequestV1, _ *[]byte) {
			request.RuntimeRef = "executor-" + strings.Repeat("f", 64)
		},
		"wrong capsule": func(request *ExecutorEvidenceRequestV1, _ *[]byte) {
			request.CapsuleDigest = testSHA256('f')
		},
		"wrong route policy": func(request *ExecutorEvidenceRequestV1, _ *[]byte) {
			request.RoutePolicyDigest = testSHA256('e')
		},
		"wrong grant": func(request *ExecutorEvidenceRequestV1, _ *[]byte) {
			request.GrantID = "grant-" + strings.Repeat("f", 64)
		},
		"truncated delta": func(_ *ExecutorEvidenceRequestV1, delta *[]byte) {
			*delta = append([]byte(nil), (*delta)[:len(*delta)-1]...)
		},
		"changed delta": func(_ *ExecutorEvidenceRequestV1, delta *[]byte) {
			changed := append([]byte(nil), (*delta)...)
			changed[len(changed)-1] ^= 1
			*delta = changed
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := fixture.request
			delta := append([]byte(nil), collected.Delta...)
			mutate(&request, &delta)
			if _, err := VerifyExecutorEvidenceDeltaV1(request, delta); err == nil {
				t.Fatal("substituted executor evidence accepted")
			}
		})
	}

	_, otherWitnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := fixture.request
	request.WitnessPublicKey = otherWitnessPrivate.Public().(ed25519.PublicKey)
	if _, err := VerifyExecutorEvidenceDeltaV1(request, collected.Delta); err == nil {
		t.Fatal("untrusted controller witness accepted")
	}
}

func TestExecutorEvidenceV1HonorsCanceledContext(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t)
	collected, err := CollectExecutorEvidenceV1(fixture.request, fixture.path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := CollectExecutorEvidenceV1Context(
		ctx, fixture.request, fixture.path,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("collect error=%v, want context canceled", err)
	}
	if _, err := VerifyExecutorEvidenceDeltaV1Context(
		ctx, fixture.request, collected.Delta,
	); !errors.Is(err, context.Canceled) {
		t.Fatalf("verify error=%v, want context canceled", err)
	}
}

func TestExecutorEvidenceV1RejectsStaleOrInvalidatingFinalWitness(t *testing.T) {
	t.Run("unrelated tenant suffix is allowed", func(t *testing.T) {
		fixture := newExecutorEvidenceFixture(t)
		log, err := evidence.Open(
			fixture.path, fixture.receiptPrivate, "node-a", 1,
		)
		if err != nil {
			t.Fatal(err)
		}
		unrelated := activationEvidenceEvent(evidence.PolicyReload)
		unrelated.RuntimeRef = "executor-" + strings.Repeat("e", 64)
		if _, err := log.Append(unrelated); err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := CollectExecutorEvidenceV1(
			fixture.request, fixture.path,
		); err != nil {
			t.Fatalf("unrelated suffix error=%v", err)
		}
	})

	t.Run("matching suffix after final witness is rejected", func(t *testing.T) {
		fixture := newExecutorEvidenceFixture(t)
		log, err := evidence.Open(
			fixture.path, fixture.receiptPrivate, "node-a", 1,
		)
		if err != nil {
			t.Fatal(err)
		}
		drift := activationEvidenceEvent(evidence.Drift)
		if _, err := log.Append(drift); err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := CollectExecutorEvidenceV1(
			fixture.request, fixture.path,
		); err == nil || !strings.Contains(err.Error(), "after the final") {
			t.Fatalf("matching suffix error=%v", err)
		}
	})

	t.Run("checkpoint digest substitution is rejected", func(t *testing.T) {
		fixture := newExecutorEvidenceFixture(t)
		request := fixture.request
		request.ActivationCheckpointDigest = testSHA256('f')
		collected, err := CollectExecutorEvidenceV1(
			fixture.request, fixture.path,
		)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := VerifyExecutorEvidenceDeltaV1(
			request, collected.Delta,
		); err == nil || !strings.Contains(err.Error(), "conflicting activation checkpoint") {
			t.Fatalf("checkpoint substitution error=%v", err)
		}
	})

	t.Run("matching lifecycle invalidation is witnessed", func(t *testing.T) {
		fixture := newExecutorEvidenceFixture(t)
		log, err := evidence.Open(
			fixture.path, fixture.receiptPrivate, "node-a", 1,
		)
		if err != nil {
			t.Fatal(err)
		}
		stopped := activationEvidenceEvent(evidence.LifecycleStop)
		if _, err := log.Append(stopped); err != nil {
			t.Fatal(err)
		}
		final, err := log.CurrentHead()
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		request := fixture.request
		request.FinalWitness = signExecutorWitness(
			t, fixture.identityProof, fixture.witnessPrivate, final,
			time.Date(2026, 7, 16, 12, 2, 0, 0, time.UTC),
		)
		if _, err := CollectExecutorEvidenceV1(
			request, fixture.path,
		); err == nil || !strings.Contains(err.Error(), "lifecycle-invalidating") {
			t.Fatalf("invalidating evidence error=%v", err)
		}
	})

	t.Run("matching state purge uses the state runtime identity", func(t *testing.T) {
		fixture := newExecutorEvidenceFixture(t)
		log, err := evidence.Open(
			fixture.path, fixture.receiptPrivate, "node-a", 1,
		)
		if err != nil {
			t.Fatal(err)
		}
		prepared := activationEvidenceEvent(evidence.JournalPrepare)
		prepared.RuntimeRef = fixture.request.StateRuntimeRef
		prepared.GrantID = "state"
		prepared.Outcome = evidence.Allowed
		if _, err := log.Append(prepared); err != nil {
			t.Fatal(err)
		}
		purged := prepared
		purged.Type = evidence.StatePurge
		purged.Outcome = evidence.Committed
		if _, err := log.Append(purged); err != nil {
			t.Fatal(err)
		}
		final, err := log.CurrentHead()
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		request := fixture.request
		request.FinalWitness = signExecutorWitness(
			t, fixture.identityProof, fixture.witnessPrivate, final,
			time.Date(2026, 7, 16, 12, 2, 0, 0, time.UTC),
		)
		if _, err := CollectExecutorEvidenceV1(
			request, fixture.path,
		); err == nil || !strings.Contains(err.Error(), "lifecycle-invalidating") {
			t.Fatalf("state-purge evidence error=%v", err)
		}
	})

	t.Run("matching workload preparation remains unresolved", func(t *testing.T) {
		fixture := newExecutorEvidenceFixture(t)
		log, err := evidence.Open(
			fixture.path, fixture.receiptPrivate, "node-a", 1,
		)
		if err != nil {
			t.Fatal(err)
		}
		prepared := activationEvidenceEvent(evidence.JournalPrepare)
		prepared.Outcome = evidence.Allowed
		if _, err := log.Append(prepared); err != nil {
			t.Fatal(err)
		}
		final, err := log.CurrentHead()
		if err != nil {
			t.Fatal(err)
		}
		if err := log.Close(); err != nil {
			t.Fatal(err)
		}
		request := fixture.request
		request.FinalWitness = signExecutorWitness(
			t, fixture.identityProof, fixture.witnessPrivate, final,
			time.Date(2026, 7, 16, 12, 2, 0, 0, time.UTC),
		)
		if _, err := CollectExecutorEvidenceV1(
			request, fixture.path,
		); err == nil || !strings.Contains(err.Error(), "unresolved") {
			t.Fatalf("unresolved preparation error=%v", err)
		}
	})
}

func newExecutorEvidenceFixture(t *testing.T) executorEvidenceFixture {
	t.Helper()
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "executor-evidence.bin")
	log, err := evidence.Open(path, receiptPrivate, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := activationEvidenceEvent(evidence.PolicyReload)
	unrelated.RuntimeRef = "executor-" + strings.Repeat("e", 64)
	if _, err := log.Append(unrelated); err != nil {
		t.Fatal(err)
	}
	baseline, err := log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}

	begin := activationEvidenceEvent(evidence.ActivationBegin)
	begin.GrantID = "activation-7"
	begin.Outcome = evidence.Allowed
	begin.MetadataHash = testSHA256('6')
	if _, err := log.AppendActivationBegin(begin); err != nil {
		t.Fatal(err)
	}
	authorization := activationEvidenceEvent(evidence.AdmissionAllow)
	authorization.GrantID = "grant-" + strings.Repeat("d", 64)
	authorization.Outcome = evidence.Allowed
	if _, err := log.Append(authorization); err != nil {
		t.Fatal(err)
	}
	prepared := activationEvidenceEvent(evidence.JournalPrepare)
	prepared.Outcome = evidence.Allowed
	prepared.ErrorCode = "admit"
	if _, err := log.Append(prepared); err != nil {
		t.Fatal(err)
	}
	committed := activationEvidenceEvent(evidence.JournalCommit)
	committed.MetadataHash = testSHA256('9')
	if _, err := log.Append(committed); err != nil {
		t.Fatal(err)
	}
	startPrepared := activationEvidenceEvent(evidence.JournalPrepare)
	startPrepared.Outcome = evidence.Allowed
	startPrepared.ErrorCode = "start"
	if _, err := log.Append(startPrepared); err != nil {
		t.Fatal(err)
	}
	compensatedStart := startPrepared
	compensatedStart.Type = evidence.JournalCompensate
	compensatedStart.Outcome = evidence.Compensated
	compensatedStart.ErrorCode = "failed_start_contained"
	if _, err := log.Append(compensatedStart); err != nil {
		t.Fatal(err)
	}
	if _, err := log.Append(startPrepared); err != nil {
		t.Fatal(err)
	}
	started := activationEvidenceEvent(evidence.LifecycleStart)
	started.MetadataHash = testSHA256('9')
	if _, err := log.Append(started); err != nil {
		t.Fatal(err)
	}
	checkpoint := activationEvidenceEvent(evidence.ActivationCheckpoint)
	checkpoint.GrantID = "activation-7"
	checkpoint.MetadataHash = testSHA256('7')
	if _, err := log.AppendActivationCheckpoint(checkpoint); err != nil {
		t.Fatal(err)
	}
	final, err := log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"controller-a", "enrollment-a", "node-a",
		"node-a", 1, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	identityProof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	baselineRaw := signExecutorWitness(
		t, identityProof, witnessPrivate, baseline,
		time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC),
	)
	finalRaw := signExecutorWitness(
		t, identityProof, witnessPrivate, final,
		time.Date(2026, 7, 16, 12, 1, 0, 0, time.UTC),
	)
	binding := validBinding(t, mustMarshalPlan(t, validPlan()))
	return executorEvidenceFixture{
		path:           path,
		receiptPrivate: receiptPrivate,
		witnessPrivate: witnessPrivate,
		identityProof:  identityProof,
		request: ExecutorEvidenceRequestV1{
			Binding:                    binding,
			RuntimeRef:                 "executor-" + strings.Repeat("1", 64),
			StateRuntimeRef:            "steward-state-" + strings.Repeat("2", 64),
			CapsuleDigest:              testSHA256('8'),
			RoutePolicyDigest:          testSHA256('9'),
			GrantID:                    "grant-" + strings.Repeat("d", 64),
			ActivationBeginDigest:      testSHA256('6'),
			ActivationCheckpointDigest: testSHA256('7'),
			BaselineWitness:            baselineRaw,
			FinalWitness:               finalRaw,
			WitnessPublicKey:           witnessPublic,
		},
	}
}

func activationEvidenceEvent(kind evidence.EventType) evidence.Event {
	return evidence.Event{
		Type: kind, TenantID: "tenant-a",
		RuntimeRef:    "executor-" + strings.Repeat("1", 64),
		CapsuleDigest: testSHA256('8'), PolicyDigest: testSHA256('2'),
		Generation: 7, GrantID: "workload", Outcome: evidence.Committed,
	}
}

func signExecutorWitness(
	t *testing.T,
	identity controlprotocol.ExecutorEvidenceIdentityProofV1,
	private ed25519.PrivateKey,
	head evidence.Head,
	at time.Time,
) []byte {
	t.Helper()
	chainHash := evidenceHash(head.ChainHash)
	publicDigest := controlprotocol.ExecutorEvidencePublicKeySHA256(
		identityPublicKey(t, identity),
	)
	witnessHead := controlprotocol.ExecutorEvidenceHeadV1{
		Stream:        controlprotocol.ExecutorEvidenceStreamV1,
		ReceiptNodeID: head.NodeID, ReceiptEpoch: head.Epoch,
		Sequence: head.Sequence, ChainHash: chainHash,
		PublicKeySHA256: publicDigest,
	}
	timestamp := at.UTC().Format(time.RFC3339Nano)
	export, err := controlprotocol.SignExecutorEvidenceExportV1(
		controlprotocol.ExecutorEvidenceExportStatementV1{
			ProtocolVersion:      controlprotocol.ExecutorEvidenceProtocolV1,
			ControllerInstanceID: "controller-a", ControlNodeID: "node-a",
			IdentityProof: identity,
			Status: controlprotocol.ExecutorEvidenceStatusV1{
				State: controlprotocol.ExecutorEvidenceStatusCurrent,
				Head:  &witnessHead, WitnessedAt: timestamp,
			},
			ExportedAt: timestamp,
		},
		private,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func identityPublicKey(
	t *testing.T,
	identity controlprotocol.ExecutorEvidenceIdentityProofV1,
) ed25519.PublicKey {
	t.Helper()
	public, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(identity)
	if err != nil {
		t.Fatal(err)
	}
	return public
}
