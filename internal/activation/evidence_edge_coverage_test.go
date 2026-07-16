package activation

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

func TestExecutorWitnessPairRejectsIdentityFindingAndChronologyDrift(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t)
	baseline, err := controlprotocol.DecodeExecutorEvidenceExportV1(
		fixture.request.BaselineWitness,
	)
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name   string
		mutate func(*ExecutorEvidenceRequestV1)
		want   string
	}{
		{
			name: "invalid binding",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.Binding.NodeID = ""
			},
			want: "binding",
		},
		{
			name: "incomplete request",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.StateRuntimeRef = ""
			},
			want: "incomplete",
		},
		{
			name: "malformed baseline",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.BaselineWitness = []byte("{")
			},
			want: "decode baseline",
		},
		{
			name: "malformed final",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.FinalWitness = []byte("{")
			},
			want: "decode final",
		},
		{
			name: "invalid final signature",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				value, decodeErr := controlprotocol.DecodeExecutorEvidenceExportV1(
					request.FinalWitness,
				)
				if decodeErr != nil {
					t.Fatal(decodeErr)
				}
				_, otherPrivate, keyErr := ed25519.GenerateKey(rand.Reader)
				if keyErr != nil {
					t.Fatal(keyErr)
				}
				value, signErr := controlprotocol.SignExecutorEvidenceExportV1(
					value.Statement, otherPrivate,
				)
				if signErr != nil {
					t.Fatal(signErr)
				}
				request.FinalWitness = mustMarshalExecutorWitness(t, value)
			},
			want: "verify final",
		},
		{
			name: "finding",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.BaselineWitness = rewriteExecutorWitness(
					t, request.BaselineWitness, fixture.witnessPrivate,
					func(statement *controlprotocol.ExecutorEvidenceExportStatementV1) {
						compared := *statement.Status.Head
						observed := compared
						observed.ChainHash = testSHA256('f')
						statement.Status.State =
							controlprotocol.ExecutorEvidenceStatusEquivocationDetected
						statement.Status.Finding =
							&controlprotocol.ExecutorEvidenceFindingV1{
								Kind:         controlprotocol.ExecutorEvidenceFindingEquivocation,
								DetectedAt:   statement.Status.WitnessedAt,
								ComparedHead: compared,
								ObservedHead: observed,
							}
					},
				)
			},
			want: "finding-free",
		},
		{
			name: "enrollment identity changed",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				receiptPublic := fixture.receiptPrivate.Public().(ed25519.PublicKey)
				claim, claimErr := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
					"controller-a", "enrollment-b", "node-a",
					"node-a", 1, receiptPublic,
				)
				if claimErr != nil {
					t.Fatal(claimErr)
				}
				proof, proofErr :=
					controlprotocol.SignExecutorEvidenceIdentityClaimV1(
						claim, fixture.receiptPrivate,
					)
				if proofErr != nil {
					t.Fatal(proofErr)
				}
				request.FinalWitness = rewriteExecutorWitness(
					t, request.FinalWitness, fixture.witnessPrivate,
					func(statement *controlprotocol.ExecutorEvidenceExportStatementV1) {
						statement.IdentityProof = proof
					},
				)
			},
			want: "changed controller, enrollment, or witness identity",
		},
		{
			name: "stream does not advance",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.FinalWitness = rewriteExecutorWitness(
					t, request.FinalWitness, fixture.witnessPrivate,
					func(statement *controlprotocol.ExecutorEvidenceExportStatementV1) {
						statement.Status.Head.Sequence =
							baseline.Statement.Status.Head.Sequence
					},
				)
			},
			want: "does not advance",
		},
		{
			name: "final predates baseline",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.BaselineWitness = rewriteExecutorWitness(
					t, request.BaselineWitness, fixture.witnessPrivate,
					func(statement *controlprotocol.ExecutorEvidenceExportStatementV1) {
						statement.ExportedAt = "2026-07-16T12:02:00Z"
					},
				)
			},
			want: "predates",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := fixture.request
			test.mutate(&request)
			err := VerifyExecutorWitnessPairV1(request)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}
}

func TestEvidenceFrameAndHashDecodersRejectAmbiguousInput(t *testing.T) {
	frameCases := []struct {
		name string
		raw  []byte
		want string
	}{
		{name: "empty", want: "empty or oversized"},
		{name: "truncated length", raw: []byte{0, 0, 0}, want: "truncated"},
		{name: "zero length", raw: make([]byte, 4), want: "invalid frame length"},
		{
			name: "declared content truncated",
			raw:  []byte{0, 0, 0, 2, 1},
			want: "invalid frame length",
		},
	}
	oversizedLength := make([]byte, 4)
	binary.BigEndian.PutUint32(
		oversizedLength, uint32(evidence.MaxEnvelopeBytes+1),
	)
	frameCases = append(frameCases, struct {
		name string
		raw  []byte
		want string
	}{
		name: "oversized frame", raw: oversizedLength,
		want: "invalid frame length",
	})
	for _, test := range frameCases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeEvidenceFrames(test.raw); err == nil ||
				!strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}

	validFrame := []byte{0, 0, 0, 1, 'a'}
	frames, err := decodeEvidenceFrames(append(validFrame, validFrame...))
	if err != nil || len(frames) != 2 {
		t.Fatalf("frames=%v err=%v", frames, err)
	}
	for name, value := range map[string]string{
		"missing prefix": strings.Repeat("a", 64),
		"invalid hex":    "sha256:" + strings.Repeat("g", 64),
		"short":          "sha256:aa",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeEvidenceHash(value); err == nil {
				t.Fatalf("invalid hash %q accepted", value)
			}
		})
	}
	if _, err := decodeEvidenceHash(testSHA256('a')); err != nil {
		t.Fatal(err)
	}
}

func TestEvidenceCollectionRejectsInvalidRequestsAndUnsafePaths(t *testing.T) {
	executorFixture := newExecutorEvidenceFixture(t)
	if _, err := CollectExecutorEvidenceV1(
		ExecutorEvidenceRequestV1{}, executorFixture.path,
	); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("invalid executor request err=%v", err)
	}
	for name, path := range map[string]string{
		"empty":   "",
		"missing": filepath.Join(t.TempDir(), "missing"),
		"folder":  t.TempDir(),
	} {
		t.Run("executor "+name, func(t *testing.T) {
			if _, err := CollectExecutorEvidenceV1(
				executorFixture.request, path,
			); err == nil {
				t.Fatal("invalid executor evidence path accepted")
			}
		})
	}
	if err := os.Chmod(executorFixture.path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectExecutorEvidenceV1(
		executorFixture.request, executorFixture.path,
	); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("unsafe executor permissions err=%v", err)
	}

	gatewayFixture := newGatewayEvidenceFixture(t)
	if _, err := CollectGatewayEvidenceV1(
		GatewayEvidenceRequestV1{}, gatewayFixture.path,
	); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("invalid Gateway request err=%v", err)
	}
	if _, err := VerifyGatewayEvidenceV1(
		GatewayEvidenceRequestV1{}, []byte("invalid"),
	); !errors.Is(err, ErrEvidenceInvalid) {
		t.Fatalf("invalid portable Gateway request err=%v", err)
	}
	for name, path := range map[string]string{
		"empty":   "",
		"missing": filepath.Join(t.TempDir(), "missing"),
		"folder":  t.TempDir(),
	} {
		t.Run("gateway "+name, func(t *testing.T) {
			if _, err := CollectGatewayEvidenceV1(
				gatewayFixture.request, path,
			); err == nil {
				t.Fatal("invalid Gateway ledger path accepted")
			}
		})
	}
	if err := os.Chmod(gatewayFixture.path, 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := CollectGatewayEvidenceV1(
		gatewayFixture.request, gatewayFixture.path,
	); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("unsafe Gateway permissions err=%v", err)
	}
}

func TestExecutorCollectionRejectsWitnessCoordinatesAbsentFromLog(t *testing.T) {
	fixture := newExecutorEvidenceFixture(t)
	tests := []struct {
		name   string
		mutate func(*ExecutorEvidenceRequestV1)
		want   string
	}{
		{
			name: "baseline hash",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.BaselineWitness = rewriteExecutorWitness(
					t, request.BaselineWitness, fixture.witnessPrivate,
					func(statement *controlprotocol.ExecutorEvidenceExportStatementV1) {
						statement.Status.Head.ChainHash = testSHA256('e')
					},
				)
			},
			want: "baseline coordinate",
		},
		{
			name: "final hash",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.FinalWitness = rewriteExecutorWitness(
					t, request.FinalWitness, fixture.witnessPrivate,
					func(statement *controlprotocol.ExecutorEvidenceExportStatementV1) {
						statement.Status.Head.ChainHash = testSHA256('e')
					},
				)
			},
			want: "final coordinate",
		},
		{
			name: "future final sequence",
			mutate: func(request *ExecutorEvidenceRequestV1) {
				request.FinalWitness = rewriteExecutorWitness(
					t, request.FinalWitness, fixture.witnessPrivate,
					func(statement *controlprotocol.ExecutorEvidenceExportStatementV1) {
						statement.Status.Head.Sequence++
						statement.Status.Head.ChainHash = testSHA256('e')
					},
				)
			},
			want: "final controller witness coordinate",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := fixture.request
			test.mutate(&request)
			if _, err := CollectExecutorEvidenceV1(
				request, fixture.path,
			); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("err=%v, want %q", err, test.want)
			}
		})
	}
}

func TestGatewayEvidenceRequestValidationRejectsIncompleteBindings(t *testing.T) {
	fixture := newGatewayEvidenceFixture(t)
	expectation, err := validateGatewayEvidenceRequest(fixture.request)
	if err != nil || expectation.taskDigest == "" ||
		expectation.receiptNodeID != "node-a/gateway" {
		t.Fatalf("expectation=%#v err=%v", expectation, err)
	}
	tests := map[string]func(*GatewayEvidenceRequestV1){
		"protocol": func(request *GatewayEvidenceRequestV1) {
			request.TaskProtocol = ""
		},
		"run": func(request *GatewayEvidenceRequestV1) {
			request.RunID = ""
		},
		"result": func(request *GatewayEvidenceRequestV1) {
			request.Result = nil
		},
		"receipt key": func(request *GatewayEvidenceRequestV1) {
			request.ReceiptPublicKey = nil
		},
		"receipt epoch": func(request *GatewayEvidenceRequestV1) {
			request.ReceiptEpoch = 0
		},
		"task key": func(request *GatewayEvidenceRequestV1) {
			request.Task.KeyID = ""
		},
		"tenant": func(request *GatewayEvidenceRequestV1) {
			request.Task.Statement.TenantID = ""
		},
		"runtime": func(request *GatewayEvidenceRequestV1) {
			request.Task.Statement.RuntimeRef = ""
		},
		"request bytes": func(request *GatewayEvidenceRequestV1) {
			request.Task.Statement.RequestBytes = 0
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := fixture.request
			mutate(&request)
			if _, err := validateGatewayEvidenceRequest(request); err == nil {
				t.Fatal("incomplete Gateway evidence request accepted")
			}
		})
	}
}

func TestEvidenceContextCancellationAtEveryCheckpoint(t *testing.T) {
	executorFixture := newExecutorEvidenceFixture(t)
	collectedExecutor, err := CollectExecutorEvidenceV1(
		executorFixture.request, executorFixture.path,
	)
	if err != nil {
		t.Fatal(err)
	}
	gatewayFixture := newGatewayEvidenceFixture(t)
	collectedGateway, err := CollectGatewayEvidenceV1(
		gatewayFixture.request, gatewayFixture.path,
	)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := CollectExecutorEvidenceV1Context(
		nil, executorFixture.request, executorFixture.path,
	); err == nil || !strings.Contains(err.Error(), "context is required") {
		t.Fatalf("nil context err=%v", err)
	}
	assertActivationCheckpointsCancel(t, "collect executor", func(ctx context.Context) error {
		_, err := CollectExecutorEvidenceV1Context(
			ctx, executorFixture.request, executorFixture.path,
		)
		return err
	})
	assertActivationCheckpointsCancel(t, "verify executor", func(ctx context.Context) error {
		_, err := VerifyExecutorEvidenceDeltaV1Context(
			ctx, executorFixture.request, collectedExecutor.Delta,
		)
		return err
	})
	assertActivationCheckpointsCancel(t, "collect Gateway", func(ctx context.Context) error {
		_, err := CollectGatewayEvidenceV1Context(
			ctx, gatewayFixture.request, gatewayFixture.path,
		)
		return err
	})
	assertActivationCheckpointsCancel(t, "verify Gateway", func(ctx context.Context) error {
		_, err := VerifyGatewayEvidenceV1Context(
			ctx, gatewayFixture.request, collectedGateway.Receipts,
		)
		return err
	})
}

func rewriteExecutorWitness(
	t *testing.T,
	raw []byte,
	private ed25519.PrivateKey,
	mutate func(*controlprotocol.ExecutorEvidenceExportStatementV1),
) []byte {
	t.Helper()
	value, err := controlprotocol.DecodeExecutorEvidenceExportV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	statement := value.Statement
	mutate(&statement)
	signed, err := controlprotocol.SignExecutorEvidenceExportV1(
		statement, private,
	)
	if err != nil {
		t.Fatal(err)
	}
	return mustMarshalExecutorWitness(t, signed)
}

func mustMarshalExecutorWitness(
	t *testing.T,
	value controlprotocol.ExecutorEvidenceExportV1,
) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type activationCheckpointContext struct {
	context.Context
	calls    int
	cancelAt int
	canceled chan struct{}
}

func newActivationCheckpointContext(cancelAt int) *activationCheckpointContext {
	canceled := make(chan struct{})
	close(canceled)
	return &activationCheckpointContext{
		Context:  context.Background(),
		cancelAt: cancelAt,
		canceled: canceled,
	}
}

func (ctx *activationCheckpointContext) Done() <-chan struct{} {
	ctx.calls++
	if ctx.calls >= ctx.cancelAt {
		return ctx.canceled
	}
	return nil
}

func (ctx *activationCheckpointContext) Err() error {
	if ctx.calls >= ctx.cancelAt {
		return context.Canceled
	}
	return nil
}

func (ctx *activationCheckpointContext) Deadline() (time.Time, bool) {
	return time.Time{}, false
}

func assertActivationCheckpointsCancel(
	t *testing.T,
	name string,
	run func(context.Context) error,
) {
	t.Helper()
	counter := newActivationCheckpointContext(int(^uint(0) >> 1))
	if err := run(counter); err != nil {
		t.Fatalf("%s baseline: %v", name, err)
	}
	for cancelAt := 1; cancelAt <= counter.calls; cancelAt++ {
		ctx := newActivationCheckpointContext(cancelAt)
		if err := run(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf(
				"%s cancellation at checkpoint %d/%d: %v",
				name, cancelAt, counter.calls, err,
			)
		}
	}
}
