package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/activationstore"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
	"github.com/hardrails/steward/internal/taskpermit"
)

type rolloutVerifyTestFixture struct {
	workspace          string
	arguments          []string
	commandPrivatePath string
	commandKeyID       string
	taskPrivatePath    string
	taskKeyID          string
	witnessPrivatePath string
	gatewayPrivatePath string
}

func TestRolloutVerifyRejectsHostileIncompleteWorkspacesAndWrongTrust(t *testing.T) {
	base := newRolloutVerifyTestFixture(t)

	tests := []struct {
		name       string
		want       string
		mutate     func(*testing.T, *rolloutVerifyTestFixture)
		mutateArgs func(*testing.T, *rolloutVerifyTestFixture)
	}{
		{
			name: "hostile Gateway key substitution",
			want: "Gateway trust differs from the plan",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				name, err := rolloutstore.TargetArtifactName(
					0, rolloutstore.TargetGatewayReceiptPublicKeyKind,
				)
				if err != nil {
					t.Fatal(err)
				}
				raw := []byte(base64.StdEncoding.EncodeToString(public) + "\n")
				if err := os.WriteFile(filepath.Join(fixture.workspace, name), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "missing companion",
			want: "service-trust.json",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				name, err := rolloutstore.TargetArtifactName(
					0, rolloutstore.TargetServiceTrustKind,
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(fixture.workspace, name)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "extra target artifact",
			want: "outside the plan",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				name, err := rolloutstore.TargetArtifactName(
					1, rolloutstore.TargetAdmissionKind,
				)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(fixture.workspace, name), []byte(`{}`), 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "incomplete rollout",
			want: "incomplete",
			mutate: func(*testing.T, *rolloutVerifyTestFixture) {
			},
		},
		{
			name: "target state gap",
			want: "state",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				zero, err := rolloutstore.TargetStateName(0, 0)
				if err != nil {
					t.Fatal(err)
				}
				one, err := rolloutstore.TargetStateName(0, 1)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(
					filepath.Join(fixture.workspace, zero),
					filepath.Join(fixture.workspace, one),
				); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong external publisher trust",
			want: "authenticate rollout release",
			mutate: func(*testing.T, *rolloutVerifyTestFixture) {
			},
			mutateArgs: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				_, wrongPublic := generateTestKeyPair(t, t.TempDir(), "wrong-publisher")
				replaceRolloutVerifyArgument(
					t, fixture.arguments, "-publisher-public-key", wrongPublic,
				)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := cloneRolloutVerifyTestFixture(t, base)
			test.mutate(t, &fixture)
			if test.mutateArgs != nil {
				test.mutateArgs(t, &fixture)
			}
			var output bytes.Buffer
			err := verifyRollout(fixture.arguments, &output)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verify error=%v, want fragment %q", err, test.want)
			}
			if output.Len() != 0 {
				t.Fatalf("failed verification emitted output %q", output.String())
			}
		})
	}
}

func TestRolloutVerifyHasNoNetworkOrClientFlags(t *testing.T) {
	for _, flagName := range []string{
		"-controller-url",
		"-node-url",
		"-gateway-url",
		"-docker-socket",
		"-token-file",
	} {
		var output bytes.Buffer
		err := verifyRollout([]string{flagName, "http://127.0.0.1:1"}, &output)
		if err == nil || !strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("flag %s error=%v", flagName, err)
		}
		if output.Len() != 0 {
			t.Fatalf("rejected flag emitted output %q", output.String())
		}
	}
}

func TestRolloutVerifyAuthenticatesCompleteFleetAndRejectsProofLayerSubstitution(t *testing.T) {
	complete := completeRolloutVerifyTestFixture(t, newRolloutVerifyTestFixture(t))

	t.Run("complete JSON and human output", func(t *testing.T) {
		fixture := cloneRolloutVerifyTestFixture(t, complete)
		var output bytes.Buffer
		if err := verifyRollout(fixture.arguments, &output); err != nil {
			t.Fatal(err)
		}
		var verified rolloutVerificationOutput
		if err := json.Unmarshal(output.Bytes(), &verified); err != nil {
			t.Fatal(err)
		}
		if verified.SchemaVersion != rolloutVerificationSchemaV1 ||
			!verified.Valid || !verified.Verified ||
			verified.RolloutID != "rollout-verify-test" ||
			verified.VerifiedTargets != 1 ||
			!controlprotocol.ValidSHA256Digest(verified.ProofDigest) {
			t.Fatalf("verification output=%#v", verified)
		}

		humanFixture := cloneRolloutVerifyTestFixture(t, complete)
		humanFixture.arguments = removeRolloutVerifyFlag(humanFixture.arguments, "-json")
		output.Reset()
		if err := verifyRollout(humanFixture.arguments, &output); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(output.String(), "verified: 1 targets, 0 signed batch promotions, proof sha256:") {
			t.Fatalf("human verification output=%q", output.String())
		}
	})

	tests := []struct {
		name   string
		want   string
		mutate func(*testing.T, *rolloutVerifyTestFixture)
	}{
		{
			name: "outer command signature substitution",
			want: "authenticate retained activation-canary command",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				mutateRolloutVerifyCanarySignature(t, fixture.workspace)
			},
		},
		{
			name: "tenant task permit substitution behind a valid outer command",
			want: "verify exact retained canary",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				mutateRolloutVerifyTaskPermit(t, *fixture)
			},
		},
		{
			name: "controller capture signature substitution",
			want: "decode retained controller capture",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				mutateRolloutVerifyCaptureSignature(t, fixture.workspace)
			},
		},
		{
			name: "activation proof substitution",
			want: "activation proof does not match",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				mutateRolloutVerifyActivationProof(t, fixture.workspace)
			},
		},
		{
			name: "archive byte substitution",
			want: "verify rollout archive",
			mutate: func(t *testing.T, fixture *rolloutVerifyTestFixture) {
				archive := rolloutVerifyArgumentValue(t, fixture.arguments, "-archive")
				raw := offlineRead(t, archive)
				raw[len(raw)/2] ^= 0xff
				mutated := filepath.Join(t.TempDir(), "substituted.tar")
				if err := os.WriteFile(mutated, raw, 0o600); err != nil {
					t.Fatal(err)
				}
				replaceRolloutVerifyArgument(t, fixture.arguments, "-archive", mutated)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fixture := cloneRolloutVerifyTestFixture(t, complete)
			test.mutate(t, &fixture)
			var output bytes.Buffer
			err := verifyRollout(fixture.arguments, &output)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("verify error=%v, want fragment %q", err, test.want)
			}
			if output.Len() != 0 {
				t.Fatalf("failed verification emitted output %q", output.String())
			}
		})
	}
}

func completeRolloutVerifyTestFixture(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
) rolloutVerifyTestFixture {
	t.Helper()
	commandPrivate, err := readPrivateKey(fixture.commandPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	commandPublic := commandPrivate.Public().(ed25519.PublicKey)
	taskPrivate, err := readPrivateKey(fixture.taskPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	taskPublic := taskPrivate.Public().(ed25519.PublicKey)
	witnessPrivate, err := readPrivateKey(fixture.witnessPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublic := witnessPrivate.Public().(ed25519.PublicKey)
	gatewayPrivate, err := readPrivateKey(fixture.gatewayPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	gatewayPublic := gatewayPrivate.Public().(ed25519.PublicKey)
	publisherPublic, err := readPublicKey(
		rolloutVerifyArgumentValue(t, fixture.arguments, "-publisher-public-key"),
	)
	if err != nil {
		t.Fatal(err)
	}
	siteRootPublic, err := readPublicKey(
		rolloutVerifyArgumentValue(t, fixture.arguments, "-site-root-public-key"),
	)
	if err != nil {
		t.Fatal(err)
	}

	store, err := rolloutstore.Open(fixture.workspace)
	if err != nil {
		t.Fatal(err)
	}
	run, err := loadVerifiedRolloutRun(
		store,
		"publisher-a", publisherPublic,
		"site-root", siteRootPublic,
		witnessPublic,
	)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	prepared := run.targets[0].prepared
	target := prepared.Target()
	issuedAt, err := time.Parse(time.RFC3339Nano, run.plan.CreatedAt)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	authorization, err := rollout.NewPlanAuthorizationV1(run.planRaw, issuedAt)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	authorizationRaw, err := rollout.SignPlanAuthorizationV1(
		authorization, fixture.commandKeyID, commandPrivate, commandPublic,
	)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.WriteOnce(
		rolloutstore.PlanAuthorizationFileName, authorizationRaw,
	); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	routePolicyDigest := dsse.Digest([]byte("rollout-verify-route-policy"))
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    prepared.RuntimeRef(),
		Status:        "created",
		CapsuleDigest: prepared.CapsuleDigest(),
		PolicyDigest:  run.plan.PolicyDigest,
		Generation:    target.InstanceGeneration,
		EvidenceKeyID: evidence.KeyID(receiptPublic),
		GrantID: gateway.GrantID(
			run.plan.TenantID, target.InstanceID, target.InstanceGeneration,
		),
		ServiceID: agentrelease.HermesServiceID,
		TaskAuthorities: []controlprotocol.ExecutorTaskAuthorityV1{{
			KeyID: fixture.taskKeyID, PublicKey: base64.StdEncoding.EncodeToString(taskPublic),
		}},
		RoutePolicyDigest:     routePolicyDigest,
		ActivationID:          target.ActivationID,
		ActivationBeginDigest: prepared.ExecutorBeginDigest(),
	}
	projection.ServicePath = "/v1/services/" + projection.GrantID + "/"
	if err := rolloutdriver.VerifyAdmissionV1(prepared, projection); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	admissionRaw, err := json.Marshal(projection)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	window := rolloutdriver.SigningWindowV1{
		KeyID: fixture.commandKeyID, PrivateKey: commandPrivate,
		PublicKey:                  commandPublic,
		AuthorizationContextDigest: dsse.Digest(authorizationRaw),
		IssuedAt:                   issuedAt, ValidFor: 4 * time.Minute,
	}
	admit, err := rolloutdriver.SignAdmissionCommandV1(prepared, window)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	start, err := rolloutdriver.SignStartCommandV1(prepared, window)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	canary, err := rolloutdriver.BuildCanaryCommandV1(rolloutdriver.CanaryInputV1{
		Prepared: prepared, Admission: projection,
		TaskKeyID: fixture.taskKeyID, TaskPrivateKey: taskPrivate,
		TaskPublicKey:         taskPublic,
		OperationPolicyDigest: target.OperationPolicyDigest,
		ReceiptAuthority: activationcanary.ReceiptAuthorityV1{
			NodeID:          gateway.ServiceTaskReceiptNodeID(target.NodeID),
			Epoch:           target.GatewayReceiptEpoch,
			PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(gatewayPublic),
		},
		Deadline: issuedAt.Add(3 * time.Minute), CommandWindow: window,
	})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	verifiedCommand, err := activationcanary.VerifyHistoricalCommandV1(
		canary.CanaryRaw(),
		activationcanary.AdmissionContextV1{
			NodeID: target.NodeID, TenantID: run.plan.TenantID,
			InstanceID: target.InstanceID, Projection: projection,
		},
		taskpermit.MaxValidity,
	)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	terminal := offlineHermesResult(t, target.ActivationID)
	receipts := rolloutVerifyGatewayReceipts(
		t, verifiedCommand, terminal,
		target.GatewayReceiptEpoch, gatewayPublic, gatewayPrivate,
	)
	verifiedEvidence, err := activationcanary.VerifyEvidenceV1(
		verifiedCommand,
		"run_0123456789abcdef0123456789abcdef",
		terminal,
		receipts,
		gatewayPublic,
	)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	checkpointRaw, err := activationcanary.BuildCheckpointV1(
		verifiedCommand, verifiedEvidence,
	)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	resultRaw, verifiedResult, err := activationcanary.BuildResultV1(
		verifiedCommand,
		"run_0123456789abcdef0123456789abcdef",
		terminal,
		receipts,
		checkpointRaw,
		gatewayPublic,
	)
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	verifiedCanary, err := rolloutdriver.VerifyCanaryV1(rolloutdriver.VerifyCanaryInputV1{
		Prepared: prepared, Admission: projection,
		CommandRaw: canary.CanaryRaw(), ResultRaw: resultRaw,
		ReceiptPublicKey: gatewayPublic,
	})
	if err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	captureRaw := rolloutVerifyControllerCapture(
		t, run.plan, 0, prepared, projection, checkpointRaw,
		verifiedResult.Gateway(), receiptPublic, receiptPrivate, witnessPrivate,
	)
	for kind, raw := range map[string][]byte{
		rolloutstore.TargetAdmitCommandKind:  admit.Raw(),
		rolloutstore.TargetAdmissionKind:     admissionRaw,
		rolloutstore.TargetStartCommandKind:  start.Raw(),
		rolloutstore.TargetCanaryCommandKind: canary.OuterCommand().Raw(),
		rolloutstore.TargetCanaryResultKind:  resultRaw,
		rolloutstore.TargetCaptureExportKind: captureRaw,
	} {
		if err := writeRolloutTargetArtifact(store, 0, kind, raw); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
	}
	run.targets[0].admitCommandRaw = admit.Raw()
	run.targets[0].admissionRaw = admissionRaw
	run.targets[0].admission = &projection
	run.targets[0].startCommandRaw = start.Raw()
	run.targets[0].canaryCommandRaw = canary.OuterCommand().Raw()
	run.targets[0].canaryResultRaw = resultRaw
	run.targets[0].verifiedCanary = &verifiedCanary
	run.targets[0].captureRaw = captureRaw

	phases := []string{
		rollout.PhasePreflightPassed,
		rollout.PhaseEvidenceCaptureArmed,
		rollout.PhaseAdmitSubmitted,
		rollout.PhaseAdmitted,
		rollout.PhaseStartSubmitted,
		rollout.PhaseRunning,
		rollout.PhaseCanaryAuthorized,
		rollout.PhaseCanarySubmitted,
		rollout.PhaseAgentReportedTerminal,
		rollout.PhaseEvidenceCollected,
	}
	for _, phase := range phases {
		phase := phase
		var mutate func(*rollout.TargetStateV1)
		switch phase {
		case rollout.PhaseAdmitted:
			mutate = func(next *rollout.TargetStateV1) {
				next.RuntimeRef = projection.RuntimeRef
				next.AdmissionDigest = dsse.Digest(admissionRaw)
			}
		case rollout.PhaseAgentReportedTerminal:
			mutate = func(next *rollout.TargetStateV1) {
				next.CanaryResultDigest = dsse.Digest(terminal)
				next.CanaryResultBytes = int64(len(terminal))
			}
		}
		if err := appendRolloutTargetPhase(store, &run, 0, phase, mutate); err != nil {
			_ = store.Close()
			t.Fatal(err)
		}
	}
	if err := ensureRolloutActivationProof(store, &run, 0); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := appendRolloutTargetPhase(store, &run, 0, rollout.PhasePassed, nil); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := ensureRolloutProofManifest(store, &run, true); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func rolloutVerifyGatewayReceipts(
	t *testing.T,
	command activationcanary.VerifiedCommandV1,
	terminal []byte,
	epoch uint64,
	public ed25519.PublicKey,
	private ed25519.PrivateKey,
) []byte {
	t.Helper()
	statement := command.Permit().Statement
	nodeID := gateway.ServiceTaskReceiptNodeID(statement.NodeID)
	path := filepath.Join(t.TempDir(), "gateway.ndjson")
	log, err := connectorledger.Open(path, private, nodeID, epoch)
	if err != nil {
		t.Fatal(err)
	}
	taskDigest := taskpermit.TaskDigest(
		statement.TenantID, statement.InstanceID, statement.TaskID,
	)
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		Kind: connectorledger.ServiceTask, TenantID: statement.TenantID,
		RuntimeRef: statement.RuntimeRef, CapsuleDigest: statement.CapsuleDigest,
		PolicyDigest: statement.PolicyDigest, RoutePolicyDigest: statement.RoutePolicyDigest,
		Generation: statement.Generation, GrantID: statement.GrantID,
		ServiceID: statement.ServiceID, OperationID: statement.OperationID,
		OperationPolicyDigest: statement.OperationPolicyDigest,
		TaskDigest:            taskDigest, AuthorityKeyID: command.Permit().KeyID,
		PermitDigest:  command.Permit().EnvelopeDigest,
		RequestDigest: statement.RequestDigest, RequestBytes: statement.RequestBytes,
		TaskProtocol: connectorledger.TaskProtocolLifecycleV1,
	}
	if _, err := log.Begin(event); err != nil {
		t.Fatal(err)
	}
	event.Phase, event.Outcome = connectorledger.Dispatch, connectorledger.Responded
	event.HTTPStatus, event.ResponseBytes = 202, 96
	event.RunID = "run_0123456789abcdef0123456789abcdef"
	if _, err := log.Dispatch(event); err != nil {
		t.Fatal(err)
	}
	event.Phase, event.HTTPStatus = connectorledger.Terminal, 200
	event.ResponseBytes = int64(len(terminal))
	event.TaskStatus = connectorledger.TaskStatusAgentReportedCompleted
	event.ResultDigest = dsse.Digest(terminal)
	if _, err := log.Finish(event); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	var selected []connectorledger.VerifiedReceipt
	if _, err := connectorledger.VerifyRecords(
		path, public, nodeID, epoch,
		func(record connectorledger.VerifiedReceipt) error {
			if record.Receipt.Event.TaskDigest == taskDigest {
				selected = append(selected, record)
			}
			return nil
		},
	); err != nil {
		t.Fatal(err)
	}
	receipts, err := connectorledger.MarshalPortableTaskEvidence(selected)
	if err != nil {
		t.Fatal(err)
	}
	return receipts
}

func rolloutVerifyControllerCapture(
	t *testing.T,
	plan rollout.PlanV1,
	targetIndex uint16,
	prepared rolloutdriver.PreparedTargetV1,
	projection controlprotocol.ExecutorAdmissionProjectionV1,
	checkpointRaw []byte,
	gatewayResult activation.GatewayEvidenceResultV1,
	receiptPublic ed25519.PublicKey,
	receiptPrivate ed25519.PrivateKey,
	witnessPrivate ed25519.PrivateKey,
) []byte {
	t.Helper()
	target := prepared.Target()
	path := filepath.Join(t.TempDir(), "executor-evidence.bin")
	log, err := evidence.Open(path, receiptPrivate, target.NodeID, 1)
	if err != nil {
		t.Fatal(err)
	}
	base := evidence.Event{
		Type: evidence.PolicyReload, TenantID: plan.TenantID,
		RuntimeRef:    "executor-" + strings.Repeat("e", 64),
		CapsuleDigest: projection.CapsuleDigest, PolicyDigest: plan.PolicyDigest,
		Generation: target.InstanceGeneration, GrantID: "baseline",
		Outcome: evidence.Committed,
	}
	if _, err := log.Append(base); err != nil {
		t.Fatal(err)
	}
	baseline, err := log.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	event := evidence.Event{
		Type: evidence.ActivationBegin, TenantID: plan.TenantID,
		RuntimeRef: prepared.RuntimeRef(), CapsuleDigest: projection.CapsuleDigest,
		PolicyDigest: plan.PolicyDigest, Generation: target.InstanceGeneration,
		GrantID: target.ActivationID, Outcome: evidence.Allowed,
		MetadataHash: prepared.ExecutorBeginDigest(),
	}
	begin, err := log.AppendActivationBegin(event)
	if err != nil {
		t.Fatal(err)
	}
	event.Type, event.GrantID = evidence.AdmissionAllow, projection.GrantID
	event.MetadataHash = ""
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type, event.GrantID = evidence.JournalPrepare, "workload"
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type, event.Outcome = evidence.JournalCommit, evidence.Committed
	event.MetadataHash = projection.RoutePolicyDigest
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type, event.Outcome = evidence.LifecycleStart, evidence.Committed
	if _, err := log.Append(event); err != nil {
		t.Fatal(err)
	}
	event.Type, event.GrantID = evidence.ActivationCheckpoint, target.ActivationID
	event.MetadataHash = dsse.Digest(checkpointRaw)
	if _, err := log.AppendActivationCheckpoint(event); err != nil {
		t.Fatal(err)
	}
	delta, err := log.ExportDelta(evidence.Coordinate{
		Sequence: baseline.Sequence, ChainHash: baseline.ChainHash,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"controller-rollout-test", "enrollment-rollout-test", target.NodeID,
		target.NodeID, 1, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(
		claim, receiptPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	armed, err := time.Parse(time.RFC3339Nano, plan.CreatedAt)
	if err != nil {
		t.Fatal(err)
	}
	observed, err := time.Parse(time.RFC3339Nano, gatewayResult.TerminalAt)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Before(armed) {
		observed = armed
	}
	sealed := observed.Add(time.Nanosecond)
	exported := sealed.Add(time.Nanosecond)
	statement := controlprotocol.ControllerEvidenceCaptureStatementV1{
		ProtocolVersion:            controlprotocol.ControllerEvidenceCaptureProtocolV1,
		ControllerInstanceID:       "controller-rollout-test",
		CaptureID:                  rolloutCaptureID(plan, targetIndex),
		NodeID:                     target.NodeID,
		TenantID:                   plan.TenantID,
		RuntimeRef:                 prepared.RuntimeRef(),
		Generation:                 target.InstanceGeneration,
		ActivationID:               target.ActivationID,
		CanaryCommandID:            target.CanaryCommandID,
		ActivationBeginDigest:      prepared.ExecutorBeginDigest(),
		ActivationBeginSequence:    begin.Sequence,
		ActivationCheckpointDigest: dsse.Digest(checkpointRaw),
		CapsuleDigest:              projection.CapsuleDigest,
		PolicyDigest:               plan.PolicyDigest,
		IdentityProof:              identity,
		BaselineHead:               rolloutVerifyEvidenceHead(baseline, receiptPublic),
		FinalHead:                  rolloutVerifyEvidenceHead(delta.Head, receiptPublic),
		FrameCount:                 uint32(len(delta.Frames)),
		FramesDigest: controlprotocol.ControllerEvidenceCaptureFramesDigestV1(
			delta.Frames,
		),
		ArmedAt:    armed.Format(time.RFC3339Nano),
		ObservedAt: observed.Format(time.RFC3339Nano),
		SealedAt:   sealed.Format(time.RFC3339Nano),
		ExportedAt: exported.Format(time.RFC3339Nano),
	}
	capture, err := controlprotocol.SignControllerEvidenceCaptureV1(
		statement, delta.Frames, witnessPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func rolloutVerifyEvidenceHead(
	head evidence.Head,
	public ed25519.PublicKey,
) controlprotocol.ExecutorEvidenceHeadV1 {
	return controlprotocol.ExecutorEvidenceHeadV1{
		Stream:          controlprotocol.ExecutorEvidenceStreamV1,
		ReceiptNodeID:   head.NodeID,
		ReceiptEpoch:    head.Epoch,
		Sequence:        head.Sequence,
		ChainHash:       "sha256:" + hex.EncodeToString(head.ChainHash[:]),
		PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(public),
	}
}

func mutateRolloutVerifyCanarySignature(t *testing.T, workspace string) {
	t.Helper()
	path := rolloutVerifyTargetPath(t, workspace, rolloutstore.TargetCanaryCommandKind)
	envelope, err := dsse.Parse(offlineRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	envelope.Signatures[0].Sig = mutateRolloutVerifyBase64(envelope.Signatures[0].Sig)
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mutateRolloutVerifyTaskPermit(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
) {
	t.Helper()
	path := rolloutVerifyTargetPath(
		t, fixture.workspace, rolloutstore.TargetCanaryCommandKind,
	)
	envelope, err := dsse.Parse(offlineRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
		t.Fatal(err)
	}
	canary, err := activationcanary.ParseCommandV1(statement.Payload)
	if err != nil {
		t.Fatal(err)
	}
	canary.TaskPermit = "not-a-tenant-task-permit"
	canaryRaw, err := json.Marshal(canary)
	if err != nil {
		t.Fatal(err)
	}
	statement.Payload = canaryRaw
	statementRaw, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	private, err := readPrivateKey(fixture.commandPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	reSigned, err := dsse.Sign(
		admission.CommandPayloadType,
		statementRaw,
		fixture.commandKeyID,
		private,
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(reSigned)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mutateRolloutVerifyCaptureSignature(t *testing.T, workspace string) {
	t.Helper()
	path := rolloutVerifyTargetPath(t, workspace, rolloutstore.TargetCaptureExportKind)
	var capture controlprotocol.ControllerEvidenceCaptureV1
	if err := json.Unmarshal(offlineRead(t, path), &capture); err != nil {
		t.Fatal(err)
	}
	capture.SignatureBase64 = mutateRolloutVerifyBase64(capture.SignatureBase64)
	raw, err := json.Marshal(capture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mutateRolloutVerifyActivationProof(t *testing.T, workspace string) {
	t.Helper()
	path := rolloutVerifyTargetPath(t, workspace, rolloutstore.TargetActivationProofKind)
	proof, err := activation.ParseProofV1(offlineRead(t, path))
	if err != nil {
		t.Fatal(err)
	}
	proof.ExecutorCheckpointDigest = dsse.Digest([]byte("substituted-checkpoint"))
	raw, err := activation.MarshalProofV1(proof)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func mutateRolloutVerifyBase64(value string) string {
	if value[0] == 'A' {
		return "B" + value[1:]
	}
	return "A" + value[1:]
}

func rolloutVerifyTargetPath(t *testing.T, workspace, kind string) string {
	t.Helper()
	name, err := rolloutstore.TargetArtifactName(0, kind)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(workspace, name)
}

func rolloutVerifyArgumentValue(
	t *testing.T,
	arguments []string,
	name string,
) string {
	t.Helper()
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			return arguments[index+1]
		}
	}
	t.Fatalf("argument %q is absent", name)
	return ""
}

func removeRolloutVerifyFlag(arguments []string, name string) []string {
	result := make([]string, 0, len(arguments))
	for _, argument := range arguments {
		if argument != name {
			result = append(result, argument)
		}
	}
	return result
}

func newRolloutVerifyTestFixture(t *testing.T) rolloutVerifyTestFixture {
	return newRolloutVerifyTestFixtureTargets(t, 1)
}

func newRolloutVerifyTestFixtureTargets(
	t *testing.T,
	targetCount int,
) rolloutVerifyTestFixture {
	t.Helper()
	if targetCount < 1 || targetCount > rollout.MaxTargets {
		t.Fatalf("invalid rollout target fixture count %d", targetCount)
	}
	offline := newOfflineActivationFixture(t)
	inputsDirectory := t.TempDir()
	commandPrivatePath, commandPublicPath := generateTestKeyPair(
		t, inputsDirectory, "rollout-verify-command",
	)
	commandPublic, err := readPublicKey(commandPublicPath)
	if err != nil {
		t.Fatal(err)
	}

	policyEnvelopeRaw := offlineRead(
		t, filepath.Join(offline.directory, activationstore.PolicyFileName),
	)
	policyEnvelope, err := dsse.Parse(policyEnvelopeRaw)
	if err != nil {
		t.Fatal(err)
	}
	policyPayload, err := base64.StdEncoding.DecodeString(policyEnvelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var policy admission.SitePolicy
	if err := json.Unmarshal(policyPayload, &policy); err != nil {
		t.Fatal(err)
	}
	policy.Tenants[0].CommandKeys = []admission.CommandKey{{
		KeyID:      "rollout-verify-command",
		PublicKey:  base64.StdEncoding.EncodeToString(commandPublic),
		Operations: []string{"admit", "start", "activation-canary"},
	}}
	sitePrivatePath := strings.TrimSuffix(offline.siteRootPublicPath, ".public") + ".private.pem"
	sitePrivate, err := readPrivateKey(sitePrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(inputsDirectory, "policy.dsse.json")
	writeSignedJSON(
		t, policyPath, admission.PolicyPayloadType, policy,
		"site-root", sitePrivate,
	)

	copyInput := func(name, source string) string {
		t.Helper()
		if err := os.WriteFile(
			filepath.Join(inputsDirectory, name), offlineRead(t, source), 0o600,
		); err != nil {
			t.Fatal(err)
		}
		return name
	}
	baseIntentRaw := offlineRead(
		t, filepath.Join(offline.directory, activationstore.IntentFileName),
	)
	var baseIntent admission.InstanceIntent
	if err := dsse.DecodeStrictInto(baseIntentRaw, dsse.MaxPayloadBytes, &baseIntent); err != nil {
		t.Fatal(err)
	}
	serviceTrustName := copyInput(
		"service-trust.json",
		filepath.Join(offline.directory, activationstore.ServiceTrustFileName),
	)
	var serviceTrust serviceTrustInventory
	if err := json.Unmarshal(
		offlineRead(t, filepath.Join(inputsDirectory, serviceTrustName)),
		&serviceTrust,
	); err != nil {
		t.Fatal(err)
	}
	prettyServiceTrust, err := json.MarshalIndent(serviceTrust, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	prettyServiceTrust = append(prettyServiceTrust, '\n')
	if err := os.WriteFile(
		filepath.Join(inputsDirectory, serviceTrustName), prettyServiceTrust, 0o600,
	); err != nil {
		t.Fatal(err)
	}
	gatewayPrivatePath, gatewayPEMPublicPath := generateTestKeyPair(
		t, inputsDirectory, "rollout-verify-gateway",
	)
	gatewayPublic, err := readPublicKey(gatewayPEMPublicPath)
	if err != nil {
		t.Fatal(err)
	}
	gatewayName := "gateway.public"
	if err := os.WriteFile(
		filepath.Join(inputsDirectory, gatewayName),
		[]byte(base64.StdEncoding.EncodeToString(gatewayPublic)+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	targetInputs := make([]rolloutTargetInputV1, targetCount)
	for index := range targetInputs {
		intent := baseIntent
		if index > 0 {
			suffix := fmt.Sprintf("-%d", index)
			intent.NodeID += suffix
			intent.InstanceID += suffix
			intent.LineageID += suffix
			intent.Generation += uint64(index)
		}
		intentRaw, err := json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		intentName := fmt.Sprintf("intent-%03d.json", index)
		if err := os.WriteFile(
			filepath.Join(inputsDirectory, intentName), intentRaw, 0o600,
		); err != nil {
			t.Fatal(err)
		}
		targetServiceTrust := serviceTrust
		targetServiceTrust.NodeID = intent.NodeID
		targetServiceTrust.TenantID = intent.TenantID
		targetServiceTrustRaw, err := json.MarshalIndent(targetServiceTrust, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		targetServiceTrustRaw = append(targetServiceTrustRaw, '\n')
		targetServiceTrustName := fmt.Sprintf("service-trust-%03d.json", index)
		if err := os.WriteFile(
			filepath.Join(inputsDirectory, targetServiceTrustName), targetServiceTrustRaw, 0o600,
		); err != nil {
			t.Fatal(err)
		}
		targetInputs[index] = rolloutTargetInputV1{
			IntentFile:                  intentName,
			ServiceTrustFile:            targetServiceTrustName,
			GatewayReceiptPublicKeyFile: gatewayName,
			GatewayReceiptEpoch:         1,
			ClaimGeneration:             uint64(index + 1),
		}
	}
	targetsRaw, err := json.Marshal(rolloutInputsV1{
		SchemaVersion: rolloutInputsSchemaV1,
		Targets:       targetInputs,
	})
	if err != nil {
		t.Fatal(err)
	}
	targetsPath := filepath.Join(inputsDirectory, "targets.json")
	if err := os.WriteFile(targetsPath, targetsRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	witnessPrivatePath, _ := generateTestKeyPair(
		t, inputsDirectory, "rollout-verify-witness",
	)
	witnessPrivate, err := readPrivateKey(witnessPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	witnessPublicPath := offlineWriteWitnessPublicKey(
		t,
		inputsDirectory,
		"rollout-verify-witness.public.pem",
		witnessPrivate.Public().(ed25519.PublicKey),
	)

	workspace := filepath.Join(t.TempDir(), "rollout")
	archivePath := filepath.Join(offline.directory, activationstore.ImageArchiveFileName)
	if err := createRollout([]string{
		"-dir", workspace,
		"-rollout-id", "rollout-verify-test",
		"-release", filepath.Join(offline.directory, activationstore.ReleaseFileName),
		"-policy", policyPath,
		"-archive", archivePath,
		"-targets", targetsPath,
		"-publisher-public-key", offline.publisherPublicPath,
		"-publisher-key-id", "publisher-a",
		"-site-root-public-key", offline.siteRootPublicPath,
		"-site-root-key-id", "site-root",
		"-witness-public-key", witnessPublicPath,
		"-batch-size", "1",
		"-valid-for", "5m",
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	return rolloutVerifyTestFixture{
		workspace:          workspace,
		commandPrivatePath: commandPrivatePath,
		commandKeyID:       "rollout-verify-command",
		taskPrivatePath: filepath.Join(
			filepath.Dir(offline.publisherPublicPath), "activation-task.private.pem",
		),
		taskKeyID:          "tenant-task",
		witnessPrivatePath: witnessPrivatePath,
		gatewayPrivatePath: gatewayPrivatePath,
		arguments: []string{
			"-dir", workspace,
			"-archive", archivePath,
			"-publisher-public-key", offline.publisherPublicPath,
			"-publisher-key-id", "publisher-a",
			"-site-root-public-key", offline.siteRootPublicPath,
			"-site-root-key-id", "site-root",
			"-witness-public-key", witnessPublicPath,
			"-json",
		},
	}
}

func cloneRolloutVerifyTestFixture(
	t *testing.T,
	base rolloutVerifyTestFixture,
) rolloutVerifyTestFixture {
	t.Helper()
	workspace := filepath.Join(t.TempDir(), "rollout")
	if err := os.Mkdir(workspace, 0o700); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(base.workspace)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			t.Fatalf("base rollout entry %q is not regular", entry.Name())
		}
		raw := offlineRead(t, filepath.Join(base.workspace, entry.Name()))
		if err := os.WriteFile(filepath.Join(workspace, entry.Name()), raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	arguments := append([]string(nil), base.arguments...)
	replaceRolloutVerifyArgument(t, arguments, "-dir", workspace)
	return rolloutVerifyTestFixture{
		workspace: workspace, arguments: arguments,
		commandPrivatePath: base.commandPrivatePath,
		commandKeyID:       base.commandKeyID,
		taskPrivatePath:    base.taskPrivatePath,
		taskKeyID:          base.taskKeyID,
		witnessPrivatePath: base.witnessPrivatePath,
		gatewayPrivatePath: base.gatewayPrivatePath,
	}
}

func replaceRolloutVerifyArgument(
	t *testing.T,
	arguments []string,
	name string,
	value string,
) {
	t.Helper()
	for index := 0; index+1 < len(arguments); index++ {
		if arguments[index] == name {
			arguments[index+1] = value
			return
		}
	}
	t.Fatalf("argument %q is absent", name)
}
