package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/rolloutdriver"
	"github.com/hardrails/steward/internal/rolloutstore"
)

func TestRolloutPromotionPrecedesNextBatchAndSurvivesRetry(t *testing.T) {
	fixture := newRolloutVerifyTestFixtureTargets(t, 2)
	run := loadRolloutRunTestFixture(t, fixture)
	controller := newRolloutFleetController(t, fixture, run)
	server := httptest.NewServer(controller)
	t.Cleanup(server.Close)

	if err := runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	if controller.requestCount(0) == 0 || controller.requestCount(1) != 0 {
		t.Fatalf("first invocation requests=%v, want canary batch only", controller.requests())
	}
	if _, err := os.Stat(filepath.Join(
		fixture.workspace, mustBatchPromotionName(t, 1),
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("promotion appeared before operator entered batch one: %v", err)
	}
	state0, _ := rolloutRunLatestTargetState(t, fixture.workspace, 0)
	state1, _ := rolloutRunLatestTargetState(t, fixture.workspace, 1)
	if state0.Phase != rollout.PhasePassed || state1.Phase != rollout.PhasePlanned {
		t.Fatalf("post-canary states=%q,%q", state0.Phase, state1.Phase)
	}

	// A backward coordinator clock must fail before writing the immutable
	// promotion or contacting the next node.
	previousNow := timeNow
	t.Cleanup(func() { timeNow = previousNow })
	stateTime, err := time.Parse(time.RFC3339Nano, state0.UpdatedAt)
	if err != nil {
		t.Fatal(err)
	}
	timeNow = func() time.Time { return stateTime.Add(-time.Nanosecond) }
	requestsBefore := controller.requestCount(1)
	err = runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	)
	// Resume at the last durable state. Advancing the fixed coordinator clock
	// by a whole second can make a fast runner's wall-clock Gateway receipt
	// predate the permit's not_before.
	promotionNow := stateTime
	timeNow = func() time.Time { return promotionNow }
	if err == nil || !strings.Contains(err.Error(), "clock precedes") {
		t.Fatalf("clock rollback error=%v", err)
	}
	if controller.requestCount(1) != requestsBefore {
		t.Fatal("clock rollback contacted the next batch")
	}
	if _, err := os.Stat(filepath.Join(
		fixture.workspace, mustBatchPromotionName(t, 1),
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("clock rollback left an immutable promotion: %v", err)
	}
	controller.failNextPreflight(1)
	err = runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	)
	if err == nil || !strings.Contains(err.Error(), "preflight rollout node") {
		t.Fatalf("interrupted next-batch run error=%v", err)
	}
	promotionPath := filepath.Join(fixture.workspace, mustBatchPromotionName(t, 1))
	promotionBeforeRetry := offlineRead(t, promotionPath)
	if !controller.promotionPresentAtFirstRequest(1) {
		t.Fatal("next-batch HTTP request occurred before durable signed promotion")
	}
	if _, err := os.Stat(rolloutRunTargetPathFor(
		t, fixture.workspace, 1, rolloutstore.TargetAdmitCommandKind,
	)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed preflight wrote a next-batch command: %v", err)
	}

	if err := runRollout(
		rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
	); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(promotionBeforeRetry, offlineRead(t, promotionPath)) {
		t.Fatal("retry changed the exact signed promotion")
	}
	state1, _ = rolloutRunLatestTargetState(t, fixture.workspace, 1)
	if state1.Phase != rollout.PhasePassed {
		t.Fatalf("next-batch target state=%q", state1.Phase)
	}
	authorizationRaw := offlineRead(
		t, filepath.Join(fixture.workspace, rolloutstore.PlanAuthorizationFileName),
	)
	assertRolloutTargetCommandContext(
		t, fixture.workspace, 0, dsse.Digest(authorizationRaw),
	)
	assertRolloutTargetCommandContext(
		t, fixture.workspace, 1, dsse.Digest(promotionBeforeRetry),
	)
	proofRaw := offlineRead(t, filepath.Join(fixture.workspace, rolloutstore.ProofFileName))
	proof, err := rollout.ParseProofManifestV1(proofRaw)
	if err != nil {
		t.Fatal(err)
	}
	if proof.PlanAuthorizationDigest != dsse.Digest(authorizationRaw) ||
		len(proof.BatchPromotionDigests) != 1 ||
		proof.BatchPromotionDigests[0] != dsse.Digest(promotionBeforeRetry) {
		t.Fatalf("aggregate proof omitted authorization chain: %#v", proof)
	}
	if err := verifyRollout(fixture.arguments, &bytes.Buffer{}); err != nil {
		t.Fatalf("verify promoted rollout offline: %v", err)
	}

	testRolloutProofPublicationRequiresAuthenticatedAuthorization(t, fixture)
	testRolloutPromotionTampering(t, fixture)
}

func testRolloutProofPublicationRequiresAuthenticatedAuthorization(
	t *testing.T,
	complete rolloutVerifyTestFixture,
) {
	t.Helper()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		requests.Add(1)
	}))
	t.Cleanup(server.Close)

	t.Run("tampered chain leaves no proof", func(t *testing.T) {
		fixture := cloneRolloutVerifyTestFixture(t, complete)
		proofPath := filepath.Join(fixture.workspace, rolloutstore.ProofFileName)
		if err := os.Remove(proofPath); err != nil {
			t.Fatal(err)
		}
		authorizationPath := filepath.Join(
			fixture.workspace, rolloutstore.PlanAuthorizationFileName,
		)
		envelope := mustDSSEEnvelope(t, offlineRead(t, authorizationPath))
		envelope.Signatures[0].Sig = mutateRolloutVerifyBase64(envelope.Signatures[0].Sig)
		writeDSSEEnvelope(t, authorizationPath, envelope)

		if err := runRollout(
			rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
		); err == nil {
			t.Fatal("tampered authorization chain published a proof")
		}
		if requests.Load() != 0 {
			t.Fatalf("tampered authorization contacted controller %d times", requests.Load())
		}
		if _, err := os.Stat(proofPath); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("tampered authorization left proof artifact: %v", err)
		}
	})

	t.Run("corrected chain recovers proof offline", func(t *testing.T) {
		fixture := cloneRolloutVerifyTestFixture(t, complete)
		proofPath := filepath.Join(fixture.workspace, rolloutstore.ProofFileName)
		if err := os.Remove(proofPath); err != nil {
			t.Fatal(err)
		}
		before := requests.Load()
		if err := runRollout(
			rolloutRunTestArguments(t, fixture, server.URL), &bytes.Buffer{},
		); err != nil {
			t.Fatal(err)
		}
		if requests.Load() != before {
			t.Fatalf("offline proof recovery contacted controller %d times", requests.Load()-before)
		}
		if _, err := os.Stat(proofPath); err != nil {
			t.Fatalf("correct authorization did not recover proof: %v", err)
		}
		if err := verifyRollout(fixture.arguments, &bytes.Buffer{}); err != nil {
			t.Fatalf("verify recovered proof: %v", err)
		}
	})
}

func testRolloutPromotionTampering(t *testing.T, complete rolloutVerifyTestFixture) {
	t.Helper()
	commandPrivate, err := readPrivateKey(complete.commandPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	commandPublic := commandPrivate.Public().(ed25519.PublicKey)
	for _, test := range []struct {
		name   string
		mutate func(*testing.T, rolloutVerifyTestFixture)
	}{
		{
			name: "missing promotion",
			mutate: func(t *testing.T, fixture rolloutVerifyTestFixture) {
				if err := os.Remove(filepath.Join(
					fixture.workspace, mustBatchPromotionName(t, 1),
				)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "extra promotion",
			mutate: func(t *testing.T, fixture rolloutVerifyTestFixture) {
				raw := offlineRead(t, filepath.Join(
					fixture.workspace, mustBatchPromotionName(t, 1),
				))
				if err := os.WriteFile(filepath.Join(
					fixture.workspace, mustBatchPromotionName(t, 2),
				), raw, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "promotion signature",
			mutate: func(t *testing.T, fixture rolloutVerifyTestFixture) {
				path := filepath.Join(fixture.workspace, mustBatchPromotionName(t, 1))
				envelope := mustDSSEEnvelope(t, offlineRead(t, path))
				envelope.Signatures[0].Sig = mutateRolloutVerifyBase64(envelope.Signatures[0].Sig)
				writeDSSEEnvelope(t, path, envelope)
			},
		},
		{
			name: "promotion boundary",
			mutate: func(t *testing.T, fixture rolloutVerifyTestFixture) {
				resignPromotion(t, fixture, commandPrivate, commandPublic, func(value *rollout.BatchPromotionV1) {
					value.NextBatch.End++
				})
			},
		},
		{
			name: "promotion time",
			mutate: func(t *testing.T, fixture rolloutVerifyTestFixture) {
				plan := rolloutRunPlan(t, fixture.workspace)
				created, _ := time.Parse(time.RFC3339Nano, plan.CreatedAt)
				resignPromotion(t, fixture, commandPrivate, commandPublic, func(value *rollout.BatchPromotionV1) {
					value.AuthorizedAt = created.Add(-time.Nanosecond).Format(time.RFC3339Nano)
				})
			},
		},
		{
			name: "promotion key",
			mutate: func(t *testing.T, fixture rolloutVerifyTestFixture) {
				_, foreign, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				resignPromotionWithKey(t, fixture, "foreign-command", foreign)
			},
		},
		{
			name: "command context",
			mutate: func(t *testing.T, fixture rolloutVerifyTestFixture) {
				authorizationRaw := offlineRead(t, filepath.Join(
					fixture.workspace, rolloutstore.PlanAuthorizationFileName,
				))
				resignRolloutCommandContext(
					t, fixture, 1, rolloutstore.TargetAdmitCommandKind,
					dsse.Digest(authorizationRaw), commandPrivate,
				)
			},
		},
		{
			name: "plan batch size",
			mutate: func(t *testing.T, fixture rolloutVerifyTestFixture) {
				path := filepath.Join(fixture.workspace, rolloutstore.PlanFileName)
				plan := rolloutRunPlan(t, fixture.workspace)
				plan.BatchSize = 2
				raw, err := rollout.MarshalPlanV1(plan)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, raw, 0o600); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := cloneRolloutVerifyTestFixture(t, complete)
			test.mutate(t, fixture)
			if err := verifyRollout(fixture.arguments, &bytes.Buffer{}); err == nil {
				t.Fatal("offline verifier accepted authorization-chain tampering")
			}
		})
	}
}

type rolloutFleetControllerTarget struct {
	index          uint16
	prepared       rolloutdriver.PreparedTargetV1
	projection     controlprotocol.ExecutorAdmissionProjectionV1
	receiptPublic  ed25519.PublicKey
	receiptPrivate ed25519.PrivateKey
	armed          controlstore.EvidenceCapture
	canaryResult   *controlprotocol.ExecutorActivationCanaryResultV1
	captureExport  *controlprotocol.ControllerEvidenceCaptureV1
	capturePolls   int
}

type rolloutFleetController struct {
	t               *testing.T
	fixture         rolloutVerifyTestFixture
	run             verifiedRolloutRun
	gatewayPublic   ed25519.PublicKey
	gatewayPrivate  ed25519.PrivateKey
	witnessPrivate  ed25519.PrivateKey
	targets         []*rolloutFleetControllerTarget
	commands        map[string][]byte
	requestCounts   []int
	promotionAtHTTP []bool
	rejectPreflight []bool
	mu              sync.Mutex
}

func newRolloutFleetController(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
	run verifiedRolloutRun,
) *rolloutFleetController {
	t.Helper()
	taskPrivate, err := readPrivateKey(fixture.taskPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	gatewayPrivate, err := readPrivateKey(fixture.gatewayPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	witnessPrivate, err := readPrivateKey(fixture.witnessPrivatePath)
	if err != nil {
		t.Fatal(err)
	}
	controller := &rolloutFleetController{
		t: t, fixture: fixture, run: run,
		gatewayPublic:  gatewayPrivate.Public().(ed25519.PublicKey),
		gatewayPrivate: gatewayPrivate, witnessPrivate: witnessPrivate,
		targets:  make([]*rolloutFleetControllerTarget, len(run.targets)),
		commands: make(map[string][]byte), requestCounts: make([]int, len(run.targets)),
		promotionAtHTTP: make([]bool, len(run.targets)), rejectPreflight: make([]bool, len(run.targets)),
	}
	for index := range run.targets {
		prepared := run.targets[index].prepared
		target := prepared.Target()
		receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		projection := controlprotocol.ExecutorAdmissionProjectionV1{
			SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
			RuntimeRef:    prepared.RuntimeRef(), Status: "created",
			CapsuleDigest: prepared.CapsuleDigest(), PolicyDigest: run.plan.PolicyDigest,
			Generation: target.InstanceGeneration, EvidenceKeyID: evidence.KeyID(receiptPublic),
			GrantID:   gateway.GrantID(run.plan.TenantID, target.InstanceID, target.InstanceGeneration),
			ServiceID: agentrelease.HermesServiceID,
			TaskAuthorities: []controlprotocol.ExecutorTaskAuthorityV1{{
				KeyID: fixture.taskKeyID,
				PublicKey: base64.StdEncoding.EncodeToString(
					taskPrivate.Public().(ed25519.PublicKey),
				),
			}},
			RoutePolicyDigest:     dsse.Digest([]byte(fmt.Sprintf("fleet-route-%d", index))),
			ActivationID:          target.ActivationID,
			ActivationBeginDigest: prepared.ExecutorBeginDigest(),
		}
		projection.ServicePath = "/v1/services/" + projection.GrantID + "/"
		if err := rolloutdriver.VerifyAdmissionV1(prepared, projection); err != nil {
			t.Fatal(err)
		}
		controller.targets[index] = &rolloutFleetControllerTarget{
			index: uint16(index), prepared: prepared, projection: projection,
			receiptPublic: receiptPublic, receiptPrivate: receiptPrivate,
		}
	}
	return controller
}

func (controller *rolloutFleetController) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	path := request.URL.Path
	if request.Method == http.MethodGet && strings.Contains(path, "/nodes/") &&
		!strings.Contains(path, "/commands/") && !strings.Contains(path, "/captures/") {
		for _, target := range controller.targets {
			indexed := target.prepared.Target()
			if !strings.HasSuffix(path, "/nodes/"+indexed.NodeID) {
				continue
			}
			controller.observeRequest(target.index)
			if controller.rejectPreflight[target.index] {
				controller.rejectPreflight[target.index] = false
				writer.Header().Set("Content-Type", "application/json")
				writer.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(writer).Encode(map[string]string{
					"error": "unavailable", "message": "retry preflight",
				})
				return
			}
			writeRolloutRunJSON(controller.t, writer, controlclient.Node{
				NodeID: indexed.NodeID, TenantIDs: []string{controller.run.plan.TenantID}, State: "active",
				Capabilities: []string{
					controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
					controlprotocol.ExecutorCapabilityActivationCanaryV1,
					controlprotocol.ExecutorCapabilityRolloutAuthorizationContextV1,
				},
			})
			return
		}
	}
	if request.Method == http.MethodPost && strings.HasSuffix(path, "/captures") {
		var input struct {
			CaptureID             string `json:"capture_id"`
			RequestID             string `json:"request_id"`
			TenantID              string `json:"tenant_id"`
			RuntimeRef            string `json:"runtime_ref"`
			Generation            uint64 `json:"generation"`
			ActivationID          string `json:"activation_id"`
			ActivationBeginDigest string `json:"activation_begin_digest"`
			TTLSeconds            int64  `json:"ttl_seconds"`
		}
		if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
			controller.t.Errorf("decode fleet capture arm: %v", err)
			return
		}
		target := controller.targetByActivation(input.ActivationID)
		if target == nil {
			http.NotFound(writer, request)
			return
		}
		controller.observeRequest(target.index)
		armedAt, _ := time.Parse(time.RFC3339Nano, controller.run.plan.CreatedAt)
		head := controlprotocol.ExecutorEvidenceHeadV1{
			Stream:        controlprotocol.ExecutorEvidenceStreamV1,
			ReceiptNodeID: target.prepared.Target().NodeID,
			ReceiptEpoch:  1, Sequence: 0,
			ChainHash:       "sha256:" + strings.Repeat("0", 64),
			PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(target.receiptPublic),
		}
		target.armed = controlstore.EvidenceCapture{
			CaptureID: input.CaptureID, RequestID: input.RequestID,
			NodeID: target.prepared.Target().NodeID, TenantID: input.TenantID,
			RuntimeRef: input.RuntimeRef, Generation: input.Generation,
			ActivationID: input.ActivationID, ActivationBeginDigest: input.ActivationBeginDigest,
			State: controlstore.EvidenceCaptureArmed, BaselineHead: head, FinalHead: head,
			ArmedAt:   armedAt.Format(time.RFC3339Nano),
			ExpiresAt: armedAt.Add(time.Duration(input.TTLSeconds) * time.Second).Format(time.RFC3339Nano),
		}
		writeRolloutRunJSON(controller.t, writer, target.armed)
		return
	}
	if request.Method == http.MethodPost && strings.HasSuffix(path, "/commands") {
		raw := rolloutRunSubmittedCommand(controller.t, request)
		statement := rolloutRunCommandStatement(controller.t, raw)
		target := controller.targetByNode(statement.NodeID)
		if target == nil {
			http.NotFound(writer, request)
			return
		}
		controller.observeRequest(target.index)
		controller.commands[statement.CommandID] = raw
		if statement.Kind == "activation-canary" {
			result, capture := buildRolloutRunCanaryEvidence(
				controller.t, controller.fixture, controller.run, target.index,
				target.projection, statement.Payload,
				controller.gatewayPublic, controller.gatewayPrivate,
				target.receiptPublic, target.receiptPrivate, controller.witnessPrivate,
			)
			target.canaryResult = &result
			target.captureExport = &capture
		}
		writeRolloutRunJSON(controller.t, writer, rolloutRunControlCommand(
			statement, raw, target.prepared.RuntimeRef(), false,
			target.projection, target.canaryResult,
		))
		return
	}
	if request.Method == http.MethodGet && strings.Contains(path, "/commands/") {
		commandID := filepath.Base(path)
		raw := controller.commands[commandID]
		if len(raw) == 0 {
			http.NotFound(writer, request)
			return
		}
		statement := rolloutRunCommandStatement(controller.t, raw)
		target := controller.targetByNode(statement.NodeID)
		controller.observeRequest(target.index)
		writeRolloutRunJSON(controller.t, writer, rolloutRunControlCommand(
			statement, raw, target.prepared.RuntimeRef(), true,
			target.projection, target.canaryResult,
		))
		return
	}
	if strings.Contains(path, "/captures/") {
		for _, target := range controller.targets {
			captureID := rolloutCaptureID(controller.run.plan, target.index)
			if !strings.Contains(path, "/captures/"+captureID) {
				continue
			}
			controller.observeRequest(target.index)
			switch {
			case request.Method == http.MethodGet && strings.HasSuffix(path, "/export"):
				writeRolloutRunJSON(controller.t, writer, target.captureExport)
			case request.Method == http.MethodPost && strings.HasSuffix(path, "/seal"):
				writeRolloutRunJSON(controller.t, writer, rolloutRunCaptureView(
					target.armed, *target.captureExport, controlstore.EvidenceCaptureSealed,
				))
			case request.Method == http.MethodGet:
				target.capturePolls++
				if target.capturePolls == 1 {
					writeRolloutRunJSON(controller.t, writer, target.armed)
				} else {
					writeRolloutRunJSON(controller.t, writer, rolloutRunCaptureView(
						target.armed, *target.captureExport, controlstore.EvidenceCaptureObserved,
					))
				}
			default:
				http.NotFound(writer, request)
			}
			return
		}
	}
	http.NotFound(writer, request)
}

func (controller *rolloutFleetController) observeRequest(index uint16) {
	controller.requestCounts[index]++
	if index == 0 || controller.promotionAtHTTP[index] {
		return
	}
	name, err := rolloutstore.BatchPromotionName(index)
	if err == nil {
		_, err = os.Stat(filepath.Join(controller.fixture.workspace, name))
	}
	controller.promotionAtHTTP[index] = err == nil
}

func (controller *rolloutFleetController) targetByNode(nodeID string) *rolloutFleetControllerTarget {
	for _, target := range controller.targets {
		if target.prepared.Target().NodeID == nodeID {
			return target
		}
	}
	return nil
}

func (controller *rolloutFleetController) targetByActivation(activationID string) *rolloutFleetControllerTarget {
	for _, target := range controller.targets {
		if target.prepared.Target().ActivationID == activationID {
			return target
		}
	}
	return nil
}

func (controller *rolloutFleetController) failNextPreflight(index int) {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	controller.rejectPreflight[index] = true
}

func (controller *rolloutFleetController) requestCount(index int) int {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.requestCounts[index]
}

func (controller *rolloutFleetController) requests() []int {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return append([]int(nil), controller.requestCounts...)
}

func (controller *rolloutFleetController) promotionPresentAtFirstRequest(index int) bool {
	controller.mu.Lock()
	defer controller.mu.Unlock()
	return controller.promotionAtHTTP[index]
}

func rolloutRunLatestTargetState(
	t *testing.T,
	workspace string,
	target uint16,
) (rollout.TargetStateV1, int) {
	t.Helper()
	store, err := rolloutstore.Open(workspace)
	if err != nil {
		t.Fatal(err)
	}
	names, err := store.ListTargetStates(target)
	if err != nil || len(names) == 0 {
		_ = store.Close()
		t.Fatal(errors.Join(err, errors.New("rollout target state chain is empty")))
	}
	raw, err := store.Read(names[len(names)-1], rollout.MaxTargetStateBytes)
	closeErr := store.Close()
	if err != nil || closeErr != nil {
		t.Fatal(errors.Join(err, closeErr))
	}
	state, err := rollout.ParseTargetStateV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	return state, len(names)
}

func rolloutRunTargetPathFor(
	t *testing.T,
	workspace string,
	target uint16,
	kind string,
) string {
	t.Helper()
	name, err := rolloutstore.TargetArtifactName(target, kind)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(workspace, name)
}

func assertRolloutTargetCommandContext(
	t *testing.T,
	workspace string,
	target uint16,
	expected string,
) {
	t.Helper()
	for _, kind := range []string{
		rolloutstore.TargetAdmitCommandKind,
		rolloutstore.TargetStartCommandKind,
		rolloutstore.TargetCanaryCommandKind,
	} {
		statement := rolloutRunCommandStatement(t, offlineRead(
			t, rolloutRunTargetPathFor(t, workspace, target, kind),
		))
		if statement.AuthorizationContextDigest != expected {
			t.Fatalf("target %d %s context=%q want %q", target, kind, statement.AuthorizationContextDigest, expected)
		}
	}
}

func mustBatchPromotionName(t *testing.T, number uint16) string {
	t.Helper()
	name, err := rolloutstore.BatchPromotionName(number)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func mustDSSEEnvelope(t *testing.T, raw []byte) dsse.Envelope {
	t.Helper()
	envelope, err := dsse.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func writeDSSEEnvelope(t *testing.T, path string, envelope dsse.Envelope) {
	t.Helper()
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func resignPromotion(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
	private ed25519.PrivateKey,
	public ed25519.PublicKey,
	mutate func(*rollout.BatchPromotionV1),
) {
	t.Helper()
	path := filepath.Join(fixture.workspace, mustBatchPromotionName(t, 1))
	envelope := mustDSSEEnvelope(t, offlineRead(t, path))
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var statement rollout.BatchPromotionV1
	if err := dsse.DecodeStrictInto(payload, rollout.MaxBatchPromotionEnvelopeBytes, &statement); err != nil {
		t.Fatal(err)
	}
	mutate(&statement)
	raw, err := rollout.SignBatchPromotionV1(
		statement, fixture.commandKeyID, private, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func resignPromotionWithKey(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
	keyID string,
	private ed25519.PrivateKey,
) {
	t.Helper()
	path := filepath.Join(fixture.workspace, mustBatchPromotionName(t, 1))
	envelope := mustDSSEEnvelope(t, offlineRead(t, path))
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var statement rollout.BatchPromotionV1
	if err := dsse.DecodeStrictInto(payload, rollout.MaxBatchPromotionEnvelopeBytes, &statement); err != nil {
		t.Fatal(err)
	}
	raw, err := rollout.SignBatchPromotionV1(
		statement, keyID, private, private.Public().(ed25519.PublicKey),
	)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func resignRolloutCommandContext(
	t *testing.T,
	fixture rolloutVerifyTestFixture,
	target uint16,
	kind string,
	contextDigest string,
	private ed25519.PrivateKey,
) {
	t.Helper()
	path := rolloutRunTargetPathFor(t, fixture.workspace, target, kind)
	envelope := mustDSSEEnvelope(t, offlineRead(t, path))
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil {
		t.Fatal(err)
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
		t.Fatal(err)
	}
	statement.AuthorizationContextDigest = contextDigest
	payload, err = json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	changed, err := dsse.Sign(
		admission.CommandPayloadType, payload, fixture.commandKeyID, private,
	)
	if err != nil {
		t.Fatal(err)
	}
	writeDSSEEnvelope(t, path, changed)
}
