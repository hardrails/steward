package executoruplink

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/gateway"
)

func TestV4SignedAdmissionReportsCompleteCorrelatedProjection(t *testing.T) {
	response, expected := executorAdmissionResponseV4()
	raw, err := json.Marshal(response)
	if err != nil {
		t.Fatal(err)
	}
	report, observed, store := runV4Admission(t, raw)
	if report.Status != controlprotocol.ExecutorStatusDone ||
		report.ReportedStatus != "stopped" ||
		report.Result.Admission == nil {
		t.Fatalf("protocol-4 admission report=%#v", report)
	}
	if !reflect.DeepEqual(*report.Result.Admission, expected) {
		t.Fatalf("admission projection=%#v want=%#v", *report.Result.Admission, expected)
	}
	if observed.Activation == nil ||
		observed.Activation.SchemaVersion != activationAdmissionRequestSchema ||
		observed.Activation.ActivationID != expected.ActivationID ||
		observed.Activation.BeginDigest != expected.ActivationBeginDigest {
		t.Fatalf("signed activation metadata was not passed through exactly: %#v", observed.Activation)
	}
	record := store.records[report.DeliveryID]
	if record.ProtocolVersion != controlprotocol.ExecutorProtocolV4 ||
		record.SettledGeneration != report.DeliveryGeneration ||
		record.Admission == nil ||
		record.Admission.ActivationID != expected.ActivationID {
		t.Fatalf("settled durable protocol-4 record=%#v", record)
	}
}

func TestV4AdmissionProjectionFailsClosedAfterMalformedOrMismatchedResponse(t *testing.T) {
	valid, _ := executorAdmissionResponseV4()
	validRaw, err := json.Marshal(valid)
	if err != nil {
		t.Fatal(err)
	}
	unknown := append(append([]byte(nil), validRaw[:len(validRaw)-1]...), []byte(`,"unexpected":true}`)...)
	runtimeMismatch := valid
	runtimeMismatch.RuntimeRef = "executor-" + strings.Repeat("f", 64)
	runtimeMismatchRaw, _ := json.Marshal(runtimeMismatch)
	activationMismatch := valid
	activationMismatch.ActivationID = "activation-other"
	activationMismatchRaw, _ := json.Marshal(activationMismatch)
	effectModeMismatch := valid
	effectModeMismatch.EffectMode = "authorized"
	effectModeMismatchRaw, _ := json.Marshal(effectModeMismatch)
	schemaInjected := append(append([]byte(nil), validRaw[:len(validRaw)-1]...), []byte(`,"schema_version":"controller-supplied"}`)...)

	for name, response := range map[string][]byte{
		"unknown field":        unknown,
		"runtime mismatch":     runtimeMismatchRaw,
		"activation mismatch":  activationMismatchRaw,
		"effect mode mismatch": effectModeMismatchRaw,
		"schema injection":     schemaInjected,
		"oversized":            []byte(`{"padding":"` + strings.Repeat("x", controlprotocol.MaxExecutorReportBytes) + `"}`),
	} {
		t.Run(name, func(t *testing.T) {
			report, _, store := runV4Admission(t, response)
			if report.Status != controlprotocol.ExecutorStatusOutcomeUnknown ||
				report.ErrorCode != "outcome_unknown" ||
				report.Result.Admission != nil {
				t.Fatalf("unsafe admission response escaped as %#v", report)
			}
			record := store.records[report.DeliveryID]
			if record.Admission != nil ||
				record.Terminal == nil ||
				record.Terminal.Status != controlprotocol.ExecutorStatusOutcomeUnknown {
				t.Fatalf("unsafe projection reached durable state: %#v", record)
			}
		})
	}
}

func TestLocalExecutorResponseWriterEnforcesHardMemoryCap(t *testing.T) {
	response := newLocalResponse(4)
	written, err := response.Write([]byte("oversized"))
	if err == nil || written != 4 || response.body.Len() != 4 || !response.overflow {
		t.Fatalf(
			"first write=(%d, %v) buffered=%d overflow=%v",
			written,
			err,
			response.body.Len(),
			response.overflow,
		)
	}
	written, err = response.Write([]byte("again"))
	if err == nil || written != 0 || response.body.Len() != 4 {
		t.Fatalf("second write=(%d, %v) buffered=%d", written, err, response.body.Len())
	}
}

func TestV4ReportNeverAddsAdmissionToNonAdmitReplayOrAbsentOutcome(t *testing.T) {
	delivery := deliveryFixtureV4("result-isolation", 1)
	projection := projectionFixtureV4()
	for name, fixture := range map[string]struct {
		report report
		kind   string
	}{
		"non-admit": {
			report: report{
				Status: "done", ReportedStatus: "stopped", ClaimGeneration: 1,
				Result:    map[string]any{"runtime_ref": projection.RuntimeRef},
				admission: &projection,
			},
		},
		"replayed admit": {
			report: report{
				Status: "done", ReportedStatus: "stopped", ClaimGeneration: 1,
				Result: map[string]any{
					"runtime_ref": projection.RuntimeRef,
					"replayed":    true,
				},
				admission: &projection,
			},
			kind: "admit",
		},
		"absent admit": {
			report: report{
				Status: "done", ReportedStatus: "stopped", ClaimGeneration: 1,
				Result: map[string]any{
					"runtime_ref": projection.RuntimeRef,
					"absent":      true,
				},
				admission: &projection,
			},
			kind: "admit",
		},
	} {
		t.Run(name, func(t *testing.T) {
			wire := makeReportV4(delivery, fixture.report, fixture.kind)
			if wire.Result.Admission != nil {
				t.Fatalf("projection escaped on %s: %#v", name, wire)
			}
			if err := wire.Validate(); err != nil {
				t.Fatalf("isolated report is invalid: %v", err)
			}
		})
	}
}

func TestV4ReportIncludesCanaryOnlyForUnambiguousRunningCanary(t *testing.T) {
	delivery := deliveryFixtureV4("canary-result-isolation", 1)
	projection := deliveryCanaryResultFixture()
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	local := report{
		Status: "done", ReportedStatus: "running", ClaimGeneration: 1,
		Result:           map[string]any{"runtime_ref": runtimeRef},
		activationCanary: &projection,
	}
	wire := makeReportV4(delivery, local, "activation-canary")
	if !reflect.DeepEqual(wire.Result.ActivationCanary, &projection) {
		t.Fatalf("canary projection = %#v", wire.Result.ActivationCanary)
	}
	if err := wire.Validate(); err != nil {
		t.Fatal(err)
	}
	wire.Result.ActivationCanary.ActivationID = "mutated"
	if local.activationCanary.ActivationID == "mutated" {
		t.Fatal("wire report aliased the local canary result")
	}

	for name, mutate := range map[string]func(*report, *string){
		"other kind": func(_ *report, kind *string) { *kind = "read" },
		"replayed": func(value *report, _ *string) {
			value.Result["replayed"] = true
		},
		"failed": func(value *report, _ *string) {
			value.Status = "failed"
			value.Result["error"] = "failed"
		},
		"not running": func(value *report, _ *string) {
			value.ReportedStatus = "stopped"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := local
			candidate.Result = map[string]any{"runtime_ref": runtimeRef}
			kind := "activation-canary"
			mutate(&candidate, &kind)
			reported := makeReportV4(delivery, candidate, kind)
			if reported.Result.ActivationCanary != nil {
				t.Fatalf("canary projection escaped: %#v", reported)
			}
		})
	}
}

func TestActivationGatewayIsEnabledOnlyForProtocolV4(t *testing.T) {
	client, err := gateway.NewControlClient("/tmp/steward-gateway-control-test.sock")
	if err != nil {
		t.Fatal(err)
	}
	if activationGatewayForProtocol(controlprotocol.ExecutorProtocolV4, client) == nil {
		t.Fatal("protocol 4 lost its configured canary Gateway client")
	}
	for _, version := range []int{1, 2, controlprotocol.ExecutorProtocolV3} {
		if activationGatewayForProtocol(version, client) != nil {
			t.Fatalf("protocol %d unexpectedly enabled activation canaries", version)
		}
	}
	if activationGatewayForProtocol(controlprotocol.ExecutorProtocolV4, nil) != nil {
		t.Fatal("protocol 4 enabled activation canaries without Gateway")
	}
}

func TestV4SelectionIsExplicitAndDoesNotChangeV3Default(t *testing.T) {
	fixture := newV3Fixture(t, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	config := fixture.config(server, http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	config.ProtocolVersion = 0
	if poller, err := NewPoller(config); err != nil ||
		poller.protocolVersion != controlprotocol.ExecutorProtocolV3 {
		t.Fatalf("implicit selection poller=%#v err=%v", poller, err)
	}

	v4Store := newDeliveryStore(t, filepath.Join(t.TempDir(), "v4-deliveries.json"))
	config.DeliveryState = v4Store
	config.ProtocolVersion = controlprotocol.ExecutorProtocolV4
	if poller, err := NewPoller(config); err != nil ||
		poller.protocolVersion != controlprotocol.ExecutorProtocolV4 ||
		!poller.dispatcher.projectAdmission {
		t.Fatalf("explicit protocol-4 selection poller=%#v err=%v", poller, err)
	}
	config.DeliveryState = nil
	if poller, err := NewPoller(config); err == nil || poller != nil {
		t.Fatal("protocol 4 started without durable delivery state")
	}
}

func TestV4AcknowledgementCannotDowngradeOrSettleWrongProtocol(t *testing.T) {
	store := newDeliveryStore(t, filepath.Join(t.TempDir(), "deliveries.json"))
	delivery := deliveryFixtureV4("ack-v4", 1)
	if _, _, err := store.AcceptV4(delivery, "tenant-a", 3, "admit"); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkExecuting(delivery.DeliveryID); err != nil {
		t.Fatal(err)
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: 1,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "stopped",
		ClaimGeneration: 3,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: "executor-" + strings.Repeat("a", 64),
		},
	}
	if err := store.MarkTerminalV4(report); err != nil {
		t.Fatal(err)
	}
	var acknowledgement atomic.Int32
	acknowledgement.Store(controlprotocol.ExecutorProtocolV3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV4{
			ProtocolVersion: int(acknowledgement.Load()),
			Applied:         true,
		})
	}))
	defer server.Close()
	poller := &Poller{
		reportURL: server.URL, client: server.Client(), deliveryState: store,
	}
	if err := poller.sendReportV4(context.Background(), "credential", report); err == nil {
		t.Fatal("protocol-3 acknowledgement silently settled a protocol-4 report")
	}
	if store.records[delivery.DeliveryID].SettledGeneration != 0 {
		t.Fatal("wrong-protocol acknowledgement changed durable settlement")
	}
	acknowledgement.Store(controlprotocol.ExecutorProtocolV4)
	if err := poller.sendReportV4(context.Background(), "credential", report); err != nil {
		t.Fatal(err)
	}
	if store.records[delivery.DeliveryID].SettledGeneration != 1 {
		t.Fatal("protocol-4 acknowledgement was not persisted")
	}
}

func runV4Admission(
	t *testing.T,
	localResponse []byte,
) (controlprotocol.ExecutorReportV4, admissionPayload, *DeliveryStore) {
	t.Helper()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := commandPolicyFixture(t, public, []string{"admit"})
	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "credential.json")
	if err := os.WriteFile(
		credentialPath,
		[]byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"bearer"}`),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	state := newStateStore(t, filepath.Join(directory, "state.json"))
	deliveryStore := newDeliveryStore(t, filepath.Join(directory, "deliveries.json"))
	runtimeRef, err := RuntimeRefV2("tenant-a", "node-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	payload := admissionPayload{
		CapsuleDSSEBase64: "opaque",
		Intent: admission.InstanceIntent{
			TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1",
			LineageID: "lineage-1", Generation: 1,
			CapsuleDigest: "sha256:" + strings.Repeat("c", 64),
			Resources: admission.ResourceLimits{
				MemoryBytes: 1,
				CPUMillis:   1,
				PIDs:        1,
			},
			Capabilities:     admission.Capabilities{Inference: true},
			StateDisposition: "none",
			InferenceRouteID: "local-model",
			ModelAlias:       "model",
		},
		Activation: &admissionActivation{
			SchemaVersion: activationAdmissionRequestSchema,
			ActivationID:  "activation-1",
			BeginDigest:   "sha256:" + strings.Repeat("0", 64),
		},
	}
	payloadRaw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	statement := admission.CommandStatement{
		SchemaVersion: admission.CommandSchemaV2,
		CommandID:     "admit-command", TenantID: "tenant-a", NodeID: "node-1",
		InstanceID: "agent-1", RuntimeRef: runtimeRef, Kind: "admit",
		ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
		IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Minute).Format(time.RFC3339Nano),
		Payload:   payloadRaw,
	}
	signed := signCommand(t, statement, "tenant-command", private)
	deliveryID, err := controlprotocol.ExecutorDeliveryID(
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil {
		t.Fatal(err)
	}
	delivery := controlprotocol.ExecutorDeliveryV4{
		DeliveryID: deliveryID, DeliveryGeneration: 1,
		CommandID: statement.CommandID, CommandDigest: dsse.Digest(signed),
		CommandDSSEBase64: base64.StdEncoding.EncodeToString(signed),
	}

	var report controlprotocol.ExecutorReportV4
	var reportCalls atomic.Int32
	controller := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/executor-uplink/poll":
			raw, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Error(readErr)
				return
			}
			var poll controlprotocol.ExecutorPollRequestV4
			if decodeErr := dsse.DecodeStrictInto(raw, maxWireBytes, &poll); decodeErr != nil ||
				poll.ProtocolVersion != controlprotocol.ExecutorProtocolV4 ||
				poll.NodeID != "node-1" ||
				!slices.Contains(
					poll.Capabilities,
					controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
				) ||
				!slices.Contains(
					poll.Capabilities,
					controlprotocol.ExecutorCapabilityAuthorizedEffectsV1,
				) ||
				!slices.Contains(
					poll.Capabilities,
					controlprotocol.ExecutorCapabilityRolloutAuthorizationContextV1,
				) ||
				slices.Contains(
					poll.Capabilities,
					controlprotocol.ExecutorCapabilityActivationCanaryV1,
				) {
				t.Errorf("protocol-4 poll=%#v err=%v", poll, decodeErr)
				return
			}
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorPollResponseV4{
				ProtocolVersion: controlprotocol.ExecutorProtocolV4,
				Deliveries:      []json.RawMessage{mustJSON(t, delivery)},
			})
		case "/executor-uplink/report":
			raw, readErr := io.ReadAll(request.Body)
			if readErr != nil {
				t.Error(readErr)
				return
			}
			decoded, decodeErr := controlprotocol.DecodeExecutorReportV4(raw)
			if decodeErr != nil {
				t.Errorf("decode protocol-4 report: %v body=%s", decodeErr, raw)
				return
			}
			report = decoded
			reportCalls.Add(1)
			_ = json.NewEncoder(w).Encode(controlprotocol.ExecutorReportResponseV4{
				ProtocolVersion: controlprotocol.ExecutorProtocolV4,
				Applied:         false,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer controller.Close()

	var observed admissionPayload
	var localCalls atomic.Int32
	local := http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		localCalls.Add(1)
		raw, readErr := io.ReadAll(request.Body)
		if readErr != nil {
			t.Error(readErr)
			return
		}
		if decodeErr := dsse.DecodeStrictInto(raw, maxWireBytes, &observed); decodeErr != nil {
			t.Errorf("decode forwarded admission: %v", decodeErr)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(localResponse)
	})
	poller, err := NewPoller(Config{
		BaseURL: controller.URL, CredentialPath: credentialPath,
		PollInterval: time.Second, HTTPClient: controller.Client(),
		Handler: local, LocalToken: "local", State: state,
		SecureExecutor: true, SecureNodeID: "node-1", ProtectedTransport: true,
		CommandPolicy: &policy, Now: func() time.Time { return now },
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryState:   deliveryStore,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := poller.pollOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if reportCalls.Load() != 1 || localCalls.Load() != 1 {
		t.Fatalf("report calls=%d local calls=%d", reportCalls.Load(), localCalls.Load())
	}
	return report, observed, deliveryStore
}

func executorAdmissionResponseV4() (
	executorAdmissionResponse,
	controlprotocol.ExecutorAdmissionProjectionV1,
) {
	runtimeRef := executor.RuntimeRef("tenant-a", "agent-1")
	grantID := gateway.GrantID("tenant-a", "agent-1", 1)
	response := executorAdmissionResponse{
		RuntimeRef:            runtimeRef,
		Status:                "created",
		CapsuleDigest:         "sha256:" + strings.Repeat("c", 64),
		PolicyDigest:          "sha256:" + strings.Repeat("d", 64),
		Generation:            1,
		EvidenceKeyID:         strings.Repeat("e", 32),
		GrantID:               grantID,
		RoutePolicyDigest:     "sha256:" + strings.Repeat("f", 64),
		ActivationID:          "activation-1",
		ActivationBeginDigest: "sha256:" + strings.Repeat("0", 64),
	}
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion:         controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:            response.RuntimeRef,
		Status:                response.Status,
		CapsuleDigest:         response.CapsuleDigest,
		PolicyDigest:          response.PolicyDigest,
		Generation:            response.Generation,
		EvidenceKeyID:         response.EvidenceKeyID,
		GrantID:               response.GrantID,
		RoutePolicyDigest:     response.RoutePolicyDigest,
		ActivationID:          response.ActivationID,
		ActivationBeginDigest: response.ActivationBeginDigest,
	}
	return response, projection
}
