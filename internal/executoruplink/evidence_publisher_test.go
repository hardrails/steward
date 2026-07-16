package executoruplink

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/evidence"
)

const evidencePublisherCredential = "steward_node_v1_node-cred-11111111111111111111111111111111_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const evidencePublisherCredentialID = "node-cred-11111111111111111111111111111111"

type evidenceWitnessServer struct {
	t           *testing.T
	mu          sync.Mutex
	auth        *controlauth.Manager
	public      ed25519.PublicKey
	nodeID      string
	epoch       uint64
	now         time.Time
	head        controlprotocol.ExecutorEvidenceHeadV1
	reportHeads []controlprotocol.ExecutorEvidenceHeadV1
	frameCounts []int
	onReport    func(int) error
}

func newEvidenceWitnessServer(t *testing.T, public ed25519.PublicKey, initial evidence.Head) *evidenceWitnessServer {
	t.Helper()
	auth, err := controlauth.New(bytes.Repeat([]byte{41}, controlauth.KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 16, 8, 0, 0, 0, time.UTC)
	return &evidenceWitnessServer{
		t: t, auth: auth, public: append(ed25519.PublicKey(nil), public...), nodeID: initial.NodeID,
		epoch: initial.Epoch, now: now, head: protocolEvidenceHead(initial, public),
	}
}

func (server *evidenceWitnessServer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	server.mu.Lock()
	defer server.mu.Unlock()
	server.t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	if request.Method != http.MethodPost || request.Header.Get("Authorization") != "Bearer "+evidencePublisherCredential ||
		request.Header.Get("Content-Type") != "application/json" || request.Header.Get("Accept") != "application/json" {
		server.t.Errorf("invalid evidence request method=%q path=%q headers=%v", request.Method, request.URL.Path, request.Header)
		writer.WriteHeader(http.StatusBadRequest)
		return
	}
	switch request.URL.Path {
	case "/evidence-uplink/poll":
		raw, err := io.ReadAll(io.LimitReader(request.Body, controlprotocol.MaxExecutorEvidenceJSONBytes+1))
		if err != nil {
			server.t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		poll, err := controlprotocol.DecodeExecutorEvidencePollRequestV1(raw)
		if err != nil || poll.ControllerInstanceID != server.auth.InstanceID() || poll.ControlNodeID != server.nodeID ||
			poll.ReceiptNodeID != server.nodeID || poll.ReceiptEpoch != server.epoch ||
			poll.PublicKeySHA256 != controlprotocol.ExecutorEvidencePublicKeySHA256(server.public) {
			server.t.Errorf("invalid evidence poll=%+v err=%v", poll, err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		challenge, err := server.auth.MintEvidenceChallenge(
			evidencePublisherCredentialID, server.nodeID, server.now, server.now.Add(5*time.Minute),
		)
		if err != nil {
			server.t.Error(err)
			writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(writer).Encode(controlprotocol.ExecutorEvidencePollResponseV1{
			ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1, Challenge: challenge,
			Status: server.currentStatus(),
		})
	case "/evidence-uplink/report":
		raw, err := io.ReadAll(io.LimitReader(request.Body, controlprotocol.MaxExecutorEvidenceJSONBytes+1))
		if err != nil {
			server.t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		report, err := controlprotocol.DecodeExecutorEvidenceReportV1(raw)
		if err != nil || controlprotocol.VerifyExecutorEvidenceHeadProofV1(report.HeadProof, server.public) != nil ||
			server.auth.VerifyEvidenceChallenge(
				report.HeadProof.Claim.Challenge, evidencePublisherCredentialID, server.nodeID, server.now,
			) != nil {
			server.t.Errorf("invalid evidence report err=%v report=%+v", err, report)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		frames, err := report.DecodeFrames()
		if err != nil {
			server.t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if report.HeadProof.Claim.Base() != server.head {
			server.t.Errorf("report base=%+v want %+v", report.HeadProof.Claim.Base(), server.head)
			writer.WriteHeader(http.StatusConflict)
			return
		}
		reported := report.HeadProof.Claim.Head()
		server.reportHeads = append(server.reportHeads, reported)
		server.frameCounts = append(server.frameCounts, len(frames))
		response := controlprotocol.ExecutorEvidenceReportResponseV1{
			ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1,
		}
		if len(frames) > 0 {
			prior, err := evidenceCoordinate(server.head)
			if err != nil {
				server.t.Error(err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
			derived, err := evidence.VerifyDelta(frames, server.public, server.nodeID, server.epoch, prior, func(string) bool { return true })
			if err != nil || protocolEvidenceHead(derived, server.public) != reported {
				server.t.Errorf("invalid evidence delta head=%+v reported=%+v err=%v", derived, reported, err)
				writer.WriteHeader(http.StatusBadRequest)
				return
			}
			server.head = reported
			response.Applied = true
			response.Status = server.currentStatus()
		} else if reported == server.head {
			response.Status = server.currentStatus()
		} else {
			kind := controlprotocol.ExecutorEvidenceFindingEquivocation
			state := controlprotocol.ExecutorEvidenceStatusEquivocationDetected
			if reported.Sequence < server.head.Sequence {
				kind = controlprotocol.ExecutorEvidenceFindingRollback
				state = controlprotocol.ExecutorEvidenceStatusRollbackDetected
			}
			retained := server.head
			response.Applied = true
			response.Status = controlprotocol.ExecutorEvidenceStatusV1{
				State: state, Head: &retained, WitnessedAt: server.now.Format(time.RFC3339Nano),
				Finding: &controlprotocol.ExecutorEvidenceFindingV1{
					Kind: kind, DetectedAt: server.now.Format(time.RFC3339Nano), ObservedHead: reported,
				},
			}
		}
		if server.onReport != nil {
			if err := server.onReport(len(server.frameCounts)); err != nil {
				server.t.Error(err)
				writer.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		_ = json.NewEncoder(writer).Encode(response)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (server *evidenceWitnessServer) currentStatus() controlprotocol.ExecutorEvidenceStatusV1 {
	head := server.head
	return controlprotocol.ExecutorEvidenceStatusV1{
		State: controlprotocol.ExecutorEvidenceStatusCurrent, Head: &head,
		WitnessedAt: server.now.Format(time.RFC3339Nano),
	}
}

func TestEvidencePublisherUploadsBoundedBatches(t *testing.T) {
	log, private, public := newPublisherLog(t, controlprotocol.MaxExecutorEvidenceFrames+1)
	controller := newEvidenceWitnessServer(t, public, evidence.Head{NodeID: "node-a", Epoch: 1})
	server := httptest.NewTLSServer(controller)
	defer server.Close()
	publisher := newTestEvidencePublisher(t, server, controller.auth.InstanceID(), log, private)
	local, err := log.CurrentHead()
	if err != nil || local.Sequence != controlprotocol.MaxExecutorEvidenceFrames+1 {
		t.Fatalf("local head=%+v err=%v", local, err)
	}
	for index := 0; index < 2; index++ {
		applied, err := publisher.publishOnce(context.Background())
		if err != nil || !applied {
			t.Fatalf("publish batch %d = (%v, %v)", index+1, applied, err)
		}
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.reportHeads) != 2 || controller.reportHeads[0].Sequence != controlprotocol.MaxExecutorEvidenceFrames ||
		controller.reportHeads[1].Sequence != controlprotocol.MaxExecutorEvidenceFrames+1 ||
		controller.frameCounts[0] != controlprotocol.MaxExecutorEvidenceFrames || controller.frameCounts[1] != 1 {
		t.Fatalf("reported heads=%+v frame counts=%v", controller.reportHeads, controller.frameCounts)
	}
}

func TestEvidencePublisherRunDrainsAllPendingBatchesBeforeWaiting(t *testing.T) {
	log, private, public := newPublisherLog(t, 2*controlprotocol.MaxExecutorEvidenceFrames+1)
	controller := newEvidenceWitnessServer(t, public, evidence.Head{NodeID: "node-a", Epoch: 1})
	server := httptest.NewTLSServer(controller)
	defer server.Close()
	publisher := newTestEvidencePublisher(t, server, controller.auth.InstanceID(), log, private)
	waitCalls := 0
	publisher.wait = func(context.Context, time.Duration) bool {
		waitCalls++
		return false
	}
	publisher.Run(context.Background())

	controller.mu.Lock()
	defer controller.mu.Unlock()
	if waitCalls != 1 || len(controller.frameCounts) != 3 ||
		controller.frameCounts[0] != controlprotocol.MaxExecutorEvidenceFrames ||
		controller.frameCounts[1] != controlprotocol.MaxExecutorEvidenceFrames ||
		controller.frameCounts[2] != 1 ||
		controller.head.Sequence != 2*controlprotocol.MaxExecutorEvidenceFrames+1 {
		t.Fatalf("waits=%d frame counts=%v head=%+v", waitCalls, controller.frameCounts, controller.head)
	}
}

func TestEvidencePublisherRunRechecksHeadBeforeSleeping(t *testing.T) {
	log, private, public := newPublisherLog(t, 1)
	controller := newEvidenceWitnessServer(t, public, evidence.Head{NodeID: "node-a", Epoch: 1})
	controller.onReport = func(reportNumber int) error {
		if reportNumber != 1 {
			return nil
		}
		_, err := log.Append(publisherEvent(2))
		return err
	}
	server := httptest.NewTLSServer(controller)
	defer server.Close()
	publisher := newTestEvidencePublisher(t, server, controller.auth.InstanceID(), log, private)
	waitCalls := 0
	publisher.wait = func(context.Context, time.Duration) bool {
		waitCalls++
		return false
	}
	publisher.Run(context.Background())

	controller.mu.Lock()
	defer controller.mu.Unlock()
	if waitCalls != 1 || len(controller.frameCounts) != 2 ||
		controller.frameCounts[0] != 1 || controller.frameCounts[1] != 1 ||
		controller.head.Sequence != 2 {
		t.Fatalf("waits=%d frame counts=%v head=%+v", waitCalls, controller.frameCounts, controller.head)
	}
}

func TestEvidencePublisherRecoversAfterStoredResponseIsLost(t *testing.T) {
	log, private, public := newPublisherLog(t, 1)
	controller := newEvidenceWitnessServer(t, public, evidence.Head{NodeID: "node-a", Epoch: 1})
	server := httptest.NewTLSServer(controller)
	defer server.Close()
	baseTransport := server.Client().Transport
	dropped := false
	client := &http.Client{Transport: v3RoundTripper(func(request *http.Request) (*http.Response, error) {
		response, err := baseTransport.RoundTrip(request)
		if err != nil || request.URL.Path != "/evidence-uplink/report" || dropped {
			return response, err
		}
		dropped = true
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, closeErr
		}
		return nil, io.ErrUnexpectedEOF
	})}
	publisher := newEvidencePublisherWithClient(t, server.URL, controller.auth.InstanceID(), log, private, client)
	if applied, err := publisher.publishOnce(context.Background()); err == nil || applied {
		t.Fatalf("lost response publish = (%v, %v)", applied, err)
	}
	if applied, err := publisher.publishOnce(context.Background()); err != nil || applied {
		t.Fatalf("recovery publish = (%v, %v)", applied, err)
	}
	controller.mu.Lock()
	defer controller.mu.Unlock()
	if len(controller.frameCounts) != 2 || controller.frameCounts[0] != 1 || controller.frameCounts[1] != 0 ||
		controller.head.Sequence != 1 {
		t.Fatalf("report frame counts=%v head=%+v", controller.frameCounts, controller.head)
	}
}

func TestEvidencePublisherReportsControllerAheadRollbackWithoutBlockingLocalWork(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	complete, err := evidence.Open(filepath.Join(t.TempDir(), "complete.bin"), private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	appendPublisherEvents(t, complete, 2)
	controllerHead, err := complete.CurrentHead()
	if err != nil {
		t.Fatal(err)
	}
	if err := complete.Close(); err != nil {
		t.Fatal(err)
	}
	local, err := evidence.Open(filepath.Join(t.TempDir(), "restored.bin"), private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	appendPublisherEvents(t, local, 1)
	controller := newEvidenceWitnessServer(t, public, controllerHead)
	server := httptest.NewTLSServer(controller)
	defer server.Close()
	publisher := newTestEvidencePublisher(t, server, controller.auth.InstanceID(), local, private)
	if applied, err := publisher.publishOnce(context.Background()); applied || !errors.Is(err, ErrEvidenceDivergence) {
		t.Fatalf("rollback publish = (%v, %v)", applied, err)
	}
	controller.mu.Lock()
	if len(controller.frameCounts) != 1 || controller.frameCounts[0] != 0 || controller.reportHeads[0].Sequence != 1 {
		controller.mu.Unlock()
		t.Fatalf("rollback reports=%+v frames=%v", controller.reportHeads, controller.frameCounts)
	}
	controller.mu.Unlock()
	if _, err := local.Append(publisherEvent(3)); err != nil {
		t.Fatalf("local enforcement evidence stopped after controller finding: %v", err)
	}
}

func TestNewEvidencePublisherRejectsBoundaryMismatches(t *testing.T) {
	log, private, _ := newPublisherLog(t, 0)
	server := httptest.NewTLSServer(http.NotFoundHandler())
	defer server.Close()
	credentialPath := writePublisherCredential(t, "node-a")
	base := EvidencePublisherConfig{
		BaseURL: server.URL, CredentialPath: credentialPath, ControllerInstanceID: "control-test",
		PollInterval: time.Second, HTTPClient: server.Client(), Log: log, PrivateKey: private,
		SecureExecutor: true, SecureNodeID: "node-a", ProtectedTransport: true,
	}
	otherPublic, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil || len(otherPublic) != ed25519.PublicKeySize {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*EvidencePublisherConfig)
	}{
		{"plaintext", func(value *EvidencePublisherConfig) { value.BaseURL = "http://127.0.0.1:8443" }},
		{"unprotected", func(value *EvidencePublisherConfig) { value.ProtectedTransport = false }},
		{"not secure", func(value *EvidencePublisherConfig) { value.SecureExecutor = false }},
		{"short interval", func(value *EvidencePublisherConfig) { value.PollInterval = time.Millisecond }},
		{"controller", func(value *EvidencePublisherConfig) { value.ControllerInstanceID = "" }},
		{"node", func(value *EvidencePublisherConfig) { value.SecureNodeID = "node-b" }},
		{"key", func(value *EvidencePublisherConfig) { value.PrivateKey = otherPrivate }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := base
			test.mutate(&changed)
			if _, err := NewEvidencePublisher(changed); err == nil {
				t.Fatal("invalid evidence publisher boundary was accepted")
			}
		})
	}
}

func TestEvidencePublisherNeverForwardsBearerAcrossRedirect(t *testing.T) {
	log, private, _ := newPublisherLog(t, 0)
	redirected := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/evidence-uplink/poll" {
			http.Redirect(writer, request, "/capture", http.StatusTemporaryRedirect)
			return
		}
		redirected++
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()
	publisher := newEvidencePublisherWithClient(t, server.URL, "control-test", log, private, server.Client())
	if _, err := publisher.publishOnce(context.Background()); err == nil || !bytes.Contains([]byte(err.Error()), []byte("redirect")) {
		t.Fatalf("redirect publish error = %v", err)
	}
	if redirected != 0 {
		t.Fatalf("evidence bearer followed redirect %d times", redirected)
	}
}

func newPublisherLog(t *testing.T, records int) (*evidence.Log, ed25519.PrivateKey, ed25519.PublicKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	log, err := evidence.Open(filepath.Join(t.TempDir(), "evidence.bin"), private, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = log.Close() })
	appendPublisherEvents(t, log, records)
	return log, private, public
}

func appendPublisherEvents(t *testing.T, log *evidence.Log, records int) {
	t.Helper()
	for index := 0; index < records; index++ {
		if _, err := log.Append(publisherEvent(index + 1)); err != nil {
			t.Fatal(err)
		}
	}
}

func publisherEvent(generation int) evidence.Event {
	return evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: "tenant-a", RuntimeRef: "runtime-a",
		CapsuleDigest: "sha256:capsule", PolicyDigest: "sha256:policy", Generation: uint64(generation),
		GrantID: "grant-a", Outcome: evidence.Allowed, ErrorCode: "none", MetadataHash: "sha256:meta",
	}
}

func newTestEvidencePublisher(
	t *testing.T,
	server *httptest.Server,
	controllerInstanceID string,
	log *evidence.Log,
	private ed25519.PrivateKey,
) *EvidencePublisher {
	t.Helper()
	return newEvidencePublisherWithClient(t, server.URL, controllerInstanceID, log, private, server.Client())
}

func newEvidencePublisherWithClient(
	t *testing.T,
	baseURL, controllerInstanceID string,
	log *evidence.Log,
	private ed25519.PrivateKey,
	client *http.Client,
) *EvidencePublisher {
	t.Helper()
	publisher, err := NewEvidencePublisher(EvidencePublisherConfig{
		BaseURL: baseURL, CredentialPath: writePublisherCredential(t, "node-a"),
		ControllerInstanceID: controllerInstanceID, PollInterval: time.Second,
		HTTPClient: client, Log: log, PrivateKey: private,
		SecureExecutor: true, SecureNodeID: "node-a", ProtectedTransport: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return publisher
}

func writePublisherCredential(t *testing.T, nodeID string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "credential.json")
	raw, err := json.Marshal(map[string]any{
		"version": 2, "scope": "node", "node_id": nodeID, "credential": evidencePublisherCredential,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func protocolEvidenceHead(head evidence.Head, public ed25519.PublicKey) controlprotocol.ExecutorEvidenceHeadV1 {
	return controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: head.NodeID,
		ReceiptEpoch: head.Epoch, Sequence: head.Sequence, ChainHash: formattedEvidenceHash(head.ChainHash),
		PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(public),
	}
}
