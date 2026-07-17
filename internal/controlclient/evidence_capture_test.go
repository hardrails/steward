package controlclient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
)

func TestEvidenceCaptureClientUsesBoundedSiteAdminRoutes(t *testing.T) {
	capture := clientEvidenceCaptureFixture(t)
	var requests int
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer operator-token" {
			t.Fatalf("authorization = %q", request.Header.Get("Authorization"))
		}
		switch requests {
		case 1:
			if request.Method != http.MethodPost ||
				request.URL.Path != "/v1/nodes/node-1/evidence/captures" {
				t.Fatalf("arm request = %s %s", request.Method, request.URL.Path)
			}
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
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.CaptureID != capture.CaptureID ||
				input.RequestID != capture.RequestID ||
				input.TenantID != capture.TenantID ||
				input.RuntimeRef != capture.RuntimeRef ||
				input.Generation != capture.Generation ||
				input.ActivationID != capture.ActivationID ||
				input.ActivationBeginDigest != capture.ActivationBeginDigest ||
				input.TTLSeconds != 60 {
				t.Fatalf("arm input = %#v, %v", input, err)
			}
			writeClientCapture(t, writer, http.StatusCreated, capture)
		case 2:
			if request.Method != http.MethodGet ||
				request.URL.Path != "/v1/nodes/node-1/evidence/captures/capture-1" {
				t.Fatalf("get request = %s %s", request.Method, request.URL.Path)
			}
			writeClientCapture(t, writer, http.StatusOK, capture)
		case 3:
			if request.Method != http.MethodDelete ||
				request.URL.Path != "/v1/nodes/node-1/evidence/captures/capture-1" {
				t.Fatalf("delete request = %s %s", request.Method, request.URL.Path)
			}
			writer.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected request %d", requests)
		}
	}))
	defer server.Close()

	client, err := New(server.URL, "operator-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	armed, err := client.ArmExecutorEvidenceCapture(
		context.Background(),
		capture.NodeID,
		EvidenceCaptureArmInput{
			CaptureID: capture.CaptureID, RequestID: capture.RequestID,
			TenantID: capture.TenantID, RuntimeRef: capture.RuntimeRef,
			Generation: capture.Generation, ActivationID: capture.ActivationID,
			ActivationBeginDigest: capture.ActivationBeginDigest,
			TTL:                   time.Minute,
		},
	)
	if err != nil || armed.CaptureID != capture.CaptureID {
		t.Fatalf("arm = %#v, %v", armed, err)
	}
	got, err := client.GetExecutorEvidenceCapture(
		context.Background(),
		capture.NodeID,
		capture.CaptureID,
	)
	if err != nil || got != capture {
		t.Fatalf("get = %#v, %v", got, err)
	}
	if err := client.DeleteExecutorEvidenceCapture(
		context.Background(),
		capture.NodeID,
		capture.CaptureID,
	); err != nil {
		t.Fatal(err)
	}
	if requests != 3 {
		t.Fatalf("requests = %d", requests)
	}
}

func TestEvidenceCaptureClientRejectsInvalidInputsAndResponses(t *testing.T) {
	capture := clientEvidenceCaptureFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(request.URL.Path, "/export"):
			_, _ = writer.Write([]byte(`{}`))
		case strings.HasSuffix(request.URL.Path, "/seal"):
			changed := capture
			changed.NodeID = "node-other"
			_ = json.NewEncoder(writer).Encode(changed)
		default:
			_ = json.NewEncoder(writer).Encode(capture)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	for name, input := range map[string]EvidenceCaptureArmInput{
		"subsecond": {
			CaptureID: "capture-1", RequestID: "request-1", TenantID: "tenant-1",
			RuntimeRef: "executor-" + strings.Repeat("a", 64),
			Generation: 1, ActivationID: "activation-1", TTL: time.Millisecond,
		},
		"too long": {
			CaptureID: "capture-1", RequestID: "request-1", TenantID: "tenant-1",
			RuntimeRef: "executor-" + strings.Repeat("a", 64),
			Generation: 1, ActivationID: "activation-1", TTL: time.Hour + time.Second,
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := client.ArmExecutorEvidenceCapture(ctx, "node-1", input); err == nil {
				t.Fatal("invalid lifetime was accepted")
			}
		})
	}
	for _, identity := range []string{"", "-capture", "capture/other", " capture", strings.Repeat("x", 129)} {
		if _, err := client.GetExecutorEvidenceCapture(ctx, "node-1", identity); err == nil {
			t.Fatalf("invalid capture identity %q accepted", identity)
		}
	}
	if _, err := client.SealExecutorEvidenceCapture(
		ctx,
		"node-1",
		"capture-1",
		"canary-1",
	); err == nil || !strings.Contains(err.Error(), "route identity") {
		t.Fatalf("changed seal response err = %v", err)
	}
	if _, err := client.ExportExecutorEvidenceCapture(
		ctx,
		"node-1",
		"capture-1",
	); err == nil || !strings.Contains(err.Error(), "validate control evidence capture export") {
		t.Fatalf("invalid export err = %v", err)
	}
}

func TestEvidenceCaptureClientRejectsValidButChangedArmAndSealBindings(t *testing.T) {
	armed := clientEvidenceCaptureFixture(t)
	changedArm := armed
	changedArm.TenantID = "tenant-other"
	sealed := armed
	sealed.State = controlstore.EvidenceCaptureSealed
	sealed.FinalHead.Sequence += 2
	sealed.FinalHead.ChainHash = "sha256:" + strings.Repeat("3", 64)
	sealed.FrameCount = 2
	sealed.ActivationBeginSequence = sealed.BaselineHead.Sequence + 1
	sealed.CapsuleDigest = "sha256:" + strings.Repeat("4", 64)
	sealed.PolicyDigest = "sha256:" + strings.Repeat("5", 64)
	sealed.ActivationCheckpointDigest = "sha256:" + strings.Repeat("6", 64)
	sealed.CanaryCommandID = "canary-other"
	sealed.ObservedAt = "2026-07-16T12:00:10Z"
	sealed.SealedAt = "2026-07-16T12:00:20Z"
	if err := changedArm.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := sealed.Validate(); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(request.URL.Path, "/seal") {
			_ = json.NewEncoder(writer).Encode(sealed)
			return
		}
		_ = json.NewEncoder(writer).Encode(changedArm)
	}))
	defer server.Close()
	client, err := New(server.URL, "operator-token", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.ArmExecutorEvidenceCapture(
		context.Background(), armed.NodeID,
		EvidenceCaptureArmInput{
			CaptureID: armed.CaptureID, RequestID: armed.RequestID,
			TenantID: armed.TenantID, RuntimeRef: armed.RuntimeRef,
			Generation: armed.Generation, ActivationID: armed.ActivationID,
			ActivationBeginDigest: armed.ActivationBeginDigest, TTL: time.Minute,
		},
	); err == nil || !strings.Contains(err.Error(), "changed the requested binding") {
		t.Fatalf("changed arm binding error = %v", err)
	}
	if _, err := client.SealExecutorEvidenceCapture(
		context.Background(), armed.NodeID, armed.CaptureID, "canary-requested",
	); err == nil || !strings.Contains(err.Error(), "changed the requested binding") {
		t.Fatalf("changed seal binding error = %v", err)
	}
}

func clientEvidenceCaptureFixture(t *testing.T) controlstore.EvidenceCapture {
	t.Helper()
	head := controlprotocol.ExecutorEvidenceHeadV1{
		Stream:          controlprotocol.ExecutorEvidenceStreamV1,
		ReceiptNodeID:   "node-1",
		ReceiptEpoch:    1,
		Sequence:        0,
		ChainHash:       "sha256:" + strings.Repeat("0", 64),
		PublicKeySHA256: "sha256:" + strings.Repeat("1", 64),
	}
	capture := controlstore.EvidenceCapture{
		CaptureID:             "capture-1",
		RequestID:             "request-1",
		NodeID:                "node-1",
		TenantID:              "tenant-1",
		RuntimeRef:            "executor-" + strings.Repeat("a", 64),
		Generation:            1,
		ActivationID:          "activation-1",
		ActivationBeginDigest: "sha256:" + strings.Repeat("2", 64),
		State:                 controlstore.EvidenceCaptureArmed,
		BaselineHead:          head,
		FinalHead:             head,
		ArmedAt:               "2026-07-16T12:00:00Z",
		ExpiresAt:             "2026-07-16T12:01:00Z",
	}
	if err := capture.Validate(); err != nil {
		t.Fatalf("capture fixture: %v", err)
	}
	return capture
}

func writeClientCapture(
	t *testing.T,
	writer http.ResponseWriter,
	status int,
	capture controlstore.EvidenceCapture,
) {
	t.Helper()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	if err := json.NewEncoder(writer).Encode(capture); err != nil {
		t.Fatal(err)
	}
}
