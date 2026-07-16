package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestClientInspectsAndExportsExecutorEvidence(t *testing.T) {
	inspection, export := controlClientEvidenceFixtures(t)
	inspectionRaw, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	exportRaw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Fatalf("method=%q", request.Method)
		}
		if request.Header.Get("Authorization") != "Bearer site-admin" {
			t.Fatalf("authorization=%q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/nodes/node-1/evidence":
			_, _ = writer.Write(inspectionRaw)
		case "/v1/nodes/node-1/evidence/export":
			_, _ = writer.Write(exportRaw)
		default:
			t.Fatalf("path=%q", request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "site-admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	gotInspection, err := client.InspectExecutorEvidence(context.Background(), "node-1")
	if err != nil || gotInspection.ControlNodeID != "node-1" || gotInspection.Status.Head == nil ||
		gotInspection.Status.Head.Sequence != 7 {
		t.Fatalf("inspection=%+v err=%v", gotInspection, err)
	}
	gotExport, err := client.ExportExecutorEvidence(context.Background(), "node-1")
	if err != nil || gotExport.Statement.ControlNodeID != "node-1" ||
		gotExport.WitnessPublicKeySHA256 != export.WitnessPublicKeySHA256 {
		t.Fatalf("export=%+v err=%v", gotExport, err)
	}
}

func TestClientEvidenceResponsesStayBoundedStrictAndValidated(t *testing.T) {
	inspection, export := controlClientEvidenceFixtures(t)
	inspectionRaw, err := json.Marshal(inspection)
	if err != nil {
		t.Fatal(err)
	}
	exportRaw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	duplicateExport := strings.Replace(string(exportRaw), `{"payload_type":`, `{"payload_type":"duplicate","payload_type":`, 1)
	unknownInspection := string(inspectionRaw[:len(inspectionRaw)-1]) + `,"unknown":true}`
	invalidInspection := inspection
	invalidInspection.Status.State = "invented"
	invalidRaw, err := json.Marshal(invalidInspection)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		export bool
		raw    string
		want   string
	}{
		{name: "inspection unknown field", raw: unknownInspection, want: "unknown JSON field"},
		{name: "export duplicate field", export: true, raw: duplicateExport, want: "duplicate JSON field"},
		{name: "inspection semantic validation", raw: string(invalidRaw), want: "validate control evidence inspection"},
		{name: "inspection response limit", raw: `{"padding":"` + strings.Repeat("x", maxWireBytes) + `"}`, want: "exceeds 1 MiB"},
		{name: "export response limit", export: true, raw: `{"padding":"` + strings.Repeat("x", maxWireBytes) + `"}`, want: "exceeds 1 MiB"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				_, _ = writer.Write([]byte(test.raw))
			}))
			defer server.Close()
			client, err := New(server.URL, "site-admin", nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.export {
				_, err = client.ExportExecutorEvidence(context.Background(), "node-1")
			} else {
				_, err = client.InspectExecutorEvidence(context.Background(), "node-1")
			}
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v, want substring %q", err, test.want)
			}
		})
	}
}

func TestClientEvidenceRedirectsAndInvalidNodeIDsFailClosed(t *testing.T) {
	targetCalled := false
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalled = true
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, target.URL+"/v1/nodes/node-1/evidence", http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()
	client, err := New(redirect.URL, "site-admin", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.InspectExecutorEvidence(context.Background(), "node-1"); err == nil ||
		!strings.Contains(err.Error(), "redirects are disabled") {
		t.Fatalf("redirect error=%v", err)
	}
	if targetCalled {
		t.Fatal("redirect target received the site-admin bearer")
	}
	for _, nodeID := range []string{"", "-node", "node/other", " node", strings.Repeat("n", 129)} {
		if _, err := client.InspectExecutorEvidence(context.Background(), nodeID); err == nil {
			t.Fatalf("invalid node identity %q accepted", nodeID)
		}
		if _, err := client.ExportExecutorEvidence(context.Background(), nodeID); err == nil {
			t.Fatalf("invalid export node identity %q accepted", nodeID)
		}
	}
}

func controlClientEvidenceFixtures(t *testing.T) (controlprotocol.ExecutorEvidenceInspectionV1, controlprotocol.ExecutorEvidenceExportV1) {
	t.Helper()
	receiptPublic, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"controller-1", "enrollment-1", "node-1", "node-1", 1, receiptPublic,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	head := controlprotocol.ExecutorEvidenceHeadV1{
		Stream: controlprotocol.ExecutorEvidenceStreamV1, ReceiptNodeID: "node-1", ReceiptEpoch: 1,
		Sequence: 7, ChainHash: "sha256:" + strings.Repeat("a", 64), PublicKeySHA256: claim.PublicKeySHA256,
	}
	status := controlprotocol.ExecutorEvidenceStatusV1{
		State: controlprotocol.ExecutorEvidenceStatusCurrent, Head: &head, WitnessedAt: "2026-07-16T01:02:03Z",
	}
	inspection := controlprotocol.ExecutorEvidenceInspectionV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1, ControllerInstanceID: "controller-1",
		ControlNodeID: "node-1", IdentityProof: &proof, Status: status,
	}
	_, witnessPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	export, err := controlprotocol.SignExecutorEvidenceExportV1(controlprotocol.ExecutorEvidenceExportStatementV1{
		ProtocolVersion: controlprotocol.ExecutorEvidenceProtocolV1, ControllerInstanceID: "controller-1",
		ControlNodeID: "node-1", IdentityProof: proof, Status: status, ExportedAt: "2026-07-16T01:03:00Z",
	}, witnessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	return inspection, export
}
