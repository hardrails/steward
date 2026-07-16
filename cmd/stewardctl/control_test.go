package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestControlDefaultOriginMatchesLoopbackServer(t *testing.T) {
	flags := flag.NewFlagSet("control-default", flag.ContinueOnError)
	values := addControlFlags(flags, true)
	if err := flags.Parse(nil); err != nil {
		t.Fatal(err)
	}
	if got := *values.url; got != "http://127.0.0.1:8443" {
		t.Fatalf("default control origin = %q", got)
	}
}

func TestControlCommandsCompleteEnrollmentAndQueueWorkflow(t *testing.T) {
	const nodeCredentialToken = "steward_node_v1_node-cred-11111111111111111111111111111111_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/enroll" && request.Header.Get("Authorization") != "Bearer admin-secret" {
			t.Fatalf("authorization=%q path=%q", request.Header.Get("Authorization"), request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/tenants":
			if request.Method == http.MethodGet {
				_, _ = w.Write([]byte(`{"tenants":[{"tenant_id":"tenant-a","state":"active"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","state":"active"}`))
			}
		case "/v1/operators":
			_, _ = w.Write([]byte(`{"credential_id":"operator-1","role":"tenant_operator","tenant_id":"tenant-a","token":"tenant-secret","created_at":"2026-07-13T12:00:00Z"}`))
		case "/v1/operators/operator-1":
			w.WriteHeader(http.StatusNoContent)
		case "/v1/enrollments":
			_, _ = w.Write([]byte(`{"controller_instance_id":"control-test","enrollment_id":"enr_1","enrollment_token":"enroll-secret","node_id":"node-1","tenant_ids":["tenant-a"],"expires_at":"2026-07-13T12:15:00Z"}`))
		case "/v1/enroll":
			if request.Header.Get("Authorization") != "" {
				t.Fatal("operator token sent to enrollment exchange")
			}
			var input struct {
				EnrollmentToken       string                                          `json:"enrollment_token"`
				RequestID             string                                          `json:"request_id"`
				EvidenceIdentityProof controlprotocol.ExecutorEvidenceIdentityProofV1 `json:"evidence_identity_proof"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.EnrollmentToken != "enroll-secret" || input.RequestID != "request-1" ||
				input.EvidenceIdentityProof.Validate() != nil ||
				input.EvidenceIdentityProof.Claim.ControllerInstanceID != "control-test" ||
				input.EvidenceIdentityProof.Claim.EnrollmentID != "enr_1" ||
				input.EvidenceIdentityProof.Claim.ControlNodeID != "node-1" ||
				input.EvidenceIdentityProof.Claim.ReceiptNodeID != "node-1" ||
				input.EvidenceIdentityProof.Claim.ReceiptEpoch != 1 {
				t.Fatalf("enrollment proof request=%+v error=%v", input, err)
			}
			_, _ = w.Write([]byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"` + nodeCredentialToken + `"}`))
		case "/v1/node-credentials/node-cred-11111111111111111111111111111111":
			_, _ = w.Write([]byte(`{"credential_id":"node-cred-11111111111111111111111111111111","node_id":"node-1","revoked":true}`))
		case "/v1/tenants/tenant-a/nodes/node-1/commands":
			_, _ = w.Write([]byte(`{"command_id":"command-1","delivery_id":"delivery-1","tenant_id":"tenant-a","node_id":"node-1","command_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"pending"}`))
		case "/v1/tenants/tenant-a/nodes/node-1/commands/command-1":
			_, _ = w.Write([]byte(`{"command_id":"command-1","tenant_id":"tenant-a","node_id":"node-1","command_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"terminal","reported_status":"running"}`))
		case "/v1/tenants/tenant-a/nodes":
			_, _ = w.Write([]byte(`{"nodes":[{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":[],"state":"active","created_at":"2026-07-13T12:00:00Z"}]}`))
		case "/v1/tenants/tenant-a/nodes/node-1":
			_, _ = w.Write([]byte(`{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":[],"state":"active","created_at":"2026-07-13T12:00:00Z"}`))
		case "/v1/nodes/node-1":
			_, _ = w.Write([]byte(`{"node_id":"node-1","revoked_credentials":1}`))
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "admin.token")
	enrollmentPath := filepath.Join(directory, "enrollment.json")
	credentialPath := filepath.Join(directory, "credential.json")
	evidencePrivatePath := filepath.Join(directory, "evidence.private.pem")
	evidencePublicPath := filepath.Join(directory, "evidence.public")
	operatorTokenPath := filepath.Join(directory, "tenant-operator.token")
	commandPath := filepath.Join(directory, "command.dsse.json")
	if err := os.WriteFile(tokenPath, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(commandPath, []byte(`{"payloadType":"opaque"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"keygen", "-private-out", evidencePrivatePath, "-public-out", evidencePublicPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	common := []string{"-control-url", server.URL, "-token-file", tokenPath}
	var output bytes.Buffer
	if err := run(append([]string{"control", "tenant", "create"}, append(common, "-tenant-id", "tenant-a")...), &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), `"tenant_id":"tenant-a"`) {
		t.Fatalf("tenant output=%q", output.String())
	}
	output.Reset()
	if err := run(append([]string{"control", "tenant", "list"}, common...), &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"tenants":[`) {
		t.Fatalf("tenant list output=%q error=%v", output.String(), err)
	}
	output.Reset()
	operatorArguments := append([]string{"control", "operator", "issue"}, common...)
	operatorArguments = append(operatorArguments, "-request-id", "operator-request-1", "-role", "tenant_operator", "-tenant-id", "tenant-a", "-token-out", operatorTokenPath)
	if err := run(operatorArguments, &output, &bytes.Buffer{}); err != nil || strings.TrimSpace(output.String()) != "operator-1" {
		t.Fatalf("operator issue output=%q error=%v", output.String(), err)
	}
	operatorToken, err := os.ReadFile(operatorTokenPath)
	if err != nil || string(operatorToken) != "tenant-secret\n" {
		t.Fatalf("operator token=%q error=%v", operatorToken, err)
	}
	if info, err := os.Stat(operatorTokenPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("operator token mode=%v error=%v", info, err)
	}
	output.Reset()
	revokeArguments := append([]string{"control", "operator", "revoke"}, common...)
	revokeArguments = append(revokeArguments, "-credential-id", "operator-1")
	if err := run(revokeArguments, &output, &bytes.Buffer{}); err != nil || strings.TrimSpace(output.String()) != "operator-1" {
		t.Fatalf("operator revoke output=%q error=%v", output.String(), err)
	}
	output.Reset()
	enrollmentArguments := append([]string{"control", "enrollment", "create"}, common...)
	enrollmentArguments = append(enrollmentArguments, "-request-id", "enrollment-request-1", "-node-id", "node-1", "-tenant-ids", "tenant-a", "-out", enrollmentPath)
	if err := run(enrollmentArguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != "enr_1" {
		t.Fatalf("enrollment output=%q", output.String())
	}
	if info, err := os.Stat(enrollmentPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment mode=%v error=%v", info, err)
	}
	output.Reset()
	if err := run([]string{"control", "enrollment", "exchange", "-control-url", server.URL,
		"-enrollment", enrollmentPath, "-request-id", "request-1",
		"-executor-evidence-private-key", evidencePrivatePath, "-credential-out", credentialPath},
		&output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != "node-cred-11111111111111111111111111111111" {
		t.Fatalf("exchange output=%q", output.String())
	}
	credential, err := os.ReadFile(credentialPath)
	if err != nil || !bytes.Contains(credential, []byte(`"credential":"`+nodeCredentialToken+`"`)) {
		t.Fatalf("credential=%s error=%v", credential, err)
	}
	output.Reset()
	nodeCredentialRevokeArguments := append([]string{"control", "node-credential", "revoke"}, common...)
	nodeCredentialRevokeArguments = append(nodeCredentialRevokeArguments, "-credential-id", "node-cred-11111111111111111111111111111111")
	if err := run(nodeCredentialRevokeArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"revoked":true`) {
		t.Fatalf("node credential revoke output=%q error=%v", output.String(), err)
	}
	output.Reset()
	nodeListArguments := append([]string{"control", "node", "list"}, common...)
	nodeListArguments = append(nodeListArguments, "-tenant-id", "tenant-a")
	if err := run(nodeListArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"nodes":[`) {
		t.Fatalf("node list output=%q error=%v", output.String(), err)
	}
	output.Reset()
	nodeStatusArguments := append([]string{"control", "node", "status"}, common...)
	nodeStatusArguments = append(nodeStatusArguments, "-tenant-id", "tenant-a", "-node-id", "node-1")
	if err := run(nodeStatusArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"state":"active"`) {
		t.Fatalf("node status output=%q error=%v", output.String(), err)
	}
	output.Reset()
	nodeRevokeArguments := append([]string{"control", "node", "revoke"}, common...)
	nodeRevokeArguments = append(nodeRevokeArguments, "-node-id", "node-1")
	if err := run(nodeRevokeArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"revoked_credentials":1`) {
		t.Fatalf("node revoke output=%q error=%v", output.String(), err)
	}
	output.Reset()
	submitArguments := append([]string{"control", "command", "submit"}, common...)
	submitArguments = append(submitArguments, "-tenant-id", "tenant-a", "-node-id", "node-1", "-command", commandPath)
	if err := run(submitArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"state":"pending"`) {
		t.Fatalf("submit output=%q error=%v", output.String(), err)
	}
	output.Reset()
	statusArguments := append([]string{"control", "command", "status"}, common...)
	statusArguments = append(statusArguments, "-tenant-id", "tenant-a", "-node-id", "node-1", "-command-id", "command-1")
	if err := run(statusArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"reported_status":"running"`) {
		t.Fatalf("status output=%q error=%v", output.String(), err)
	}
}

func TestControlCommandsRejectAmbiguousScopeAndMissingSecrets(t *testing.T) {
	if err := controlCommand(nil, &bytes.Buffer{}); err == nil {
		t.Fatal("missing control action accepted")
	}
	if err := controlCommand([]string{"tenant", "unknown"}, &bytes.Buffer{}); err == nil {
		t.Fatal("unknown control action accepted")
	}
	for _, value := range []string{"", "tenant-a,tenant-a", "tenant-a,"} {
		if _, err := parseTenantIDs(value); err == nil {
			t.Fatalf("tenant list %q accepted", value)
		}
	}
	if err := controlTenantCreate([]string{"-tenant-id", "tenant-a"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "token") {
		t.Fatalf("missing token error=%v", err)
	}
	if err := controlEnrollmentExchange([]string{
		"-enrollment", "/tmp/enrollment", "-request-id", "request", "-credential-out", "/tmp/credential",
	}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "evidence private key") {
		t.Fatalf("missing evidence private key error=%v", err)
	}
}
