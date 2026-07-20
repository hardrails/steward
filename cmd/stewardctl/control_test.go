package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
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
	attentionCursor := base64.RawURLEncoding.EncodeToString([]byte("attention-v1\x00attention-a"))
	timelineCursor := base64.RawURLEncoding.EncodeToString([]byte("incident-timeline-v1\x00incident-a"))
	agentCursor := base64.RawURLEncoding.EncodeToString([]byte("agent-v1\x00agent-a"))
	commandCursor := base64.RawURLEncoding.EncodeToString([]byte("command-v1\x00command-a"))
	credentialCursor := base64.RawURLEncoding.EncodeToString([]byte("credential-v1\x00credential-a"))
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
		case "/v1/nodes/node-1/placement":
			_, _ = w.Write([]byte(`{"node":{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":[],"state":"active","created_at":"2026-07-13T12:00:00Z","placement":{"mode":"cordoned","reason":"maintenance","changed_at":"2026-07-13T12:01:00Z"}},"changed":true}`))
		case "/v1/nodes/node-1/drain":
			var input struct {
				RequestID string `json:"request_id"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.RequestID == "" {
				t.Fatalf("drain request=%+v error=%v", input, err)
			}
			state := "active"
			if request.Method == http.MethodDelete {
				state = "cancelled"
			}
			_, _ = w.Write([]byte(`{"node":{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":[],"state":"active","created_at":"2026-07-13T12:00:00Z","placement":{"mode":"cordoned","reason":"kernel upgrade","changed_at":"2026-07-13T12:01:00Z"},"drain":{"request_id":"` + input.RequestID + `","state":"` + state + `","reason":"kernel upgrade","requested_at":"2026-07-13T12:01:00Z","updated_at":"2026-07-13T12:01:00Z"}},"changed":true}`))
		case "/v1/operations/summary":
			query := request.URL.Query()
			if request.Method != http.MethodGet || query.Get("tenant_id") != "tenant-a" {
				t.Fatalf("operations summary request=%s %s", request.Method, request.URL.String())
			}
			_, _ = w.Write([]byte(`{"generated_at":"2026-07-16T12:00:00Z","tenant_id":"tenant-a","capacity":[],"commands":{"total":1,"pending":1,"leased":0,"terminal":0,"done":0,"failed":0,"rejected":0,"outcome_unknown":0},"evidence":{"nodes":1,"active_nodes":1,"witnessed":1,"unwitnessed":0,"current":1,"stale":0,"rollback_detected":0,"equivocation_detected":0},"attention":{"total":1,"warnings":1,"critical":0,"counts":[{"reason":"node_stale","severity":"warning","count":1}]}}`))
		case "/v1/operations/attention":
			query := request.URL.Query()
			if request.Method != http.MethodGet || query.Get("tenant_id") != "tenant-a" ||
				query.Get("reason") != "node_stale" || query.Get("cursor") != attentionCursor ||
				query.Get("limit") != "25" {
				t.Fatalf("attention request=%s %s", request.Method, request.URL.String())
			}
			_, _ = w.Write([]byte(`{"items":[{"id":"attention-a","reason":"node_stale","severity":"warning","resource":"node","tenant_id":"tenant-a","node_id":"node-1","since":"2026-07-16T11:55:00Z"}],"next_cursor":"next-attention"}`))
		case "/v1/operations/timeline":
			query := request.URL.Query()
			if request.Method != http.MethodGet || query.Get("tenant_id") != "tenant-a" ||
				query.Get("node_id") != "node-1" || query.Get("kind") != "containment" ||
				query.Get("severity") != "critical" || query.Get("cursor") != timelineCursor ||
				query.Get("limit") != "20" {
				t.Fatalf("incident timeline request=%s %s", request.Method, request.URL.String())
			}
			_, _ = w.Write([]byte(`{"events":[{"id":"incident-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","occurred_at":"2026-07-16T11:56:00Z","kind":"containment","action":"node_quarantined","severity":"critical","scope":"tenant","tenant_id":"tenant-a","node_id":"node-1","reason":"evidence mismatch"}]}`))
		case "/v1/operations/commands":
			query := request.URL.Query()
			if request.Method != http.MethodGet || query.Get("tenant_id") != "tenant-a" ||
				query.Get("node_id") != "node-1" || query.Get("state") != "terminal" ||
				query.Get("terminal_status") != "failed" || query.Get("cursor") != commandCursor ||
				query.Get("limit") != "50" {
				t.Fatalf("command inventory request=%s %s", request.Method, request.URL.String())
			}
			_, _ = w.Write([]byte(`{"commands":[{"tenant_id":"tenant-a","node_id":"node-1","id":"command-1","delivery_id":"delivery-1","digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"terminal","delivery_generation":1,"created_at":"2026-07-16T11:00:00Z","terminal_status":"failed","completed_at":"2026-07-16T11:01:00Z"}],"next_cursor":"next-command"}`))
		case "/v1/operations/agents":
			query := request.URL.Query()
			if request.Method != http.MethodGet || query.Get("tenant_id") != "tenant-a" ||
				query.Get("node_id") != "node-1" || query.Get("status") != "running" ||
				query.Get("cursor") != agentCursor || query.Get("limit") != "40" {
				t.Fatalf("agent inventory request=%s %s", request.Method, request.URL.String())
			}
			_, _ = w.Write([]byte(`{"agents":[{"tenant_id":"tenant-a","node_id":"node-1","runtime_ref":"executor-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","instance_generation":1,"observed_status":"running","latest_command_id":"command-1","latest_command_kind":"start","latest_command_state":"terminal","latest_terminal_status":"done","created_at":"2026-07-16T11:00:00Z","updated_at":"2026-07-16T11:01:00Z"}],"next_cursor":"next-agent"}`))
		case "/v1/operations/credentials":
			query := request.URL.Query()
			if request.Method != http.MethodGet || query.Get("tenant_id") != "tenant-a" ||
				query.Get("kind") != "operator" || query.Get("role") != "tenant_operator" ||
				query.Get("revoked") != "false" || query.Get("cursor") != credentialCursor ||
				query.Get("limit") != "10" {
				t.Fatalf("credential inventory request=%s %s", request.Method, request.URL.String())
			}
			_, _ = w.Write([]byte(`{"credentials":[{"id":"operator-1","kind":"operator","role":"tenant_operator","tenant_id":"tenant-a","request_id":"request-operator-1","created_at":"2026-07-16T10:00:00Z","revoked":false}],"next_cursor":"next-credential"}`))
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "admin.token")
	enrollmentPath := filepath.Join(directory, "enrollment.json")
	credentialPath := filepath.Join(directory, "credential.json")
	evidenceConfigPath := filepath.Join(directory, "executor-evidence.env")
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
		"-executor-evidence-private-key", evidencePrivatePath, "-credential-out", credentialPath,
		"-executor-evidence-config-out", evidenceConfigPath},
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
	evidenceConfig, err := os.ReadFile(evidenceConfigPath)
	if err != nil || !bytes.Contains(evidenceConfig, []byte(
		"STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID=control-test\n"+
			"STEWARD_EXECUTOR_EVIDENCE_NODE_ID=node-1\n",
	)) || !bytes.Contains(evidenceConfig, []byte("STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_BASE64=")) {
		t.Fatalf("evidence config=%s error=%v", evidenceConfig, err)
	}
	if info, err := os.Stat(evidenceConfigPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("evidence config mode=%v error=%v", info, err)
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
	cordonArguments := append([]string{"control", "node", "cordon"}, common...)
	cordonArguments = append(cordonArguments, "-reason", "maintenance", "node-1")
	if err := run(cordonArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"mode":"cordoned"`) {
		t.Fatalf("node cordon output=%q error=%v", output.String(), err)
	}
	output.Reset()
	drainArguments := append([]string{"control", "node", "drain"}, common...)
	drainArguments = append(drainArguments, "-reason", "kernel upgrade", "node-1")
	if err := run(drainArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"state":"active"`) {
		t.Fatalf("node drain output=%q error=%v", output.String(), err)
	}
	output.Reset()
	cancelDrainArguments := append([]string{"control", "node", "cancel-drain"}, common...)
	cancelDrainArguments = append(cancelDrainArguments, "-request-id", "maintenance-1", "node-1")
	if err := run(cancelDrainArguments, &output, &bytes.Buffer{}); err != nil || !strings.Contains(output.String(), `"state":"cancelled"`) {
		t.Fatalf("node cancel drain output=%q error=%v", output.String(), err)
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
	output.Reset()
	operationsArguments := append([]string{"control", "operations", "status"}, common...)
	operationsArguments = append(operationsArguments, "-tenant-id", "tenant-a")
	if err := run(operationsArguments, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"generated_at":"2026-07-16T12:00:00Z"`) ||
		!strings.Contains(output.String(), `"node_stale"`) {
		t.Fatalf("operations output=%q error=%v", output.String(), err)
	}
	output.Reset()
	attentionArguments := append([]string{"control", "attention", "list"}, common...)
	attentionArguments = append(
		attentionArguments, "-tenant-id", "tenant-a", "-reason", "node_stale",
		"-cursor", attentionCursor, "-limit", "25",
	)
	if err := run(attentionArguments, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"id":"attention-a"`) {
		t.Fatalf("attention output=%q error=%v", output.String(), err)
	}
	output.Reset()
	incidentArguments := append([]string{"control", "incident", "timeline"}, common...)
	incidentArguments = append(
		incidentArguments, "-tenant-id", "tenant-a", "-node-id", "node-1",
		"-kind", "containment", "-severity", "critical", "-cursor", timelineCursor, "-limit", "20",
	)
	if err := run(incidentArguments, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"action":"node_quarantined"`) {
		t.Fatalf("incident timeline output=%q error=%v", output.String(), err)
	}
	output.Reset()
	agentListArguments := append([]string{"control", "agent", "list"}, common...)
	agentListArguments = append(
		agentListArguments, "-tenant-id", "tenant-a", "-node-id", "node-1",
		"-status", "running", "-cursor", agentCursor, "-limit", "40",
	)
	if err := run(agentListArguments, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"observed_status":"running"`) ||
		!strings.Contains(output.String(), `"latest_command_kind":"start"`) {
		t.Fatalf("agent inventory output=%q error=%v", output.String(), err)
	}
	output.Reset()
	commandListArguments := append([]string{"control", "command", "list"}, common...)
	commandListArguments = append(
		commandListArguments, "-tenant-id", "tenant-a", "-node-id", "node-1",
		"-state", "terminal", "-terminal-status", "failed",
		"-cursor", commandCursor, "-limit", "50",
	)
	if err := run(commandListArguments, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"terminal_status":"failed"`) ||
		strings.Contains(output.String(), `"command_dsse"`) ||
		strings.Contains(output.String(), `"result"`) ||
		strings.Contains(output.String(), `"runtime_ref"`) ||
		strings.Contains(output.String(), `"reported_status"`) ||
		strings.Contains(output.String(), `"error_code"`) {
		t.Fatalf("command inventory output=%q error=%v", output.String(), err)
	}
	output.Reset()
	credentialListArguments := append([]string{"control", "credential", "list"}, common...)
	credentialListArguments = append(
		credentialListArguments, "-tenant-id", "tenant-a", "-kind", "operator",
		"-role", "tenant_operator", "-revoked", "false",
		"-cursor", credentialCursor, "-limit", "10",
	)
	if err := run(credentialListArguments, &output, &bytes.Buffer{}); err != nil ||
		!strings.Contains(output.String(), `"id":"operator-1"`) ||
		strings.Contains(output.String(), `"token"`) ||
		strings.Contains(output.String(), `"token_mac"`) ||
		strings.Contains(output.String(), `"credential"`) {
		t.Fatalf("credential inventory output=%q error=%v", output.String(), err)
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

func TestControlOperationsCommandsRejectInvalidFilters(t *testing.T) {
	validCursor := base64.RawURLEncoding.EncodeToString([]byte("cursor-v1\x00item-a"))
	tests := []struct {
		name string
		call func([]string, io.Writer) error
		args []string
	}{
		{name: "operations tenant", call: controlOperationsStatus, args: []string{"-tenant-id", "-tenant"}},
		{name: "operations positional", call: controlOperationsStatus, args: []string{"unexpected"}},
		{name: "attention reason", call: controlAttentionList, args: []string{"-reason", "not-a-reason"}},
		{name: "attention cursor", call: controlAttentionList, args: []string{"-cursor", "%%%"}},
		{name: "attention zero limit", call: controlAttentionList, args: []string{"-limit", "0"}},
		{name: "attention oversized limit", call: controlAttentionList, args: []string{"-limit", "501"}},
		{name: "incident kind", call: controlIncidentTimeline, args: []string{"-kind", "unknown"}},
		{name: "incident severity", call: controlIncidentTimeline, args: []string{"-severity", "urgent"}},
		{name: "incident node", call: controlIncidentTimeline, args: []string{"-node-id", "-node"}},
		{name: "incident cursor", call: controlIncidentTimeline, args: []string{"-cursor", validCursor + "="}},
		{name: "incident zero limit", call: controlIncidentTimeline, args: []string{"-limit", "0"}},
		{name: "agent status", call: controlAgentList, args: []string{"-status", "destroyed"}},
		{name: "agent node", call: controlAgentList, args: []string{"-node-id", "-node"}},
		{name: "agent cursor", call: controlAgentList, args: []string{"-cursor", validCursor + "="}},
		{name: "command state", call: controlCommandList, args: []string{"-state", "running"}},
		{name: "command terminal without state", call: controlCommandList, args: []string{"-terminal-status", "failed"}},
		{name: "command terminal status", call: controlCommandList, args: []string{"-state", "terminal", "-terminal-status", "running"}},
		{name: "command node", call: controlCommandList, args: []string{"-node-id", "-node"}},
		{name: "command cursor", call: controlCommandList, args: []string{"-cursor", validCursor + "="}},
		{name: "credential kind", call: controlCredentialList, args: []string{"-kind", "enrollment"}},
		{name: "credential role", call: controlCredentialList, args: []string{"-role", "owner"}},
		{name: "credential revoked", call: controlCredentialList, args: []string{"-revoked", "yes"}},
		{name: "credential role and node", call: controlCredentialList, args: []string{"-role", "tenant_operator", "-node-id", "node-a"}},
		{name: "node credential with role", call: controlCredentialList, args: []string{"-kind", "node", "-role", "tenant_operator"}},
		{name: "operator credential with node", call: controlCredentialList, args: []string{"-kind", "operator", "-node-id", "node-a"}},
		{name: "credential zero limit", call: controlCredentialList, args: []string{"-limit", "0"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(test.args, &bytes.Buffer{}); err == nil {
				t.Fatalf("invalid arguments accepted: %#v", test.args)
			}
		})
	}
}

func TestControlInventoryCursorAndRevokedParsingAreStrict(t *testing.T) {
	validCursor := base64.RawURLEncoding.EncodeToString([]byte("cursor-v1\x00item-a"))
	if !validControlInventoryPage(validCursor, 1, false) ||
		!validControlInventoryPage("", controlstore.MaxInventoryPageLimit, false) {
		t.Fatal("valid inventory page rejected")
	}
	for _, cursor := range []string{
		"YQ==",
		"%%%",
		base64.RawURLEncoding.EncodeToString(make([]byte, 4097)),
	} {
		if validControlInventoryPage(cursor, 1, false) {
			t.Fatalf("invalid cursor %q accepted", cursor)
		}
	}
	if validControlInventoryPage(validCursor, 0, false) ||
		validControlInventoryPage(validCursor, controlstore.MaxInventoryPageLimit+1, false) {
		t.Fatal("invalid inventory limit accepted")
	}
	for input, expected := range map[string]*bool{
		"any": nil,
		"true": func() *bool {
			value := true
			return &value
		}(),
		"false": func() *bool {
			value := false
			return &value
		}(),
	} {
		got, err := parseControlRevoked(input)
		if err != nil || got == nil != (expected == nil) || got != nil && *got != *expected {
			t.Fatalf("parseControlRevoked(%q)=(%v,%v), want %v", input, got, err, expected)
		}
	}
	if _, err := parseControlRevoked(""); err == nil {
		t.Fatal("empty revoked filter accepted by CLI")
	}
}

func TestEnrollmentCredentialValidationRejectsEndpointSubstitution(t *testing.T) {
	const token = "steward_node_v1_node-cred-11111111111111111111111111111111_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	enrollment := controlclient.Enrollment{NodeID: "node-1"}
	valid := controlclient.NodeCredential{
		Version: 2, Scope: "node", NodeID: "node-1", Credential: token,
	}
	if credentialID, err := validateEnrollmentCredential(enrollment, valid); err != nil ||
		credentialID != "node-cred-11111111111111111111111111111111" {
		t.Fatalf("valid credential = (%q, %v)", credentialID, err)
	}
	tests := []struct {
		name   string
		mutate func(*controlclient.NodeCredential)
	}{
		{"version", func(value *controlclient.NodeCredential) { value.Version = 1 }},
		{"scope", func(value *controlclient.NodeCredential) { value.Scope = "tenant" }},
		{"tenant", func(value *controlclient.NodeCredential) { value.TenantID = "tenant-a" }},
		{"node", func(value *controlclient.NodeCredential) { value.NodeID = "node-other" }},
		{"bearer", func(value *controlclient.NodeCredential) { value.Credential = "not-a-node-credential" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			changed := valid
			test.mutate(&changed)
			if _, err := validateEnrollmentCredential(enrollment, changed); err == nil {
				t.Fatalf("substituted credential accepted: %+v", changed)
			}
		})
	}
}

func TestControlNodePlacementRejectsAmbiguousCLIInput(t *testing.T) {
	flags, positional := placementFlagArguments([]string{
		"-reason", "maintenance", "node-1", "-control-url", "http://127.0.0.1:8443", "-token-file=/tmp/token",
	})
	if len(positional) != 1 || positional[0] != "node-1" || len(flags) != 5 {
		t.Fatalf("placement argument normalization = flags %v positional %v", flags, positional)
	}
	for _, test := range []struct {
		arguments []string
		action    controlstore.NodePlacementAction
	}{
		{nil, controlstore.NodePlacementCordon},
		{[]string{"-node-id", "node-1"}, controlstore.NodePlacementCordon},
		{[]string{"-node-id", "node-1", "-reason", "unexpected"}, controlstore.NodePlacementUncordon},
		{[]string{"node-1", "node-2"}, controlstore.NodePlacementQuarantine},
	} {
		if err := controlNodePlacement(test.arguments, &bytes.Buffer{}, test.action); err == nil {
			t.Fatalf("ambiguous placement input accepted: %+v", test)
		}
	}
}

func TestControlEnrollmentExchangeDoesNotPublishMismatchedCredential(t *testing.T) {
	const token = "steward_node_v1_node-cred-11111111111111111111111111111111_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/enroll" {
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"version":2,"scope":"node","node_id":"node-other","credential":"` + token + `"}`))
	}))
	defer server.Close()

	directory := t.TempDir()
	enrollmentPath := filepath.Join(directory, "enrollment.json")
	privatePath := filepath.Join(directory, "evidence.private.pem")
	publicPath := filepath.Join(directory, "evidence.public")
	outputPath := filepath.Join(directory, "credential.json")
	evidenceConfigPath := filepath.Join(directory, "executor-evidence.env")
	if err := os.WriteFile(enrollmentPath, []byte(
		`{"controller_instance_id":"control-test","enrollment_id":"enr-1","enrollment_token":"secret","node_id":"node-1","tenant_ids":["tenant-a"],"expires_at":"2026-07-13T12:15:00Z"}`,
	), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{
		"keygen", "-private-out", privatePath, "-public-out", publicPath,
	}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	err := controlEnrollmentExchange([]string{
		"-control-url", server.URL,
		"-enrollment", enrollmentPath,
		"-request-id", "request-1",
		"-executor-evidence-private-key", privatePath,
		"-credential-out", outputPath,
		"-executor-evidence-config-out", evidenceConfigPath,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "outside the enrollment identity") {
		t.Fatalf("mismatched endpoint response error=%v", err)
	}
	if _, err := os.Stat(outputPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched credential output exists: %v", err)
	}
	if _, err := os.Stat(evidenceConfigPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("mismatched evidence config output exists: %v", err)
	}
}

func TestWriteEnrollmentOutputsRollsBackAndRejectsAliases(t *testing.T) {
	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "credential.json")
	configPath := filepath.Join(directory, "evidence.env")
	if err := writeEnrollmentOutputs(credentialPath, []byte("credential"), credentialPath, []byte("config")); err == nil {
		t.Fatal("aliased enrollment outputs were accepted")
	}
	if err := os.WriteFile(credentialPath, []byte("occupied"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeEnrollmentOutputs(credentialPath, []byte("credential"), configPath, []byte("config")); err == nil {
		t.Fatal("existing credential output was overwritten")
	}
	if _, err := os.Stat(configPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("config output survived failed enrollment output: %v", err)
	}
}
