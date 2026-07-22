package controlclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

func TestClientDrivesBoundedAuthenticatedControlAPI(t *testing.T) {
	commandRaw := []byte(`{"payloadType":"x"}`)
	projection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    "executor-" + strings.Repeat("a", 64), Status: "created",
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("c", 64),
		Generation:    1, EvidenceKeyID: strings.Repeat("d", 32),
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		"control-test", "enr_1", "node-1", "node-1", 1, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, private)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/enroll" && request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatalf("missing operator bearer on %s", request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/tenants":
			if request.Method == http.MethodGet {
				if request.URL.Query().Get("after") != "tenant-0" || request.URL.Query().Get("limit") != "25" {
					t.Fatalf("tenant pagination=%q", request.URL.RawQuery)
				}
				_, _ = w.Write([]byte(`{"tenants":[{"tenant_id":"tenant-a","state":"active"}]}`))
			} else {
				_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","state":"active"}`))
			}
		case "/v1/operators":
			var input struct {
				RequestID string `json:"request_id"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.RequestID != "operator-request-1" {
				t.Fatalf("operator request=%+v error=%v", input, err)
			}
			_, _ = w.Write([]byte(`{"credential_id":"operator-1","role":"tenant_operator","tenant_id":"tenant-a","token":"new-secret","created_at":"2026-07-13T12:00:00Z"}`))
		case "/v1/operators/operator-1":
			w.WriteHeader(http.StatusNoContent)
		case "/v1/enrollments":
			_, _ = w.Write([]byte(`{"controller_instance_id":"control-test","enrollment_id":"enr_1","enrollment_token":"secret","node_id":"node-1","tenant_ids":["tenant-a"],"expires_at":"2026-07-13T12:15:00Z"}`))
		case "/v1/enroll":
			if request.Header.Get("Authorization") != "" {
				t.Fatal("enrollment leaked operator bearer")
			}
			var input struct {
				EnrollmentToken       string                                          `json:"enrollment_token"`
				RequestID             string                                          `json:"request_id"`
				EvidenceIdentityProof controlprotocol.ExecutorEvidenceIdentityProofV1 `json:"evidence_identity_proof"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil ||
				input.EnrollmentToken != "secret" || input.RequestID != "request-1" ||
				input.EvidenceIdentityProof != proof {
				t.Fatalf("enrollment exchange request=%+v error=%v", input, err)
			}
			_, _ = w.Write([]byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"node-secret"}`))
		case "/v1/tenants/tenant-a/nodes/node-1/commands":
			var input struct {
				Command string `json:"command_dsse_base64"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil {
				t.Fatal(err)
			}
			if input.Command != base64.StdEncoding.EncodeToString(commandRaw) {
				t.Fatalf("command=%q", input.Command)
			}
			_, _ = w.Write([]byte(`{"command_id":"c1","delivery_id":"d1","tenant_id":"tenant-a","node_id":"node-1","command_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"pending"}`))
		case "/v1/tenants/tenant-a/nodes/node-1/commands/c1":
			claimGeneration := uint64(1)
			_ = json.NewEncoder(w).Encode(Command{
				CommandID: "c1", TenantID: "tenant-a", NodeID: "node-1",
				CommandDigest: "sha256:" + strings.Repeat("a", 64),
				CommandKind:   "admit", SignedRuntimeRef: projection.RuntimeRef,
				SignedClaimGeneration: 1, SignedInstanceGeneration: projection.Generation,
				State: "terminal", DeliveryProtocol: controlprotocol.ExecutorProtocolV4,
				TerminalStatus: "done", ReportedStatus: "stopped",
				ClaimGeneration: &claimGeneration, AdmissionProjectionState: "present",
				Result: &CommandResult{RuntimeRef: projection.RuntimeRef, Admission: &projection},
			})
		case "/v1/tenants/tenant-a/nodes":
			_, _ = w.Write([]byte(`{"nodes":[{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":[],"state":"active","created_at":"2026-07-13T12:00:00Z"}]}`))
		case "/v1/tenants/tenant-a/nodes/node-1":
			_, _ = w.Write([]byte(`{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":["signed-commands-v2"],"state":"active","created_at":"2026-07-13T12:00:00Z","pool_membership":{"pool_id":"pool-a"}}`))
		case "/v1/nodes/node-1":
			_, _ = w.Write([]byte(`{"node_id":"node-1","revoked_credentials":1}`))
		case "/v1/nodes/node-1/placement":
			var input struct {
				Action string `json:"action"`
				Reason string `json:"reason"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Action != "cordon" || input.Reason != "maintenance" {
				t.Fatalf("placement request=%+v error=%v", input, err)
			}
			_, _ = w.Write([]byte(`{"node":{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":[],"state":"active","created_at":"2026-07-13T12:00:00Z","placement":{"mode":"cordoned","reason":"maintenance","changed_at":"2026-07-13T12:01:00Z"}},"changed":true}`))
		case "/v1/nodes/node-1/drain":
			var input struct {
				RequestID string `json:"request_id"`
				Reason    string `json:"reason"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.RequestID != "maintenance-1" ||
				request.Method == http.MethodPut && input.Reason != "kernel upgrade" ||
				request.Method == http.MethodDelete && input.Reason != "" {
				t.Fatalf("drain request=%+v method=%s error=%v", input, request.Method, err)
			}
			state := "active"
			if request.Method == http.MethodDelete {
				state = "cancelled"
			}
			_, _ = w.Write([]byte(`{"node":{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":[],"state":"active","created_at":"2026-07-13T12:00:00Z","placement":{"mode":"cordoned","reason":"kernel upgrade","changed_at":"2026-07-13T12:01:00Z"},"drain":{"request_id":"maintenance-1","state":"` + state + `","reason":"kernel upgrade","requested_at":"2026-07-13T12:01:00Z","updated_at":"2026-07-13T12:01:00Z"}},"changed":true}`))
		case "/v1/node-credentials/node-credential-1":
			_, _ = w.Write([]byte(`{"credential_id":"node-credential-1","node_id":"node-1","revoked":true}`))
		default:
			t.Fatalf("unexpected path %s", request.URL.Path)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if tenant, err := client.CreateTenant(ctx, "tenant-a"); err != nil || tenant.State != "active" {
		t.Fatalf("tenant=%#v error=%v", tenant, err)
	}
	if tenants, err := client.ListTenants(ctx, "tenant-0", 25); err != nil || len(tenants.Tenants) != 1 {
		t.Fatalf("tenants=%#v error=%v", tenants, err)
	}
	if operator, err := client.IssueOperator(ctx, "operator-request-1", "tenant_operator", "tenant-a"); err != nil || operator.Token != "new-secret" {
		t.Fatalf("operator=%#v error=%v", operator, err)
	}
	if err := client.RevokeOperator(ctx, "operator-1"); err != nil {
		t.Fatal(err)
	}
	if enrollment, err := client.CreateEnrollment(ctx, "enrollment-request-1", "node-1", []string{"tenant-a"}, 15*time.Minute); err != nil || enrollment.EnrollmentToken != "secret" {
		t.Fatalf("enrollment=%#v error=%v", enrollment, err)
	}
	if _, err := client.Enroll(ctx, "secret", "request-1", controlprotocol.ExecutorEvidenceIdentityProofV1{}); err == nil {
		t.Fatal("invalid evidence identity proof reached the enrollment endpoint")
	}
	if credential, err := client.Enroll(ctx, "secret", "request-1", proof); err != nil || credential.Version != 2 {
		t.Fatalf("credential=%#v error=%v", credential, err)
	}
	if nodes, err := client.ListNodes(ctx, "tenant-a", "", 100); err != nil || len(nodes.Nodes) != 1 {
		t.Fatalf("nodes=%#v error=%v", nodes, err)
	}
	if node, err := client.GetNode(ctx, "tenant-a", "node-1"); err != nil || node.State != "active" ||
		node.PoolMembership == nil || node.PoolMembership.PoolID != "pool-a" {
		t.Fatalf("node=%#v error=%v", node, err)
	}
	if change, err := client.ChangeNodePlacement(ctx, "node-1", controlstore.NodePlacementCordon, "maintenance"); err != nil ||
		!change.Changed || change.Node.Placement.Mode != controlstore.NodeCordoned {
		t.Fatalf("placement=%#v error=%v", change, err)
	}
	if change, err := client.StartNodeDrain(ctx, "node-1", "maintenance-1", "kernel upgrade"); err != nil ||
		!change.Changed || change.Node.Drain == nil || change.Node.Drain.State != controlstore.NodeDrainActive {
		t.Fatalf("start drain=%#v error=%v", change, err)
	}
	if change, err := client.CancelNodeDrain(ctx, "node-1", "maintenance-1"); err != nil ||
		!change.Changed || change.Node.Drain == nil || change.Node.Drain.State != controlstore.NodeDrainCancelled {
		t.Fatalf("cancel drain=%#v error=%v", change, err)
	}
	if revoked, err := client.RevokeNode(ctx, "node-1"); err != nil || revoked.RevokedCredentials != 1 {
		t.Fatalf("revoked=%#v error=%v", revoked, err)
	}
	if revoked, err := client.RevokeNodeCredential(ctx, "node-credential-1"); err != nil || !revoked.Revoked || revoked.NodeID != "node-1" {
		t.Fatalf("node credential revocation=%#v error=%v", revoked, err)
	}
	if command, err := client.SubmitCommand(ctx, "tenant-a", "node-1", commandRaw); err != nil || command.State != "pending" {
		t.Fatalf("command=%#v error=%v", command, err)
	}
	if command, err := client.GetCommand(ctx, "tenant-a", "node-1", "c1"); err != nil || command.TerminalStatus != "done" ||
		command.ReportedStatus != "stopped" || command.CommandKind != "admit" ||
		command.SignedRuntimeRef != projection.RuntimeRef || command.SignedInstanceGeneration != projection.Generation ||
		command.SignedClaimGeneration != 1 || command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
		command.AdmissionProjectionState != "present" ||
		command.ClaimGeneration == nil || *command.ClaimGeneration != 1 ||
		command.Result == nil || command.Result.Admission == nil ||
		command.Result.Admission.RuntimeRef != projection.RuntimeRef {
		t.Fatalf("command=%#v error=%v", command, err)
	}
}

func TestClientRejectsUnsafeTransportAndErrors(t *testing.T) {
	for _, endpoint := range []string{"http://control.example:8080", "http://localhost:8080", "https://control.example", "https://user@control.example:443", "https://control.example:443/path"} {
		if client, err := New(endpoint, "token", nil); err == nil || client != nil {
			t.Fatalf("unsafe endpoint %q accepted", endpoint)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "3")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"error":"command_conflict","message":"different signed bytes"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "token", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.SubmitCommand(context.Background(), "tenant-a", "node-1", []byte("x"))
	api, ok := err.(*APIError)
	if !ok || api.Status != http.StatusConflict || api.RetryAfter != 3*time.Second ||
		!strings.Contains(api.Error(), "command_conflict") ||
		!strings.Contains(api.Error(), "retry after 3s") {
		t.Fatalf("error=%T %v", err, err)
	}
}

func TestClientRejectsInconsistentAdmissionProjectionViews(t *testing.T) {
	valid := func() Command {
		projection := controlprotocol.ExecutorAdmissionProjectionV1{
			SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
			RuntimeRef:    "executor-" + strings.Repeat("a", 64), Status: "created",
			CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
			PolicyDigest:  "sha256:" + strings.Repeat("c", 64),
			Generation:    1, EvidenceKeyID: strings.Repeat("d", 32),
		}
		claim := uint64(7)
		return Command{
			CommandKind: "admit", SignedRuntimeRef: projection.RuntimeRef,
			SignedClaimGeneration: claim, SignedInstanceGeneration: projection.Generation,
			State: "terminal", DeliveryProtocol: controlprotocol.ExecutorProtocolV4,
			TerminalStatus: controlprotocol.ExecutorStatusDone, ReportedStatus: "stopped",
			ClaimGeneration: &claim, AdmissionProjectionState: "present",
			Result: &CommandResult{RuntimeRef: projection.RuntimeRef, Admission: &projection},
		}
	}
	if err := validateCommandAdmissionProjection(valid()); err != nil {
		t.Fatalf("valid projection view: %v", err)
	}
	missing := valid()
	missing.AdmissionProjectionState = "missing"
	missing.Result.Admission = nil
	if err := validateCommandAdmissionProjection(missing); err != nil {
		t.Fatalf("detectable missing projection view: %v", err)
	}

	tests := map[string]func(*Command){
		"projection without state": func(value *Command) { value.AdmissionProjectionState = "" },
		"omitted missing state": func(value *Command) {
			value.AdmissionProjectionState = ""
			value.Result.Admission = nil
		},
		"unknown state":      func(value *Command) { value.AdmissionProjectionState = "unknown" },
		"wrong command kind": func(value *Command) { value.CommandKind = "start" },
		"wrong delivery protocol": func(value *Command) {
			value.DeliveryProtocol = controlprotocol.ExecutorProtocolV3
		},
		"claim mismatch": func(value *Command) { *value.ClaimGeneration++ },
		"runtime mismatch": func(value *Command) {
			value.Result.RuntimeRef = "executor-" + strings.Repeat("e", 64)
		},
		"signed runtime mismatch": func(value *Command) {
			value.SignedRuntimeRef = "executor-" + strings.Repeat("e", 64)
		},
		"signed generation mismatch": func(value *Command) { value.SignedInstanceGeneration++ },
		"invalid projection":         func(value *Command) { value.Result.Admission.PolicyDigest = "invalid" },
		"reported status":            func(value *Command) { value.ReportedStatus = "running" },
		"missing payload":            func(value *Command) { value.Result.Admission = nil },
		"missing state with payload": func(value *Command) {
			value.AdmissionProjectionState = "missing"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			mutate(&candidate)
			if err := validateCommandAdmissionProjection(candidate); err == nil {
				t.Fatal("inconsistent admission projection view was accepted")
			}
		})
	}
}

func TestClientRejectsInconsistentActivationCanaryProjectionViews(t *testing.T) {
	valid := func() Command {
		terminal := []byte(`{"ok":true}`)
		receipts := []byte("authorize\nterminal\nexport\n")
		projection := controlprotocol.ExecutorActivationCanaryResultV1{
			SchemaVersion:        controlprotocol.ExecutorActivationCanaryResultSchemaV1,
			ActivationID:         "activation-1",
			AdmissionDigest:      "sha256:" + strings.Repeat("1", 64),
			TaskDigest:           "sha256:" + strings.Repeat("2", 64),
			PermitDigest:         "sha256:" + strings.Repeat("3", 64),
			RunID:                "run_" + strings.Repeat("4", 32),
			TerminalResultDigest: dsse.Digest(terminal), TerminalResultBytes: int64(len(terminal)),
			TerminalResultBase64:       base64.StdEncoding.EncodeToString(terminal),
			GatewayEvidenceBase64:      base64.StdEncoding.EncodeToString(receipts),
			ActivationCheckpointDigest: "sha256:" + strings.Repeat("5", 64), Qualified: true,
		}
		claim := uint64(7)
		return Command{
			CommandKind: "activation-canary", SignedRuntimeRef: "executor-" + strings.Repeat("a", 64),
			SignedClaimGeneration: claim, SignedInstanceGeneration: 11,
			State: "terminal", DeliveryProtocol: controlprotocol.ExecutorProtocolV4,
			TerminalStatus: controlprotocol.ExecutorStatusDone, ReportedStatus: "running",
			ClaimGeneration: &claim, ActivationCanaryProjectionState: "present",
			Result: &CommandResult{
				RuntimeRef:       "executor-" + strings.Repeat("a", 64),
				ActivationCanary: &projection,
			},
		}
	}
	if err := validateCommandProjections(valid()); err != nil {
		t.Fatalf("valid activation canary projection view: %v", err)
	}
	missing := valid()
	missing.ActivationCanaryProjectionState = "missing"
	missing.Result.ActivationCanary = nil
	if err := validateCommandProjections(missing); err != nil {
		t.Fatalf("detectable missing canary projection view: %v", err)
	}

	tests := map[string]func(*Command){
		"projection without state": func(value *Command) { value.ActivationCanaryProjectionState = "" },
		"omitted missing state": func(value *Command) {
			value.ActivationCanaryProjectionState = ""
			value.Result.ActivationCanary = nil
		},
		"unknown state":      func(value *Command) { value.ActivationCanaryProjectionState = "unknown" },
		"wrong command kind": func(value *Command) { value.CommandKind = "start" },
		"wrong delivery protocol": func(value *Command) {
			value.DeliveryProtocol = controlprotocol.ExecutorProtocolV3
		},
		"terminal status": func(value *Command) { value.TerminalStatus = controlprotocol.ExecutorStatusFailed },
		"reported status": func(value *Command) { value.ReportedStatus = "passed" },
		"claim mismatch":  func(value *Command) { *value.ClaimGeneration++ },
		"runtime mismatch": func(value *Command) {
			value.Result.RuntimeRef = "executor-" + strings.Repeat("e", 64)
		},
		"signed runtime mismatch": func(value *Command) {
			value.SignedRuntimeRef = "executor-" + strings.Repeat("e", 64)
		},
		"missing instance generation": func(value *Command) { value.SignedInstanceGeneration = 0 },
		"invalid projection":          func(value *Command) { value.Result.ActivationCanary.Qualified = false },
		"missing payload":             func(value *Command) { value.Result.ActivationCanary = nil },
		"missing state with payload": func(value *Command) {
			value.ActivationCanaryProjectionState = "missing"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			candidate := valid()
			mutate(&candidate)
			if err := validateCommandProjections(candidate); err == nil {
				t.Fatal("inconsistent activation canary projection view was accepted")
			}
		})
	}
}

func TestRetryAfterDurationRejectsAmbiguousHeaders(t *testing.T) {
	for name, test := range map[string]struct {
		values []string
		want   time.Duration
		valid  bool
	}{
		"absent":       {valid: true},
		"one second":   {values: []string{"1"}, want: time.Second, valid: true},
		"maximum":      {values: []string{"3600"}, want: time.Hour, valid: true},
		"duplicate":    {values: []string{"1", "2"}},
		"combined":     {values: []string{"1, 2"}},
		"leading plus": {values: []string{"+1"}},
		"leading zero": {values: []string{"01"}},
		"zero":         {values: []string{"0"}},
		"over maximum": {values: []string{"3601"}},
		"HTTP date":    {values: []string{"Thu, 16 Jul 2026 12:00:00 GMT"}},
		"empty":        {values: []string{""}},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := retryAfterDuration(test.values)
			if test.valid && (err != nil || got != test.want) {
				t.Fatalf("retry after=%s want=%s err=%v", got, test.want, err)
			}
			if !test.valid && err == nil {
				t.Fatalf("invalid Retry-After values %q produced %s", test.values, got)
			}
		})
	}
}

func TestExplicitControlCAReplacesSystemTrust(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "private control CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	client, err := New("https://127.0.0.1:8443", "operator", caPEM)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := client.http.Transport.(*http.Transport)
	if !ok || transport.TLSClientConfig == nil || transport.TLSClientConfig.RootCAs == nil {
		t.Fatal("control client omitted its explicit private trust pool")
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Fatalf("control client minimum TLS version = %#x, want TLS 1.3", transport.TLSClientConfig.MinVersion)
	}
	expected := x509.NewCertPool()
	if !expected.AppendCertsFromPEM(caPEM) {
		t.Fatal("test CA could not be added to the expected trust pool")
	}
	if !transport.TLSClientConfig.RootCAs.Equal(expected) {
		t.Fatal("explicit private CA did not replace the system trust pool")
	}
}

func TestClientRejectsAmbiguousResponsesAndPagination(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","tenant_id":"tenant-b","state":"active"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.CreateTenant(context.Background(), "tenant-a"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("ambiguous response error=%v", err)
	}
	if _, err := client.ListTenants(context.Background(), strings.Repeat("x", 129), 1); err == nil {
		t.Fatal("oversized cursor accepted")
	}
	if _, err := client.ListNodes(context.Background(), "tenant-a", "", 501); err == nil {
		t.Fatal("oversized node page accepted")
	}
	if _, err := New(server.URL, " token ", nil); err == nil {
		t.Fatal("whitespace-bearing token accepted")
	}
}

func TestDecodeEnrollmentCapabilityRejectsAmbiguousInput(t *testing.T) {
	valid := []byte(`{"controller_instance_id":"control-test","enrollment_id":"enr-1","enrollment_token":"secret","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"}`)
	if enrollment, err := DecodeEnrollmentCapability(valid); err != nil || enrollment.NodeID != "node-1" {
		t.Fatalf("valid enrollment=%+v error=%v", enrollment, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"controller_instance_id":"control-test","enrollment_id":"enr-1","enrollment_token":"first","enrollment_token":"second","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"}`),
		[]byte(`{"controller_instance_id":"control-test","enrollment_id":"enr-1","enrollment_token":"secret","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z","unexpected":true}`),
		[]byte(`{"controller_instance_id":"control-test","enrollment_id":"enr-1","enrollment_token":"secret","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"} {}`),
		[]byte(`{"controller_instance_id":"control-test","enrollment_id":"enr-1","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"}`),
		[]byte(`{"enrollment_id":"enr-1","enrollment_token":"secret","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"}`),
	} {
		if _, err := DecodeEnrollmentCapability(raw); err == nil {
			t.Fatalf("ambiguous enrollment accepted: %s", raw)
		}
	}
}
