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
)

func TestClientDrivesBoundedAuthenticatedControlAPI(t *testing.T) {
	commandRaw := []byte(`{"payloadType":"x"}`)
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
			_, _ = w.Write([]byte(`{"enrollment_id":"enr_1","enrollment_token":"secret","node_id":"node-1","tenant_ids":["tenant-a"],"expires_at":"2026-07-13T12:15:00Z"}`))
		case "/v1/enroll":
			if request.Header.Get("Authorization") != "" {
				t.Fatal("enrollment leaked operator bearer")
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
			_, _ = w.Write([]byte(`{"command_id":"c1","tenant_id":"tenant-a","node_id":"node-1","command_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"terminal","terminal_status":"done","reported_status":"running","claim_generation":1,"result":{"runtime_ref":"runtime-1"}}`))
		case "/v1/tenants/tenant-a/nodes":
			_, _ = w.Write([]byte(`{"nodes":[{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":[],"state":"active","created_at":"2026-07-13T12:00:00Z"}]}`))
		case "/v1/tenants/tenant-a/nodes/node-1":
			_, _ = w.Write([]byte(`{"node_id":"node-1","tenant_ids":["tenant-a"],"capabilities":["signed-commands-v2"],"state":"active","created_at":"2026-07-13T12:00:00Z"}`))
		case "/v1/nodes/node-1":
			_, _ = w.Write([]byte(`{"node_id":"node-1","revoked_credentials":1}`))
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
	if credential, err := client.Enroll(ctx, "secret", "request-1"); err != nil || credential.Version != 2 {
		t.Fatalf("credential=%#v error=%v", credential, err)
	}
	if nodes, err := client.ListNodes(ctx, "tenant-a", "", 100); err != nil || len(nodes.Nodes) != 1 {
		t.Fatalf("nodes=%#v error=%v", nodes, err)
	}
	if node, err := client.GetNode(ctx, "tenant-a", "node-1"); err != nil || node.State != "active" {
		t.Fatalf("node=%#v error=%v", node, err)
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
		command.ReportedStatus != "running" || command.ClaimGeneration == nil || *command.ClaimGeneration != 1 ||
		command.Result == nil || command.Result.RuntimeRef != "runtime-1" {
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
	if !ok || api.Status != http.StatusConflict || !strings.Contains(api.Error(), "command_conflict") {
		t.Fatalf("error=%T %v", err, err)
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
	valid := []byte(`{"enrollment_id":"enr-1","enrollment_token":"secret","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"}`)
	if enrollment, err := DecodeEnrollmentCapability(valid); err != nil || enrollment.NodeID != "node-1" {
		t.Fatalf("valid enrollment=%+v error=%v", enrollment, err)
	}
	for _, raw := range [][]byte{
		[]byte(`{"enrollment_id":"enr-1","enrollment_token":"first","enrollment_token":"second","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"}`),
		[]byte(`{"enrollment_id":"enr-1","enrollment_token":"secret","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z","unexpected":true}`),
		[]byte(`{"enrollment_id":"enr-1","enrollment_token":"secret","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"} {}`),
		[]byte(`{"enrollment_id":"enr-1","node_id":"node-1","expires_at":"2026-07-13T12:00:00Z"}`),
	} {
		if _, err := DecodeEnrollmentCapability(raw); err == nil {
			t.Fatalf("ambiguous enrollment accepted: %s", raw)
		}
	}
}
