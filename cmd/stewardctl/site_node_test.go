package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
)

func TestSiteNodePrepareVerifyAndResumeActivation(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	previousNow := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousNow })

	secret := base64.RawURLEncoding.EncodeToString(make([]byte, sha256.Size))
	nodeCredential := "steward_node_v1_node-cred-test_" + secret
	var mu sync.Mutex
	exchanges := 0
	var firstProof controlprotocol.ExecutorEvidenceIdentityProofV1
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/tenants":
			if request.Header.Get("Authorization") != "Bearer operator-token" {
				t.Errorf("tenant bearer = %q", request.Header.Get("Authorization"))
			}
			_, _ = writer.Write([]byte(`{"tenant_id":"tenant-a","state":"active"}`))
		case "/v1/enrollments":
			if request.Header.Get("Authorization") != "Bearer operator-token" {
				t.Errorf("enrollment bearer = %q", request.Header.Get("Authorization"))
			}
			var input struct {
				RequestID string   `json:"request_id"`
				NodeID    string   `json:"node_id"`
				TenantIDs []string `json:"tenant_ids"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.NodeID != "node-a" ||
				len(input.TenantIDs) != 1 || input.TenantIDs[0] != "tenant-a" || !strings.HasPrefix(input.RequestID, "site-node-enroll-") {
				t.Errorf("enrollment input = %#v err=%v", input, err)
			}
			_, _ = writer.Write([]byte(`{"controller_instance_id":"control-a","enrollment_id":"enrollment-a","enrollment_token":"one-time-secret","node_id":"node-a","tenant_ids":["tenant-a"],"expires_at":"2026-07-20T12:30:00Z"}`))
		case "/v1/enroll":
			if request.Header.Get("Authorization") != "" {
				t.Errorf("exchange leaked bearer = %q", request.Header.Get("Authorization"))
			}
			var input struct {
				EnrollmentToken       string                                          `json:"enrollment_token"`
				RequestID             string                                          `json:"request_id"`
				EvidenceIdentityProof controlprotocol.ExecutorEvidenceIdentityProofV1 `json:"evidence_identity_proof"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.EnrollmentToken != "one-time-secret" ||
				!strings.HasPrefix(input.RequestID, "site-node-exchange-") {
				t.Errorf("exchange input = %#v err=%v", input, err)
			}
			if err := input.EvidenceIdentityProof.Validate(); err != nil {
				t.Errorf("exchange proof: %v", err)
			}
			mu.Lock()
			exchanges++
			attempt := exchanges
			if attempt == 1 {
				firstProof = input.EvidenceIdentityProof
			} else if input.EvidenceIdentityProof != firstProof {
				t.Errorf("activation retry changed the receipt proof")
			}
			mu.Unlock()
			if attempt == 1 {
				writer.WriteHeader(http.StatusServiceUnavailable)
				_, _ = writer.Write([]byte(`{"error":"temporary","message":"retry"}`))
				return
			}
			_, _ = writer.Write([]byte(`{"version":2,"scope":"node","node_id":"node-a","credential":"` + nodeCredential + `"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	parent := t.TempDir()
	siteDirectory := filepath.Join(parent, "site")
	if err := siteCommand([]string{"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(parent, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	packageDirectory := filepath.Join(parent, "node-package")
	var prepared bytes.Buffer
	if err := siteCommand([]string{
		"node", "prepare", siteDirectory, "node-a", "-no-context",
		"-control-url", server.URL, "-token-file", tokenPath, "-out", packageDirectory,
	}, &prepared); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(prepared.String(), "one-time-secret") || !strings.Contains(prepared.String(), `"phase":"prepared"`) {
		t.Fatalf("prepare output = %s", prepared.String())
	}
	if err := siteCommand([]string{"node", "verify", packageDirectory}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	activationDirectory := filepath.Join(parent, "activation")
	arguments := []string{"node", "activate", packageDirectory, "-out", activationDirectory}
	if err := siteCommand(arguments, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "rerun the same command") {
		t.Fatalf("first activation error = %v", err)
	}
	privateBefore, err := os.ReadFile(filepath.Join(activationDirectory, "private", "node-receipts.private.pem"))
	if err != nil {
		t.Fatal(err)
	}
	var activated bytes.Buffer
	if err := siteCommand(arguments, &activated); err != nil {
		t.Fatal(err)
	}
	privateAfter, err := os.ReadFile(filepath.Join(activationDirectory, "private", "node-receipts.private.pem"))
	if err != nil || !bytes.Equal(privateBefore, privateAfter) {
		t.Fatalf("activation retry changed receipt key: err=%v", err)
	}
	if strings.Contains(activated.String(), nodeCredential) || !strings.Contains(activated.String(), `"phase":"ready"`) ||
		!strings.Contains(activated.String(), `"credential_id":"node-cred-test"`) {
		t.Fatalf("activation output = %s", activated.String())
	}
	if err := siteCommand(arguments, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Hour)
	if err := siteCommand(arguments, &bytes.Buffer{}); err != nil {
		t.Fatalf("recover completed activation after enrollment expiry: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if exchanges != 2 {
		t.Fatalf("exchange requests = %d, want 2", exchanges)
	}
}

func TestSiteNodeVerifyRejectsTamperedTrustAndUnexpectedFiles(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	previousNow := timeNow
	timeNow = func() time.Time { return now }
	t.Cleanup(func() { timeNow = previousNow })
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/v1/tenants" {
			_, _ = writer.Write([]byte(`{"tenant_id":"tenant-a","state":"active"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"controller_instance_id":"control-a","enrollment_id":"enrollment-a","enrollment_token":"secret","node_id":"node-a","tenant_ids":["tenant-a"],"expires_at":"2026-07-20T12:30:00Z"}`))
	}))
	t.Cleanup(server.Close)
	parent := t.TempDir()
	siteDirectory := filepath.Join(parent, "site")
	if err := siteCommand([]string{"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(parent, "operator.token")
	if err := os.WriteFile(tokenPath, []byte("operator-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	prepare := func(name string) string {
		t.Helper()
		output := filepath.Join(parent, name)
		if err := siteCommand([]string{
			"node", "prepare", siteDirectory, "node-a", "-no-context", "-request-id", name,
			"-control-url", server.URL, "-token-file", tokenPath, "-out", output,
		}, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
		return output
	}
	tampered := prepare("tampered")
	if err := os.WriteFile(filepath.Join(tampered, "public", "site-root.public"), []byte("replaced\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := siteCommand([]string{"node", "verify", tampered}, &bytes.Buffer{}); err == nil {
		t.Fatal("tampered node trust was accepted")
	}
	extra := prepare("extra")
	if err := os.WriteFile(filepath.Join(extra, "private", "extra"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := siteCommand([]string{"node", "verify", extra}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unexpected path") {
		t.Fatalf("unexpected node package file error = %v", err)
	}
}
