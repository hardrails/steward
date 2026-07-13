package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestControlCommandsCompleteEnrollmentAndQueueWorkflow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/enroll" && request.Header.Get("Authorization") != "Bearer admin-secret" {
			t.Fatalf("authorization=%q path=%q", request.Header.Get("Authorization"), request.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/tenants":
			_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","state":"active"}`))
		case "/v1/enrollments":
			_, _ = w.Write([]byte(`{"enrollment_id":"enr_1","enrollment_token":"enroll-secret","node_id":"node-1","tenant_ids":["tenant-a"],"expires_at":"2026-07-13T12:15:00Z"}`))
		case "/v1/enroll":
			if request.Header.Get("Authorization") != "" {
				t.Fatal("operator token sent to enrollment exchange")
			}
			_, _ = w.Write([]byte(`{"version":2,"scope":"node","node_id":"node-1","credential":"node-secret"}`))
		case "/v1/tenants/tenant-a/nodes/node-1/commands":
			_, _ = w.Write([]byte(`{"command_id":"command-1","delivery_id":"delivery-1","tenant_id":"tenant-a","node_id":"node-1","command_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"pending"}`))
		case "/v1/tenants/tenant-a/nodes/node-1/commands/command-1":
			_, _ = w.Write([]byte(`{"command_id":"command-1","tenant_id":"tenant-a","node_id":"node-1","command_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"terminal","reported_status":"running"}`))
		default:
			t.Fatalf("unexpected path %q", request.URL.Path)
		}
	}))
	defer server.Close()
	directory := t.TempDir()
	tokenPath := filepath.Join(directory, "admin.token")
	enrollmentPath := filepath.Join(directory, "enrollment.json")
	credentialPath := filepath.Join(directory, "credential.json")
	commandPath := filepath.Join(directory, "command.dsse.json")
	if err := os.WriteFile(tokenPath, []byte("admin-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(commandPath, []byte(`{"payloadType":"opaque"}`), 0o600); err != nil {
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
	enrollmentArguments := append([]string{"control", "enrollment", "create"}, common...)
	enrollmentArguments = append(enrollmentArguments, "-node-id", "node-1", "-tenant-ids", "tenant-a", "-out", enrollmentPath)
	if err := run(enrollmentArguments, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(output.String()) != "enr_1" {
		t.Fatalf("enrollment output=%q", output.String())
	}
	if info, err := os.Stat(enrollmentPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("enrollment mode=%v error=%v", info, err)
	}
	if err := run([]string{"control", "enrollment", "exchange", "-control-url", server.URL,
		"-enrollment", enrollmentPath, "-request-id", "request-1", "-credential-out", credentialPath},
		&output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	credential, err := os.ReadFile(credentialPath)
	if err != nil || !bytes.Contains(credential, []byte(`"credential":"node-secret"`)) {
		t.Fatalf("credential=%s error=%v", credential, err)
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
}
