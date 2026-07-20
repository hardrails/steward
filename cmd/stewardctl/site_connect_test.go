package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSiteConnectCreatesLeastPrivilegeRecoverableContext(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer site-admin-token" {
			t.Errorf("authorization = %q", request.Header.Get("Authorization"))
		}
		writer.Header().Set("Content-Type", "application/json")
		switch request.URL.Path {
		case "/v1/tenants":
			_, _ = writer.Write([]byte(`{"tenant_id":"tenant-a","state":"active"}`))
		case "/v1/operators":
			requests++
			var input struct {
				RequestID string `json:"request_id"`
				Role      string `json:"role"`
				TenantID  string `json:"tenant_id"`
			}
			if err := json.NewDecoder(request.Body).Decode(&input); err != nil || input.Role != "tenant_operator" ||
				input.TenantID != "tenant-a" || !strings.HasPrefix(input.RequestID, "site-node-operator-") {
				t.Errorf("operator input = %#v err=%v", input, err)
			}
			_, _ = writer.Write([]byte(`{"credential_id":"tenant-operator-a","role":"tenant_operator","tenant_id":"tenant-a","token":"tenant-operator-token","created_at":"2026-07-20T12:00:00Z"}`))
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)

	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(parent, "contexts.json"))
	siteDirectory := filepath.Join(parent, "site")
	if err := siteCommand([]string{"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	adminToken := filepath.Join(parent, "site-admin.token")
	if err := os.WriteFile(adminToken, []byte("site-admin-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	operatorToken := filepath.Join(parent, "tenant-operator.token")
	arguments := []string{
		"connect", siteDirectory, "-no-context", "-control-url", server.URL,
		"-token-file", adminToken, "-operator-token-out", operatorToken, "-node-id", "node-a",
	}
	var output bytes.Buffer
	if err := siteCommand(arguments, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "site-admin-token") || strings.Contains(output.String(), "tenant-operator-token") ||
		!strings.Contains(output.String(), `"context":"site-a-tenant-a"`) ||
		!strings.Contains(output.String(), `"credential_id":"tenant-operator-a"`) {
		t.Fatalf("site connect output = %s", output.String())
	}
	retained, err := os.ReadFile(operatorToken)
	if err != nil || string(retained) != "tenant-operator-token\n" {
		t.Fatalf("operator token = %q err=%v", retained, err)
	}
	var shown bytes.Buffer
	if err := contextCommand([]string{"show"}, &shown); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(shown.String(), "tenant-operator-token") || !strings.Contains(shown.String(), operatorToken) ||
		!strings.Contains(shown.String(), `"tenant_id":"tenant-a"`) || !strings.Contains(shown.String(), `"node_id":"node-a"`) {
		t.Fatalf("saved context = %s", shown.String())
	}
	if err := siteCommand(arguments, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if requests != 2 {
		t.Fatalf("operator issuance calls = %d, want exact idempotent retry", requests)
	}
	if err := siteCommand([]string{"verify", siteDirectory}, &bytes.Buffer{}); err != nil {
		t.Fatalf("site connect modified signed package: %v", err)
	}
}

func TestSiteConnectRejectsConflictingRetainedAuthority(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		if request.URL.Path == "/v1/tenants" {
			_, _ = writer.Write([]byte(`{"tenant_id":"tenant-a","state":"active"}`))
			return
		}
		_, _ = writer.Write([]byte(`{"credential_id":"tenant-operator-a","role":"tenant_operator","tenant_id":"tenant-a","token":"expected-token","created_at":"2026-07-20T12:00:00Z"}`))
	}))
	t.Cleanup(server.Close)
	parent := t.TempDir()
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(parent, "contexts.json"))
	siteDirectory := filepath.Join(parent, "site")
	if err := siteCommand([]string{"init", siteDirectory, "-site-id", "site-a", "-tenant-id", "tenant-a"}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	adminToken := filepath.Join(parent, "site-admin.token")
	operatorToken := filepath.Join(parent, "tenant-operator.token")
	if err := os.WriteFile(adminToken, []byte("site-admin-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(operatorToken, []byte("different-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err := siteCommand([]string{
		"connect", siteDirectory, "-no-context", "-control-url", server.URL,
		"-token-file", adminToken, "-operator-token-out", operatorToken,
	}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "different authority") {
		t.Fatalf("conflicting token error = %v", err)
	}
}

func TestSaveSiteOperatorContextPreservesDownstreamConnectionsAndRejectsAuthorityReplacement(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("STEWARD_CONTEXT_FILE", filepath.Join(directory, "contexts.json"))
	operatorToken := filepath.Join(directory, "operator.token")
	nodeToken := filepath.Join(directory, "node.token")
	for path, contents := range map[string]string{
		operatorToken: "operator-token\n",
		nodeToken:     "node-token\n",
	} {
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := contextCommand([]string{
		"set", "production", "-node-url", "http://127.0.0.1:8090", "-node-token-file", nodeToken,
	}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := saveSiteOperatorContext(
		"production", "http://127.0.0.1:8443", operatorToken, "", "tenant-a", "node-a",
	); err != nil {
		t.Fatal(err)
	}
	config, _, err := loadCLIContextConfig()
	if err != nil {
		t.Fatal(err)
	}
	retained, found := findCLIContext(config, "production")
	if !found || retained.NodeURL != "http://127.0.0.1:8090" || retained.NodeTokenFile != nodeToken ||
		retained.ControlURL != "http://127.0.0.1:8443" || retained.TokenFile != operatorToken ||
		retained.TenantID != "tenant-a" || retained.NodeID != "node-a" {
		t.Fatalf("retained context = %+v", retained)
	}
	if err := saveSiteOperatorContext(
		"production", "http://127.0.0.1:9443", operatorToken, "", "tenant-a", "node-a",
	); err == nil || !strings.Contains(err.Error(), "different Control URL") {
		t.Fatalf("authority replacement error = %v", err)
	}
}
