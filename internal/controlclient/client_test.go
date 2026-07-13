package controlclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
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
			_, _ = w.Write([]byte(`{"tenant_id":"tenant-a","state":"active"}`))
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
			_, _ = w.Write([]byte(`{"command_id":"c1","tenant_id":"tenant-a","node_id":"node-1","command_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","state":"terminal","reported_status":"running"}`))
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
	if enrollment, err := client.CreateEnrollment(ctx, "node-1", []string{"tenant-a"}, 15*time.Minute); err != nil || enrollment.EnrollmentToken != "secret" {
		t.Fatalf("enrollment=%#v error=%v", enrollment, err)
	}
	if credential, err := client.Enroll(ctx, "secret", "request-1"); err != nil || credential.Version != 2 {
		t.Fatalf("credential=%#v error=%v", credential, err)
	}
	if command, err := client.SubmitCommand(ctx, "tenant-a", "node-1", commandRaw); err != nil || command.State != "pending" {
		t.Fatalf("command=%#v error=%v", command, err)
	}
	if command, err := client.GetCommand(ctx, "tenant-a", "node-1", "c1"); err != nil || command.ReportedStatus != "running" {
		t.Fatalf("command=%#v error=%v", command, err)
	}
}

func TestClientRejectsUnsafeTransportAndErrors(t *testing.T) {
	for _, endpoint := range []string{"http://control.example:8080", "https://control.example", "https://user@control.example:443", "https://control.example:443/path"} {
		if client, err := New(endpoint, "token", nil); err == nil || client != nil {
			t.Fatalf("unsafe endpoint %q accepted", endpoint)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
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
