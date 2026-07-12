package gateway

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func TestControlClientCoversBoundedGrantLifecycle(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "gc-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	socket := filepath.Join(directory, "control.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	grant := Grant{GrantID: GrantID("tenant", "agent", 1), TenantID: "tenant", InstanceID: "agent", Generation: 1, RouteID: "route", ModelAlias: "model"}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/grants":
			var received Grant
			_ = json.NewDecoder(r.Body).Decode(&received)
			if !grantsEqual(received, grant) {
				t.Errorf("grant=%#v", received)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/grants/"+grant.GrantID:
			_ = json.NewEncoder(w).Encode(grant)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/grants/"+grant.GrantID+"/egress":
			_ = json.NewEncoder(w).Encode(EgressStats{Allowed: 3})
		case r.Method == http.MethodPost && (r.URL.Path == "/v1/grants/"+grant.GrantID+"/activate" || r.URL.Path == "/v1/grants/"+grant.GrantID+"/deactivate"):
			_ = json.NewEncoder(w).Encode(map[string]any{"active": true})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/grants/"+grant.GrantID:
			w.WriteHeader(http.StatusNoContent)
		default:
			writeGatewayError(w, http.StatusBadRequest, "unexpected", "unexpected request")
		}
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	client, err := NewControlClient(socket)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := client.Register(ctx, grant); err != nil {
		t.Fatal(err)
	}
	got, err := client.Inspect(ctx, grant.GrantID)
	if err != nil || !grantsEqual(got, grant) {
		t.Fatalf("inspect=%#v err=%v", got, err)
	}
	if err := client.Activate(ctx, grant.GrantID); err != nil {
		t.Fatal(err)
	}
	if err := client.Deactivate(ctx, grant.GrantID); err != nil {
		t.Fatal(err)
	}
	stats, err := client.EgressStats(ctx, grant.GrantID)
	if err != nil || stats.Allowed != 3 {
		t.Fatalf("stats=%#v err=%v", stats, err)
	}
	if err := client.Unregister(ctx, grant.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := client.Inspect(ctx, "bad"); err == nil {
		t.Fatal("invalid grant accepted")
	}
	if _, err := NewControlClient("relative.sock"); err == nil {
		t.Fatal("relative control socket accepted")
	}
}

func TestControlClientReportsStructuredAndOversizedErrors(t *testing.T) {
	directory, _ := os.MkdirTemp("/tmp", "gc-")
	defer os.RemoveAll(directory)
	socket := filepath.Join(directory, "c.sock")
	listener, _ := net.Listen("unix", socket)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeGatewayError(w, http.StatusConflict, "conflict", "denied")
	})}
	go func() { _ = server.Serve(listener) }()
	defer server.Close()
	client, _ := NewControlClient(socket)
	err := client.Register(context.Background(), Grant{})
	if err == nil || err.Error() != "gateway conflict: denied" {
		t.Fatalf("error=%v", err)
	}
}
