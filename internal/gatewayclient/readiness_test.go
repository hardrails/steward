package gatewayclient

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHermesReadyUsesOnlyFixedBoundedHealthRequest(t *testing.T) {
	var observedPath string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		observedPath = r.URL.Path
		if r.Method != http.MethodGet || r.Header.Get("Authorization") != "Bearer gateway-token" {
			t.Fatalf("request method=%s authorization=%q", r.Method, r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()

	client, err := New(server.URL, "gateway-token")
	if err != nil {
		t.Fatal(err)
	}
	servicePath := "/v1/services/grant-" + strings.Repeat("a", 64) + "/"
	if err := client.HermesReady(context.Background(), servicePath); err != nil {
		t.Fatal(err)
	}
	if observedPath != strings.TrimSuffix(servicePath, "/")+"/health" {
		t.Fatalf("readiness path=%q", observedPath)
	}
	if err := client.HermesReady(context.Background(), "/v1/services/other/"); err == nil {
		t.Fatal("invalid service path was accepted")
	}
}

func TestHermesReadyRejectsNonReadyAndOversizedResponses(t *testing.T) {
	status := http.StatusBadGateway
	body := `{"error":"upstream_unavailable"}`
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server.Listener = listener
	server.Start()
	defer server.Close()
	client, err := New(server.URL, "gateway-token")
	if err != nil {
		t.Fatal(err)
	}
	servicePath := "/v1/services/grant-" + strings.Repeat("b", 64) + "/"
	if err := client.HermesReady(context.Background(), servicePath); err == nil ||
		!strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("non-ready response = %v", err)
	}
	status = http.StatusOK
	body = strings.Repeat("x", maxServiceReadinessBytes+1)
	if err := client.HermesReady(context.Background(), servicePath); err == nil ||
		!strings.Contains(err.Error(), "16 KiB") {
		t.Fatalf("oversized response = %v", err)
	}
}
