package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTestControlClient(t *testing.T, handler http.Handler) *ControlClient {
	t.Helper()
	directory, err := os.MkdirTemp("/tmp", "gateway-control-client-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	listener, err := net.Listen("unix", filepath.Join(directory, "control.sock"))
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	client, err := NewControlClient(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return client
}

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
			_ = json.NewEncoder(w).Encode(GrantInspection{Grant: grant, RoutePolicyDigest: "sha256:test"})
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
	inspection, err := client.InspectWithPolicy(ctx, grant.GrantID)
	if err != nil || !grantsEqual(inspection.Grant, grant) || inspection.RoutePolicyDigest != "sha256:test" {
		t.Fatalf("policy inspection=%#v err=%v", inspection, err)
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

func TestControlClientReportsTypedErrorsWithoutChangingErrorText(t *testing.T) {
	client := newTestControlClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "7")
		writeGatewayError(w, http.StatusTooManyRequests, "task_observation_throttled", "task observation is limited by host policy")
	}))
	err := client.Register(context.Background(), Grant{})
	var apiError *ControlAPIError
	if !errors.As(err, &apiError) || apiError.Status != http.StatusTooManyRequests ||
		apiError.Code != "task_observation_throttled" ||
		apiError.Message != "task observation is limited by host policy" ||
		apiError.RetryAfter != 7*time.Second ||
		err.Error() != "gateway task_observation_throttled: task observation is limited by host policy" {
		t.Fatalf("error=%v typed=%#v", err, apiError)
	}

	withoutRetry := newTestControlClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeGatewayError(w, http.StatusConflict, "conflict", "denied")
	}))
	err = withoutRetry.Register(context.Background(), Grant{})
	apiError = nil
	if !errors.As(err, &apiError) || apiError.Status != http.StatusConflict ||
		apiError.Code != "conflict" || apiError.Message != "denied" || apiError.RetryAfter != 0 ||
		err.Error() != "gateway conflict: denied" {
		t.Fatalf("error=%v typed=%#v", err, apiError)
	}
}

func TestControlClientRejectsMalformedRetryAfterAndUnboundedErrors(t *testing.T) {
	validError, err := json.Marshal(map[string]string{"error": "denied", "message": "no"})
	if err != nil {
		t.Fatal(err)
	}
	overlongCode, _ := json.Marshal(map[string]string{
		"error": strings.Repeat("a", maxControlErrorCodeBytes+1), "message": "no",
	})
	overlongMessage, _ := json.Marshal(map[string]string{
		"error": "denied", "message": strings.Repeat("m", maxControlErrorMessageBytes+1),
	})
	for _, test := range []struct {
		name       string
		body       []byte
		retryAfter []string
		want       string
	}{
		{name: "zero retry", body: validError, retryAfter: []string{"0"}, want: "invalid Retry-After"},
		{name: "negative retry", body: validError, retryAfter: []string{"-1"}, want: "invalid Retry-After"},
		{name: "padded retry", body: validError, retryAfter: []string{"01"}, want: "invalid Retry-After"},
		{name: "signed retry", body: validError, retryAfter: []string{"+1"}, want: "invalid Retry-After"},
		{name: "HTTP date retry", body: validError, retryAfter: []string{"Thu, 16 Jul 2026 12:00:00 GMT"}, want: "invalid Retry-After"},
		{name: "retry above bound", body: validError, retryAfter: []string{"3601"}, want: "invalid Retry-After"},
		{name: "multiple retry", body: validError, retryAfter: []string{"1", "2"}, want: "invalid Retry-After"},
		{name: "overlong code", body: overlongCode, want: "gateway returned HTTP 400"},
		{name: "overlong message", body: overlongMessage, want: "gateway returned HTTP 400"},
		{name: "control message", body: []byte(`{"error":"denied","message":"bad\u001b"}`), want: "gateway returned HTTP 400"},
		{name: "duplicate code", body: []byte(`{"error":"denied","error":"other","message":"no"}`), want: "gateway returned HTTP 400"},
		{name: "trailing JSON", body: append(append([]byte(nil), validError...), []byte(`{}`)...), want: "gateway returned HTTP 400"},
		{name: "oversized response", body: []byte(strings.Repeat("x", maxControlResponse+1)), want: "gateway control response exceeds limit"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := newTestControlClient(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				for _, value := range test.retryAfter {
					w.Header().Add("Retry-After", value)
				}
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write(test.body)
			}))
			err := client.Register(context.Background(), Grant{})
			var apiError *ControlAPIError
			if err == nil || errors.As(err, &apiError) || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("error=%v typed=%#v want substring=%q", err, apiError, test.want)
			}
		})
	}
}
