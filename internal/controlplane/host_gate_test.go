package controlplane

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHostGateBindsLoopbackToActualLiteralListenerAuthority(t *testing.T) {
	called := 0
	gate, err := NewHostGate("127.0.0.1:39147", nil, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		called++
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}

	assertHostGateStatus(t, gate, "127.0.0.1:39147", http.StatusNoContent)
	for _, authority := range []string{
		"localhost:39147",
		"127.0.0.1:39148",
		"127.0.0.1",
		"127.0.0.1:039147",
	} {
		assertHostGateRejected(t, gate, authority)
	}
	if called != 1 {
		t.Fatalf("protected handler calls=%d want 1", called)
	}
}

func TestHostGateUsesOnlyExactTLSCertificateSANsAtListenerPort(t *testing.T) {
	config := hostGateTLSConfig(t, []string{"control.internal", "ops.example", "*.wild.example"}, []net.IP{net.ParseIP("192.0.2.10")})
	gate, err := NewHostGate("0.0.0.0:8443", config, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}

	for _, authority := range []string{"control.internal:8443", "CONTROL.INTERNAL:8443", "ops.example:8443", "192.0.2.10:8443"} {
		assertHostGateStatus(t, gate, authority, http.StatusNoContent)
	}
	for _, authority := range []string{
		"unrelated.internal:8443",
		"tenant.wild.example:8443",
		"control.internal:8444",
		"control.internal",
		"192.0.2.11:8443",
	} {
		assertHostGateRejected(t, gate, authority)
	}
}

func TestHostGateAllowsTLSDefaultPortOmissionOnlyFor443(t *testing.T) {
	config := hostGateTLSConfig(t, []string{"control.internal"}, nil)
	gate, err := NewHostGate("0.0.0.0:443", config, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	assertHostGateStatus(t, gate, "control.internal", http.StatusNoContent)
	assertHostGateStatus(t, gate, "control.internal:443", http.StatusNoContent)
	assertHostGateRejected(t, gate, "control.internal:8443")
}

func TestHostGateRejectsMalformedAndAmbiguousAuthoritiesWithoutCORS(t *testing.T) {
	config := hostGateTLSConfig(t, []string{"control.internal"}, nil)
	innerCalled := false
	gate, err := NewHostGate("0.0.0.0:8443", config, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		innerCalled = true
		writer.Header().Set("Access-Control-Allow-Origin", "*")
		writer.WriteHeader(http.StatusNoContent)
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, authority := range []string{
		"",
		" control.internal:8443",
		"control.internal:8443 ",
		"control.internal:08443",
		"control.internal:",
		"user@control.internal:8443",
		"control.internal:8443,evil.internal:8443",
		"control.internal.:8443",
		"control_internal:8443",
		"[::1",
		"::1:8443",
		"control.internal/attack:8443",
	} {
		t.Run(strings.ReplaceAll(authority, "/", "_"), func(t *testing.T) {
			assertHostGateRejected(t, gate, authority)
		})
	}
	if innerCalled {
		t.Fatal("malformed Host reached the protected handler")
	}
}

func TestHostGateRejectsUnsafeListenerAndCertificatePolicies(t *testing.T) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	if _, err := NewHostGate("0.0.0.0:8443", nil, next); err == nil {
		t.Fatal("non-loopback plaintext listener received a Host policy")
	}
	if _, err := NewHostGate("localhost:8443", nil, next); err == nil {
		t.Fatal("DNS loopback alias received a plaintext Host policy")
	}
	if _, err := NewHostGate("127.0.0.1:0", nil, next); err == nil {
		t.Fatal("unbound listener port received a Host policy")
	}
	if _, err := NewHostGate("127.0.0.1:8443", nil, nil); err == nil {
		t.Fatal("nil protected handler received a Host policy")
	}
	if _, err := NewHostGate("0.0.0.0:8443", hostGateTLSConfig(t, []string{"*.example"}, nil), next); err == nil || !strings.Contains(err.Error(), "only wildcard") {
		t.Fatalf("wildcard-only certificate Host policy error=%v", err)
	}
	if _, err := NewHostGate("0.0.0.0:8443", hostGateTLSConfig(t, nil, nil), next); err == nil || !strings.Contains(err.Error(), "at least one exact") {
		t.Fatalf("SAN-less certificate Host policy error=%v", err)
	}
	if _, err := NewHostGate("0.0.0.0:8443", hostGateTLSConfig(t, []string{"bad_name.example"}, nil), next); err == nil || !strings.Contains(err.Error(), "invalid exact DNS SAN") {
		t.Fatalf("invalid DNS SAN Host policy error=%v", err)
	}
	if _, err := NewHostGate("0.0.0.0:8443", hostGateTLSConfig(t, []string{"192.0.2.10"}, nil), next); err == nil || !strings.Contains(err.Error(), "IP SAN") {
		t.Fatalf("IP encoded as DNS SAN Host policy error=%v", err)
	}
}

func assertHostGateStatus(t *testing.T, handler http.Handler, authority string, expected int) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://placeholder.invalid/v1/healthz", nil)
	request.Host = authority
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != expected {
		t.Fatalf("Host %q status=%d want %d body=%q", authority, response.Code, expected, response.Body.String())
	}
}

func assertHostGateRejected(t *testing.T, handler http.Handler, authority string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "https://placeholder.invalid/v1/healthz", nil)
	request.Host = authority
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("Host %q status=%d want %d body=%q", authority, response.Code, http.StatusBadRequest, response.Body.String())
	}
	var body struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil || body.Error != "invalid_request" || body.Message == "" {
		t.Fatalf("Host %q error response=%q decode=%v", authority, response.Body.String(), err)
	}
	if response.Header().Get("Content-Type") != "application/json" ||
		response.Header().Get("Cache-Control") != "no-store" ||
		response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("Host %q headers=%v", authority, response.Header())
	}
	if response.Header().Get("Access-Control-Allow-Origin") != "" ||
		response.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Fatalf("Host %q unexpectedly enabled CORS: %v", authority, response.Header())
	}
}

func hostGateTLSConfig(t *testing.T, dnsNames []string, ipAddresses []net.IP) *tls.Config {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ignored-common-name.invalid"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     append([]string(nil), dnsNames...),
		IPAddresses:  append([]net.IP(nil), ipAddresses...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{der},
			PrivateKey:  private,
		}},
	}
}
