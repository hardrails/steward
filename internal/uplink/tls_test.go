package uplink

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestNewHTTPClientVerifiesServerCert is Feature 1's core promise: the client
// rejects a self-signed control plane by default, accepts it once its CA is
// configured, and (insecurely) accepts anything under SkipVerify.
func TestNewHTTPClientVerifiesServerCert(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// (1) No custom CA: the self-signed server cert is untrusted, so the default
	// client must reject the connection rather than silently trusting it.
	noCA, err := NewHTTPClient(TLSConfig{})
	if err != nil {
		t.Fatalf("NewHTTPClient(default): %v", err)
	}
	if _, err := noCA.Get(srv.URL); err == nil {
		t.Error("a client with no custom CA must reject a self-signed server certificate")
	}

	// (2) With the server's certificate configured as a trusted CA, verification
	// succeeds and the request goes through.
	caFile := writeCertPEM(t, srv.Certificate())
	withCA, err := NewHTTPClient(TLSConfig{CAFile: caFile})
	if err != nil {
		t.Fatalf("NewHTTPClient(CA): %v", err)
	}
	resp, err := withCA.Get(srv.URL)
	if err != nil {
		t.Fatalf("a client with the server's CA configured must accept it: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	// (3) SkipVerify accepts any certificate, insecurely — the diagnostic escape hatch.
	skip, err := NewHTTPClient(TLSConfig{SkipVerify: true})
	if err != nil {
		t.Fatalf("NewHTTPClient(skip): %v", err)
	}
	resp, err = skip.Get(srv.URL)
	if err != nil {
		t.Fatalf("a client with SkipVerify must accept an unverified certificate: %v", err)
	}
	_ = resp.Body.Close()
}

// TestNewHTTPClientFailsClosed pins the fail-closed TLS misconfiguration paths:
// each is a startup error naming the fix, never a silent fall back to defaults.
func TestNewHTTPClientFailsClosed(t *testing.T) {
	dir := t.TempDir()
	missingCA := filepath.Join(dir, "no-such-ca.pem")
	junk := filepath.Join(dir, "junk.pem")
	if err := os.WriteFile(junk, []byte("this is not a PEM certificate"), 0o600); err != nil {
		t.Fatalf("write junk fixture: %v", err)
	}
	certFile, keyFile := generateCertPair(t)

	cases := []struct {
		name string
		cfg  TLSConfig
		want string // a substring the fail-closed message must contain
	}{
		{"missing CA file", TLSConfig{CAFile: missingCA}, missingCA},
		{"CA file with no certificate", TLSConfig{CAFile: junk}, "no valid PEM certificate"},
		{"client cert without key", TLSConfig{ClientCertFile: certFile}, "no client key"},
		{"client key without cert", TLSConfig{ClientKeyFile: keyFile}, "no client certificate"},
		{"unloadable cert/key pair", TLSConfig{ClientCertFile: junk, ClientKeyFile: junk}, "client certificate/key pair"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHTTPClient(tc.cfg)
			if err == nil {
				t.Fatalf("NewHTTPClient(%s): got nil err, want fail-closed", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err, tc.want)
			}
		})
	}
}

// TestNewHTTPClientLoadsValidClientCert proves a valid mTLS cert/key pair loads
// and is actually wired onto the transport (not just accepted and dropped).
func TestNewHTTPClientLoadsValidClientCert(t *testing.T) {
	certFile, keyFile := generateCertPair(t)
	client, err := NewHTTPClient(TLSConfig{ClientCertFile: certFile, ClientKeyFile: keyFile})
	if err != nil {
		t.Fatalf("a valid client cert/key pair must load: %v", err)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("transport is %T, want *http.Transport", client.Transport)
	}
	if got := len(tr.TLSClientConfig.Certificates); got != 1 {
		t.Errorf("transport carries %d client certificates, want 1", got)
	}
}

// TestNewHTTPClientRejectsOverPermissiveClientKey pins that the mTLS private key
// gets the same owner-only permission gate the bearer credential does: a group- or
// other-accessible key is refused fail-closed (naming the chmod fix), so a local
// user cannot copy it and impersonate the node. A 0600 key still loads.
func TestNewHTTPClientRejectsOverPermissiveClientKey(t *testing.T) {
	certFile, keyFile := generateCertPair(t)
	// Loosen the key to group/other-readable — exactly the posture to refuse.
	if err := os.Chmod(keyFile, 0o644); err != nil {
		t.Fatalf("chmod key: %v", err)
	}

	_, err := NewHTTPClient(TLSConfig{ClientCertFile: certFile, ClientKeyFile: keyFile})
	if err == nil {
		t.Fatal("NewHTTPClient with a group-readable client key: got nil err, want fail-closed")
	}
	for _, want := range []string{keyFile, "permission", "chmod 600"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// Tightening the key back to owner-only lets it load.
	if err := os.Chmod(keyFile, 0o600); err != nil {
		t.Fatalf("chmod key: %v", err)
	}
	if _, err := NewHTTPClient(TLSConfig{ClientCertFile: certFile, ClientKeyFile: keyFile}); err != nil {
		t.Fatalf("NewHTTPClient with a 0600 client key: unexpected err %v", err)
	}
}

// TestNewHTTPClientMutualTLS drives an end-to-end mTLS handshake: a server that
// requires and verifies a client certificate accepts the client only when the
// client presents its cert, proving the -uplink-tls-client-cert/-key path is
// wired through to the actual handshake, not merely parsed.
func TestNewHTTPClientMutualTLS(t *testing.T) {
	clientCertFile, clientKeyFile := generateCertPair(t)
	clientPEM, err := os.ReadFile(clientCertFile)
	if err != nil {
		t.Fatalf("read client cert: %v", err)
	}
	clientPool := x509.NewCertPool()
	if !clientPool.AppendCertsFromPEM(clientPEM) {
		t.Fatal("build client trust pool")
	}

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
		ClientCAs:  clientPool,
	}
	srv.StartTLS()
	defer srv.Close()

	serverCAFile := writeCertPEM(t, srv.Certificate())

	// With the client certificate, the mutual handshake completes.
	withCert, err := NewHTTPClient(TLSConfig{
		CAFile: serverCAFile, ClientCertFile: clientCertFile, ClientKeyFile: clientKeyFile,
	})
	if err != nil {
		t.Fatalf("NewHTTPClient(mTLS): %v", err)
	}
	resp, err := withCert.Get(srv.URL)
	if err != nil {
		t.Fatalf("mTLS with a client certificate must succeed: %v", err)
	}
	_ = resp.Body.Close()

	// Without a client certificate, the server rejects the handshake.
	noCert, err := NewHTTPClient(TLSConfig{CAFile: serverCAFile})
	if err != nil {
		t.Fatalf("NewHTTPClient(no client cert): %v", err)
	}
	if _, err := noCert.Get(srv.URL); err == nil {
		t.Error("a server requiring client certs must reject a client that presents none")
	}
}

// writeCertPEM PEM-encodes cert to a 0600 temp file and returns its path, for use
// as a NewHTTPClient CA bundle (a self-signed leaf is its own CA).
func writeCertPEM(t *testing.T, cert *x509.Certificate) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca.pem")
	block := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, block, 0o600); err != nil {
		t.Fatalf("write cert PEM: %v", err)
	}
	return path
}

// generateCertPair writes a self-signed ECDSA certificate and its PKCS#8 key to
// two 0600 temp files and returns their paths. The certificate is a CA (so it can
// anchor its own verification in a trust pool) valid for loopback, usable as both
// a server and a client certificate in these tests — no external PKI needed.
func generateCertPair(t *testing.T) (certFile, keyFile string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "steward-uplink-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	dir := t.TempDir()
	certFile = filepath.Join(dir, "cert.pem")
	keyFile = filepath.Join(dir, "key.pem")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}
