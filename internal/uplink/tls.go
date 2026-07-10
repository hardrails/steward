package uplink

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// TLSConfig carries the operator-configured TLS settings for the outbound uplink
// HTTP client — the -uplink-tls-* flags, their STEWARD_UPLINK_TLS_* env vars, and
// the uplink_tls_* config-file keys. Every field is optional; the zero value is
// the default posture: verify the control plane's server certificate against the
// host's system root CAs and present no client certificate. It is built with only
// crypto/tls and crypto/x509 from the standard library, so it adds no dependency.
type TLSConfig struct {
	// CAFile is a PEM bundle of certificate authorities used to verify the
	// control plane's server certificate. Empty means the host's system root CA
	// set. A custom CA lets a node trust a private or internal control-plane CA
	// without adding it to the system trust store.
	CAFile string
	// ClientCertFile and ClientKeyFile are the PEM certificate and private key a
	// node presents for mutual TLS (mTLS). Both must be set together or both left
	// empty; one without the other is a fail-closed misconfiguration.
	ClientCertFile string
	ClientKeyFile  string
	// SkipVerify disables verification of the control plane's certificate
	// entirely. It is INSECURE — it defeats the authentication half of TLS and
	// exposes the outbound channel to a man-in-the-middle — and exists only for a
	// deliberate, temporary diagnostic. It defaults false; cmd/steward logs a loud
	// warning whenever it is set true.
	SkipVerify bool
}

// NewHTTPClient builds the outbound uplink HTTP client with a transport whose
// crypto/tls settings come from cfg. It clones http.DefaultTransport (preserving
// its connection-pool, proxy, and HTTP/2 defaults) and overrides only the
// TLSClientConfig, then applies the same httpTimeout the default uplink client
// uses so a blackholed control plane cannot wedge a request.
//
// It fails closed: an unreadable CA file, a CA file with no usable certificate, a
// client certificate set without its key (or the reverse), or a cert/key pair
// that does not load is an error naming the path and the fix — the same discipline
// LoadCredential applies. Because cmd/steward builds this in prepareRuntime, a TLS
// misconfiguration is caught at startup and by -check-config, never a silent fall
// back to system defaults that would then fail every poll (or, with SkipVerify,
// connect insecurely) forever.
func NewHTTPClient(cfg TLSConfig) (*http.Client, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		// InsecureSkipVerify is opt-in, off by default, and cmd/steward logs a loud
		// warning whenever it is set; see TLSConfig.SkipVerify.
		InsecureSkipVerify: cfg.SkipVerify,
	}

	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read uplink TLS CA file %q: %w (fix its path or permissions, or drop -uplink-tls-ca-file to verify against the system root CAs)", cfg.CAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("uplink TLS CA file %q contains no valid PEM certificate; it must be a PEM-encoded CA bundle (re-export the control plane's CA certificate to that path)", cfg.CAFile)
		}
		tlsConfig.RootCAs = pool
	}

	switch {
	case cfg.ClientCertFile != "" && cfg.ClientKeyFile == "":
		return nil, fmt.Errorf("uplink TLS client certificate %q is set but no client key is; set -uplink-tls-client-key (or STEWARD_UPLINK_TLS_CLIENT_KEY) too, or drop both to disable mTLS", cfg.ClientCertFile)
	case cfg.ClientKeyFile != "" && cfg.ClientCertFile == "":
		return nil, fmt.Errorf("uplink TLS client key %q is set but no client certificate is; set -uplink-tls-client-cert (or STEWARD_UPLINK_TLS_CLIENT_CERT) too, or drop both to disable mTLS", cfg.ClientKeyFile)
	case cfg.ClientCertFile != "" && cfg.ClientKeyFile != "":
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load uplink TLS client certificate/key pair (cert %q, key %q): %w (check both are PEM-encoded and match; re-issue the node's client certificate if unsure)", cfg.ClientCertFile, cfg.ClientKeyFile, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// http.DefaultTransport is always *http.Transport in the standard library.
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	return &http.Client{Timeout: httpTimeout, Transport: transport}, nil
}
