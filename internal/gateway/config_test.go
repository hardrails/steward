package gateway

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigValidatesRoutesAndSecretPermissions(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sg-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	token := filepath.Join(directory, "service-token")
	credential := filepath.Join(directory, "route-token")
	if err := os.WriteFile(token, []byte("service-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(credential, []byte("route-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"),
		ServiceAddress: "127.0.0.1:8092", ServiceTokenFile: token,
		StateFile: filepath.Join(directory, "state.json"), GrantRoot: filepath.Join(directory, "grants"),
		// Configuration deliberately rejects root group IDs. Use a stable
		// non-root fixture so the test also runs inside a root build container.
		ExecutorGID: 1, RelayGID: 1,
		Routes: []Route{{ID: "local", BaseURL: "http://127.0.0.1:11434/v1", CredentialFile: credential, MaxConcurrent: 2}},
	}
	raw, _ := json.Marshal(config)
	path := filepath.Join(directory, "gateway.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, routes, _, serviceToken, err := LoadConfig(path)
	if err != nil || loaded.Version != 1 || serviceToken != "service-secret" || routes["local"].credential != "route-secret" {
		t.Fatalf("loaded=%#v routes=%#v token=%q err=%v", loaded, routes, serviceToken, err)
	}
	if err := os.Chmod(credential, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := LoadConfig(path); err == nil {
		t.Fatal("permissive route credential accepted")
	}
}

func TestConfigRejectsUnsafeOriginsAndAddresses(t *testing.T) {
	base := Config{
		Version: 1, ControlSocket: "/tmp/control.sock", ServiceAddress: "127.0.0.1:8092",
		ServiceTokenFile: "/tmp/token", StateFile: "/tmp/state", GrantRoot: "/tmp/grants",
		ExecutorGID: 1, RelayGID: 1, Routes: []Route{{ID: "route", BaseURL: "http://127.0.0.1:1/v1", MaxConcurrent: 1}},
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.ServiceAddress = "0.0.0.0:8092" },
		func(config *Config) { config.ServiceAddress = "127.0.0.1:0" },
		func(config *Config) { config.ServiceAddress = "127.0.0.1:65536" },
		func(config *Config) { config.ServiceAddress = "127.0.0.1:not-a-port" },
		func(config *Config) { config.Routes[0].BaseURL = "file:///etc/passwd" },
		func(config *Config) { config.Routes[0].BaseURL = "http://user@example.test" },
		func(config *Config) { config.Routes[0].BaseURL = "http://example.test/path" },
		func(config *Config) { config.Routes[0].MaxConcurrent = 0 },
		func(config *Config) { config.GrantRoot = "/" + strings.Repeat("long/", 30) + "grants" },
	} {
		config := base
		config.Routes = append([]Route(nil), base.Routes...)
		mutate(&config)
		if _, err := config.validateAndLoadRoutes(); err == nil {
			t.Fatalf("invalid config accepted: %#v", config)
		}
	}
}

func TestConfigValidatesBoundedEgressRoutes(t *testing.T) {
	base := Config{EgressAuditFile: "/var/lib/steward-gateway/egress.jsonl", EgressRoutes: []EgressRoute{{
		ID: "package-mirrors", MaxConcurrent: 8, MaxRequestBytes: 4 << 20, MaxResponseBytes: 256 << 20, MaxTunnelSeconds: 300,
		Destinations: []EgressDestination{{Host: "*.example.com", Ports: []int{443}}, {Host: "10.1.2.3", Ports: []int{8080}, AllowedCIDRs: []string{"10.1.0.0/16"}}},
	}}}
	loaded, err := base.validateEgressRoutes()
	if err != nil || len(loaded) != 1 || len(loaded["package-mirrors"].destinations) != 2 {
		t.Fatalf("loaded=%#v err=%v", loaded, err)
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.EgressAuditFile = "relative" },
		func(config *Config) { config.EgressRoutes[0].ID = "bad route" },
		func(config *Config) { config.EgressRoutes[0].MaxConcurrent = 0 },
		func(config *Config) { config.EgressRoutes[0].MaxRequestBytes = 0 },
		func(config *Config) { config.EgressRoutes[0].MaxResponseBytes = 1<<30 + 1 },
		func(config *Config) { config.EgressRoutes[0].MaxTunnelSeconds = 0 },
		func(config *Config) { config.EgressRoutes[0].Destinations = nil },
		func(config *Config) { config.EgressRoutes[0].Destinations[0].Host = "*example.com" },
		func(config *Config) { config.EgressRoutes[0].Destinations[0].Ports = []int{0} },
		func(config *Config) { config.EgressRoutes[0].Destinations[0].AllowedCIDRs = []string{"10.0.0.1/8"} },
		func(config *Config) { config.EgressRoutes = append(config.EgressRoutes, config.EgressRoutes[0]) },
	} {
		config := base
		config.EgressRoutes = append([]EgressRoute(nil), base.EgressRoutes...)
		config.EgressRoutes[0].Destinations = append([]EgressDestination(nil), base.EgressRoutes[0].Destinations...)
		mutate(&config)
		if _, err := config.validateEgressRoutes(); err == nil {
			t.Fatalf("invalid egress config accepted: %#v", config)
		}
	}
}

func TestConfigLoadsFiniteConnectorsAndOwnerOnlyCredentials(t *testing.T) {
	directory := t.TempDir()
	credential := filepath.Join(directory, "connector-token")
	if err := os.WriteFile(credential, []byte("connector-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{Connectors: []Connector{connectorFixture(credential)}}
	loaded, err := config.validateAndLoadConnectors()
	if err != nil {
		t.Fatal(err)
	}
	connector := loaded["issues"]
	if connector.credential != "connector-secret" || connector.base.String() != "https://api.example.test:8443" ||
		len(connector.prefixes) != 1 || connector.operations["create"].Path != "/v1/issues" {
		t.Fatalf("loaded connector = %#v", connector)
	}
	insecure := connectorFixture(credential)
	insecure.BaseURL, insecure.AllowInsecureHTTP = "http://api.example.test:8080", true
	if _, err := (Config{Connectors: []Connector{insecure}}).validateAndLoadConnectors(); err != nil {
		t.Fatalf("explicitly acknowledged HTTP origin rejected: %v", err)
	}
	if err := os.Chmod(credential, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := config.validateAndLoadConnectors(); err == nil || !strings.Contains(err.Error(), "owner-only") {
		t.Fatalf("permissive connector credential accepted: %v", err)
	}
}

func TestConfigSeparatesConnectorCredentialsFromGatewayAuthority(t *testing.T) {
	directory := t.TempDir()
	credential := filepath.Join(directory, "connector-token")
	if err := os.WriteFile(credential, []byte("connector-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	base := Config{
		ServiceTokenFile:        filepath.Join(directory, "service-token"),
		StateFile:               filepath.Join(directory, "state.json"),
		EgressAuditFile:         filepath.Join(directory, "egress-audit.jsonl"),
		ControlSocket:           filepath.Join(directory, "control.sock"),
		GrantRoot:               filepath.Join(directory, "grants"),
		ConnectorReceiptFile:    filepath.Join(directory, "connector-receipts.ndjson"),
		ConnectorReceiptKeyFile: filepath.Join(directory, "connector-receipts.private.pem"),
		Routes:                  []Route{{ID: "inference", CredentialFile: filepath.Join(directory, "inference-token")}},
		Connectors:              []Connector{connectorFixture(credential)},
	}
	reserved := map[string]string{
		"service token":    base.ServiceTokenFile,
		"state":            base.StateFile,
		"audit":            base.EgressAuditFile,
		"control socket":   base.ControlSocket,
		"receipt log":      base.ConnectorReceiptFile,
		"receipt key":      base.ConnectorReceiptKeyFile,
		"inference token":  base.Routes[0].CredentialFile,
		"grant root":       base.GrantRoot,
		"grant descendant": filepath.Join(base.GrantRoot, "grant-a", "credential"),
	}
	for name, path := range reserved {
		t.Run(name, func(t *testing.T) {
			config := base
			config.Connectors = append([]Connector(nil), base.Connectors...)
			config.Connectors[0].CredentialFile = path
			if _, err := config.validateAndLoadConnectors(); err == nil || !strings.Contains(err.Error(), "must be separate") {
				t.Fatalf("reserved credential path %q err=%v", path, err)
			}
		})
	}

	t.Run("hard-link aliases", func(t *testing.T) {
		for _, fixture := range []struct {
			name string
			path string
		}{
			{name: "service token", path: base.ServiceTokenFile},
			{name: "inference token", path: base.Routes[0].CredentialFile},
		} {
			t.Run(fixture.name, func(t *testing.T) {
				if err := os.WriteFile(fixture.path, []byte("protected-secret\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				alias := filepath.Join(directory, strings.ReplaceAll(fixture.name, " ", "-")+"-alias")
				if err := os.Link(fixture.path, alias); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
				config := base
				config.Connectors = []Connector{connectorFixture(alias)}
				if _, err := config.validateAndLoadConnectors(); err == nil || !strings.Contains(err.Error(), "must not alias") {
					t.Fatalf("hard-link authority alias accepted: %v", err)
				}
			})
		}
	})

	t.Run("connector credential sharing", func(t *testing.T) {
		alias := filepath.Join(directory, "shared-connector-alias")
		if err := os.Link(credential, alias); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		second := connectorFixture(alias)
		second.ID = "calendar"
		config := base
		config.Connectors = []Connector{connectorFixture(credential), second}
		if _, err := config.validateAndLoadConnectors(); err == nil || !strings.Contains(err.Error(), "must not be shared") {
			t.Fatalf("shared connector credential accepted: %v", err)
		}
	})
}

func TestConfigSeparatesInferenceCredentialsFromAllAuthority(t *testing.T) {
	directory, err := os.MkdirTemp("/tmp", "sir-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	credential := filepath.Join(directory, "inference-token")
	connectorCredential := filepath.Join(directory, "connector-token")
	serviceToken := filepath.Join(directory, "service-token")
	receiptKey := filepath.Join(directory, "connector-receipts.private.pem")
	for path, value := range map[string]string{
		credential: "inference-secret\n", connectorCredential: "connector-secret\n",
		serviceToken: "service-secret\n", receiptKey: "receipt-key-material\n",
	} {
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := Config{
		Version: 1, ControlSocket: filepath.Join(directory, "control.sock"), ServiceAddress: "127.0.0.1:8092",
		ServiceTokenFile: serviceToken, StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ExecutorGID: 1, RelayGID: 1,
		ConnectorReceiptFile: filepath.Join(directory, "connector-receipts.ndjson"), ConnectorReceiptKeyFile: receiptKey,
		Connectors: []Connector{connectorFixture(connectorCredential)},
		Routes:     []Route{{ID: "inference", BaseURL: "https://models.example.test/v1", CredentialFile: credential, MaxConcurrent: 2}},
	}
	for name, path := range map[string]string{
		"service token": serviceToken, "receipt key": receiptKey, "connector credential": connectorCredential,
		"state": base.StateFile, "grant descendant": filepath.Join(base.GrantRoot, "grant-a", "secret"),
	} {
		t.Run("exact "+name, func(t *testing.T) {
			config := base
			config.Routes = append([]Route(nil), base.Routes...)
			config.Routes[0].CredentialFile = path
			if _, err := config.validateAndLoadRoutes(); err == nil || !strings.Contains(err.Error(), "must be separate") {
				t.Fatalf("reserved inference credential path accepted: %v", err)
			}
		})
	}
	for name, target := range map[string]string{
		"service token": serviceToken, "receipt key": receiptKey, "connector credential": connectorCredential,
	} {
		t.Run("hard-link "+name, func(t *testing.T) {
			alias := filepath.Join(directory, "inference-alias-"+strings.ReplaceAll(name, " ", "-"))
			if err := os.Link(target, alias); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
			config := base
			config.Routes = append([]Route(nil), base.Routes...)
			config.Routes[0].CredentialFile = alias
			if _, err := config.validateAndLoadRoutes(); err == nil || !strings.Contains(err.Error(), "must not alias") {
				t.Fatalf("hard-link inference authority alias accepted: %v", err)
			}
		})
	}
	t.Run("route credential sharing", func(t *testing.T) {
		alias := filepath.Join(directory, "second-route-token")
		if err := os.Link(credential, alias); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		config := base
		config.Routes = append(config.Routes, Route{
			ID: "secondary", BaseURL: "https://secondary.example.test/v1", CredentialFile: alias, MaxConcurrent: 1,
		})
		if _, err := config.validateAndLoadRoutes(); err == nil || !strings.Contains(err.Error(), "must not be shared") {
			t.Fatalf("shared inference credential accepted: %v", err)
		}
	})
}

func TestReadCredentialUsesOneBoundedVerifiedFile(t *testing.T) {
	directory := t.TempDir()
	credential := filepath.Join(directory, "credential")
	if err := os.WriteFile(credential, []byte("expected-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if value, err := readCredential(credential); err != nil || value != "expected-secret" {
		t.Fatalf("credential=%q err=%v", value, err)
	}

	t.Run("inode replacement", func(t *testing.T) {
		replacement := filepath.Join(directory, "replacement")
		if err := os.WriteFile(replacement, []byte("attacker-secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		expected, err := os.Lstat(credential)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := os.Open(replacement)
		if err != nil {
			t.Fatal(err)
		}
		defer opened.Close()
		if value, err := readOpenedCredential(expected, opened); err == nil || value != "" || !strings.Contains(err.Error(), "changed while opening") {
			t.Fatalf("replacement credential=%q err=%v", value, err)
		}
	})

	t.Run("permission replacement", func(t *testing.T) {
		path := filepath.Join(directory, "permission-change")
		if err := os.WriteFile(path, []byte("secret\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		expected, err := os.Lstat(path)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer opened.Close()
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := readOpenedCredential(expected, opened); err == nil {
			t.Fatal("credential whose permissions changed after validation was accepted")
		}
	})

	t.Run("oversized", func(t *testing.T) {
		path := filepath.Join(directory, "oversized")
		if err := os.WriteFile(path, []byte(strings.Repeat("x", maxCredentialBytes+1)), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readCredential(path); err == nil {
			t.Fatal("oversized credential was accepted")
		}
	})

	t.Run("symlink", func(t *testing.T) {
		path := filepath.Join(directory, "credential-link")
		if err := os.Symlink(credential, path); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := readCredential(path); err == nil {
			t.Fatal("credential symlink was accepted")
		}
	})

	for name, value := range map[string]string{
		"nul": "secret\x00suffix", "tab": "secret\tsuffix", "unicode": "secret-π",
	} {
		t.Run(name+" control", func(t *testing.T) {
			path := filepath.Join(directory, name+"-credential")
			if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := readCredential(path); err == nil || !strings.Contains(err.Error(), "visible ASCII") {
				t.Fatalf("unsafe HTTP credential accepted: %v", err)
			}
		})
	}
}

func TestExactConnectorOriginAndPathBoundaries(t *testing.T) {
	maximumHost := strings.Repeat("a.", 126) + "a"
	if len(maximumHost) != 253 {
		t.Fatalf("maximum host fixture length=%d", len(maximumHost))
	}
	if _, err := exactConnectorOrigin("https://" + maximumHost); err != nil {
		t.Fatalf("253-byte canonical host rejected: %v", err)
	}
	for _, path := range []string{"/", "/v1/issues", "/v1/tickets:close"} {
		if !canonicalConnectorPath(path) {
			t.Errorf("canonical path %q rejected", path)
		}
	}
}

func TestConfigRejectsAmbiguousOrUnboundedConnectors(t *testing.T) {
	credential := filepath.Join(t.TempDir(), "credential")
	if err := os.WriteFile(credential, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"duplicate connector", func(c *Config) { c.Connectors = append(c.Connectors, c.Connectors[0]) }},
		{"query", func(c *Config) { c.Connectors[0].BaseURL = "https://api.example.test?scope=all" }},
		{"fragment", func(c *Config) { c.Connectors[0].BaseURL = "https://api.example.test#fragment" }},
		{"userinfo", func(c *Config) { c.Connectors[0].BaseURL = "https://user@api.example.test" }},
		{"origin path", func(c *Config) { c.Connectors[0].BaseURL = "https://api.example.test/v1" }},
		{"http without acknowledgement", func(c *Config) { c.Connectors[0].BaseURL = "http://api.example.test" }},
		{"trailing slash", func(c *Config) { c.Connectors[0].BaseURL = "https://api.example.test/" }},
		{"noncanonical host", func(c *Config) { c.Connectors[0].BaseURL = "https://API.example.test" }},
		{"wildcard host", func(c *Config) { c.Connectors[0].BaseURL = "https://*.example.test" }},
		{"overlong host", func(c *Config) { c.Connectors[0].BaseURL = "https://" + strings.Repeat("a.", 127) + "a" }},
		{"empty port", func(c *Config) { c.Connectors[0].BaseURL = "https://api.example.test:" }},
		{"credential mode", func(c *Config) { c.Connectors[0].CredentialMode = "authorization" }},
		{"relative credential", func(c *Config) { c.Connectors[0].CredentialFile = "credential" }},
		{"bad cidr", func(c *Config) { c.Connectors[0].AllowedCIDRs = []string{"10.0.0.1/8"} }},
		{"duplicate cidr", func(c *Config) { c.Connectors[0].AllowedCIDRs = []string{"10.0.0.0/8", "10.0.0.0/8"} }},
		{"zero concurrency", func(c *Config) { c.Connectors[0].MaxConcurrent = 0 }},
		{"request limit", func(c *Config) { c.Connectors[0].MaxRequestBytes = maxConnectorRequestBytes + 1 }},
		{"response limit", func(c *Config) { c.Connectors[0].MaxResponseBytes = maxConnectorResponseBytes + 1 }},
		{"duration", func(c *Config) { c.Connectors[0].MaxSeconds = maxConnectorSeconds + 1 }},
		{"call limit", func(c *Config) { c.Connectors[0].MaxCallsPerGrant = maxConnectorCallsPerGrant + 1 }},
		{"no operations", func(c *Config) { c.Connectors[0].Operations = nil }},
		{"duplicate operation", func(c *Config) {
			c.Connectors[0].Operations = append(c.Connectors[0].Operations, c.Connectors[0].Operations[0])
		}},
		{"lowercase method", func(c *Config) { c.Connectors[0].Operations[0].Method = "post" }},
		{"connect method", func(c *Config) { c.Connectors[0].Operations[0].Method = http.MethodConnect }},
		{"relative path", func(c *Config) { c.Connectors[0].Operations[0].Path = "v1/issues" }},
		{"query path", func(c *Config) { c.Connectors[0].Operations[0].Path = "/v1/issues?all=true" }},
		{"encoded path", func(c *Config) { c.Connectors[0].Operations[0].Path = "/v1/%69ssues" }},
		{"space path", func(c *Config) { c.Connectors[0].Operations[0].Path = "/v1/issue report" }},
		{"control path", func(c *Config) { c.Connectors[0].Operations[0].Path = "/v1/issues\nadmin" }},
		{"unicode path", func(c *Config) { c.Connectors[0].Operations[0].Path = "/v1/café" }},
		{"escaped delimiter path", func(c *Config) { c.Connectors[0].Operations[0].Path = "/v1/[issues]" }},
		{"traversal path", func(c *Config) { c.Connectors[0].Operations[0].Path = "/v1/../admin" }},
		{"double slash", func(c *Config) { c.Connectors[0].Operations[0].Path = "/v1//issues" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := Config{Connectors: []Connector{connectorFixture(credential)}}
			test.mutate(&config)
			if _, err := config.validateAndLoadConnectors(); err == nil {
				t.Fatalf("invalid connector accepted: %#v", config.Connectors)
			}
		})
	}
}

func TestConfigRequiresAndValidatesConnectorReceiptIdentity(t *testing.T) {
	directory := t.TempDir()
	credential := filepath.Join(directory, "connector-token")
	if err := os.WriteFile(credential, []byte("connector-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(directory, "connector-receipts.private.pem")
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	config := Config{
		ControlSocket: filepath.Join(directory, "control.sock"), StateFile: filepath.Join(directory, "state.json"),
		GrantRoot: filepath.Join(directory, "grants"), ServiceTokenFile: filepath.Join(directory, "service.token"),
		Connectors:           []Connector{connectorFixture(credential)},
		ConnectorReceiptFile: filepath.Join(directory, "connector-receipts.ndjson"), ConnectorReceiptKeyFile: keyPath,
		ConnectorReceiptNodeID: "node-a/gateway", ConnectorReceiptEpoch: 1,
	}
	loaded, err := config.validateAndLoadConnectorReceiptKey()
	if err != nil || !loaded.Equal(private) {
		t.Fatalf("loaded key equal=%t err=%v", loaded.Equal(private), err)
	}
	if _, err := os.Stat(config.ConnectorReceiptFile); !os.IsNotExist(err) {
		t.Fatalf("read-only validation created ledger: %v", err)
	}

	for name, mutate := range map[string]func(*Config){
		"partial":              func(value *Config) { value.ConnectorReceiptEpoch = 0 },
		"state collision":      func(value *Config) { value.ConnectorReceiptFile = value.StateFile },
		"control collision":    func(value *Config) { value.ConnectorReceiptFile = value.ControlSocket },
		"grant tree log":       func(value *Config) { value.ConnectorReceiptFile = filepath.Join(value.GrantRoot, "receipts") },
		"credential collision": func(value *Config) { value.ConnectorReceiptKeyFile = credential },
	} {
		t.Run(name, func(t *testing.T) {
			invalid := config
			mutate(&invalid)
			if _, err := invalid.validateAndLoadConnectorReceiptKey(); err == nil {
				t.Fatalf("invalid receipt configuration accepted: %#v", invalid)
			}
		})
	}
	missing := Config{Connectors: config.Connectors}
	if _, err := missing.validateAndLoadConnectorReceiptKey(); err == nil {
		t.Fatal("connector without signed receipts accepted")
	}
}

func connectorFixture(credential string) Connector {
	return Connector{
		ID: "issues", BaseURL: "https://api.example.test:8443", CredentialFile: credential,
		CredentialMode: CredentialModeBearer, AllowedCIDRs: []string{"203.0.113.0/24"},
		MaxConcurrent: 2, MaxRequestBytes: 4096, MaxResponseBytes: 8192,
		MaxSeconds: 30, MaxCallsPerGrant: 4,
		Operations: []ConnectorOperation{
			{ID: "create", Method: http.MethodPost, Path: "/v1/issues"},
			{ID: "get", Method: http.MethodGet, Path: "/v1/issues/current"},
		},
	}
}
