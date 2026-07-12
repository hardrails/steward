package gateway

import (
	"encoding/json"
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
		ExecutorGID: os.Getgid(), RelayGID: os.Getgid(),
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
