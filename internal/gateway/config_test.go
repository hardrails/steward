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
	loaded, routes, serviceToken, err := LoadConfig(path)
	if err != nil || loaded.Version != 1 || serviceToken != "service-secret" || routes["local"].credential != "route-secret" {
		t.Fatalf("loaded=%#v routes=%#v token=%q err=%v", loaded, routes, serviceToken, err)
	}
	if err := os.Chmod(credential, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := LoadConfig(path); err == nil {
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
