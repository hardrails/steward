package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/nodeclient"
)

const maxConfigBytes = 1 << 20

type Config struct {
	Version          int     `json:"version"`
	ControlSocket    string  `json:"control_socket"`
	ServiceAddress   string  `json:"service_address"`
	ServiceTokenFile string  `json:"service_token_file"`
	StateFile        string  `json:"state_file"`
	GrantRoot        string  `json:"grant_root"`
	ExecutorGID      int     `json:"executor_gid"`
	RelayGID         int     `json:"relay_gid"`
	Routes           []Route `json:"routes"`
}

type Route struct {
	ID             string `json:"id"`
	BaseURL        string `json:"base_url"`
	CredentialFile string `json:"credential_file,omitempty"`
	MaxConcurrent  int    `json:"max_concurrent"`
}

type loadedRoute struct {
	Route
	base       *url.URL
	credential string
}

func LoadConfig(path string) (Config, map[string]loadedRoute, string, error) {
	raw, err := nodeclient.ReadBounded(path, maxConfigBytes)
	if err != nil {
		return Config{}, nil, "", err
	}
	var config Config
	if err := dsse.DecodeStrictInto(raw, maxConfigBytes, &config); err != nil {
		return Config{}, nil, "", fmt.Errorf("decode gateway config: %w", err)
	}
	routes, err := config.validateAndLoadRoutes()
	if err != nil {
		return Config{}, nil, "", err
	}
	token, err := nodeclient.ReadToken(config.ServiceTokenFile)
	if err != nil {
		return Config{}, nil, "", fmt.Errorf("read gateway service token: %w", err)
	}
	return config, routes, token, nil
}

func (c Config) validateAndLoadRoutes() (map[string]loadedRoute, error) {
	if c.Version != 1 || !absoluteClean(c.ControlSocket) || !absoluteClean(c.StateFile) || !absoluteClean(c.GrantRoot) ||
		!absoluteClean(c.ServiceTokenFile) || c.ExecutorGID <= 0 || c.RelayGID <= 0 || len(c.Routes) == 0 || len(c.Routes) > 128 {
		return nil, errors.New("gateway config requires version 1, absolute control/state/grant/token paths, and 1 to 128 routes")
	}
	// Linux sockaddr_un.sun_path is 108 bytes including the terminator. Keep a
	// conservative cross-platform ceiling for both the control and derived grant
	// sockets so failure happens at config validation rather than first admission.
	if len(c.ControlSocket) > 103 || len(inferenceSocketPath(c.GrantRoot, "grant-"+strings.Repeat("a", 64))) > 103 {
		return nil, errors.New("gateway Unix socket paths must not exceed 103 bytes")
	}
	host, _, err := net.SplitHostPort(c.ServiceAddress)
	if err != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("gateway service_address must be an explicit loopback IP and port")
	}
	loaded := make(map[string]loadedRoute, len(c.Routes))
	for _, route := range c.Routes {
		if !bounded(route.ID, 128) || route.MaxConcurrent < 1 || route.MaxConcurrent > 256 {
			return nil, errors.New("gateway route requires bounded id and max_concurrent from 1 to 256")
		}
		if _, exists := loaded[route.ID]; exists {
			return nil, fmt.Errorf("duplicate gateway route %q", route.ID)
		}
		base, err := url.Parse(route.BaseURL)
		if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil ||
			base.RawQuery != "" || base.Fragment != "" || (base.Path != "" && base.Path != "/v1" && base.Path != "/v1/") {
			return nil, fmt.Errorf("gateway route %q base_url must be an exact HTTP(S) origin optionally ending in /v1", route.ID)
		}
		credential := ""
		if route.CredentialFile != "" {
			if !absoluteClean(route.CredentialFile) {
				return nil, fmt.Errorf("gateway route %q credential path must be absolute", route.ID)
			}
			credential, err = readCredential(route.CredentialFile)
			if err != nil {
				return nil, fmt.Errorf("gateway route %q credential: %w", route.ID, err)
			}
		}
		loaded[route.ID] = loadedRoute{Route: route, base: base, credential: credential}
	}
	return loaded, nil
}

func readCredential(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() <= 0 || info.Size() > 16<<10 {
		return "", errors.New("credential must be a bounded owner-only regular file")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	value := strings.TrimSpace(string(raw))
	if value == "" || strings.ContainsAny(value, "\r\n") {
		return "", errors.New("credential must contain one non-empty line")
	}
	return value, nil
}

func absoluteClean(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, '\x00')
}

func bounded(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}
