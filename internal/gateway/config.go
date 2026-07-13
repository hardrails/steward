package gateway

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	pathpkg "path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/nodeclient"
)

const (
	maxConfigBytes            = 1 << 20
	maxConnectors             = 128
	maxConnectorOperations    = 64
	maxConnectorAllowedCIDRs  = 64
	maxConnectorRequestBytes  = int64(4 << 20)
	maxConnectorResponseBytes = int64(32 << 20)
	maxConnectorSeconds       = 3600
	maxConnectorCallsPerGrant = 256
)

type Config struct {
	Version          int           `json:"version"`
	ControlSocket    string        `json:"control_socket"`
	ServiceAddress   string        `json:"service_address"`
	ServiceTokenFile string        `json:"service_token_file"`
	StateFile        string        `json:"state_file"`
	GrantRoot        string        `json:"grant_root"`
	ExecutorGID      int           `json:"executor_gid"`
	RelayGID         int           `json:"relay_gid"`
	Routes           []Route       `json:"routes"`
	EgressAuditFile  string        `json:"egress_audit_file,omitempty"`
	EgressRoutes     []EgressRoute `json:"egress_routes,omitempty"`
	Connectors       []Connector   `json:"connectors,omitempty"`

	// loadedConnectors contains validated origins, credentials, CIDRs, and
	// operation indexes populated by LoadConfig. It is deliberately absent from
	// JSON so secret contents can never be serialized with operator policy.
	loadedConnectors map[string]loadedConnector
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

type EgressRoute struct {
	ID               string              `json:"id"`
	Destinations     []EgressDestination `json:"destinations"`
	MaxConcurrent    int                 `json:"max_concurrent"`
	MaxRequestBytes  int64               `json:"max_request_bytes"`
	MaxResponseBytes int64               `json:"max_response_bytes"`
	MaxTunnelSeconds int                 `json:"max_tunnel_seconds"`
}

type EgressDestination struct {
	Host         string   `json:"host"`
	Ports        []int    `json:"ports"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}

type loadedEgressDestination struct {
	EgressDestination
	prefixes []netip.Prefix
}

type loadedEgressRoute struct {
	EgressRoute
	destinations []loadedEgressDestination
}

// CredentialMode is the complete connector credential-injection vocabulary.
// A connector cannot select an arbitrary header name.
type CredentialMode string

const (
	CredentialModeBearer  CredentialMode = "bearer"
	CredentialModeXAPIKey CredentialMode = "x-api-key"
)

// Connector binds a finite set of logical operations to one exact upstream
// origin and one operator-owned credential.
type Connector struct {
	ID                string               `json:"id"`
	BaseURL           string               `json:"base_url"`
	CredentialFile    string               `json:"credential_file"`
	CredentialMode    CredentialMode       `json:"credential_mode"`
	AllowInsecureHTTP bool                 `json:"allow_insecure_http,omitempty"`
	AllowedCIDRs      []string             `json:"allowed_cidrs,omitempty"`
	MaxConcurrent     int                  `json:"max_concurrent"`
	MaxRequestBytes   int64                `json:"max_request_bytes"`
	MaxResponseBytes  int64                `json:"max_response_bytes"`
	MaxSeconds        int                  `json:"max_seconds"`
	MaxCallsPerGrant  int                  `json:"max_calls_per_grant"`
	Operations        []ConnectorOperation `json:"operations"`
}

// ConnectorOperation is one exact method and path. Paths have no templates,
// query strings, fragments, or alternate percent-encoded spelling.
type ConnectorOperation struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

type loadedConnector struct {
	Connector
	base       *url.URL
	credential string
	prefixes   []netip.Prefix
	operations map[string]ConnectorOperation
}

func LoadConfig(path string) (Config, map[string]loadedRoute, map[string]loadedEgressRoute, string, error) {
	raw, err := nodeclient.ReadBounded(path, maxConfigBytes)
	if err != nil {
		return Config{}, nil, nil, "", err
	}
	var config Config
	if err := dsse.DecodeStrictInto(raw, maxConfigBytes, &config); err != nil {
		return Config{}, nil, nil, "", fmt.Errorf("decode gateway config: %w", err)
	}
	routes, err := config.validateAndLoadRoutes()
	if err != nil {
		return Config{}, nil, nil, "", err
	}
	egressRoutes, err := config.validateEgressRoutes()
	if err != nil {
		return Config{}, nil, nil, "", err
	}
	connectors, err := config.validateAndLoadConnectors()
	if err != nil {
		return Config{}, nil, nil, "", err
	}
	config.loadedConnectors = connectors
	token, err := nodeclient.ReadToken(config.ServiceTokenFile)
	if err != nil {
		return Config{}, nil, nil, "", fmt.Errorf("read gateway service token: %w", err)
	}
	return config, routes, egressRoutes, token, nil
}

func (c Config) connectorMap() (map[string]loadedConnector, error) {
	if c.loadedConnectors != nil {
		return c.loadedConnectors, nil
	}
	return c.validateAndLoadConnectors()
}

func (c Config) validateAndLoadConnectors() (map[string]loadedConnector, error) {
	if len(c.Connectors) > maxConnectors {
		return nil, fmt.Errorf("gateway config permits at most %d connectors", maxConnectors)
	}
	loaded := make(map[string]loadedConnector, len(c.Connectors))
	for _, connector := range c.Connectors {
		if !routeID(connector.ID) || connector.MaxConcurrent < 1 || connector.MaxConcurrent > 256 ||
			connector.MaxRequestBytes < 1 || connector.MaxRequestBytes > maxConnectorRequestBytes ||
			connector.MaxResponseBytes < 1 || connector.MaxResponseBytes > maxConnectorResponseBytes ||
			connector.MaxSeconds < 1 || connector.MaxSeconds > maxConnectorSeconds ||
			connector.MaxCallsPerGrant < 1 || connector.MaxCallsPerGrant > maxConnectorCallsPerGrant ||
			len(connector.Operations) < 1 || len(connector.Operations) > maxConnectorOperations ||
			len(connector.AllowedCIDRs) > maxConnectorAllowedCIDRs {
			return nil, fmt.Errorf("connector %q has invalid limits or operations", connector.ID)
		}
		if _, exists := loaded[connector.ID]; exists {
			return nil, fmt.Errorf("duplicate connector %q", connector.ID)
		}
		base, err := exactConnectorOrigin(connector.BaseURL)
		if err != nil {
			return nil, fmt.Errorf("connector %q base_url: %w", connector.ID, err)
		}
		if base.Scheme == "http" && !connector.AllowInsecureHTTP {
			return nil, fmt.Errorf("connector %q requires allow_insecure_http for an HTTP origin", connector.ID)
		}
		if !absoluteClean(connector.CredentialFile) {
			return nil, fmt.Errorf("connector %q credential path must be absolute", connector.ID)
		}
		if connector.CredentialMode != CredentialModeBearer && connector.CredentialMode != CredentialModeXAPIKey {
			return nil, fmt.Errorf("connector %q has unsupported credential mode", connector.ID)
		}
		credential, err := readCredential(connector.CredentialFile)
		if err != nil {
			return nil, fmt.Errorf("connector %q credential: %w", connector.ID, err)
		}
		entry := loadedConnector{
			Connector: connector, base: base, credential: credential,
			operations: make(map[string]ConnectorOperation, len(connector.Operations)),
		}
		seenCIDRs := make(map[string]struct{}, len(connector.AllowedCIDRs))
		for _, cidr := range connector.AllowedCIDRs {
			prefix, err := netip.ParsePrefix(cidr)
			if err != nil || prefix.String() != cidr || prefix.Masked() != prefix {
				return nil, fmt.Errorf("connector %q has invalid canonical allowed CIDR", connector.ID)
			}
			if _, duplicate := seenCIDRs[cidr]; duplicate {
				return nil, fmt.Errorf("connector %q has duplicate allowed CIDR", connector.ID)
			}
			seenCIDRs[cidr] = struct{}{}
			entry.prefixes = append(entry.prefixes, prefix)
		}
		for _, operation := range connector.Operations {
			if !routeID(operation.ID) || !connectorMethod(operation.Method) || !canonicalConnectorPath(operation.Path) {
				return nil, fmt.Errorf("connector %q has invalid operation", connector.ID)
			}
			if _, duplicate := entry.operations[operation.ID]; duplicate {
				return nil, fmt.Errorf("connector %q has duplicate operation %q", connector.ID, operation.ID)
			}
			entry.operations[operation.ID] = operation
		}
		loaded[connector.ID] = entry
	}
	return loaded, nil
}

func exactConnectorOrigin(value string) (*url.URL, error) {
	base, err := url.Parse(value)
	if err != nil || base.Scheme != strings.ToLower(base.Scheme) ||
		(base.Scheme != "http" && base.Scheme != "https") || base.Host == "" || base.User != nil ||
		base.Path != "" || base.RawPath != "" || base.RawQuery != "" || base.ForceQuery || base.Fragment != "" || base.Opaque != "" ||
		base.String() != value || base.Host != strings.ToLower(base.Host) {
		return nil, errors.New("must be an exact canonical HTTP(S) origin")
	}
	host := base.Hostname()
	if host == "" || strings.HasSuffix(host, ".") || (!egressHostPattern.MatchString(host) && net.ParseIP(host) == nil) {
		return nil, errors.New("must contain a canonical hostname or IP address")
	}
	if portText := base.Port(); portText != "" {
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText {
			return nil, errors.New("must contain a canonical numeric port")
		}
	} else if strings.HasSuffix(base.Host, ":") {
		return nil, errors.New("must not contain an empty port")
	}
	return base, nil
}

func connectorMethod(value string) bool {
	switch value {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func connectorMethodHasBody(value string) bool {
	return value == http.MethodPost || value == http.MethodPut || value == http.MethodPatch
}

func canonicalConnectorPath(value string) bool {
	return strings.HasPrefix(value, "/") && len(value) <= 2048 && pathpkg.Clean(value) == value &&
		!strings.Contains(value, "//") && !strings.ContainsAny(value, "%\\?#\x00")
}

func (c Config) validateAndLoadRoutes() (map[string]loadedRoute, error) {
	if c.Version != 1 || !absoluteClean(c.ControlSocket) || !absoluteClean(c.StateFile) || !absoluteClean(c.GrantRoot) ||
		!absoluteClean(c.ServiceTokenFile) || c.ExecutorGID <= 0 || c.RelayGID <= 0 || len(c.Routes) > 128 {
		return nil, errors.New("gateway config requires version 1, absolute control/state/grant/token paths, and at most 128 inference routes")
	}
	// Linux sockaddr_un.sun_path is 108 bytes including the terminator. Keep a
	// conservative cross-platform ceiling for both the control and derived grant
	// sockets so failure happens at config validation rather than first admission.
	if len(c.ControlSocket) > 103 || len(inferenceSocketPath(c.GrantRoot, "grant-"+strings.Repeat("a", 64))) > 103 {
		return nil, errors.New("gateway Unix socket paths must not exceed 103 bytes")
	}
	host, portText, err := net.SplitHostPort(c.ServiceAddress)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port < 1 || port > 65535 || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
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

var egressHostPattern = regexp.MustCompile(`^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)

func (c Config) validateEgressRoutes() (map[string]loadedEgressRoute, error) {
	if len(c.EgressRoutes) > 128 {
		return nil, errors.New("gateway config permits at most 128 egress routes")
	}
	if len(c.EgressRoutes) > 0 && !absoluteClean(c.EgressAuditFile) {
		return nil, errors.New("egress routes require an absolute egress_audit_file")
	}
	loaded := make(map[string]loadedEgressRoute, len(c.EgressRoutes))
	for _, route := range c.EgressRoutes {
		if !routeID(route.ID) || route.MaxConcurrent < 1 || route.MaxConcurrent > 256 ||
			route.MaxRequestBytes < 1 || route.MaxRequestBytes > 1<<30 ||
			route.MaxResponseBytes < 1 || route.MaxResponseBytes > 1<<30 ||
			route.MaxTunnelSeconds < 1 || route.MaxTunnelSeconds > 86400 ||
			len(route.Destinations) == 0 || len(route.Destinations) > 128 {
			return nil, fmt.Errorf("egress route %q has invalid limits or destinations", route.ID)
		}
		if _, exists := loaded[route.ID]; exists {
			return nil, fmt.Errorf("duplicate egress route %q", route.ID)
		}
		entry := loadedEgressRoute{EgressRoute: route, destinations: make([]loadedEgressDestination, 0, len(route.Destinations))}
		seen := make(map[string]struct{}, len(route.Destinations))
		for _, destination := range route.Destinations {
			host := strings.ToLower(destination.Host)
			if len(host) > 253 || (!egressHostPattern.MatchString(host) && net.ParseIP(host) == nil) || len(destination.Ports) == 0 || len(destination.Ports) > 16 {
				return nil, fmt.Errorf("egress route %q has invalid destination", route.ID)
			}
			ports := make(map[int]struct{}, len(destination.Ports))
			for _, port := range destination.Ports {
				if port < 1 || port > 65535 {
					return nil, fmt.Errorf("egress route %q has invalid destination port", route.ID)
				}
				ports[port] = struct{}{}
			}
			if len(ports) != len(destination.Ports) {
				return nil, fmt.Errorf("egress route %q has duplicate destination port", route.ID)
			}
			key := host + fmt.Sprint(destination.Ports)
			if _, exists := seen[key]; exists {
				return nil, fmt.Errorf("egress route %q has duplicate destination", route.ID)
			}
			seen[key] = struct{}{}
			item := loadedEgressDestination{EgressDestination: destination}
			item.Host = host
			for _, cidr := range destination.AllowedCIDRs {
				prefix, err := netip.ParsePrefix(cidr)
				if err != nil || prefix.String() != cidr || prefix.Masked() != prefix {
					return nil, fmt.Errorf("egress route %q has invalid canonical allowed CIDR", route.ID)
				}
				item.prefixes = append(item.prefixes, prefix)
			}
			entry.destinations = append(entry.destinations, item)
		}
		loaded[route.ID] = entry
	}
	return loaded, nil
}

func routeID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for i, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9' ||
			(i > 0 && (character == '.' || character == '_' || character == '-')) {
			continue
		}
		return false
	}
	return true
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
