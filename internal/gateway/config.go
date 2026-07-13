package gateway

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
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
	"syscall"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/nodeclient"
)

const (
	maxConfigBytes              = 1 << 20
	maxConnectors               = 128
	maxConnectorOperations      = 64
	maxConnectorAllowedCIDRs    = 64
	maxConnectorRequestBytes    = int64(4 << 20)
	maxConnectorResponseBytes   = int64(32 << 20)
	maxConnectorSeconds         = 3600
	maxConnectorCallsPerGrant   = 256
	minConnectorCredentialBytes = 12
	maxCredentialBytes          = 16 << 10
)

type Config struct {
	Version                       int                            `json:"version"`
	ControlSocket                 string                         `json:"control_socket"`
	ServiceAddress                string                         `json:"service_address"`
	ServiceTokenFile              string                         `json:"service_token_file"`
	StateFile                     string                         `json:"state_file"`
	GrantRoot                     string                         `json:"grant_root"`
	ExecutorGID                   int                            `json:"executor_gid"`
	RelayGID                      int                            `json:"relay_gid"`
	Routes                        []Route                        `json:"routes"`
	EgressAuditFile               string                         `json:"egress_audit_file,omitempty"`
	EgressRoutes                  []EgressRoute                  `json:"egress_routes,omitempty"`
	Connectors                    []Connector                    `json:"connectors,omitempty"`
	ConnectorReceiptFile          string                         `json:"connector_receipt_file,omitempty"`
	ConnectorReceiptKeyFile       string                         `json:"connector_receipt_key_file,omitempty"`
	ConnectorReceiptNodeID        string                         `json:"connector_receipt_node_id,omitempty"`
	ConnectorReceiptEpoch         uint64                         `json:"connector_receipt_epoch,omitempty"`
	ConnectorReceiptTenantBudgets []ConnectorReceiptTenantBudget `json:"connector_receipt_tenant_budgets,omitempty"`

	// loadedConnectors contains validated origins, credentials, CIDRs, and
	// operation indexes populated by LoadConfig. It is deliberately absent from
	// JSON so secret contents can never be serialized with operator policy.
	loadedConnectors    map[string]loadedConnector
	connectorReceiptKey ed25519.PrivateKey
}

// ConnectorReceiptTenantBudget reserves non-borrowing signed receipt capacity
// for one exact tenant identity. Capacity is not shared with other tenants.
type ConnectorReceiptTenantBudget struct {
	TenantID string `json:"tenant_id"`
	Bytes    int64  `json:"bytes"`
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
	receiptKey, err := config.validateAndLoadConnectorReceiptKey()
	if err != nil {
		return Config{}, nil, nil, "", err
	}
	config.connectorReceiptKey = receiptKey
	token, err := nodeclient.ReadToken(config.ServiceTokenFile)
	if err != nil {
		return Config{}, nil, nil, "", fmt.Errorf("read gateway service token: %w", err)
	}
	return config, routes, egressRoutes, token, nil
}

func (c Config) connectorReceiptPrivateKey() (ed25519.PrivateKey, error) {
	if c.connectorReceiptKey != nil {
		return append(ed25519.PrivateKey(nil), c.connectorReceiptKey...), nil
	}
	return c.validateAndLoadConnectorReceiptKey()
}

func (c Config) connectorReceiptLimits() (connectorledger.Limits, error) {
	budgets := make(map[string]int64, len(c.ConnectorReceiptTenantBudgets))
	for _, budget := range c.ConnectorReceiptTenantBudgets {
		if _, duplicate := budgets[budget.TenantID]; duplicate {
			return connectorledger.Limits{}, fmt.Errorf("duplicate connector receipt tenant budget %q", budget.TenantID)
		}
		budgets[budget.TenantID] = budget.Bytes
	}
	limits := connectorledger.Limits{TenantBudgets: budgets}
	if err := limits.Validate(); err != nil {
		return connectorledger.Limits{}, fmt.Errorf("connector receipt tenant budgets: %w", err)
	}
	return limits, nil
}

func (c Config) connectorReceiptBudget(tenantID string) (int64, bool) {
	for _, budget := range c.ConnectorReceiptTenantBudgets {
		if budget.TenantID == tenantID {
			return budget.Bytes, true
		}
	}
	return 0, false
}

func (c Config) validateAndLoadConnectorReceiptKey() (ed25519.PrivateKey, error) {
	configured := 0
	for _, present := range []bool{
		c.ConnectorReceiptFile != "", c.ConnectorReceiptKeyFile != "",
		c.ConnectorReceiptNodeID != "", c.ConnectorReceiptEpoch != 0,
	} {
		if present {
			configured++
		}
	}
	if configured == 0 {
		if len(c.ConnectorReceiptTenantBudgets) != 0 {
			return nil, errors.New("connector receipt tenant budgets require a connector receipt identity")
		}
		if len(c.Connectors) > 0 {
			return nil, errors.New("connectors require a signed connector receipt ledger")
		}
		return nil, nil
	}
	if configured != 4 {
		return nil, errors.New("connector receipt file, private key, node id, and epoch must be configured together")
	}
	limits, err := c.connectorReceiptLimits()
	if err != nil {
		return nil, err
	}
	if len(c.Connectors) > 0 && len(c.ConnectorReceiptTenantBudgets) == 0 {
		return nil, errors.New("connectors require at least one explicit connector receipt tenant budget")
	}
	if !absoluteClean(c.ConnectorReceiptFile) || !absoluteClean(c.ConnectorReceiptKeyFile) ||
		c.ConnectorReceiptFile == c.ConnectorReceiptKeyFile || c.ConnectorReceiptFile == c.StateFile ||
		c.ConnectorReceiptFile == c.EgressAuditFile || c.ConnectorReceiptFile == c.ServiceTokenFile ||
		c.ConnectorReceiptFile == c.ControlSocket || c.ConnectorReceiptKeyFile == c.ControlSocket ||
		pathWithin(c.ConnectorReceiptFile, c.GrantRoot) || pathWithin(c.ConnectorReceiptKeyFile, c.GrantRoot) {
		return nil, errors.New("connector receipt paths must be clean, absolute, and separate from Gateway state, audit, token, and key files")
	}
	for _, route := range c.Routes {
		if route.CredentialFile != "" && (c.ConnectorReceiptFile == route.CredentialFile || c.ConnectorReceiptKeyFile == route.CredentialFile) {
			return nil, errors.New("connector receipt files must not share an inference credential path")
		}
	}
	for _, connector := range c.Connectors {
		if c.ConnectorReceiptFile == connector.CredentialFile || c.ConnectorReceiptKeyFile == connector.CredentialFile {
			return nil, errors.New("connector receipt files must not share a connector credential path")
		}
	}
	key, err := connectorledger.ReadPrivateKey(c.ConnectorReceiptKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read connector receipt private key: %w", err)
	}
	if _, err := connectorledger.ValidateWithLimits(
		c.ConnectorReceiptFile, key, c.ConnectorReceiptNodeID, c.ConnectorReceiptEpoch, limits,
	); err != nil {
		return nil, fmt.Errorf("validate connector receipt ledger: %w", err)
	}
	return key, nil
}

func pathWithin(path, root string) bool {
	return root != "" && (path == root || strings.HasPrefix(path, root+string(filepath.Separator)))
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
	reservedFiles, err := c.connectorReservedFileIdentities()
	if err != nil {
		return nil, err
	}
	loaded := make(map[string]loadedConnector, len(c.Connectors))
	connectorCredentials := make([]os.FileInfo, 0, len(c.Connectors))
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
		if c.reservedConnectorCredentialPath(connector.CredentialFile) {
			return nil, fmt.Errorf("connector %q credential path must be separate from Gateway and inference authority paths", connector.ID)
		}
		if connector.CredentialMode != CredentialModeBearer && connector.CredentialMode != CredentialModeXAPIKey {
			return nil, fmt.Errorf("connector %q has unsupported credential mode", connector.ID)
		}
		credential, credentialInfo, err := readCredentialWithInfo(connector.CredentialFile)
		if err != nil {
			return nil, fmt.Errorf("connector %q credential: %w", connector.ID, err)
		}
		if len(credential) < minConnectorCredentialBytes {
			return nil, fmt.Errorf("connector %q credential must contain at least %d visible ASCII bytes", connector.ID, minConnectorCredentialBytes)
		}
		for _, reserved := range reservedFiles {
			if os.SameFile(credentialInfo, reserved) {
				return nil, fmt.Errorf("connector %q credential file must not alias Gateway or inference authority", connector.ID)
			}
		}
		for _, prior := range connectorCredentials {
			if os.SameFile(credentialInfo, prior) {
				return nil, fmt.Errorf("connector %q credential file must not be shared by connectors", connector.ID)
			}
		}
		connectorCredentials = append(connectorCredentials, credentialInfo)
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

func (c Config) reservedConnectorCredentialPath(path string) bool {
	for _, reserved := range []string{
		c.ServiceTokenFile, c.StateFile, c.EgressAuditFile, c.ControlSocket,
		c.ConnectorReceiptFile, c.ConnectorReceiptKeyFile,
	} {
		if reserved != "" && path == reserved {
			return true
		}
	}
	for _, route := range c.Routes {
		if route.CredentialFile != "" && path == route.CredentialFile {
			return true
		}
	}
	return pathWithin(path, c.GrantRoot)
}

func (c Config) connectorReservedFileIdentities() ([]os.FileInfo, error) {
	paths := []string{
		c.ServiceTokenFile, c.StateFile, c.EgressAuditFile, c.ControlSocket,
		c.ConnectorReceiptFile, c.ConnectorReceiptKeyFile,
	}
	for _, route := range c.Routes {
		paths = append(paths, route.CredentialFile)
	}
	return existingFileIdentities("connector-reserved", paths)
}

func (c Config) routeReservedFileIdentities() ([]os.FileInfo, error) {
	paths := []string{
		c.ServiceTokenFile, c.StateFile, c.EgressAuditFile, c.ControlSocket,
		c.ConnectorReceiptFile, c.ConnectorReceiptKeyFile,
	}
	for _, connector := range c.Connectors {
		paths = append(paths, connector.CredentialFile)
	}
	return existingFileIdentities("inference-reserved", paths)
}

func existingFileIdentities(label string, paths []string) ([]os.FileInfo, error) {
	identities := make([]os.FileInfo, 0, len(paths))
	seen := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		if path == "" {
			continue
		}
		if _, duplicate := seen[path]; duplicate {
			continue
		}
		seen[path] = struct{}{}
		info, err := os.Lstat(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("inspect %s path %q: %w", label, path, err)
		}
		identities = append(identities, info)
	}
	return identities, nil
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
	if host == "" || len(host) > 253 || strings.HasPrefix(host, "*.") || strings.HasSuffix(host, ".") ||
		(!egressHostPattern.MatchString(host) && net.ParseIP(host) == nil) {
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
	if !strings.HasPrefix(value, "/") || len(value) > 2048 || pathpkg.Clean(value) != value || strings.Contains(value, "//") {
		return false
	}
	for index := 0; index < len(value); index++ {
		if !canonicalConnectorPathByte(value[index]) {
			return false
		}
	}
	return (&url.URL{Path: value}).EscapedPath() == value
}

func canonicalConnectorPathByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' ||
		strings.ContainsRune("/-._~!$&'()*+,;=:@", rune(value))
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
	reservedFiles, err := c.routeReservedFileIdentities()
	if err != nil {
		return nil, err
	}
	loaded := make(map[string]loadedRoute, len(c.Routes))
	routeCredentials := make([]os.FileInfo, 0, len(c.Routes))
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
			if c.reservedRouteCredentialPath(route.CredentialFile) {
				return nil, fmt.Errorf("gateway route %q credential path must be separate from Gateway and connector authority paths", route.ID)
			}
			var credentialInfo os.FileInfo
			credential, credentialInfo, err = readCredentialWithInfo(route.CredentialFile)
			if err != nil {
				return nil, fmt.Errorf("gateway route %q credential: %w", route.ID, err)
			}
			for _, reserved := range reservedFiles {
				if os.SameFile(credentialInfo, reserved) {
					return nil, fmt.Errorf("gateway route %q credential file must not alias Gateway or connector authority", route.ID)
				}
			}
			for _, prior := range routeCredentials {
				if os.SameFile(credentialInfo, prior) {
					return nil, fmt.Errorf("gateway route %q credential file must not be shared by inference routes", route.ID)
				}
			}
			routeCredentials = append(routeCredentials, credentialInfo)
		}
		loaded[route.ID] = loadedRoute{Route: route, base: base, credential: credential}
	}
	return loaded, nil
}

func (c Config) reservedRouteCredentialPath(path string) bool {
	for _, reserved := range []string{
		c.ServiceTokenFile, c.StateFile, c.EgressAuditFile, c.ControlSocket,
		c.ConnectorReceiptFile, c.ConnectorReceiptKeyFile,
	} {
		if reserved != "" && path == reserved {
			return true
		}
	}
	for _, connector := range c.Connectors {
		if connector.CredentialFile != "" && path == connector.CredentialFile {
			return true
		}
	}
	return pathWithin(path, c.GrantRoot)
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
	value, _, err := readCredentialWithInfo(path)
	return value, err
}

func readCredentialWithInfo(path string) (string, os.FileInfo, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", nil, err
	}
	if !validCredentialFileInfo(info) {
		return "", nil, errors.New("credential must be a bounded owner-only regular file")
	}
	// O_NONBLOCK is ignored for regular files but prevents a validated path
	// from being swapped to a FIFO that would hang Gateway between Lstat and
	// Open. The descriptor identity and metadata are checked before any read.
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", nil, err
	}
	defer file.Close()
	value, err := readOpenedCredential(info, file)
	if err != nil {
		return "", nil, err
	}
	final, err := file.Stat()
	if err != nil || !os.SameFile(info, final) || !validCredentialFileInfo(final) {
		return "", nil, errors.New("credential changed after reading")
	}
	return value, final, nil
}

func readOpenedCredential(expected os.FileInfo, file *os.File) (string, error) {
	opened, err := file.Stat()
	if err != nil || !os.SameFile(expected, opened) || !validCredentialFileInfo(opened) || opened.Size() != expected.Size() {
		return "", errors.New("credential changed while opening")
	}
	raw := make([]byte, int(opened.Size()))
	if _, err := io.ReadFull(file, raw); err != nil {
		return "", err
	}
	var extra [1]byte
	count, readErr := file.Read(extra[:])
	if count != 0 || !errors.Is(readErr, io.EOF) {
		return "", errors.New("credential changed while reading")
	}
	final, err := file.Stat()
	if err != nil || !os.SameFile(opened, final) || !validCredentialFileInfo(final) || final.Size() != opened.Size() {
		return "", errors.New("credential changed while reading")
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", errors.New("credential must contain one non-empty visible ASCII line")
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return "", errors.New("credential must contain one non-empty visible ASCII line")
		}
	}
	return value, nil
}

func validCredentialFileInfo(info os.FileInfo) bool {
	return info != nil && info.Mode().IsRegular() && info.Mode().Perm()&0o077 == 0 &&
		info.Size() > 0 && info.Size() <= maxCredentialBytes
}

func absoluteClean(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && !strings.ContainsRune(path, '\x00')
}

func bounded(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}
