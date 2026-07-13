package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
)

type routePolicyDocument struct {
	Version    int                    `json:"version"`
	Inference  *inferenceRoutePolicy  `json:"inference,omitempty"`
	Egress     []egressRoutePolicy    `json:"egress,omitempty"`
	Connectors []connectorRoutePolicy `json:"connectors,omitempty"`
}

type inferenceRoutePolicy struct {
	ID                   string `json:"id"`
	ModelAlias           string `json:"model_alias"`
	BaseURL              string `json:"base_url"`
	CredentialFile       string `json:"credential_file,omitempty"`
	CredentialConfigured bool   `json:"credential_configured"`
	MaxConcurrent        int    `json:"max_concurrent"`
}

type egressRoutePolicy struct {
	ID               string                    `json:"id"`
	Destinations     []egressDestinationPolicy `json:"destinations"`
	MaxConcurrent    int                       `json:"max_concurrent"`
	MaxRequestBytes  int64                     `json:"max_request_bytes"`
	MaxResponseBytes int64                     `json:"max_response_bytes"`
	MaxTunnelSeconds int                       `json:"max_tunnel_seconds"`
}

type egressDestinationPolicy struct {
	Host         string   `json:"host"`
	Ports        []int    `json:"ports"`
	AllowedCIDRs []string `json:"allowed_cidrs,omitempty"`
}

type connectorRoutePolicy struct {
	ID                   string                     `json:"id"`
	BaseURL              string                     `json:"base_url"`
	CredentialFile       string                     `json:"credential_file"`
	CredentialMode       CredentialMode             `json:"credential_mode"`
	CredentialConfigured bool                       `json:"credential_configured"`
	AllowInsecureHTTP    bool                       `json:"allow_insecure_http"`
	AllowedCIDRs         []string                   `json:"allowed_cidrs,omitempty"`
	MaxConcurrent        int                        `json:"max_concurrent"`
	MaxRequestBytes      int64                      `json:"max_request_bytes"`
	MaxResponseBytes     int64                      `json:"max_response_bytes"`
	MaxSeconds           int                        `json:"max_seconds"`
	MaxCallsPerGrant     int                        `json:"max_calls_per_grant"`
	Operations           []connectorOperationPolicy `json:"operations"`
}

type connectorOperationPolicy struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Path   string `json:"path"`
}

func sameLoadedRoute(left, right loadedRoute) bool {
	return left.Route == right.Route && routeBaseURL(left.base) == routeBaseURL(right.base) && left.credential == right.credential
}

func sameLoadedEgressRoute(left, right loadedEgressRoute) bool {
	if left.ID != right.ID || left.MaxConcurrent != right.MaxConcurrent || left.MaxRequestBytes != right.MaxRequestBytes ||
		left.MaxResponseBytes != right.MaxResponseBytes || left.MaxTunnelSeconds != right.MaxTunnelSeconds ||
		len(left.destinations) != len(right.destinations) {
		return false
	}
	for index := range left.destinations {
		leftDestination, rightDestination := left.destinations[index], right.destinations[index]
		if leftDestination.Host != rightDestination.Host || !slices.Equal(leftDestination.Ports, rightDestination.Ports) ||
			!slices.Equal(leftDestination.prefixes, rightDestination.prefixes) {
			return false
		}
	}
	return true
}

func sameLoadedConnector(left, right loadedConnector) bool {
	if left.ID != right.ID || routeBaseURL(left.base) != routeBaseURL(right.base) ||
		left.CredentialFile != right.CredentialFile || left.CredentialMode != right.CredentialMode ||
		left.AllowInsecureHTTP != right.AllowInsecureHTTP ||
		left.credential != right.credential || left.MaxConcurrent != right.MaxConcurrent ||
		left.MaxRequestBytes != right.MaxRequestBytes || left.MaxResponseBytes != right.MaxResponseBytes ||
		left.MaxSeconds != right.MaxSeconds || left.MaxCallsPerGrant != right.MaxCallsPerGrant ||
		!slices.Equal(left.prefixes, right.prefixes) || len(left.operations) != len(right.operations) {
		return false
	}
	for id, operation := range left.operations {
		if operation != right.operations[id] {
			return false
		}
	}
	return true
}

func routeBaseURL(value *url.URL) string {
	if value == nil {
		return ""
	}
	return value.String()
}

// routePolicyDigest identifies the non-secret route policy bound to a grant.
// Credential presence and file identity are included, but credential contents
// are deliberately excluded so the inspection API cannot become an offline
// oracle for weak operator-provided bearer tokens.
func routePolicyDigest(grant Grant, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute, connectorMaps ...map[string]loadedConnector) string {
	if grant.RouteID == "" && len(grant.EgressRouteIDs) == 0 && len(grant.ConnectorIDs) == 0 {
		return ""
	}
	document := routePolicyDocument{Version: 1}
	var connectors map[string]loadedConnector
	if len(connectorMaps) > 0 {
		connectors = connectorMaps[0]
	}
	if grant.RouteID != "" {
		route := routes[grant.RouteID]
		document.Inference = &inferenceRoutePolicy{
			ID: route.ID, ModelAlias: grant.ModelAlias, BaseURL: routeBaseURL(route.base), CredentialFile: route.CredentialFile,
			CredentialConfigured: route.credential != "", MaxConcurrent: route.MaxConcurrent,
		}
	}
	for _, id := range grant.EgressRouteIDs {
		route := egressRoutes[id]
		policy := egressRoutePolicy{ID: route.ID, MaxConcurrent: route.MaxConcurrent, MaxRequestBytes: route.MaxRequestBytes,
			MaxResponseBytes: route.MaxResponseBytes, MaxTunnelSeconds: route.MaxTunnelSeconds}
		for _, destination := range route.destinations {
			item := egressDestinationPolicy{Host: destination.Host, Ports: append([]int(nil), destination.Ports...)}
			for _, prefix := range destination.prefixes {
				item.AllowedCIDRs = append(item.AllowedCIDRs, prefix.String())
			}
			policy.Destinations = append(policy.Destinations, item)
		}
		document.Egress = append(document.Egress, policy)
	}
	if len(grant.ConnectorIDs) > 0 {
		document.Version = 2
	}
	for _, id := range grant.ConnectorIDs {
		connector := connectors[id]
		policy := connectorRoutePolicy{
			ID: connector.ID, BaseURL: routeBaseURL(connector.base), CredentialFile: connector.CredentialFile,
			CredentialMode: connector.CredentialMode, CredentialConfigured: connector.credential != "",
			AllowInsecureHTTP: connector.AllowInsecureHTTP,
			MaxConcurrent:     connector.MaxConcurrent, MaxRequestBytes: connector.MaxRequestBytes,
			MaxResponseBytes: connector.MaxResponseBytes, MaxSeconds: connector.MaxSeconds,
			MaxCallsPerGrant: connector.MaxCallsPerGrant,
		}
		for _, prefix := range connector.prefixes {
			policy.AllowedCIDRs = append(policy.AllowedCIDRs, prefix.String())
		}
		operationIDs := make([]string, 0, len(connector.operations))
		for operationID := range connector.operations {
			operationIDs = append(operationIDs, operationID)
		}
		slices.Sort(operationIDs)
		for _, operationID := range operationIDs {
			operation := connector.operations[operationID]
			policy.Operations = append(policy.Operations, connectorOperationPolicy{
				ID: operation.ID, Method: operation.Method, Path: operation.Path,
			})
		}
		document.Connectors = append(document.Connectors, policy)
	}
	raw, err := json.Marshal(document)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + fmt.Sprintf("%x", digest[:])
}

func (s *Server) routePolicyDigestLocked(grant Grant) string {
	return routePolicyDigest(grant, s.routes, s.egressRoutes, s.connectors)
}

// routeCredentialBindingDigest is retained only in the owner-readable state
// file. It detects credential-content replacement across process restarts
// without exposing a bearer-token hash through the public inspection API.
func routeCredentialBindingDigest(grant Grant, routes map[string]loadedRoute, connectorMaps ...map[string]loadedConnector) string {
	if grant.RouteID == "" && len(grant.ConnectorIDs) == 0 {
		return ""
	}
	if len(grant.ConnectorIDs) == 0 {
		route := routes[grant.RouteID]
		digest := sha256.New()
		_, _ = digest.Write([]byte("steward-gateway-route-credential-v1\x00"))
		_, _ = digest.Write([]byte(grant.RouteID))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(route.credential))
		return "sha256:" + fmt.Sprintf("%x", digest.Sum(nil))
	}
	var connectors map[string]loadedConnector
	if len(connectorMaps) > 0 {
		connectors = connectorMaps[0]
	}
	route := routes[grant.RouteID]
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-gateway-route-credential-v2\x00"))
	_, _ = digest.Write([]byte("inference\x00"))
	_, _ = digest.Write([]byte(grant.RouteID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(route.credential))
	for _, id := range grant.ConnectorIDs {
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte("connector\x00"))
		_, _ = digest.Write([]byte(id))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write([]byte(connectors[id].credential))
	}
	return "sha256:" + fmt.Sprintf("%x", digest.Sum(nil))
}
