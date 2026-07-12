package gateway

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
)

type routePolicyDocument struct {
	Version   int                   `json:"version"`
	Inference *inferenceRoutePolicy `json:"inference,omitempty"`
	Egress    []egressRoutePolicy   `json:"egress,omitempty"`
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
func routePolicyDigest(grant Grant, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute) string {
	if grant.RouteID == "" && len(grant.EgressRouteIDs) == 0 {
		return ""
	}
	document := routePolicyDocument{Version: 1}
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
	raw, err := json.Marshal(document)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(raw)
	return "sha256:" + fmt.Sprintf("%x", digest[:])
}

func (s *Server) routePolicyDigestLocked(grant Grant) string {
	return routePolicyDigest(grant, s.routes, s.egressRoutes)
}

// routeCredentialBindingDigest is retained only in the owner-readable state
// file. It detects credential-content replacement across process restarts
// without exposing a bearer-token hash through the public inspection API.
func routeCredentialBindingDigest(grant Grant, routes map[string]loadedRoute) string {
	if grant.RouteID == "" {
		return ""
	}
	route := routes[grant.RouteID]
	digest := sha256.New()
	_, _ = digest.Write([]byte("steward-gateway-route-credential-v1\x00"))
	_, _ = digest.Write([]byte(grant.RouteID))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write([]byte(route.credential))
	return "sha256:" + fmt.Sprintf("%x", digest.Sum(nil))
}
