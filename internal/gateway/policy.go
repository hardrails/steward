package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
)

type routePolicyDocument struct {
	Version                     int                     `json:"version"`
	Inference                   *inferenceRoutePolicy   `json:"inference,omitempty"`
	Egress                      []egressRoutePolicy     `json:"egress,omitempty"`
	Connectors                  []connectorRoutePolicy  `json:"connectors,omitempty"`
	ServiceTask                 *serviceTaskRoutePolicy `json:"service_task,omitempty"`
	ConnectorReceiptBudgetBytes int64                   `json:"connector_receipt_budget_bytes,omitempty"`
}

type serviceTaskRoutePolicy struct {
	ServiceID   string                   `json:"service_id"`
	Authorities []actionAuthorityPolicy  `json:"authorities"`
	Operations  []serviceOperationPolicy `json:"operations"`
}

type serviceOperationPolicy struct {
	ServiceID           string `json:"service_id"`
	ID                  string `json:"id"`
	Method              string `json:"method"`
	Path                string `json:"path"`
	ContentType         string `json:"content_type"`
	MaxRequestBytes     int64  `json:"max_request_bytes"`
	MaxResponseBytes    int64  `json:"max_response_bytes"`
	MaxSeconds          int    `json:"max_seconds"`
	MaxPermitSeconds    int    `json:"max_permit_seconds"`
	TaskProtocol        string `json:"task_protocol,omitempty"`
	StatusPathPrefix    string `json:"status_path_prefix,omitempty"`
	StatusMaxSeconds    int    `json:"status_max_seconds,omitempty"`
	PollIntervalSeconds int    `json:"poll_interval_seconds,omitempty"`
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
	ID                     string                     `json:"id"`
	BaseURL                string                     `json:"base_url"`
	CredentialFile         string                     `json:"credential_file"`
	CredentialMode         CredentialMode             `json:"credential_mode"`
	CredentialConfigured   bool                       `json:"credential_configured"`
	CredentialEpoch        uint64                     `json:"credential_epoch,omitempty"`
	AllowInsecureHTTP      bool                       `json:"allow_insecure_http"`
	AllowedCIDRs           []string                   `json:"allowed_cidrs,omitempty"`
	MaxConcurrent          int                        `json:"max_concurrent"`
	MaxRequestBytes        int64                      `json:"max_request_bytes"`
	MaxResponseBytes       int64                      `json:"max_response_bytes"`
	MaxSeconds             int                        `json:"max_seconds"`
	MaxCallsPerGrant       int                        `json:"max_calls_per_grant"`
	ActionAuthorities      []actionAuthorityPolicy    `json:"action_authorities,omitempty"`
	ActionPermitNodeID     string                     `json:"action_permit_node_id,omitempty"`
	MaxActionPermitSeconds int                        `json:"max_action_permit_seconds,omitempty"`
	Operations             []connectorOperationPolicy `json:"operations"`
}

type actionAuthorityPolicy struct {
	KeyID           string `json:"key_id"`
	TenantID        string `json:"tenant_id"`
	PublicKeyDigest string `json:"public_key_digest"`
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
		left.CredentialEpoch != right.CredentialEpoch ||
		left.MaxRequestBytes != right.MaxRequestBytes || left.MaxResponseBytes != right.MaxResponseBytes ||
		left.MaxSeconds != right.MaxSeconds || left.MaxCallsPerGrant != right.MaxCallsPerGrant ||
		left.MaxActionPermitSeconds != right.MaxActionPermitSeconds ||
		left.permitNodeID != right.permitNodeID ||
		!slices.Equal(left.ActionAuthorityIDs, right.ActionAuthorityIDs) ||
		!slices.Equal(left.prefixes, right.prefixes) || len(left.operations) != len(right.operations) ||
		len(left.authorities) != len(right.authorities) {
		return false
	}
	for id, key := range left.authorities {
		if string(key) != string(right.authorities[id]) || left.authorityTenants[id] != right.authorityTenants[id] {
			return false
		}
	}
	for id, operation := range left.operations {
		if operation != right.operations[id] {
			return false
		}
	}
	return true
}

func sameServiceOperations(left, right map[string]ServiceOperation) bool {
	if len(left) != len(right) {
		return false
	}
	for id, operation := range left {
		if operation != right[id] {
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
func routePolicyDigest(grant Grant, routes map[string]loadedRoute, egressRoutes map[string]loadedEgressRoute, connectors map[string]loadedConnector, serviceOperations map[string]map[string]ServiceOperation, connectorReceiptBudget int64) string {
	if grant.RouteID == "" && len(grant.EgressRouteIDs) == 0 && len(grant.ConnectorIDs) == 0 && len(grant.TaskAuthorities) == 0 {
		return ""
	}
	document := routePolicyDocument{Version: 1}
	if len(grant.TaskAuthorities) > 0 {
		document.Version = 5
		document.ConnectorReceiptBudgetBytes = connectorReceiptBudget
		service := &serviceTaskRoutePolicy{ServiceID: grant.ServiceID}
		for _, authority := range grant.TaskAuthorities {
			public, _ := base64.StdEncoding.DecodeString(authority.PublicKey)
			sum := sha256.Sum256(public)
			service.Authorities = append(service.Authorities, actionAuthorityPolicy{
				KeyID: authority.KeyID, TenantID: grant.TenantID,
				PublicKeyDigest: "sha256:" + fmt.Sprintf("%x", sum[:]),
			})
		}
		operationIDs := make([]string, 0, len(serviceOperations[grant.ServiceID]))
		for id := range serviceOperations[grant.ServiceID] {
			operationIDs = append(operationIDs, id)
		}
		slices.Sort(operationIDs)
		for _, id := range operationIDs {
			operation := serviceOperations[grant.ServiceID][id]
			if operation.TaskProtocol != "" {
				document.Version = 6
			}
			service.Operations = append(service.Operations, serviceOperationPolicy(operation))
		}
		document.ServiceTask = service
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
		if document.Version < 3 {
			document.Version = 3
		}
		document.ConnectorReceiptBudgetBytes = connectorReceiptBudget
	}
	for _, id := range grant.ConnectorIDs {
		connector := connectors[id]
		policy := connectorRoutePolicy{
			ID: connector.ID, BaseURL: routeBaseURL(connector.base), CredentialFile: connector.CredentialFile,
			CredentialMode: connector.CredentialMode, CredentialConfigured: connector.credential != "",
			CredentialEpoch:   connector.CredentialEpoch,
			AllowInsecureHTTP: connector.AllowInsecureHTTP,
			MaxConcurrent:     connector.MaxConcurrent, MaxRequestBytes: connector.MaxRequestBytes,
			MaxResponseBytes: connector.MaxResponseBytes, MaxSeconds: connector.MaxSeconds,
			MaxCallsPerGrant: connector.MaxCallsPerGrant, ActionPermitNodeID: connector.permitNodeID,
			MaxActionPermitSeconds: connector.MaxActionPermitSeconds,
		}
		if len(connector.ActionAuthorityIDs) > 0 {
			if document.Version < 4 {
				document.Version = 4
			}
		}
		for _, keyID := range connector.ActionAuthorityIDs {
			sum := sha256.Sum256(connector.authorities[keyID])
			policy.ActionAuthorities = append(policy.ActionAuthorities, actionAuthorityPolicy{
				KeyID: keyID, TenantID: connector.authorityTenants[keyID],
				PublicKeyDigest: "sha256:" + fmt.Sprintf("%x", sum[:]),
			})
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
			policy.Operations = append(policy.Operations, connectorOperationPolicy(operation))
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
	budget, _ := s.config.connectorReceiptBudget(grant.TenantID)
	return routePolicyDigest(grant, s.routes, s.egressRoutes, s.connectors, s.serviceOperations, budget)
}

// ServiceOperationDigest binds a task permit to the complete non-secret
// operator policy for one exact service request.
func ServiceOperationDigest(operation ServiceOperation) string {
	raw, err := json.Marshal(serviceOperationPolicy(operation))
	if err != nil {
		return ""
	}
	hash := sha256.New()
	domain := "steward-service-operation-v1\x00"
	if operation.TaskProtocol != "" {
		domain = "steward-service-operation-v2\x00"
	}
	_, _ = hash.Write([]byte(domain))
	_, _ = hash.Write(raw)
	return "sha256:" + fmt.Sprintf("%x", hash.Sum(nil))
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
