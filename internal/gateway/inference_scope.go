package gateway

import (
	"net/http"
	"strings"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
)

const inferencePermitHeader = "X-Steward-Inference-Permit"

// inferenceTaskScope accepts the exact envelope already authenticated during
// service admission. It does not trust a task ID or create another authority.
// The ledger independently rechecks the live parent under its append lock, so
// a terminal task transition between this lookup and transport cannot leak a
// newly authorized provider call.
func (s *Server) inferenceTaskScope(request *http.Request, grant Grant) (connectorledger.Event, bool) {
	values := request.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		return connectorledger.Event{}, false
	}
	raw, err := decodeServiceTaskPermitHeader(strings.TrimPrefix(values[0], "Bearer "))
	if err != nil {
		return connectorledger.Event{}, false
	}
	permitDigest := dsse.Digest(raw)
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.grants[grant.GrantID]
	if !exists || !current.Active || !grantsEqual(current, grant) {
		return connectorledger.Event{}, false
	}
	identity, exists := s.serviceTaskPermits[permitDigest]
	if !exists {
		return connectorledger.Event{}, false
	}
	state, exists := s.serviceTasks[identity]
	event := state.Authorization
	if !exists || state.Terminal.Phase != "" || state.authorizationAmbiguous || state.dispatchAmbiguous || state.terminalUnavailable ||
		event.Kind != connectorledger.ServiceTask || event.TaskProtocol != TaskProtocolLifecycleV1 || event.TargetTaskDigest != "" ||
		event.PermitDigest != permitDigest || event.TaskDigest != identity || event.TenantID != grant.TenantID ||
		event.RuntimeRef != grant.RuntimeRef || event.CapsuleDigest != grant.CapsuleDigest || event.PolicyDigest != grant.PolicyDigest ||
		event.GrantID != grant.GrantID || event.ServiceID != grant.ServiceID || event.Generation != grant.Generation || event.RoutePolicyDigest != s.policyDigests[grant.GrantID] {
		return connectorledger.Event{}, false
	}
	return event, true
}
