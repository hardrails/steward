package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/hardrails/steward/internal/connectorledger"
)

func hermesStopOperation(operation ServiceOperation) bool {
	return operation.ID == "hermes.stop" && operation.Method == http.MethodPost &&
		operation.Path == "/steward/v1/run-stop" && operation.ContentType == "application/json" &&
		operation.MaxRequestBytes == 49 && operation.TaskProtocol == TaskProtocolLifecycleV1 &&
		operation.StatusPathPrefix == "/v1/runs/"
}

// linkStopTask treats a target as a reference, never a new run allocation. The
// ledger repeats the identity fence under its append lock and on every restart.
func (s *Server) linkStopTask(event connectorledger.Event, operation ServiceOperation, body []byte) (connectorledger.Event, error) {
	var target struct {
		RunID string `json:"run_id"`
	}
	if !hermesStopOperation(operation) || json.Unmarshal(body, &target) != nil {
		return connectorledger.Event{}, errors.New("invalid native stop request")
	}
	exact, err := connectorledger.HermesStopRequest(target.RunID)
	if err != nil || !bytes.Equal(body, exact) {
		return connectorledger.Event{}, errors.New("stop request differs from its canonical target")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, state := range s.serviceTasks {
		parent := state.Dispatch
		if parent.Phase != connectorledger.Dispatch || parent.TargetTaskDigest != "" ||
			parent.RunID != target.RunID || parent.GrantID != event.GrantID ||
			parent.ServiceID != event.ServiceID || parent.TenantID != event.TenantID ||
			parent.RuntimeRef != event.RuntimeRef || parent.Generation != event.Generation ||
			parent.CapsuleDigest != event.CapsuleDigest || parent.PolicyDigest != event.PolicyDigest ||
			parent.RoutePolicyDigest != event.RoutePolicyDigest || parent.AuthorityKeyID != event.AuthorityKeyID ||
			state.dispatchAmbiguous || state.authorizationAmbiguous {
			continue
		}
		event.TargetRunID, event.TargetTaskDigest = target.RunID, parent.TaskDigest
		return event, nil
	}
	return connectorledger.Event{}, errors.New("stop target has no retained dispatch")
}
