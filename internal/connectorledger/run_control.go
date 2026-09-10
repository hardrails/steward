package connectorledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
)

var hermesRunID = regexp.MustCompile(`^run_[0-9a-f]{32}$`)

// HermesStopRequest is the closed, canonical request whose tenant signature
// authorizes one exact target. It is not an agent-supplied ownership assertion.
func HermesStopRequest(runID string) ([]byte, error) {
	if !hermesRunID.MatchString(runID) {
		return nil, errors.New("stop target is not a native Hermes run identity")
	}
	return []byte(`{"run_id":"` + runID + `"}`), nil
}

func validateRunControl(event Event) error {
	if event.TargetTaskDigest == "" && event.TargetRunID == "" {
		return nil
	}
	body, err := HermesStopRequest(event.TargetRunID)
	if err != nil {
		return err
	}
	hash := sha256.Sum256(body)
	if event.Kind != ServiceTask || event.TaskProtocol != TaskProtocolLifecycleV1 ||
		event.OperationID != "hermes.stop" || !digest(event.TargetTaskDigest) ||
		event.TargetTaskDigest == event.TaskDigest || event.Phase == Deny ||
		event.RequestBytes != int64(len(body)) || event.RequestDigest != "sha256:"+hex.EncodeToString(hash[:]) ||
		(event.RunID != "" && event.RunID != event.TargetRunID) {
		return errors.New("stop receipt does not bind one canonical request and original task")
	}
	return nil
}

func validateRunControlOwner(event Event, owners map[runOwnership]Event) error {
	if event.TargetTaskDigest == "" {
		return nil
	}
	owner, exists := owners[runOwnership{grantID: event.GrantID, serviceID: event.ServiceID, runID: event.TargetRunID}]
	if !exists || owner.TaskDigest != event.TargetTaskDigest || owner.TargetTaskDigest != "" ||
		owner.Kind != ServiceTask || owner.TaskProtocol != TaskProtocolLifecycleV1 ||
		owner.TenantID != event.TenantID || owner.RuntimeRef != event.RuntimeRef ||
		owner.CapsuleDigest != event.CapsuleDigest || owner.PolicyDigest != event.PolicyDigest ||
		owner.RoutePolicyDigest != event.RoutePolicyDigest || owner.Generation != event.Generation ||
		owner.AuthorityKeyID != event.AuthorityKeyID {
		return errors.New("stop receipt has no matching previously dispatched task")
	}
	return nil
}
