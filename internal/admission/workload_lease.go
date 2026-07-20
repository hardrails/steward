package admission

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	WorkloadLeaseSchemaV1 = "steward.workload-lease.v1"

	// MaxWorkloadLeaseDuration bounds how long an isolated Executor can retain
	// managed workload authority after one accepted renewal.
	MaxWorkloadLeaseDuration = 5 * time.Minute

	// CommandClockSkew is the signed-command clock tolerance. Control waits at
	// least this long beyond the last accepted workload lease before replacement.
	CommandClockSkew = 2 * time.Minute
)

// WorkloadLease is the exact payload of a signed renew command. Its surrounding
// command binds tenant, node, instance, generation, sequence, and delegation.
type WorkloadLease struct {
	SchemaVersion string `json:"schema_version"`
	ExpiresAt     string `json:"expires_at"`
}

// DecodeWorkloadLease strictly decodes one bounded canonical lease payload.
// Passing a zero observation time validates shape only; command validation
// separately binds the expiry to the signed issue and command-expiry window.
func DecodeWorkloadLease(raw json.RawMessage, observedAt time.Time) (WorkloadLease, error) {
	var lease WorkloadLease
	if err := dsse.DecodeStrictInto(raw, maxCommandPayloadBytes, &lease); err != nil ||
		lease.SchemaVersion != WorkloadLeaseSchemaV1 {
		return WorkloadLease{}, errors.New("invalid workload lease payload")
	}
	expires, err := time.Parse(time.RFC3339Nano, lease.ExpiresAt)
	if err != nil || expires.IsZero() || lease.ExpiresAt != expires.UTC().Format(time.RFC3339Nano) {
		return WorkloadLease{}, errors.New("invalid workload lease expiry")
	}
	if !observedAt.IsZero() && (!expires.After(observedAt) ||
		expires.After(observedAt.Add(MaxWorkloadLeaseDuration+CommandClockSkew))) {
		return WorkloadLease{}, errors.New("workload lease expiry is outside its local bound")
	}
	return lease, nil
}
