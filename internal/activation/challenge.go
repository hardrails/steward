package activation

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"

	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	ChallengeSchemaV1  = "steward.activation-canary-challenge.v1"
	MaxChallengeBytes  = 64 << 10
	MaxTaskAuthorities = 8
)

var grantIDPattern = regexp.MustCompile(`^grant-[a-f0-9]{64}$`)

// TaskAuthorityPinV1 identifies a public task authority returned by the real
// Executor admission response. The private key remains outside the activation
// directory and node.
type TaskAuthorityPinV1 struct {
	KeyID           string `json:"key_id"`
	PublicKeySHA256 string `json:"public_key_sha256"`
}

// CanaryChallengeV1 is a bounded, unsigned handoff to the tenant signing
// workstation. It grants no authority; it correlates the exact admission,
// intent, service inventory, and request that `stewardctl task issue` must
// verify before the tenant signs a short-lived permit.
type CanaryChallengeV1 struct {
	SchemaVersion      string               `json:"schema_version"`
	ActivationID       string               `json:"activation_id"`
	PlanDigest         string               `json:"plan_digest"`
	ReleaseDigest      string               `json:"release_digest"`
	AdmissionDigest    string               `json:"admission_digest"`
	IntentDigest       string               `json:"intent_digest"`
	ServiceTrustDigest string               `json:"service_trust_digest"`
	RequestDigest      string               `json:"request_digest"`
	TenantID           string               `json:"tenant_id"`
	NodeID             string               `json:"node_id"`
	InstanceID         string               `json:"instance_id"`
	RuntimeRef         string               `json:"runtime_ref"`
	Generation         uint64               `json:"generation"`
	GrantID            string               `json:"grant_id"`
	ServiceID          string               `json:"service_id"`
	OperationID        string               `json:"operation_id"`
	TaskAuthorities    []TaskAuthorityPinV1 `json:"task_authorities"`
	CreatedAt          string               `json:"created_at"`
}

func ParseChallengeV1(raw []byte) (CanaryChallengeV1, error) {
	var challenge CanaryChallengeV1
	if err := dsse.DecodeStrictInto(raw, MaxChallengeBytes, &challenge); err != nil {
		return CanaryChallengeV1{}, fmt.Errorf("invalid activation canary challenge: %w", err)
	}
	if err := challenge.Validate(); err != nil {
		return CanaryChallengeV1{}, err
	}
	return challenge, nil
}

func MarshalChallengeV1(challenge CanaryChallengeV1) ([]byte, error) {
	if err := challenge.Validate(); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(challenge)
	if err != nil {
		return nil, err
	}
	if len(raw) > MaxChallengeBytes {
		return nil, fmt.Errorf("activation canary challenge exceeds %d bytes", MaxChallengeBytes)
	}
	return raw, nil
}

func ChallengeDigestV1(raw []byte) (string, error) {
	if _, err := ParseChallengeV1(raw); err != nil {
		return "", err
	}
	return dsse.Digest(raw), nil
}

func (challenge CanaryChallengeV1) Validate() error {
	if challenge.SchemaVersion != ChallengeSchemaV1 || !identifier(challenge.ActivationID) {
		return errors.New("invalid activation canary challenge identity")
	}
	for _, digest := range []string{
		challenge.PlanDigest,
		challenge.ReleaseDigest,
		challenge.AdmissionDigest,
		challenge.IntentDigest,
		challenge.ServiceTrustDigest,
		challenge.RequestDigest,
	} {
		if !sha256Digest(digest) {
			return errors.New("activation canary challenge contains an invalid digest")
		}
	}
	if !publicIdentity(challenge.TenantID, 128) || !publicIdentity(challenge.NodeID, 128) ||
		!publicIdentity(challenge.InstanceID, 256) || !runtimeRef(challenge.RuntimeRef) ||
		challenge.Generation == 0 || !grantIDPattern.MatchString(challenge.GrantID) {
		return errors.New("activation canary challenge contains an invalid runtime binding")
	}
	if challenge.ServiceID != agentrelease.HermesServiceID ||
		challenge.OperationID != agentrelease.HermesOperationID {
		return errors.New("activation canary challenge is not the closed Hermes operation")
	}
	if len(challenge.TaskAuthorities) == 0 || len(challenge.TaskAuthorities) > MaxTaskAuthorities {
		return errors.New("activation canary challenge has an invalid task-authority count")
	}
	for index, authority := range challenge.TaskAuthorities {
		if !identifier(authority.KeyID) || !sha256Digest(authority.PublicKeySHA256) ||
			index > 0 && challenge.TaskAuthorities[index-1].KeyID >= authority.KeyID {
			return errors.New("activation canary challenge task authorities must be valid, unique, and sorted")
		}
	}
	if _, ok := canonicalTimestamp(challenge.CreatedAt); !ok {
		return errors.New("activation canary challenge created_at must be canonical UTC RFC3339Nano")
	}
	return nil
}
