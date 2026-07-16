package activation

import (
	"reflect"
	"strings"
	"testing"
)

func TestCanaryChallengeRoundTrip(t *testing.T) {
	challenge := validChallenge()
	raw, err := MarshalChallengeV1(challenge)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseChallengeV1(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(parsed, challenge) {
		t.Fatalf("parsed challenge = %#v, want %#v", parsed, challenge)
	}
	digest, err := ChallengeDigestV1(raw)
	if err != nil || !strings.HasPrefix(digest, "sha256:") {
		t.Fatalf("challenge digest = %q, %v", digest, err)
	}
}

func TestCanaryChallengeRejectsSubstitution(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*CanaryChallengeV1)
	}{
		{"schema", func(challenge *CanaryChallengeV1) { challenge.SchemaVersion = "other" }},
		{"admission digest", func(challenge *CanaryChallengeV1) { challenge.AdmissionDigest = "bad" }},
		{"tenant", func(challenge *CanaryChallengeV1) { challenge.TenantID = "" }},
		{"runtime", func(challenge *CanaryChallengeV1) { challenge.RuntimeRef = "executor-other" }},
		{"generation", func(challenge *CanaryChallengeV1) { challenge.Generation = 0 }},
		{"grant", func(challenge *CanaryChallengeV1) { challenge.GrantID = "grant-other" }},
		{"service", func(challenge *CanaryChallengeV1) { challenge.ServiceID = "other" }},
		{"operation", func(challenge *CanaryChallengeV1) { challenge.OperationID = "other.run" }},
		{"no authority", func(challenge *CanaryChallengeV1) { challenge.TaskAuthorities = nil }},
		{"duplicate authority", func(challenge *CanaryChallengeV1) {
			challenge.TaskAuthorities = append(challenge.TaskAuthorities, challenge.TaskAuthorities[0])
		}},
		{"unsorted authority", func(challenge *CanaryChallengeV1) {
			challenge.TaskAuthorities = []TaskAuthorityPinV1{
				{KeyID: "z", PublicKeySHA256: testSHA256('a')},
				{KeyID: "a", PublicKeySHA256: testSHA256('b')},
			}
		}},
		{"time", func(challenge *CanaryChallengeV1) { challenge.CreatedAt = "later" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			challenge := validChallenge()
			test.mutate(&challenge)
			if err := challenge.Validate(); err == nil {
				t.Fatal("invalid challenge accepted")
			}
		})
	}
}

func TestCanaryChallengeStrictDecode(t *testing.T) {
	raw, err := MarshalChallengeV1(validChallenge())
	if err != nil {
		t.Fatal(err)
	}
	duplicate := strings.Replace(
		string(raw),
		`"activation_id":"activation-001"`,
		`"activation_id":"activation-001","activation_id":"activation-002"`,
		1,
	)
	if _, err := ParseChallengeV1([]byte(duplicate)); err == nil {
		t.Fatal("duplicate challenge field accepted")
	}
	unknown := strings.Replace(string(raw), `}`, `,"extra":true}`, 1)
	if _, err := ParseChallengeV1([]byte(unknown)); err == nil {
		t.Fatal("unknown challenge field accepted")
	}
	if _, err := ParseChallengeV1(make([]byte, MaxChallengeBytes+1)); err == nil {
		t.Fatal("oversized challenge accepted")
	}
	if _, err := ChallengeDigestV1([]byte("{}")); err == nil {
		t.Fatal("invalid challenge produced a digest")
	}
}

func validChallenge() CanaryChallengeV1 {
	return CanaryChallengeV1{
		SchemaVersion:      ChallengeSchemaV1,
		ActivationID:       "activation-001",
		PlanDigest:         testSHA256('a'),
		ReleaseDigest:      testSHA256('b'),
		AdmissionDigest:    testSHA256('c'),
		IntentDigest:       testSHA256('d'),
		ServiceTrustDigest: testSHA256('e'),
		RequestDigest:      testSHA256('f'),
		TenantID:           "tenant-a",
		NodeID:             "node-a",
		InstanceID:         "agent-a",
		RuntimeRef:         "executor-" + strings.Repeat("1", 64),
		Generation:         1,
		GrantID:            "grant-" + strings.Repeat("2", 64),
		ServiceID:          "hermes-api",
		OperationID:        "hermes.run",
		TaskAuthorities: []TaskAuthorityPinV1{{
			KeyID: "task-key", PublicKeySHA256: testSHA256('9'),
		}},
		CreatedAt: "2026-07-16T12:00:00.123456789Z",
	}
}
