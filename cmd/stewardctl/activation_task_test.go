package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/dsse"
)

type activationTaskFixture struct {
	taskRaw         []byte
	serviceTrustRaw []byte
	requestRaw      []byte
	challenge       activation.CanaryChallengeV1
	admitted        permitAdmission
	inputs          verifiedActivationInputs
}

func TestVerifyActivationTaskAuthenticatesHistoricalExactBundle(t *testing.T) {
	fixture := newActivationTaskFixture(t)
	timeNow = func() time.Time { return fixtureTime().Add(24 * time.Hour) }
	verified, err := verifyActivationTask(
		fixture.taskRaw,
		fixture.challenge,
		fixture.admitted,
		fixture.inputs,
		fixture.serviceTrustRaw,
		fixture.requestRaw,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.Verified.Statement.RuntimeRef != fixture.admitted.RuntimeRef ||
		verified.Verified.Statement.RequestDigest != dsse.Digest(fixture.requestRaw) ||
		verified.Verified.Statement.ServiceID != agentrelease.HermesServiceID {
		t.Fatalf("verified activation task = %#v", verified)
	}
}

func TestVerifyActivationTaskRejectsSubstitutions(t *testing.T) {
	tests := map[string]func(*activationTaskFixture){
		"task bytes": func(fixture *activationTaskFixture) {
			fixture.taskRaw[len(fixture.taskRaw)-2] ^= 1
		},
		"request bytes": func(fixture *activationTaskFixture) {
			fixture.requestRaw = append(fixture.requestRaw, ' ')
		},
		"runtime": func(fixture *activationTaskFixture) {
			fixture.admitted.RuntimeRef = "executor-" + strings.Repeat("f", 64)
		},
		"authority pin": func(fixture *activationTaskFixture) {
			fixture.challenge.TaskAuthorities[0].PublicKeySHA256 = digest('f')
		},
		"admission digest": func(fixture *activationTaskFixture) {
			fixture.challenge.AdmissionDigest = digest('f')
		},
		"admitted authority": func(fixture *activationTaskFixture) {
			fixture.admitted.TaskAuthorities[0].PublicKey = fixture.admitted.TaskAuthorities[0].PublicKey[:len(fixture.admitted.TaskAuthorities[0].PublicKey)-1] + "A"
		},
		"service inventory": func(fixture *activationTaskFixture) {
			var inventory serviceTrustInventory
			_ = json.Unmarshal(fixture.serviceTrustRaw, &inventory)
			inventory.NodeID = "node-b"
			fixture.serviceTrustRaw, _ = json.Marshal(inventory)
			fixture.challenge.ServiceTrustDigest = dsse.Digest(fixture.serviceTrustRaw)
		},
		"permit outlives capsule": func(fixture *activationTaskFixture) {
			fixture.inputs.release.Capsule.ExpiresAt = fixtureTime().
				Add(time.Minute).Format(time.RFC3339)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			fixture := newActivationTaskFixture(t)
			mutate(&fixture)
			if _, err := verifyActivationTask(
				fixture.taskRaw,
				fixture.challenge,
				fixture.admitted,
				fixture.inputs,
				fixture.serviceTrustRaw,
				fixture.requestRaw,
			); err == nil {
				t.Fatal("substituted activation task accepted")
			}
		})
	}
}

func newActivationTaskFixture(t *testing.T) activationTaskFixture {
	t.Helper()
	fixture := newTaskCLIFixture(t)
	activationID := "activation-task-test"
	request, err := agentrelease.BuildCanaryRequest(
		agentrelease.RequestRecipe{
			Input:           agentrelease.HermesWorkspaceAuditInput,
			SessionIDPrefix: agentrelease.HermesSessionIDPrefix,
		},
		activationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	fixture.request = request
	if err := os.WriteFile(fixture.requestPath, request, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixtureTime()
	fixture.issue(t)
	taskRaw, err := os.ReadFile(fixture.bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	serviceTrustRaw, err := os.ReadFile(fixture.trustPath)
	if err != nil {
		t.Fatal(err)
	}
	releaseDigest := digest('7')
	planRaw := []byte(`{"fixture":"activation-plan"}`)
	inputs := verifiedActivationInputs{
		planRaw: planRaw,
		plan: activation.PlanV1{
			ActivationID:  activationID,
			ReleaseDigest: releaseDigest,
		},
		release: agentrelease.Verified{
			EnvelopeDigest:        releaseDigest,
			CapsuleEnvelopeDigest: fixture.admitted.CapsuleDigest,
			Release: agentrelease.Release{
				Canary: agentrelease.Canary{
					Kind:        agentrelease.CanaryKindHermesWorkspaceAuditV1,
					ServiceID:   agentrelease.HermesServiceID,
					OperationID: agentrelease.HermesOperationID,
					Request: agentrelease.RequestRecipe{
						Input:           agentrelease.HermesWorkspaceAuditInput,
						SessionIDPrefix: agentrelease.HermesSessionIDPrefix,
					},
				},
			},
		},
		intent: fixture.intent,
	}
	inputs.release.Capsule.ExpiresAt = fixture.now.
		Add(10 * time.Minute).Format(time.RFC3339)
	pins, err := activationTaskAuthorities(fixture.admitted)
	if err != nil {
		t.Fatal(err)
	}
	admissionRaw, err := json.Marshal(fixture.admitted)
	if err != nil {
		t.Fatal(err)
	}
	challenge := activation.CanaryChallengeV1{
		SchemaVersion:      activation.ChallengeSchemaV1,
		ActivationID:       activationID,
		PlanDigest:         dsse.Digest(planRaw),
		ReleaseDigest:      releaseDigest,
		AdmissionDigest:    dsse.Digest(admissionRaw),
		IntentDigest:       dsse.Digest(inputs.intentRaw),
		ServiceTrustDigest: dsse.Digest(serviceTrustRaw),
		RequestDigest:      dsse.Digest(request),
		TenantID:           fixture.intent.TenantID,
		NodeID:             fixture.intent.NodeID,
		InstanceID:         fixture.intent.InstanceID,
		RuntimeRef:         fixture.admitted.RuntimeRef,
		Generation:         fixture.intent.Generation,
		GrantID:            fixture.admitted.GrantID,
		ServiceID:          agentrelease.HermesServiceID,
		OperationID:        agentrelease.HermesOperationID,
		TaskAuthorities:    pins,
		CreatedAt:          fixture.now.Format(time.RFC3339Nano),
	}
	if err := challenge.Validate(); err != nil {
		t.Fatal(err)
	}
	return activationTaskFixture{
		taskRaw:         taskRaw,
		serviceTrustRaw: serviceTrustRaw,
		requestRaw:      request,
		challenge:       challenge,
		admitted:        fixture.admitted,
		inputs:          inputs,
	}
}

func fixtureTime() time.Time {
	return time.Date(2026, 7, 16, 19, 0, 0, 0, time.UTC)
}
