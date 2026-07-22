package admission

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

func TestVerifyDelegatedCommandRequiresBothSignaturesAndExactScope(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	_, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tenantPublic, tenantPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	cleanupPublic, cleanupPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	policy := testPolicy(publisherPrivate.Public().(ed25519.PublicKey))
	policy.Tenants[0].CommandKeys = []CommandKey{{
		KeyID: "tenant-lifecycle", PublicKey: base64.StdEncoding.EncodeToString(tenantPublic),
		Operations: []string{"admit", "start", "stop"},
	}}
	policy.SiteCleanupCommandKeys = []CommandKey{{
		KeyID: "site-cleanup", PublicKey: base64.StdEncoding.EncodeToString(cleanupPublic),
		Operations: []string{"stop"},
	}}
	if err := policy.Validate(); err != nil {
		t.Fatal(err)
	}
	capsuleRaw := []byte(`{"signed":"capsule"}`)
	delegation := CommandDelegation{
		SchemaVersion: CommandDelegationSchemaV1, DelegationID: "deployment-1",
		TenantID: "tenant-a", ControllerKeyID: "controller-1",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          []string{"admit", "start", "stop"}, NodeIDs: []string{"node-a", "node-b"},
		Instances: []CommandDelegationInstance{
			{InstanceID: "analyst-1", LineageID: "lineage-1", MinInstanceGeneration: 10, MaxInstanceGeneration: 20},
			{InstanceID: "analyst-2", LineageID: "lineage-2", MinInstanceGeneration: 1, MaxInstanceGeneration: 1},
		},
		ClaimGeneration: 7,
		Admission: &CommandDelegationAdmissionTemplate{
			CapsuleDigest: dsse.Digest(capsuleRaw),
			Resources:     ResourceLimits{MemoryBytes: 512 << 20, CPUMillis: 500, PIDs: 64},
			Capabilities:  Capabilities{}, StateDisposition: "none",
		},
		IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	forkDelegation := delegation
	forkAdmission := *delegation.Admission
	forkDelegation.Admission = &forkAdmission
	forkDelegation.Operations = []string{"admit", "clone-state", "destroy", "purge", "renew", "start", "stop"}
	forkDelegation.NodeIDs = []string{"node-a"}
	forkDelegation.Instances = forkDelegation.Instances[:1]
	forkDelegation.Admission.Capabilities.State = true
	forkDelegation.Admission.StateDisposition = "resume"
	forkDelegation.IssuedAt = now.Format(time.RFC3339Nano)
	forkDelegation.ExpiresAt = now.Add(30*24*time.Hour + 4*time.Hour).Format(time.RFC3339Nano)
	if err := forkDelegation.Validate(now); err != nil {
		t.Fatalf("finite exact fork delegation rejected: %v", err)
	}
	notFork := forkDelegation
	notFork.Operations = []string{"admit", "destroy", "purge", "renew", "start", "stop"}
	if err := notFork.Validate(now); err == nil {
		t.Fatal("ordinary delegation exceeded the 24 hour lifetime")
	}
	delegationRaw := signDelegationForTest(t, delegation, "tenant-lifecycle", tenantPrivate)
	command := delegatedCommandForTest(now, delegationRaw)
	commandRaw := signDelegatedCommandForTest(t, command, controllerPrivate)
	verified, err := VerifyDelegatedCommand(commandRaw, delegationRaw, policy, now)
	if err != nil || verified.CommandID != command.CommandID {
		t.Fatalf("verify delegated command = (%+v, %v)", verified, err)
	}
	cleanupDelegation := delegation
	cleanupDelegation.Operations = []string{"stop"}
	cleanupDelegation.Admission = nil
	if _, err := VerifyCommandDelegation(
		signDelegationForTest(t, cleanupDelegation, "site-cleanup", cleanupPrivate), policy, now,
	); err == nil {
		t.Fatal("site cleanup key was accepted as tenant controller delegation authority")
	}

	for name, mutate := range map[string]func(*CommandStatement){
		"tenant":     func(value *CommandStatement) { value.TenantID = "tenant-b" },
		"node":       func(value *CommandStatement) { value.NodeID = "node-c" },
		"operation":  func(value *CommandStatement) { value.Kind = "destroy" },
		"instance":   func(value *CommandStatement) { value.InstanceID = "analyst-3" },
		"claim":      func(value *CommandStatement) { value.ClaimGeneration++ },
		"generation": func(value *CommandStatement) { value.InstanceGeneration = 21 },
		"context":    func(value *CommandStatement) { value.AuthorizationContextDigest = testDigest('f') },
		"embedded":   func(value *CommandStatement) { value.DelegationDSSEBase64 = "" },
		"issued": func(value *CommandStatement) {
			value.IssuedAt = now.Add(-2 * time.Minute).Format(time.RFC3339Nano)
		},
		"expires": func(value *CommandStatement) {
			value.ExpiresAt = now.Add(2 * time.Hour).Format(time.RFC3339Nano)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := command
			mutate(&candidate)
			raw := signDelegatedCommandForTest(t, candidate, controllerPrivate)
			if _, err := VerifyDelegatedCommand(raw, delegationRaw, policy, now); err == nil {
				t.Fatal("out-of-scope delegated command was accepted")
			}
		})
	}

	_, otherController, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyDelegatedCommand(
		signDelegatedCommandForTest(t, command, otherController), delegationRaw, policy, now,
	); err == nil {
		t.Fatal("command signed by another controller key was accepted")
	}
}

func TestDelegatedAdmissionBindsExactCapsule(t *testing.T) {
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	controllerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsuleRaw := []byte(`{"capsule":true}`)
	template := CommandDelegationAdmissionTemplate{
		CapsuleDigest: dsse.Digest(capsuleRaw),
		Resources:     ResourceLimits{MemoryBytes: 512 << 20, CPUMillis: 500, PIDs: 64},
		Capabilities:  Capabilities{}, StateDisposition: "none",
	}
	delegation := VerifiedCommandDelegation{Statement: CommandDelegation{
		SchemaVersion: CommandDelegationSchemaV1, DelegationID: "deployment-1",
		TenantID: "tenant-a", ControllerKeyID: "controller-1",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations:          []string{"admit"}, NodeIDs: []string{"node-a"},
		Instances: []CommandDelegationInstance{{
			InstanceID: "agent-1", LineageID: "lineage-1",
			MinInstanceGeneration: 1, MaxInstanceGeneration: 1,
		}},
		ClaimGeneration: 1, Admission: &template,
		IssuedAt:  now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}, EnvelopeDigest: testDigest('d')}
	payload, err := json.Marshal(struct {
		Capsule string         `json:"capsule_dsse_base64"`
		Intent  InstanceIntent `json:"intent"`
	}{Capsule: base64.StdEncoding.EncodeToString(capsuleRaw), Intent: InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-1", LineageID: "lineage-1",
		Generation: 1, CapsuleDigest: template.CapsuleDigest, Resources: template.Resources,
		Capabilities: template.Capabilities, StateDisposition: template.StateDisposition,
	}})
	if err != nil {
		t.Fatal(err)
	}
	command := delegatedCommandForTest(now, []byte("ignored"))
	command.Kind = "admit"
	command.InstanceID = "agent-1"
	command.ClaimGeneration = 1
	command.InstanceGeneration = 1
	command.AuthorizationContextDigest = delegation.EnvelopeDigest
	command.DelegationDSSEBase64 = base64.StdEncoding.EncodeToString([]byte("ignored"))
	command.Payload = payload
	if err := delegation.Authorize(command, []byte("ignored")); err == nil {
		// The synthetic envelope digest intentionally differs. Prove the digest
		// binding before testing the capsule-specific branch.
		t.Fatal("mismatched delegation envelope was accepted")
	}
	delegation.EnvelopeDigest = dsse.Digest([]byte("ignored"))
	command.AuthorizationContextDigest = delegation.EnvelopeDigest
	if err := delegation.Authorize(command, []byte("ignored")); err != nil {
		t.Fatalf("exact delegated capsule: %v", err)
	}
	payload = []byte(strings.ReplaceAll(string(payload), base64.StdEncoding.EncodeToString(capsuleRaw), base64.StdEncoding.EncodeToString([]byte("other"))))
	command.Payload = payload
	if err := delegation.Authorize(command, []byte("ignored")); err == nil {
		t.Fatal("different delegated capsule was accepted")
	}
	command.Payload = mustDelegatedAdmissionPayload(t, capsuleRaw, InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-1", LineageID: "lineage-1",
		Generation: 1, CapsuleDigest: template.CapsuleDigest, Resources: ResourceLimits{
			MemoryBytes: template.Resources.MemoryBytes + 1, CPUMillis: template.Resources.CPUMillis, PIDs: template.Resources.PIDs,
		}, Capabilities: template.Capabilities, StateDisposition: template.StateDisposition,
	})
	if err := delegation.Authorize(command, []byte("ignored")); err == nil {
		t.Fatal("different delegated resources were accepted")
	}
}

func TestCommandDelegationPlacementRequiresCanonicalFiniteConstraints(t *testing.T) {
	valid := CommandDelegationPlacement{
		RequiredIsolation: "gvisor",
		RequiredLabels: []CommandDelegationLabel{
			{Key: "accelerator", Value: "gpu"},
			{Key: "region", Value: "west"},
		},
		PreferredLabels: []CommandDelegationLabel{
			{Key: "rack", Value: "r1"},
			{Key: "zone", Value: "west-a"},
		},
		SpreadBy:    "zone",
		Tolerations: []string{"dedicated", "gpu"},
	}
	if !validCommandDelegationPlacement(valid) {
		t.Fatal("valid placement was rejected")
	}
	for _, test := range []struct {
		name   string
		mutate func(*CommandDelegationPlacement)
	}{
		{"isolation", func(value *CommandDelegationPlacement) { value.RequiredIsolation = "runc" }},
		{"nil labels", func(value *CommandDelegationPlacement) { value.RequiredLabels = nil }},
		{"unsorted labels", func(value *CommandDelegationPlacement) {
			value.RequiredLabels[0], value.RequiredLabels[1] = value.RequiredLabels[1], value.RequiredLabels[0]
		}},
		{"empty label", func(value *CommandDelegationPlacement) { value.RequiredLabels[0].Key = "" }},
		{"invalid label", func(value *CommandDelegationPlacement) { value.RequiredLabels[0].Value = "gpu pool" }},
		{"unsorted preferred labels", func(value *CommandDelegationPlacement) {
			value.PreferredLabels[0], value.PreferredLabels[1] = value.PreferredLabels[1], value.PreferredLabels[0]
		}},
		{"invalid preferred label", func(value *CommandDelegationPlacement) { value.PreferredLabels[0].Value = "rack one" }},
		{"invalid spread label", func(value *CommandDelegationPlacement) { value.SpreadBy = "zone name" }},
		{"nil tolerations", func(value *CommandDelegationPlacement) { value.Tolerations = nil }},
		{"duplicate toleration", func(value *CommandDelegationPlacement) { value.Tolerations[1] = "dedicated" }},
		{"empty toleration", func(value *CommandDelegationPlacement) { value.Tolerations[0] = "" }},
		{"invalid toleration", func(value *CommandDelegationPlacement) { value.Tolerations[0] = "gpu pool" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := valid
			candidate.RequiredLabels = append([]CommandDelegationLabel{}, valid.RequiredLabels...)
			candidate.PreferredLabels = append([]CommandDelegationLabel{}, valid.PreferredLabels...)
			candidate.Tolerations = append([]string{}, valid.Tolerations...)
			test.mutate(&candidate)
			if validCommandDelegationPlacement(candidate) {
				t.Fatal("invalid placement was accepted")
			}
		})
	}
}

func delegatedCommandForTest(now time.Time, delegationRaw []byte) CommandStatement {
	return CommandStatement{
		SchemaVersion: CommandSchemaV2, CommandID: "controller-command-1",
		AuthorizationContextDigest: dsse.Digest(delegationRaw),
		DelegationDSSEBase64:       base64.StdEncoding.EncodeToString(delegationRaw),
		TenantID:                   "tenant-a", NodeID: "node-a", InstanceID: "analyst-1",
		RuntimeRef: "uplink:v2:8:tenant-a:6:node-a:analyst-1", Kind: "start",
		ClaimGeneration: 7, InstanceGeneration: 11, CommandSequence: 1,
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(10 * time.Minute).Format(time.RFC3339Nano),
		Payload: json.RawMessage(`{}`),
	}
}

func mustDelegatedAdmissionPayload(t *testing.T, capsule []byte, intent InstanceIntent) []byte {
	t.Helper()
	payload, err := json.Marshal(struct {
		Capsule string         `json:"capsule_dsse_base64"`
		Intent  InstanceIntent `json:"intent"`
	}{Capsule: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func signDelegationForTest(t *testing.T, statement CommandDelegation, keyID string, private ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := MarshalCommandDelegation(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(CommandDelegationPayloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func signDelegatedCommandForTest(t *testing.T, statement CommandStatement, private ed25519.PrivateKey) []byte {
	t.Helper()
	payload, err := json.Marshal(statement)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(CommandPayloadType, payload, "controller-1", private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
