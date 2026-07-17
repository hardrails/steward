package rolloutdriver

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/executor"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/ocibundle"
	"github.com/hardrails/steward/internal/rollout"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestPrepareTargetV1ConstructsExactRemoteActivationArtifacts(t *testing.T) {
	fixture := newDriverFixture(t)
	prepared := fixture.prepare(t)

	if prepared.TargetIndex() != 0 || prepared.Target() != fixture.plan.Targets[0] ||
		prepared.RuntimeRef() != executor.RuntimeRef("tenant-a", "hermes-a") ||
		prepared.StateRuntimeRef() != executor.StateVolumeName("tenant-a", "lineage-a") ||
		prepared.CapsuleDigest() != fixture.verified.CapsuleDigest {
		t.Fatalf("unexpected prepared identity: target=%#v runtime=%q state=%q capsule=%q",
			prepared.Target(), prepared.RuntimeRef(), prepared.StateRuntimeRef(), prepared.CapsuleDigest())
	}
	wantOuter := "uplink:v2:8:tenant-a:6:node-a:hermes-a"
	if prepared.OuterRuntimeRef() != wantOuter {
		t.Fatalf("outer runtime ref = %q, want %q", prepared.OuterRuntimeRef(), wantOuter)
	}
	activationPlanRaw := prepared.ActivationPlanRaw()
	activationPlan, err := activation.ParsePlanV1(activationPlanRaw)
	if err != nil {
		t.Fatal(err)
	}
	if activationPlan.Transport != activation.TransportControlUplink ||
		activationPlan.ActivationID != fixture.plan.Targets[0].ActivationID ||
		dsse.Digest(activationPlanRaw) != fixture.plan.Targets[0].ActivationPlanDigest ||
		activationPlan.Timeouts != fixture.timeouts {
		t.Fatalf("unexpected activation plan: %#v", activationPlan)
	}
	binding := prepared.Binding()
	if binding.PlanDigest != fixture.plan.Targets[0].ActivationPlanDigest ||
		binding.IntentDigest != dsse.Digest(fixture.intentRaw) ||
		binding.Generation != fixture.intent.Generation {
		t.Fatalf("unexpected activation binding: %#v", binding)
	}
	begin, err := activation.ParseExecutorBeginV1(prepared.ExecutorBeginRaw())
	if err != nil {
		t.Fatal(err)
	}
	if begin.Binding != binding || begin.RuntimeRef != prepared.RuntimeRef() ||
		begin.StateRuntimeRef != prepared.StateRuntimeRef() ||
		begin.CapsuleDigest != fixture.verified.CapsuleDigest ||
		prepared.ExecutorBeginDigest() != dsse.Digest(prepared.ExecutorBeginRaw()) {
		t.Fatalf("unexpected begin marker: %#v", begin)
	}

	var admissionPayload admissionPayloadV1
	if err := dsse.DecodeStrictInto(
		prepared.AdmissionPayloadRaw(), maxAdmissionPayloadBytes, &admissionPayload,
	); err != nil {
		t.Fatal(err)
	}
	if admissionPayload.CapsuleDSSEBase64 != base64.StdEncoding.EncodeToString(fixture.capsuleRaw) ||
		!reflect.DeepEqual(admissionPayload.Intent, fixture.intent) ||
		admissionPayload.Activation != (activationAdmissionV1{
			SchemaVersion: activationAdmissionSchemaV1,
			ActivationID:  fixture.plan.Targets[0].ActivationID,
			BeginDigest:   prepared.ExecutorBeginDigest(),
		}) {
		t.Fatalf("unexpected admission payload: %#v", admissionPayload)
	}

	// Returned slices are detached from the immutable preparation result.
	activationPlanRaw[0] ^= 0xff
	beginRaw := prepared.ExecutorBeginRaw()
	beginRaw[0] ^= 0xff
	admissionRaw := prepared.AdmissionPayloadRaw()
	admissionRaw[0] ^= 0xff
	if _, err := activation.ParsePlanV1(prepared.ActivationPlanRaw()); err != nil {
		t.Fatalf("activation plan accessor leaked mutation: %v", err)
	}
	if _, err := activation.ParseExecutorBeginV1(prepared.ExecutorBeginRaw()); err != nil {
		t.Fatalf("begin accessor leaked mutation: %v", err)
	}
	var stillValid admissionPayloadV1
	if err := dsse.DecodeStrictInto(prepared.AdmissionPayloadRaw(), maxAdmissionPayloadBytes, &stillValid); err != nil {
		t.Fatalf("admission accessor leaked mutation: %v", err)
	}
}

func TestPrepareTargetV1RejectsBindingMutations(t *testing.T) {
	fixture := newDriverFixture(t)

	tests := map[string]func(*PrepareInputV1){
		"intent bytes": func(input *PrepareInputV1) {
			input.IntentRaw = append(append([]byte(nil), input.IntentRaw...), ' ')
		},
		"capsule bytes": func(input *PrepareInputV1) {
			input.CapsuleEnvelope = append(append([]byte(nil), input.CapsuleEnvelope...), ' ')
		},
		"authenticated capsule digest": func(input *PrepareInputV1) {
			input.VerifiedCapsule.CapsuleDigest = testDigest("other-capsule")
		},
		"authenticated capsule value": func(input *PrepareInputV1) {
			input.VerifiedCapsule.Capsule.CapsuleID = "another-capsule"
		},
		"activation plan digest": func(input *PrepareInputV1) {
			plan := fixture.plan
			plan.Targets = append([]rollout.TargetV1(nil), plan.Targets...)
			plan.Targets[0].ActivationPlanDigest = testDigest("another-plan")
			input.PlanRaw = mustRolloutPlan(t, plan)
		},
		"target node": func(input *PrepareInputV1) {
			plan := fixture.plan
			plan.Targets = append([]rollout.TargetV1(nil), plan.Targets...)
			plan.Targets[0].NodeID = "node-b"
			plan.Targets[0].AdmitCommandID,
				plan.Targets[0].StartCommandID,
				plan.Targets[0].CanaryCommandID = rollout.TargetCommandIDsV1(
				plan.RolloutID, 0, plan.Targets[0].NodeID,
			)
			input.PlanRaw = mustRolloutPlan(t, plan)
		},
		"target generation": func(input *PrepareInputV1) {
			plan := fixture.plan
			plan.Targets = append([]rollout.TargetV1(nil), plan.Targets...)
			plan.Targets[0].InstanceGeneration++
			input.PlanRaw = mustRolloutPlan(t, plan)
		},
		"Gateway receipt epoch": func(input *PrepareInputV1) {
			plan := fixture.plan
			plan.Targets = append([]rollout.TargetV1(nil), plan.Targets...)
			plan.Targets[0].GatewayReceiptEpoch = 0
			input.PlanRaw = mustJSON(t, plan)
		},
		"policy digest": func(input *PrepareInputV1) {
			plan := fixture.plan
			plan.PolicyDigest = testDigest("another-policy")
			plan.Targets = append([]rollout.TargetV1(nil), plan.Targets...)
			input.PlanRaw = mustRolloutPlan(t, plan)
		},
		"timeouts": func(input *PrepareInputV1) {
			input.ActivationTimeouts.CanarySeconds++
		},
		"target index": func(input *PrepareInputV1) {
			input.TargetIndex = 1
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := fixture.prepareInput()
			mutate(&input)
			if _, err := PrepareTargetV1(input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

func TestSignAdmissionAndStartCommandsUsePredeterminedFences(t *testing.T) {
	fixture := newDriverFixture(t)
	prepared := fixture.prepare(t)
	window := fixture.commandWindow(5 * time.Minute)

	admit, err := SignAdmissionCommandV1(prepared, window)
	if err != nil {
		t.Fatal(err)
	}
	start, err := SignStartCommandV1(prepared, window)
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		command  SignedCommandV1
		kind     string
		id       string
		sequence uint64
		payload  []byte
	}{
		{admit, "admit", prepared.Target().AdmitCommandID, 1, prepared.AdmissionPayloadRaw()},
		{start, "start", prepared.Target().StartCommandID, 2, []byte(`{}`)},
	} {
		statement := check.command.Statement()
		if statement.Kind != check.kind || statement.CommandID != check.id ||
			statement.CommandSequence != check.sequence ||
			statement.ClaimGeneration != prepared.Target().ClaimGeneration ||
			statement.InstanceGeneration != prepared.Target().InstanceGeneration ||
			statement.RuntimeRef != prepared.OuterRuntimeRef() ||
			!bytes.Equal(statement.Payload, check.payload) {
			t.Fatalf("unexpected %s statement: %#v", check.kind, statement)
		}
		payload, keyID, err := dsse.Verify(
			check.command.Raw(), admission.CommandPayloadType,
			map[string]ed25519.PublicKey{fixture.commandKeyID: fixture.commandPublic},
		)
		if err != nil || keyID != fixture.commandKeyID {
			t.Fatalf("verify %s: key=%q err=%v", check.kind, keyID, err)
		}
		var parsed admission.CommandStatement
		if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &parsed); err != nil ||
			!reflect.DeepEqual(parsed, statement) {
			t.Fatalf("parse %s: %#v err=%v", check.kind, parsed, err)
		}
	}
}

func TestSigningRejectsKeyAndValidityFailures(t *testing.T) {
	fixture := newDriverFixture(t)
	prepared := fixture.prepare(t)
	foreignPublic, foreignPrivate := testKey(90)

	tests := map[string]SigningWindowV1{
		"private public mismatch": {
			KeyID: fixture.commandKeyID, PrivateKey: fixture.commandPrivate,
			PublicKey: foreignPublic, IssuedAt: fixture.now, ValidFor: time.Minute,
		},
		"unauthorized key": {
			KeyID: "foreign-command", PrivateKey: foreignPrivate,
			PublicKey: foreignPublic, IssuedAt: fixture.now, ValidFor: time.Minute,
		},
		"zero validity": {
			KeyID: fixture.commandKeyID, PrivateKey: fixture.commandPrivate,
			PublicKey: fixture.commandPublic, IssuedAt: fixture.now,
		},
		"before rollout": {
			KeyID: fixture.commandKeyID, PrivateKey: fixture.commandPrivate,
			PublicKey: fixture.commandPublic,
			IssuedAt:  fixture.now.Add(-2 * time.Minute), ValidFor: time.Minute,
		},
		"after rollout": {
			KeyID: fixture.commandKeyID, PrivateKey: fixture.commandPrivate,
			PublicKey: fixture.commandPublic,
			IssuedAt:  fixture.now.Add(59 * time.Minute), ValidFor: 2 * time.Minute,
		},
		"command lifetime": {
			KeyID: fixture.commandKeyID, PrivateKey: fixture.commandPrivate,
			PublicKey: fixture.commandPublic, IssuedAt: fixture.now, ValidFor: 16 * time.Minute,
		},
	}
	for name, window := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := SignStartCommandV1(prepared, window); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
	expiring := prepared
	expiring.capsuleExpiresAt = fixture.now.Add(time.Minute)
	if _, err := SignStartCommandV1(expiring, fixture.commandWindow(2*time.Minute)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("capsule-expiry err = %v, want ErrInvalid", err)
	}
}

func TestBuildCanaryCommandV1ClosesPermitPayloadAndOuterCommand(t *testing.T) {
	fixture := newDriverFixture(t)
	prepared := fixture.prepare(t)
	projection := fixture.projection(prepared)
	deadline := fixture.now.Add(4 * time.Minute)
	artifacts, err := BuildCanaryCommandV1(CanaryInputV1{
		Prepared:              prepared,
		Admission:             projection,
		TaskKeyID:             fixture.taskKeyID,
		TaskPrivateKey:        fixture.taskPrivate,
		TaskPublicKey:         fixture.taskPublic,
		OperationPolicyDigest: testDigest("operation-policy"),
		ReceiptAuthority:      fixture.receiptAuthority(),
		Deadline:              deadline,
		CommandWindow:         fixture.commandWindow(5 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	statement := artifacts.TaskStatement()
	request, err := agentrelease.BuildCanaryRequest(
		agentrelease.RequestRecipe{
			Input:           agentrelease.HermesWorkspaceAuditInput,
			SessionIDPrefix: agentrelease.HermesSessionIDPrefix,
		},
		prepared.Target().ActivationID,
	)
	if err != nil {
		t.Fatal(err)
	}
	if statement.TaskID != prepared.Target().CanaryCommandID ||
		statement.RequestDigest != taskpermit.RequestDigest(request) ||
		statement.RequestBytes != int64(len(request)) ||
		statement.RuntimeRef != prepared.RuntimeRef() ||
		statement.GrantID != projection.GrantID ||
		statement.OperationPolicyDigest != testDigest("operation-policy") ||
		statement.ExpiresAt != fixture.now.Add(5*time.Minute).Format(time.RFC3339) {
		t.Fatalf("unexpected task statement: %#v", statement)
	}
	verifiedPermit, err := taskpermit.Verify(
		artifacts.TaskPermitRaw(),
		map[string]ed25519.PublicKey{fixture.taskKeyID: fixture.taskPublic},
		fixture.now,
		taskpermit.MaxValidity,
	)
	if err != nil || verifiedPermit.Statement != statement {
		t.Fatalf("verify permit: %#v err=%v", verifiedPermit, err)
	}
	canary := artifacts.Canary()
	if canary.ActivationID != prepared.Target().ActivationID ||
		canary.Deadline != deadline.Format(time.RFC3339Nano) ||
		canary.AdmissionDigest != dsse.Digest(mustJSON(t, projection)) ||
		canary.ReceiptAuthority != fixture.receiptAuthority() {
		t.Fatalf("unexpected canary: %#v", canary)
	}
	context := activationcanary.AdmissionContextV1{
		NodeID: prepared.Target().NodeID, TenantID: prepared.Plan().TenantID,
		InstanceID: prepared.Target().InstanceID, Projection: projection,
	}
	if _, err := activationcanary.VerifyCommandV1(
		artifacts.CanaryRaw(), context, fixture.now, taskpermit.MaxValidity,
	); err != nil {
		t.Fatalf("verify live canary: %v", err)
	}
	if _, err := activationcanary.VerifyHistoricalCommandV1(
		artifacts.CanaryRaw(), context, taskpermit.MaxValidity,
	); err != nil {
		t.Fatalf("verify historical canary: %v", err)
	}
	outer := artifacts.OuterCommand().Statement()
	if outer.CommandID != prepared.Target().CanaryCommandID || outer.Kind != "activation-canary" ||
		outer.CommandSequence != 3 || !bytes.Equal(outer.Payload, artifacts.CanaryRaw()) {
		t.Fatalf("unexpected outer canary command: %#v", outer)
	}

	// Deep-copy accessors cannot mutate retained admission authority.
	canary.Admission.TaskAuthorities[0].KeyID = "mutated"
	if artifacts.Canary().Admission.TaskAuthorities[0].KeyID != fixture.taskKeyID {
		t.Fatal("canary accessor leaked task-authority mutation")
	}
}

func TestBuildCanaryCommandV1RejectsMutationsAndIncoherentExpiry(t *testing.T) {
	fixture := newDriverFixture(t)
	prepared := fixture.prepare(t)
	base := CanaryInputV1{
		Prepared:              prepared,
		Admission:             fixture.projection(prepared),
		TaskKeyID:             fixture.taskKeyID,
		TaskPrivateKey:        fixture.taskPrivate,
		TaskPublicKey:         fixture.taskPublic,
		OperationPolicyDigest: testDigest("operation-policy"),
		ReceiptAuthority:      fixture.receiptAuthority(),
		Deadline:              fixture.now.Add(4 * time.Minute),
		CommandWindow:         fixture.commandWindow(5 * time.Minute),
	}
	foreignPublic, foreignPrivate := testKey(91)
	tests := map[string]func(*CanaryInputV1){
		"projection runtime": func(input *CanaryInputV1) {
			input.Admission.RuntimeRef = executor.RuntimeRef("tenant-a", "other")
		},
		"projection capsule": func(input *CanaryInputV1) {
			input.Admission.CapsuleDigest = testDigest("other-capsule")
		},
		"projection task authority": func(input *CanaryInputV1) {
			input.Admission.TaskAuthorities[0].PublicKey = base64.StdEncoding.EncodeToString(foreignPublic)
		},
		"projection egress escalation": func(input *CanaryInputV1) {
			input.Admission.EgressProxy = egressProxyV1
			input.Admission.EgressRouteIDs = []string{"unrequested"}
		},
		"task private key": func(input *CanaryInputV1) {
			input.TaskPrivateKey = foreignPrivate
		},
		"task key ID": func(input *CanaryInputV1) {
			input.TaskKeyID = "foreign-task"
		},
		"operation digest": func(input *CanaryInputV1) {
			input.OperationPolicyDigest = "sha256:invalid"
		},
		"substituted operation digest": func(input *CanaryInputV1) {
			input.OperationPolicyDigest = testDigest("another-operation")
		},
		"expired deadline": func(input *CanaryInputV1) {
			input.Deadline = fixture.now
		},
		"deadline after permit": func(input *CanaryInputV1) {
			input.Deadline = fixture.now.Add(6 * time.Minute)
		},
		"deadline after canary timeout": func(input *CanaryInputV1) {
			input.CommandWindow.ValidFor = 10 * time.Minute
			input.Deadline = fixture.now.Add(6 * time.Minute)
		},
		"wrong receipt node": func(input *CanaryInputV1) {
			input.ReceiptAuthority.NodeID = "node-b/gateway"
		},
		"receipt epoch": func(input *CanaryInputV1) {
			input.ReceiptAuthority.Epoch++
		},
		"receipt key digest": func(input *CanaryInputV1) {
			input.ReceiptAuthority.PublicKeySHA256 = testDigest("another-receipt-key")
		},
		"outer command expiry": func(input *CanaryInputV1) {
			input.CommandWindow.ValidFor = 16 * time.Minute
			input.Deadline = fixture.now.Add(4 * time.Minute)
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := base
			input.Admission.TaskAuthorities = append(
				[]controlprotocol.ExecutorTaskAuthorityV1(nil), base.Admission.TaskAuthorities...,
			)
			input.Admission.EgressRouteIDs = append([]string(nil), base.Admission.EgressRouteIDs...)
			input.Admission.ConnectorIDs = append([]string(nil), base.Admission.ConnectorIDs...)
			mutate(&input)
			if _, err := BuildCanaryCommandV1(input); !errors.Is(err, ErrInvalid) {
				t.Fatalf("err = %v, want ErrInvalid", err)
			}
		})
	}
}

type driverFixture struct {
	now            time.Time
	timeouts       activation.TimeoutsV1
	capsuleRaw     []byte
	verified       admission.VerifiedCapsuleImport
	intent         admission.InstanceIntent
	intentRaw      []byte
	plan           rollout.PlanV1
	planRaw        []byte
	commandKeyID   string
	commandPublic  ed25519.PublicKey
	commandPrivate ed25519.PrivateKey
	taskKeyID      string
	taskPublic     ed25519.PublicKey
	taskPrivate    ed25519.PrivateKey
	receiptPublic  ed25519.PublicKey
}

func newDriverFixture(t *testing.T) driverFixture {
	t.Helper()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	publisherPublic, publisherPrivate := testKey(1)
	sitePublic, sitePrivate := testKey(2)
	commandPublic, commandPrivate := testKey(3)
	taskPublic, taskPrivate := testKey(4)
	receiptPublic, _ := testKey(5)
	profileRef := admission.ProfileRef{ID: "hermes-v1", Version: "v1"}
	profile, ok := admission.DefaultProfiles().Lookup(profileRef)
	if !ok {
		t.Fatal("Hermes profile is unavailable")
	}
	resources := admission.ResourceLimits{MemoryBytes: 1 << 30, CPUMillis: 2000, PIDs: 256}
	capsule := admission.ProfileCapsule{
		SchemaVersion:  admission.SchemaV1,
		CapsuleID:      "hermes-capsule",
		PublisherKeyID: "publisher-a",
		Profile:        profileRef,
		Image: admission.ImageIdentity{
			Repository:     "registry.invalid/hermes",
			ManifestDigest: testDigest("manifest"),
			ConfigDigest:   testDigest("config"),
			Platform:       admission.Platform{OS: "linux", Architecture: "amd64"},
		},
		Command:      []string{"/opt/hermes/entrypoint"},
		Resources:    resources,
		Capabilities: admission.Capabilities{State: true, Service: true},
		State:        admission.StateShape{SchemaVersion: profile.StateSchemaVersion, Path: profile.StatePath},
		Service:      admission.ServiceShape{ID: agentrelease.HermesServiceID, Port: 8766},
	}
	capsuleRaw := mustSignJSON(t, admission.CapsulePayloadType, capsule, "publisher-a", publisherPrivate)
	commandKeyID := "tenant-command"
	taskKeyID := "tenant-task"
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1,
		PolicyID:      "site-a",
		PolicyEpoch:   1,
		Publishers: []admission.PublisherRule{{
			KeyID:                  "publisher-a",
			PublicKey:              base64.StdEncoding.EncodeToString(publisherPublic),
			AllowedProfiles:        []admission.ProfileRef{profileRef},
			AllowedRepositories:    []string{capsule.Image.Repository},
			AllowedManifestDigests: []string{capsule.Image.ManifestDigest},
			ResourceCeiling:        resources,
		}},
		Tenants: []admission.TenantRule{{
			TenantID:        "tenant-a",
			PublisherKeyIDs: []string{"publisher-a"},
			ResourceCeiling: resources,
			ServiceIDs:      []string{agentrelease.HermesServiceID},
			CommandKeys: []admission.CommandKey{{
				KeyID:      commandKeyID,
				PublicKey:  base64.StdEncoding.EncodeToString(commandPublic),
				Operations: []string{"admit", "start", "activation-canary"},
			}},
			TaskKeys: []admission.TaskKey{{
				KeyID:      taskKeyID,
				PublicKey:  base64.StdEncoding.EncodeToString(taskPublic),
				ServiceIDs: []string{agentrelease.HermesServiceID},
			}},
		}},
	}
	policyRaw := mustSignJSON(t, admission.PolicyPayloadType, policy, "site-root", sitePrivate)
	verified, err := admission.VerifyCapsuleForImport(
		capsuleRaw, policyRaw,
		map[string]ed25519.PublicKey{"site-root": sitePublic},
		now,
		admission.DefaultProfiles(),
	)
	if err != nil {
		t.Fatal(err)
	}
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "hermes-a",
		LineageID: "lineage-a", Generation: 7,
		CapsuleDigest:    verified.CapsuleDigest,
		Resources:        resources,
		Capabilities:     admission.Capabilities{State: true, Service: true},
		StateDisposition: "new",
		ServiceID:        agentrelease.HermesServiceID,
	}
	intentRaw := mustJSON(t, intent)
	timeouts := activation.TimeoutsV1{
		PreflightSeconds: 30, ImageImportSeconds: 1800,
		AdmissionSeconds: 60, StartupSeconds: 120,
		CanarySeconds: 300, EvidenceSeconds: 60,
	}
	releaseDigest := testDigest("release")
	archive := ocibundle.ArchiveIdentity{Digest: testDigest("archive"), Bytes: 4096}
	activationPlan := activation.PlanV1{
		SchemaVersion: activation.PlanSchemaV1,
		ActivationID:  "activation-a",
		ReleaseDigest: releaseDigest,
		PolicyDigest:  verified.PolicyDigest,
		IntentDigest:  dsse.Digest(intentRaw),
		Archive:       archive,
		Transport:     activation.TransportControlUplink,
		Canary:        activation.CanaryV1{Kind: activation.CanaryHermesWorkspaceAuditV1},
		Timeouts:      timeouts,
	}
	activationPlanRaw, err := activation.MarshalPlanV1(activationPlan)
	if err != nil {
		t.Fatal(err)
	}
	plan := rollout.PlanV1{
		SchemaVersion: rollout.PlanSchemaV1,
		RolloutID:     "rollout-a",
		TenantID:      "tenant-a",
		ReleaseDigest: releaseDigest,
		PolicyDigest:  verified.PolicyDigest,
		Archive:       archive,
		Canary:        activation.CanaryV1{Kind: activation.CanaryHermesWorkspaceAuditV1},
		BatchSize:     1,
		CreatedAt:     now.Add(-time.Minute).Format(time.RFC3339Nano),
		Deadline:      now.Add(time.Hour).Format(time.RFC3339Nano),
		Targets: []rollout.TargetV1{{
			NodeID: "node-a", InstanceID: "hermes-a", ActivationID: "activation-a",
			IntentDigest:                  dsse.Digest(intentRaw),
			ActivationPlanDigest:          dsse.Digest(activationPlanRaw),
			GatewayReceiptEpoch:           1,
			GatewayReceiptPublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic),
			OperationPolicyDigest:         testDigest("operation-policy"),
			ClaimGeneration:               11,
			InstanceGeneration:            intent.Generation,
		}},
	}
	plan.Targets[0].AdmitCommandID,
		plan.Targets[0].StartCommandID,
		plan.Targets[0].CanaryCommandID = rollout.TargetCommandIDsV1(
		plan.RolloutID, 0, plan.Targets[0].NodeID,
	)
	return driverFixture{
		now: now, timeouts: timeouts, capsuleRaw: capsuleRaw, verified: verified,
		intent: intent, intentRaw: intentRaw, plan: plan, planRaw: mustRolloutPlan(t, plan),
		commandKeyID: commandKeyID, commandPublic: commandPublic, commandPrivate: commandPrivate,
		taskKeyID: taskKeyID, taskPublic: taskPublic, taskPrivate: taskPrivate,
		receiptPublic: receiptPublic,
	}
}

func (fixture driverFixture) prepareInput() PrepareInputV1 {
	return PrepareInputV1{
		PlanRaw: append([]byte(nil), fixture.planRaw...), TargetIndex: 0,
		IntentRaw:          append([]byte(nil), fixture.intentRaw...),
		CapsuleEnvelope:    append([]byte(nil), fixture.capsuleRaw...),
		VerifiedCapsule:    fixture.verified,
		ActivationTimeouts: fixture.timeouts,
	}
}

func (fixture driverFixture) prepare(t *testing.T) PreparedTargetV1 {
	t.Helper()
	prepared, err := PrepareTargetV1(fixture.prepareInput())
	if err != nil {
		t.Fatal(err)
	}
	return prepared
}

func (fixture driverFixture) commandWindow(validFor time.Duration) SigningWindowV1 {
	return SigningWindowV1{
		KeyID:                      fixture.commandKeyID,
		PrivateKey:                 fixture.commandPrivate,
		PublicKey:                  fixture.commandPublic,
		AuthorizationContextDigest: testDigest("authorization"),
		IssuedAt:                   fixture.now,
		ValidFor:                   validFor,
	}
}

func (fixture driverFixture) projection(prepared PreparedTargetV1) controlprotocol.ExecutorAdmissionProjectionV1 {
	grantID := gateway.GrantID("tenant-a", "hermes-a", fixture.intent.Generation)
	return controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    prepared.RuntimeRef(), Status: "created",
		CapsuleDigest: prepared.CapsuleDigest(), PolicyDigest: fixture.plan.PolicyDigest,
		Generation: fixture.intent.Generation, EvidenceKeyID: strings.Repeat("a", 32),
		GrantID: grantID, ServicePath: "/v1/services/" + grantID + "/",
		ServiceID: agentrelease.HermesServiceID,
		TaskAuthorities: []controlprotocol.ExecutorTaskAuthorityV1{{
			KeyID:     fixture.taskKeyID,
			PublicKey: base64.StdEncoding.EncodeToString(fixture.taskPublic),
		}},
		RoutePolicyDigest:     testDigest("route-policy"),
		ActivationID:          prepared.Target().ActivationID,
		ActivationBeginDigest: prepared.ExecutorBeginDigest(),
	}
}

func (fixture driverFixture) receiptAuthority() activationcanary.ReceiptAuthorityV1 {
	return activationcanary.ReceiptAuthorityV1{
		NodeID:          gateway.ServiceTaskReceiptNodeID("node-a"),
		Epoch:           1,
		PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(fixture.receiptPublic),
	}
}

func mustSignJSON(
	t *testing.T,
	payloadType string,
	value any,
	keyID string,
	private ed25519.PrivateKey,
) []byte {
	t.Helper()
	payload := mustJSON(t, value)
	envelope, err := dsse.Sign(payloadType, payload, keyID, private)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustRolloutPlan(t *testing.T, plan rollout.PlanV1) []byte {
	t.Helper()
	raw, err := rollout.MarshalPlanV1(plan)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testKey(fill byte) (ed25519.PublicKey, ed25519.PrivateKey) {
	seed := bytes.Repeat([]byte{fill}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	return append(ed25519.PublicKey(nil), private.Public().(ed25519.PublicKey)...), private
}

func testDigest(value string) string { return dsse.Digest([]byte(value)) }
