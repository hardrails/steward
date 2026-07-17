package controlstore

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/activation"
	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/agentrelease"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/taskpermit"
)

func TestActivationCanaryLeaseRequiresProtocolV4Capability(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	statement := baseV4CommandStatement(
		"canary-command", "tenant-a", "node-1", "activation-canary", 7, 11,
	)
	_ = controlStoreCanaryFixture(t, &statement, fixture.now)
	raw := signV4CommandStatement(t, statement)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		raw,
		fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit activation canary = (%v, %v)", created, err)
	}

	v3, err := fixture.store.Poll(
		node,
		[]string{controlprotocol.ExecutorCapabilityActivationCanaryV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(v3) != 0 {
		t.Fatalf("protocol 3 leased activation canary: deliveries=%+v err=%v", v3, err)
	}
	v4WithoutCapability, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityAdmissionProjectionV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(v4WithoutCapability) != 0 {
		t.Fatalf("old protocol-4 node leased activation canary: deliveries=%+v err=%v", v4WithoutCapability, err)
	}
	retained, found, err := fixture.store.GetCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil || !found || retained.State != CommandPending || retained.DeliveryGeneration != 0 {
		t.Fatalf("ineligible polls changed pending canary: command=%+v found=%v err=%v", retained, found, err)
	}
	v4, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityActivationCanaryV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(v4) != 1 || v4[0].CommandID != statement.CommandID {
		t.Fatalf("capable protocol-4 node did not lease canary: deliveries=%+v err=%v", v4, err)
	}
}

func TestActivationCanaryPollLeasesOneCanaryWithoutBlockingOtherCommands(
	t *testing.T,
) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	for _, commandID := range []string{"canary-a", "canary-b", "canary-c"} {
		statement := baseV4CommandStatement(
			commandID,
			"tenant-a",
			"node-1",
			"activation-canary",
			7,
			11,
		)
		_ = controlStoreCanaryFixture(t, &statement, fixture.now)
		if _, created, err := fixture.store.SubmitCommand(
			fixture.admin,
			statement.TenantID,
			statement.NodeID,
			signV4CommandStatement(t, statement),
			fixture.now.Add(2*time.Minute),
		); err != nil || !created {
			t.Fatalf("submit %s = (%v, %v)", commandID, created, err)
		}
	}
	ordinary := baseV4CommandStatement(
		"reconcile-read",
		"tenant-a",
		"node-1",
		"read",
		7,
		11,
	)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin,
		ordinary.TenantID,
		ordinary.NodeID,
		signV4CommandStatement(t, ordinary),
		fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit ordinary command = (%v, %v)", created, err)
	}

	deliveries, err := fixture.store.PollV4(
		node,
		[]string{
			controlprotocol.ExecutorCapabilityActivationCanaryV1,
			controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
		},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		4,
	)
	if err != nil {
		t.Fatal(err)
	}
	var canaries, ordinaryCommands int
	leasedCanaryID := ""
	for _, delivery := range deliveries {
		switch delivery.CommandID {
		case "canary-a", "canary-b", "canary-c":
			canaries++
			leasedCanaryID = delivery.CommandID
		case ordinary.CommandID:
			ordinaryCommands++
		}
	}
	if canaries != 1 || ordinaryCommands != 1 || len(deliveries) != 2 {
		t.Fatalf(
			"poll deliveries=%+v, want one canary and the ordinary command",
			deliveries,
		)
	}
	for _, commandID := range []string{"canary-a", "canary-b", "canary-c"} {
		command, found, getErr := fixture.store.GetCommand(
			fixture.admin,
			"tenant-a",
			"node-1",
			commandID,
		)
		if getErr != nil || !found {
			t.Fatalf("get %s = (%v, %v)", commandID, found, getErr)
		}
		if commandID == leasedCanaryID {
			if command.State != CommandLeased {
				t.Fatalf("%s state=%s, want leased", commandID, command.State)
			}
		} else if command.State != CommandPending {
			t.Fatalf("%s state=%s, want pending", commandID, command.State)
		}
	}
}

func TestActivationCanaryProjectionPersistsAndDeepClonesAcrossRecovery(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, node := fixture.createNode(t, "tenant-a")
	statement := baseV4CommandStatement(
		"canary-command", "tenant-a", "node-1", "activation-canary", 7, 11,
	)
	projection := controlStoreCanaryFixture(t, &statement, fixture.now)
	delivery := submitAndPollActivationCanaryV4(t, fixture, node, statement)
	report := activationCanaryReportV4(delivery, statement, projection)
	if applied, err := fixture.store.ApplyReportV4(
		node,
		report,
		fixture.now.Add(4*time.Minute),
	); err != nil || !applied {
		t.Fatalf("apply activation canary report = (%v, %v)", applied, err)
	}

	retained, found, err := fixture.store.GetCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil || !found || retained.Terminal == nil ||
		!reflect.DeepEqual(retained.Terminal.ActivationCanary, &projection) {
		t.Fatalf("retained activation canary = (%+v, %v, %v)", retained.Terminal, found, err)
	}
	retained.Terminal.ActivationCanary.ActivationID = "mutated"
	retained, found, err = fixture.store.GetCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil || !found || retained.Terminal == nil ||
		!reflect.DeepEqual(retained.Terminal.ActivationCanary, &projection) {
		t.Fatalf("returned canary aliases retained state: (%+v, %v, %v)", retained.Terminal, found, err)
	}

	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	retained, found, err = reopened.GetCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		statement.CommandID,
	)
	if err != nil || !found || retained.Terminal == nil ||
		!reflect.DeepEqual(retained.Terminal.ActivationCanary, &projection) {
		t.Fatalf("reopened activation canary = (%+v, %v, %v)", retained.Terminal, found, err)
	}
	if applied, err := reopened.ApplyReportV4(
		node,
		report,
		fixture.now.Add(5*time.Minute),
	); err != nil || applied {
		t.Fatalf("exact recovered report retry = (%v, %v)", applied, err)
	}
}

func TestActivationCanaryProjectionRequiresExactSignedCommandBinding(t *testing.T) {
	runtimeRef := "executor-" + strings.Repeat("a", 64)
	statement := baseV4CommandStatement(
		"command-1",
		"tenant-a",
		"node-1",
		"activation-canary",
		7,
		11,
	)
	projection := controlStoreCanaryFixture(
		t,
		&statement,
		time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC),
	)
	commandRaw := signV4CommandStatement(t, statement)
	base := Command{
		CommandDSSE:              commandRaw,
		CommandKind:              "activation-canary",
		SignedRuntimeRef:         runtimeRef,
		SignedClaimGeneration:    7,
		SignedInstanceGeneration: 11,
		DeliveryProtocol:         controlprotocol.ExecutorProtocolV4,
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      "delivery-1", DeliveryGeneration: 1,
		CommandID: "command-1", CommandDigest: "sha256:" + strings.Repeat("a", 64),
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "running",
		ClaimGeneration: 7,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: runtimeRef, ActivationCanary: &projection,
		},
	}
	if err := report.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := validateExecutorReportV4Binding(base, report); err != nil {
		t.Fatalf("valid canary binding: %v", err)
	}
	tests := map[string]func(*Command, *controlprotocol.ExecutorReportV4){
		"command kind": func(command *Command, _ *controlprotocol.ExecutorReportV4) { command.CommandKind = "start" },
		"runtime reference": func(_ *Command, value *controlprotocol.ExecutorReportV4) {
			value.Result.RuntimeRef = "executor-" + strings.Repeat("b", 64)
		},
		"claim generation":    func(_ *Command, value *controlprotocol.ExecutorReportV4) { value.ClaimGeneration++ },
		"instance generation": func(command *Command, _ *controlprotocol.ExecutorReportV4) { command.SignedInstanceGeneration = 0 },
		"delivery protocol": func(command *Command, _ *controlprotocol.ExecutorReportV4) {
			command.DeliveryProtocol = controlprotocol.ExecutorProtocolV3
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			command := base
			candidate := report
			projectionCopy := projection
			candidate.Result.ActivationCanary = &projectionCopy
			mutate(&command, &candidate)
			if err := validateExecutorReportV4Binding(command, candidate); err == nil {
				t.Fatal("mismatched activation canary binding was accepted")
			}
		})
	}
}

func submitAndPollActivationCanaryV4(
	t *testing.T,
	fixture recordsFixture,
	node controlauth.NodeIdentity,
	statement admission.CommandStatement,
) controlprotocol.ExecutorDeliveryV4 {
	t.Helper()
	raw := signV4CommandStatement(t, statement)
	if _, created, err := fixture.store.SubmitCommand(
		fixture.admin,
		statement.TenantID,
		statement.NodeID,
		raw,
		fixture.now.Add(2*time.Minute),
	); err != nil || !created {
		t.Fatalf("submit activation canary = (%v, %v)", created, err)
	}
	deliveries, err := fixture.store.PollV4(
		node,
		[]string{controlprotocol.ExecutorCapabilityActivationCanaryV1},
		fixture.now.Add(3*time.Minute),
		time.Minute,
		1,
	)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll activation canary = (%+v, %v)", deliveries, err)
	}
	return deliveries[0]
}

func controlStoreCanaryFixture(
	t *testing.T,
	outer *admission.CommandStatement,
	now time.Time,
) controlprotocol.ExecutorActivationCanaryResultV1 {
	t.Helper()
	activationID := "activation-1"
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
	taskPublic, taskPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	receiptPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grantID := gateway.GrantID(
		outer.TenantID,
		outer.InstanceID,
		outer.InstanceGeneration,
	)
	permitStatement := taskpermit.Statement{
		SchemaVersion:         taskpermit.SchemaV1,
		NodeID:                outer.NodeID,
		TenantID:              outer.TenantID,
		InstanceID:            outer.InstanceID,
		RuntimeRef:            outer.RuntimeRef,
		GrantID:               grantID,
		Generation:            outer.InstanceGeneration,
		CapsuleDigest:         dsse.Digest([]byte("capsule")),
		PolicyDigest:          dsse.Digest([]byte("policy")),
		RoutePolicyDigest:     dsse.Digest([]byte("route-policy")),
		ServiceID:             agentrelease.HermesServiceID,
		OperationID:           agentrelease.HermesOperationID,
		OperationPolicyDigest: dsse.Digest([]byte("operation-policy")),
		TaskID:                "activation-task",
		RequestDigest:         taskpermit.RequestDigest(request),
		RequestBytes:          int64(len(request)),
		ContentType:           "application/json",
		NotBefore:             now.Add(-time.Minute).Format(time.RFC3339),
		ExpiresAt:             now.Add(10 * time.Minute).Format(time.RFC3339),
	}
	permitEnvelope, err := dsse.Sign(
		taskpermit.PayloadType,
		mustControlStoreJSON(t, permitStatement),
		"tenant-task",
		taskPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	permitRaw, err := dsse.Marshal(permitEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	permitHeader, err := taskpermit.EncodeHeader(permitRaw)
	if err != nil {
		t.Fatal(err)
	}
	binding := activation.BindingV1{
		ActivationID:  activationID,
		PlanDigest:    dsse.Digest([]byte("plan")),
		ReleaseDigest: dsse.Digest([]byte("release")),
		PolicyDigest:  permitStatement.PolicyDigest,
		IntentDigest:  dsse.Digest([]byte("intent")),
		Archive: activation.ArchiveV1{
			Digest: dsse.Digest([]byte("archive")),
			Bytes:  1024,
		},
		TenantID:   outer.TenantID,
		NodeID:     outer.NodeID,
		InstanceID: outer.InstanceID,
		Generation: outer.InstanceGeneration,
	}
	beginRaw, err := activation.MarshalExecutorBeginV1(
		binding,
		outer.RuntimeRef,
		"steward-state-"+strings.Repeat("b", 64),
		permitStatement.CapsuleDigest,
	)
	if err != nil {
		t.Fatal(err)
	}
	admissionProjection := controlprotocol.ExecutorAdmissionProjectionV1{
		SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
		RuntimeRef:    outer.RuntimeRef,
		Status:        "created",
		CapsuleDigest: permitStatement.CapsuleDigest,
		PolicyDigest:  permitStatement.PolicyDigest,
		Generation:    outer.InstanceGeneration,
		EvidenceKeyID: strings.Repeat("a", 32),
		GrantID:       grantID,
		ServicePath:   "/v1/services/" + grantID + "/",
		ServiceID:     agentrelease.HermesServiceID,
		TaskAuthorities: []controlprotocol.ExecutorTaskAuthorityV1{{
			KeyID:     "tenant-task",
			PublicKey: base64.StdEncoding.EncodeToString(taskPublic),
		}},
		RoutePolicyDigest:     permitStatement.RoutePolicyDigest,
		ActivationID:          activationID,
		ActivationBeginDigest: dsse.Digest(beginRaw),
	}
	if err := admissionProjection.Validate(); err != nil {
		t.Fatal(err)
	}
	command := activationcanary.CommandV1{
		SchemaVersion:       activationcanary.CommandSchemaV1,
		ActivationID:        activationID,
		AdmissionDigest:     dsse.Digest(mustControlStoreJSON(t, admissionProjection)),
		Admission:           admissionProjection,
		ExecutorBeginBase64: base64.StdEncoding.EncodeToString(beginRaw),
		GrantID:             grantID,
		OperationID:         agentrelease.HermesOperationID,
		TaskPermit:          permitHeader,
		RequestBase64:       base64.StdEncoding.EncodeToString(request),
		Deadline:            now.Add(5 * time.Minute).Format(time.RFC3339Nano),
		ReceiptAuthority: activationcanary.ReceiptAuthorityV1{
			NodeID:          gateway.ServiceTaskReceiptNodeID(outer.NodeID),
			Epoch:           1,
			PublicKeySHA256: controlprotocol.ExecutorEvidencePublicKeySHA256(receiptPublic),
		},
	}
	commandRaw, err := activationcanary.MarshalCommandV1(command)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := activationcanary.VerifyHistoricalCommandV1(
		commandRaw,
		activationcanary.AdmissionContextV1{
			NodeID:     outer.NodeID,
			TenantID:   outer.TenantID,
			InstanceID: outer.InstanceID,
			Projection: admissionProjection,
		},
		taskpermit.MaxValidity,
	); err != nil {
		t.Fatal(err)
	}
	outer.Payload = commandRaw

	terminal := []byte(`{"ok":true}`)
	receipts := []byte("authorize\nterminal\nexport\n")
	return controlprotocol.ExecutorActivationCanaryResultV1{
		SchemaVersion:   controlprotocol.ExecutorActivationCanaryResultSchemaV1,
		ActivationID:    activationID,
		AdmissionDigest: command.AdmissionDigest,
		TaskDigest: taskpermit.TaskDigest(
			permitStatement.TenantID,
			permitStatement.InstanceID,
			permitStatement.TaskID,
		),
		PermitDigest:         dsse.Digest(permitRaw),
		RunID:                "run_" + strings.Repeat("4", 32),
		TerminalResultDigest: dsse.Digest(terminal), TerminalResultBytes: int64(len(terminal)),
		TerminalResultBase64:       base64.StdEncoding.EncodeToString(terminal),
		GatewayEvidenceBase64:      base64.StdEncoding.EncodeToString(receipts),
		ActivationCheckpointDigest: "sha256:" + strings.Repeat("5", 64),
		Qualified:                  true,
	}
}

func mustControlStoreJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func activationCanaryReportV4(
	delivery controlprotocol.ExecutorDeliveryV4,
	statement admission.CommandStatement,
	projection controlprotocol.ExecutorActivationCanaryResultV1,
) controlprotocol.ExecutorReportV4 {
	return controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      delivery.DeliveryID, DeliveryGeneration: delivery.DeliveryGeneration,
		CommandID: delivery.CommandID, CommandDigest: delivery.CommandDigest,
		Status: controlprotocol.ExecutorStatusDone, ReportedStatus: "running",
		ClaimGeneration: statement.ClaimGeneration,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef: statement.RuntimeRef, ActivationCanary: &projection,
		},
	}
}
