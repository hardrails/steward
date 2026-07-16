package controlstore

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

func TestRecordAPIsFailClosedForUnavailableAndInvalidCallers(t *testing.T) {
	var unavailable *Store
	now := time.Date(2026, 7, 14, 0, 0, 0, 0, time.UTC)
	operator := controlauth.Identity{CredentialID: "operator", Role: controlauth.RoleSiteAdmin}
	node := controlauth.NodeIdentity{CredentialID: "node-credential", NodeID: "node-1", TenantIDs: []string{"tenant-a"}, Audience: "executor"}
	report := validMissingReport()

	assertErrorIs(t, func() error { _, _, _, err := unavailable.BootstrapSiteAdmin(nil, now); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error { _, err := unavailable.AuthenticateOperator(nil, "token"); return err }(), controlauth.ErrUnauthorized)
	assertErrorIs(t, func() error { _, err := unavailable.AuthenticateNode(nil, "token"); return err }(), controlauth.ErrUnauthorized)
	assertErrorIs(t, func() error { _, _, err := unavailable.CreateTenant(operator, "tenant-a", now); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error { _, _, err := unavailable.GetTenant(operator, "tenant-a"); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error { _, err := unavailable.ListTenants(operator); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error {
		_, _, _, err := unavailable.IssueOperator(operator, nil, "request", controlauth.RoleSiteAdmin, "", now)
		return err
	}(), ErrUnavailable)
	assertErrorIs(t, func() error { _, err := unavailable.RevokeCredential(operator, "credential", now); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error { _, _, err := unavailable.RevokeNodeCredential(operator, "credential", now); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error { _, err := unavailable.RevokeNode(operator, "node-1", now); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error {
		_, _, _, _, err := unavailable.CreateEnrollmentForRequest(operator, nil, "request", "node-1", []string{"tenant-a"}, now.Add(time.Hour), now)
		return err
	}(), ErrUnavailable)
	assertErrorIs(t, func() error { _, err := unavailable.ExchangeEnrollment(nil, "token", "request", now); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error { _, err := unavailable.ListNodes(operator, "tenant-a"); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error { _, _, err := unavailable.GetNode(operator, "tenant-a", "node-1"); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error {
		_, _, err := unavailable.SubmitCommand(operator, "tenant-a", "node-1", []byte("command"), now)
		return err
	}(), ErrUnavailable)
	assertErrorIs(t, func() error {
		_, _, err := unavailable.GetCommand(operator, "tenant-a", "node-1", "command-1")
		return err
	}(), ErrUnavailable)
	assertErrorIs(t, func() error { _, err := unavailable.Poll(node, []string{}, now, time.Minute, 1); return err }(), ErrUnavailable)
	assertErrorIs(t, func() error { _, err := unavailable.ApplyReport(node, report, now); return err }(), ErrUnavailable)
}

func TestRecordAPIsRejectBoundaryViolationsWithoutMutation(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	nonAdminRaw, _, _, err := fixture.store.IssueOperator(
		fixture.admin, fixture.auth, "boundary-tenant-operator", controlauth.RoleTenantOperator, "tenant-a", fixture.now,
	)
	if err != nil {
		t.Fatal(err)
	}
	nonAdmin, err := fixture.store.AuthenticateOperator(fixture.auth, nonAdminRaw)
	if err != nil {
		t.Fatal(err)
	}
	invalidActor := controlauth.Identity{CredentialID: "invalid"}
	before, err := fixture.store.Status()
	if err != nil {
		t.Fatal(err)
	}

	assertErrorIs(t, func() error { _, _, err := fixture.store.CreateTenant(nonAdmin, "tenant-b", fixture.now); return err }(), ErrForbidden)
	assertErrorIs(t, func() error { _, _, err := fixture.store.CreateTenant(fixture.admin, " bad", fixture.now); return err }(), ErrInvalid)
	assertErrorIs(t, func() error {
		_, _, err := fixture.store.CreateTenant(fixture.admin, "tenant-b", time.Time{})
		return err
	}(), ErrInvalid)
	assertErrorIs(t, func() error { _, err := fixture.store.ListTenants(invalidActor); return err }(), controlauth.ErrUnauthorized)
	assertErrorIs(t, func() error {
		_, _, _, err := fixture.store.IssueOperator(nonAdmin, fixture.auth, "request", controlauth.RoleSiteAdmin, "", fixture.now)
		return err
	}(), ErrForbidden)
	assertErrorIs(t, func() error {
		_, _, _, err := fixture.store.IssueOperator(fixture.admin, nil, "request", controlauth.RoleSiteAdmin, "", fixture.now)
		return err
	}(), ErrUnavailable)
	for _, input := range []struct {
		requestID string
		role      controlauth.Role
		tenantID  string
	}{
		{"", controlauth.RoleSiteAdmin, ""},
		{controlauth.BootstrapRequestID, controlauth.RoleSiteAdmin, ""},
		{"request", "unknown", ""},
		{"request", controlauth.RoleSiteAdmin, "tenant-a"},
		{"request", controlauth.RoleTenantOperator, ""},
	} {
		_, _, _, err := fixture.store.IssueOperator(fixture.admin, fixture.auth, input.requestID, input.role, input.tenantID, fixture.now)
		assertErrorIs(t, err, ErrInvalid)
	}
	assertErrorIs(t, func() error {
		_, _, _, err := fixture.store.IssueOperator(fixture.admin, fixture.auth, "missing-tenant", controlauth.RoleTenantOperator, "tenant-b", fixture.now)
		return err
	}(), ErrNotFound)

	assertErrorIs(t, func() error {
		_, err := fixture.store.RevokeCredential(nonAdmin, fixture.adminRecord.ID, fixture.now)
		return err
	}(), ErrForbidden)
	assertErrorIs(t, func() error {
		_, err := fixture.store.RevokeCredential(fixture.admin, "bad id", fixture.now)
		return err
	}(), ErrInvalid)
	assertErrorIs(t, func() error {
		_, err := fixture.store.RevokeCredential(fixture.admin, "missing", fixture.now)
		return err
	}(), ErrNotFound)
	assertErrorIs(t, func() error {
		_, err := fixture.store.RevokeCredential(fixture.admin, fixture.adminRecord.ID, fixture.now.Add(-time.Second))
		return err
	}(), ErrInvalid)
	assertErrorIs(t, func() error {
		_, _, err := fixture.store.RevokeNodeCredential(nonAdmin, "missing", fixture.now)
		return err
	}(), ErrForbidden)
	assertErrorIs(t, func() error {
		_, _, err := fixture.store.RevokeNodeCredential(fixture.admin, "bad id", fixture.now)
		return err
	}(), ErrInvalid)
	assertErrorIs(t, func() error {
		_, _, err := fixture.store.RevokeNodeCredential(fixture.admin, fixture.adminRecord.ID, fixture.now)
		return err
	}(), ErrNotFound)
	assertErrorIs(t, func() error { _, err := fixture.store.RevokeNode(nonAdmin, "node-1", fixture.now); return err }(), ErrForbidden)
	assertErrorIs(t, func() error { _, err := fixture.store.RevokeNode(fixture.admin, "bad id", fixture.now); return err }(), ErrInvalid)
	assertErrorIs(t, func() error { _, err := fixture.store.RevokeNode(fixture.admin, "missing", fixture.now); return err }(), ErrNotFound)

	invalidEnrollments := []struct {
		requestID string
		nodeID    string
		tenants   []string
		expires   time.Time
		now       time.Time
	}{
		{"request", "bad id", []string{"tenant-a"}, fixture.now.Add(time.Hour), fixture.now},
		{"request", "node-1", nil, fixture.now.Add(time.Hour), fixture.now},
		{"request", "node-1", []string{"tenant-a"}, fixture.now, fixture.now},
		{"request", "node-1", []string{"tenant-a"}, fixture.now.Add(25 * time.Hour), fixture.now},
		{"bad id", "node-1", []string{"tenant-a"}, fixture.now.Add(time.Hour), fixture.now},
	}
	for _, input := range invalidEnrollments {
		_, _, _, _, err := fixture.store.CreateEnrollmentForRequest(fixture.admin, fixture.auth, input.requestID, input.nodeID, input.tenants, input.expires, input.now)
		assertErrorIs(t, err, ErrInvalid)
	}
	_, _, _, _, err = fixture.store.CreateEnrollmentForRequest(nonAdmin, fixture.auth, "cross-tenant", "node-1", []string{"tenant-b"}, fixture.now.Add(time.Hour), fixture.now)
	assertErrorIs(t, err, ErrNotFound)

	assertErrorIs(t, func() error {
		_, err := fixture.store.ExchangeEnrollment(nil, "token", "request", fixture.now)
		return err
	}(), controlauth.ErrUnauthorized)
	assertErrorIs(t, func() error {
		_, err := fixture.store.ExchangeEnrollment(fixture.auth, "token", "bad id", fixture.now)
		return err
	}(), ErrInvalid)
	assertErrorIs(t, func() error {
		_, err := fixture.store.ExchangeEnrollment(fixture.auth, "not-a-token", "request", fixture.now)
		return err
	}(), controlauth.ErrUnauthorized)
	assertErrorIs(t, func() error { _, err := fixture.store.ListNodes(nonAdmin, "tenant-b"); return err }(), ErrNotFound)

	assertErrorIs(t, func() error {
		_, _, err := fixture.store.SubmitCommand(nonAdmin, "tenant-b", "node-1", []byte("command"), fixture.now)
		return err
	}(), ErrNotFound)
	assertErrorIs(t, func() error {
		_, _, err := fixture.store.SubmitCommand(nonAdmin, "tenant-a", "node-1", nil, fixture.now)
		return err
	}(), ErrInvalid)
	assertErrorIs(t, func() error {
		_, _, err := fixture.store.SubmitCommand(nonAdmin, "tenant-a", "node-1", []byte("not-dsse"), fixture.now)
		return err
	}(), ErrInvalid)

	after, err := fixture.store.Status()
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatalf("rejected boundary calls mutated durable state: before=%+v after=%+v", before, after)
	}
}

func TestRecordAPIsFenceUnknownNodesCommandsAndReports(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")

	if _, found, err := fixture.store.GetTenant(controlauth.Identity{}, "tenant-a"); !errors.Is(err, controlauth.ErrUnauthorized) || found {
		t.Fatalf("unauthorized tenant lookup = (%v, %v)", found, err)
	}
	if _, found, err := fixture.store.GetNode(fixture.admin, "tenant-a", "missing"); err != nil || found {
		t.Fatalf("missing node lookup = (%v, %v)", found, err)
	}
	if _, found, err := fixture.store.GetCommand(fixture.admin, "tenant-a", "node-1", "missing"); err != nil || found {
		t.Fatalf("missing command lookup = (%v, %v)", found, err)
	}
	assertErrorIs(t, func() error {
		_, err := fixture.store.Poll(controlauth.NodeIdentity{NodeID: "missing", TenantIDs: []string{"tenant-a"}, Audience: "executor"}, []string{}, fixture.now, time.Minute, 1)
		return err
	}(), controlauth.ErrUnauthorized)
	for _, call := range []func() error{
		func() error { _, err := fixture.store.Poll(identity, nil, fixture.now, time.Minute, 1); return err },
		func() error {
			_, err := fixture.store.Poll(identity, []string{"duplicate", "duplicate"}, fixture.now, time.Minute, 1)
			return err
		},
		func() error {
			_, err := fixture.store.Poll(identity, []string{}, time.Time{}, time.Minute, 1)
			return err
		},
		func() error { _, err := fixture.store.Poll(identity, []string{}, fixture.now, 0, 1); return err },
		func() error {
			_, err := fixture.store.Poll(identity, []string{}, fixture.now, MaxDeliveryLease+time.Second, 1)
			return err
		},
		func() error {
			_, err := fixture.store.Poll(identity, []string{}, fixture.now, time.Minute, controlprotocol.MaxExecutorDeliveries+1)
			return err
		},
	} {
		assertErrorIs(t, call(), ErrInvalid)
	}
	assertErrorIs(t, func() error {
		_, err := fixture.store.ApplyReport(identity, controlprotocol.ExecutorReportV3{}, fixture.now)
		return err
	}(), ErrInvalid)
	assertErrorIs(t, func() error {
		_, err := fixture.store.ApplyReport(identity, validMissingReport(), fixture.now)
		return err
	}(), ErrNotFound)
}

func TestCommandIdentityParserRejectsUntrustedEnvelopeShapes(t *testing.T) {
	valid := signedCommand(t, "command-1", "tenant-a", "node-1", 0)
	var envelope dsse.Envelope
	if err := json.Unmarshal(valid, &envelope); err != nil {
		t.Fatal(err)
	}

	cases := [][]byte{[]byte("not-json")}
	wrongType := envelope
	wrongType.PayloadType = "application/example"
	cases = append(cases, marshalEnvelope(t, wrongType))
	emptyPayload := envelope
	emptyPayload.Payload = ""
	emptyPayload.Signatures = envelope.Signatures
	raw, err := json.Marshal(emptyPayload)
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, raw)
	badPayload := envelope
	badPayload.Payload = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":2,"command_id":"bad id","tenant_id":"tenant-a","node_id":"node-1"}`))
	cases = append(cases, marshalEnvelope(t, badPayload))
	unknownPayload := envelope
	unknownPayload.Payload = base64.StdEncoding.EncodeToString([]byte(`{"schema_version":2,"command_id":"command-1","tenant_id":"tenant-a","node_id":"node-1","unknown":true}`))
	cases = append(cases, marshalEnvelope(t, unknownPayload))

	for index, raw := range cases {
		if _, _, _, err := parseCommandIdentity(raw); err == nil {
			t.Fatalf("untrusted command envelope %d was accepted", index)
		}
	}
	if _, _, _, err := parseCommandIdentity(valid); err != nil {
		t.Fatalf("valid signed command identity rejected: %v", err)
	}
}

func TestDeliveryFencingRejectsPrematureStaleFutureAndChangedReports(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")

	commandRaw := signedCommand(t, "command-1", "tenant-a", "node-1", 0)
	command, created, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", commandRaw, fixture.now.Add(2*time.Minute))
	if err != nil || !created {
		t.Fatalf("submit command = (%v, %v)", created, err)
	}
	premature := reportFor(controlprotocol.ExecutorDeliveryV3{
		DeliveryID: command.DeliveryID, DeliveryGeneration: 1, CommandID: command.ID,
		CommandDigest: command.Digest,
	}, controlprotocol.ExecutorStatusDone)
	assertErrorIs(t, func() error {
		_, err := fixture.store.ApplyReport(identity, premature, fixture.now.Add(3*time.Minute))
		return err
	}(), ErrConflict)

	deliveries, err := fixture.store.Poll(identity, []string{}, fixture.now.Add(3*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("first lease = (%d, %v)", len(deliveries), err)
	}
	report := reportFor(deliveries[0], controlprotocol.ExecutorStatusDone)
	wrongDigest := report
	wrongDigest.CommandDigest = "sha256:" + strings.Repeat("f", 64)
	assertErrorIs(t, func() error {
		_, err := fixture.store.ApplyReport(identity, wrongDigest, fixture.now.Add(4*time.Minute))
		return err
	}(), ErrConflict)
	future := report
	future.DeliveryGeneration++
	assertErrorIs(t, func() error {
		_, err := fixture.store.ApplyReport(identity, future, fixture.now.Add(4*time.Minute))
		return err
	}(), ErrConflict)
	assertErrorIs(t, func() error { _, err := fixture.store.ApplyReport(identity, report, fixture.now); return err }(), ErrInvalid)
	if applied, err := fixture.store.ApplyReport(identity, report, fixture.now.Add(4*time.Minute)); err != nil || !applied {
		t.Fatalf("terminal report = (%v, %v)", applied, err)
	}
	if applied, err := fixture.store.ApplyReport(identity, report, fixture.now.Add(5*time.Minute)); err != nil || applied {
		t.Fatalf("exact terminal replay = (%v, %v)", applied, err)
	}
	changed := report
	changed.Status = controlprotocol.ExecutorStatusFailed
	if _, err := fixture.store.ApplyReport(identity, changed, fixture.now.Add(5*time.Minute)); !errors.Is(err, ErrConflict) {
		t.Fatalf("changed terminal replay error = %v", err)
	}

	secondRaw := signedCommand(t, "command-2", "tenant-a", "node-1", 0)
	if _, created, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", secondRaw, fixture.now.Add(6*time.Minute)); err != nil || !created {
		t.Fatalf("submit second command = (%v, %v)", created, err)
	}
	deliveries, err = fixture.store.Poll(identity, []string{}, fixture.now.Add(7*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("second command first lease = (%d, %v)", len(deliveries), err)
	}
	stale := reportFor(deliveries[0], controlprotocol.ExecutorStatusDone)
	deliveries, err = fixture.store.Poll(identity, []string{}, fixture.now.Add(9*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 || deliveries[0].DeliveryGeneration != 2 {
		t.Fatalf("second command replacement lease = (%+v, %v)", deliveries, err)
	}
	if applied, err := fixture.store.ApplyReport(identity, stale, fixture.now.Add(10*time.Minute)); err != nil || applied {
		t.Fatalf("stale report = (%v, %v)", applied, err)
	}

	fixture.store.mu.Lock()
	for key, retained := range fixture.store.current.commands {
		if retained.ID == "command-2" {
			retained.DeliveryGeneration = math.MaxUint64
			retained.LeaseUntil = canonicalTimestamp(fixture.now)
			fixture.store.current.commands[key] = retained
		}
	}
	fixture.store.mu.Unlock()
	if _, err := fixture.store.Poll(identity, []string{}, fixture.now.Add(11*time.Minute), time.Minute, 1); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("generation exhaustion error = %v", err)
	}
}

func TestTerminalPruningPrioritizesTheConstrainedTenantAndNode(t *testing.T) {
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")
	raw := signedCommand(t, "seed", "tenant-a", "node-1", 0)
	if _, _, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", raw, fixture.now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	deliveries, err := fixture.store.Poll(identity, []string{}, fixture.now.Add(2*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("lease seed = (%d, %v)", len(deliveries), err)
	}
	if _, err := fixture.store.ApplyReport(identity, reportFor(deliveries[0], controlprotocol.ExecutorStatusDone), fixture.now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}

	fixture.store.mu.Lock()
	seed := firstCommand(fixture.store.current)
	seed.Terminal.CompletedAt = canonicalTimestamp(fixture.now.Add(-48 * time.Hour))
	fixture.store.current.commands = make(map[string]Command)
	for _, scope := range []struct {
		tenantID string
		nodeID   string
		id       string
	}{
		{"tenant-a", "node-1", "same-node"},
		{"tenant-a", "node-2", "same-tenant"},
		{"tenant-b", "node-3", "other-tenant"},
	} {
		candidate := cloneCommand(seed)
		candidate.TenantID, candidate.NodeID, candidate.ID = scope.tenantID, scope.nodeID, scope.id
		candidate.DeliveryID = "delivery-" + scope.id
		candidate.Terminal.Report.DeliveryID = candidate.DeliveryID
		candidate.Terminal.Report.CommandID = candidate.ID
		fixture.store.current.commands[commandKey(candidate.TenantID, candidate.NodeID, candidate.ID)] = candidate
	}
	unknown := cloneCommand(seed)
	unknown.ID = "unknown-outcome"
	unknown.Terminal.Report.Status = controlprotocol.ExecutorStatusOutcomeUnknown
	fixture.store.current.commands[commandKey(unknown.TenantID, unknown.NodeID, unknown.ID)] = unknown
	pending := cloneCommand(seed)
	pending.ID, pending.State, pending.Terminal = "pending", CommandPending, nil
	fixture.store.current.commands[commandKey(pending.TenantID, pending.NodeID, pending.ID)] = pending
	prunable := fixture.store.prunableCommandsLocked("tenant-a", "node-1", fixture.now)
	fixture.store.mu.Unlock()

	if len(prunable) != 3 || prunable[0].ID != "same-node" || prunable[1].ID != "same-tenant" || prunable[2].ID != "other-tenant" {
		t.Fatalf("prune priority = %+v", prunable)
	}
	if prunePriority(prunable[0], "tenant-a", "node-1") != 0 ||
		prunePriority(prunable[1], "tenant-a", "node-1") != 1 ||
		prunePriority(prunable[2], "tenant-a", "node-1") != 2 {
		t.Fatal("prune priority values changed")
	}
}

func validMissingReport() controlprotocol.ExecutorReportV3 {
	return controlprotocol.ExecutorReportV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3,
		DeliveryID:      "delivery-missing", DeliveryGeneration: 1, CommandID: "command-missing",
		CommandDigest: "sha256:" + strings.Repeat("0", 64), Status: controlprotocol.ExecutorStatusDone,
		ReportedStatus: "completed", ClaimGeneration: 1,
	}
}

func marshalEnvelope(t *testing.T, envelope dsse.Envelope) []byte {
	t.Helper()
	raw, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func assertErrorIs(t *testing.T, err, target error) {
	t.Helper()
	if !errors.Is(err, target) {
		t.Fatalf("error = %v, want %v", err, target)
	}
}
