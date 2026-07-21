package controlstore

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
)

func TestSnapshotDecoderRejectsAmbiguousOrCorruptDurableRecords(t *testing.T) {
	current, limits := populatedControlState(t)
	raw, err := encodeState(current, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeState(raw, limits.MaxStateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateState(decoded, limits); err != nil {
		t.Fatalf("round-tripped state is invalid: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*snapshotState)
	}{
		{"version", func(value *snapshotState) { value.Version++ }},
		{"missing tenants", func(value *snapshotState) { value.Tenants = nil }},
		{"missing freezes", func(value *snapshotState) { value.Freezes = nil }},
		{"missing snapshot quarantines", func(value *snapshotState) { value.Quarantines = nil }},
		{"missing nodes", func(value *snapshotState) { value.Nodes = nil }},
		{"missing credentials", func(value *snapshotState) { value.Credentials = nil }},
		{"missing enrollments", func(value *snapshotState) { value.Enrollments = nil }},
		{"missing commands", func(value *snapshotState) { value.Commands = nil }},
		{"missing deployments", func(value *snapshotState) { value.Deployments = nil }},
		{"duplicate tenant", func(value *snapshotState) { value.Tenants = append(value.Tenants, value.Tenants[0]) }},
		{"duplicate node", func(value *snapshotState) { value.Nodes = append(value.Nodes, value.Nodes[0]) }},
		{"duplicate credential", func(value *snapshotState) { value.Credentials = append(value.Credentials, value.Credentials[0]) }},
		{"duplicate enrollment", func(value *snapshotState) { value.Enrollments = append(value.Enrollments, value.Enrollments[0]) }},
		{"duplicate command", func(value *snapshotState) { value.Commands = append(value.Commands, value.Commands[0]) }},
		{"credential base64", func(value *snapshotState) { value.Credentials[0].TokenMACBase64 = "not-base64" }},
		{"enrollment base64", func(value *snapshotState) { value.Enrollments[0].TokenMACBase64 = "not-base64" }},
		{"command base64", func(value *snapshotState) { value.Commands[0].CommandDSSEBase64 = "not-base64" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var candidate snapshotState
			if err := json.Unmarshal(raw, &candidate); err != nil {
				t.Fatal(err)
			}
			test.mutate(&candidate)
			corrupt, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeState(corrupt, limits.MaxStateBytes); err == nil {
				t.Fatal("corrupt durable snapshot was accepted")
			}
		})
	}
	if _, err := decodeState([]byte(`{"version":1,"tenants":[],"nodes":[],"credentials":[],"enrollments":[],"commands":[],"extra":true}`), limits.MaxStateBytes); err == nil {
		t.Fatal("snapshot with an unknown field was accepted")
	}
	if _, err := decodeState(raw, len(raw)-1); err == nil {
		t.Fatal("snapshot above its configured read bound was accepted")
	}
}

func TestWALDecoderRejectsStructurallyAmbiguousMutations(t *testing.T) {
	current, limits := populatedControlState(t)
	if _, err := encodeTransaction(); err == nil {
		t.Fatal("empty WAL transaction was accepted")
	}
	tooMany := make([]mutation, maxMutationsPerRecord+1)
	if _, err := encodeTransaction(tooMany...); err == nil {
		t.Fatal("oversized WAL transaction was accepted")
	}
	for _, raw := range [][]byte{
		[]byte(`{"version":16,"mutations":[{"kind":"tenant_upsert","tenant":{"id":"tenant-a"}}]}`),
		[]byte(`{"version":1,"mutations":[]}`),
		[]byte(`{"version":1,"mutations":[{"kind":"unknown"}],"extra":true}`),
	} {
		if _, err := decodeTransaction(raw, limits.MaxRecordBytes); err == nil {
			t.Fatalf("invalid WAL transaction was accepted: %s", raw)
		}
	}

	tenant := firstTenant(current)
	node := firstNode(current)
	tests := []mutation{
		{Kind: mutationTenant, Tenant: &tenant, Node: &node},
		{Kind: mutationTenant, Node: &node},
		{Kind: mutationNode, Tenant: &tenant},
		{Kind: mutationCredential, Tenant: &tenant},
		{Kind: mutationEnrollment, Tenant: &tenant},
		{Kind: mutationCommand, Tenant: &tenant},
		{Kind: mutationDeployment, Tenant: &tenant},
		{Kind: mutationCredential, Credential: &storedCredential{TokenMACBase64: "not-base64"}},
		{Kind: mutationEnrollment, Enrollment: &storedEnrollment{TokenMACBase64: "not-base64"}},
		{Kind: mutationCommand, Command: &storedCommand{CommandDSSEBase64: "not-base64"}},
		{Kind: mutationDeployment, Deployment: &storedDeployment{CapsuleDSSEBase64: "not-base64"}},
		{Kind: mutationEnrollmentDelete, EnrollmentID: "bad id"},
		{Kind: mutationEnrollmentDelete, EnrollmentID: "missing"},
		{Kind: mutationCommandDelete, CommandRef: &commandReference{TenantID: "bad id", NodeID: "node-1", ID: "command-1"}},
		{Kind: mutationCommandDelete, CommandRef: &commandReference{TenantID: "tenant-a", NodeID: "node-1", ID: "missing"}},
		{Kind: mutationNodeRevoke, NodeRevoke: &nodeRevocation{NodeID: "bad id", RevokedAt: tenant.CreatedAt}},
		{Kind: mutationNodeRevoke, NodeRevoke: &nodeRevocation{NodeID: "missing", RevokedAt: tenant.CreatedAt}},
		{Kind: "unknown", Tenant: &tenant},
	}
	for index, change := range tests {
		if _, err := applyTransaction(current, transaction{Version: transactionFormatWriteVersion, Mutations: []mutation{change}}); err == nil {
			t.Fatalf("ambiguous WAL mutation %d was accepted: %+v", index, change)
		}
	}
}

func TestStateValidationFencesCrossRecordCorruptionAndQuotaBypass(t *testing.T) {
	baseline, defaultLimits := populatedControlState(t)
	admin := firstOperatorCredential(baseline)
	nodeCredential := firstNodeCredential(baseline)
	enrollment := firstEnrollment(baseline)
	command := firstCommand(baseline)

	tests := []struct {
		name   string
		limits func(*Limits)
		mutate func(*state)
	}{
		{"global quota", func(limits *Limits) { limits.MaxTenants = 0 }, func(*state) {}},
		{"tenant map identity", nil, func(value *state) {
			tenant := value.tenants["tenant-a"]
			delete(value.tenants, "tenant-a")
			value.tenants["wrong"] = tenant
		}},
		{"tenant timestamp", nil, func(value *state) {
			tenant := value.tenants["tenant-a"]
			tenant.CreatedAt = "not-a-time"
			value.tenants[tenant.ID] = tenant
		}},
		{"node map identity", nil, func(value *state) {
			node := value.nodes["node-1"]
			delete(value.nodes, "node-1")
			value.nodes["wrong"] = node
		}},
		{"node tenant set", nil, func(value *state) {
			node := value.nodes["node-1"]
			node.TenantIDs = []string{"tenant-a", "tenant-a"}
			value.nodes[node.ID] = node
		}},
		{"node capabilities", nil, func(value *state) {
			node := value.nodes["node-1"]
			node.Capabilities = []string{"z", "a"}
			value.nodes[node.ID] = node
		}},
		{"node observation before creation", nil, func(value *state) {
			node := value.nodes["node-1"]
			node.LastSeenAt = canonicalTimestamp(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
			value.nodes[node.ID] = node
		}},
		{"node revocation before creation", nil, func(value *state) {
			node := value.nodes["node-1"]
			node.Active = false
			node.RevokedAt = canonicalTimestamp(time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC))
			value.nodes[node.ID] = node
		}},
		{"node unknown tenant", nil, func(value *state) {
			node := value.nodes["node-1"]
			node.TenantIDs = []string{"missing"}
			value.nodes[node.ID] = node
		}},
		{"node tenant quota", func(limits *Limits) { limits.MaxNodesPerTenant = 0 }, func(*state) {}},
		{"credential map identity", nil, func(value *state) {
			credential := admin
			value.credentials["wrong"] = credential
			delete(value.credentials, admin.ID)
		}},
		{"duplicate operator request", nil, func(value *state) {
			duplicate := admin
			duplicate.ID = "operator-duplicate"
			value.credentials[duplicate.ID] = duplicate
		}},
		{"operator unknown tenant", nil, func(value *state) {
			credential := admin
			credential.ID = "operator-tenant"
			credential.RequestID = "operator-tenant"
			credential.Role = controlauth.RoleTenantOperator
			credential.TenantID = "missing"
			value.credentials[credential.ID] = credential
		}},
		{"credential tenant quota", func(limits *Limits) { limits.MaxCredentialsPerTenant = 0 }, func(*state) {}},
		{"node credential unknown node", nil, func(value *state) {
			credential := nodeCredential
			credential.ID = "node-credential-missing"
			credential.NodeID = "missing"
			value.credentials[credential.ID] = credential
		}},
		{"enrollment map identity", nil, func(value *state) {
			candidate := enrollment
			value.enrollments["wrong"] = candidate
			delete(value.enrollments, candidate.ID)
		}},
		{"enrollment unknown node", nil, func(value *state) {
			candidate := enrollment
			candidate.ID = "enrollment-missing-node"
			candidate.NodeID = "missing"
			value.enrollments[candidate.ID] = candidate
		}},
		{"enrollment missing credential", nil, func(value *state) {
			candidate := enrollment
			candidate.CredentialID = "missing"
			value.enrollments[candidate.ID] = candidate
		}},
		{"enrollment unknown issuer", nil, func(value *state) {
			candidate := enrollment
			candidate.IssueRequestID = "request"
			candidate.IssuerCredentialID = "missing"
			value.enrollments[candidate.ID] = candidate
		}},
		{"duplicate enrollment request", nil, func(value *state) {
			first := enrollment
			first.IssueRequestID = "request"
			first.IssuerCredentialID = admin.ID
			value.enrollments[first.ID] = first
			duplicate := first
			duplicate.ID = "enrollment-duplicate"
			value.enrollments[duplicate.ID] = duplicate
		}},
		{"enrollment tenant quota", func(limits *Limits) { limits.MaxEnrollmentsPerTenant = 0 }, func(*state) {}},
		{"command map identity", nil, func(value *state) {
			candidate := command
			delete(value.commands, commandKey(candidate.TenantID, candidate.NodeID, candidate.ID))
			value.commands["wrong"] = candidate
		}},
		{"command unknown node", nil, func(value *state) {
			candidate := command
			delete(value.commands, commandKey(candidate.TenantID, candidate.NodeID, candidate.ID))
			candidate.NodeID = "missing"
			value.commands[commandKey(candidate.TenantID, candidate.NodeID, candidate.ID)] = candidate
		}},
		{"command tenant quota", func(limits *Limits) { limits.MaxCommandsPerTenant = 0 }, func(*state) {}},
		{"encoded state quota", func(limits *Limits) { limits.MaxStateBytes = 1 }, func(*state) {}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			candidate := baseline.clone()
			limits := defaultLimits
			if test.limits != nil {
				test.limits(&limits)
			}
			test.mutate(&candidate)
			if err := validateState(candidate, limits); err == nil {
				t.Fatal("corrupt or over-quota state was accepted")
			}
		})
	}
}

func TestCommandValidationRejectsImpossibleLifecycleStates(t *testing.T) {
	baseline, limits := populatedControlState(t)
	terminal := firstCommand(baseline)
	leased := cloneCommand(terminal)
	leased.State = CommandLeased
	leased.Terminal = nil
	leased.LeaseUntil = canonicalTimestamp(mustParseTime(t, leased.CreatedAt).Add(time.Minute))
	pending := cloneCommand(terminal)
	pending.State = CommandPending
	pending.DeliveryGeneration = 0
	pending.LeaseUntil = ""
	pending.Terminal = nil

	tests := []Command{
		func() Command { value := pending; value.Digest = "sha256:bad"; return value }(),
		func() Command { value := pending; value.DeliveryGeneration = 1; return value }(),
		func() Command { value := leased; value.DeliveryGeneration = 0; return value }(),
		func() Command { value := leased; value.LeaseUntil = value.CreatedAt; return value }(),
		func() Command { value := terminal; value.Terminal = nil; return value }(),
		func() Command { value := terminal; value.Terminal.Report.CommandID = "another"; return value }(),
		func() Command { value := terminal; value.Terminal.Digest = "sha256:bad"; return value }(),
		func() Command {
			value := terminal
			value.Terminal.CompletedAt = canonicalTimestamp(mustParseTime(t, value.CreatedAt).Add(-time.Second))
			return value
		}(),
		func() Command { value := pending; value.State = "unknown"; return value }(),
	}
	for index, command := range tests {
		if err := validateCommand(command, limits); err == nil {
			t.Fatalf("impossible command lifecycle %d was accepted", index)
		}
	}
}

func populatedControlState(t *testing.T) (state, Limits) {
	t.Helper()
	fixture := newRecordsFixture(t, DefaultLimits())
	fixture.createTenant(t, "tenant-a")
	_, identity := fixture.createNode(t, "tenant-a")
	commandRaw := signedCommand(t, "command-1", "tenant-a", "node-1", 0)
	if _, created, err := fixture.store.SubmitCommand(fixture.admin, "tenant-a", "node-1", commandRaw, fixture.now.Add(2*time.Minute)); err != nil || !created {
		t.Fatalf("submit command = (%v, %v)", created, err)
	}
	deliveries, err := fixture.store.Poll(identity, []string{"signed-commands-v2"}, fixture.now.Add(3*time.Minute), time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll command = (%d, %v)", len(deliveries), err)
	}
	if applied, err := fixture.store.ApplyReport(identity, reportFor(deliveries[0], "done"), fixture.now.Add(4*time.Minute)); err != nil || !applied {
		t.Fatalf("apply report = (%v, %v)", applied, err)
	}
	fixture.store.mu.Lock()
	current := fixture.store.current.clone()
	fixture.store.mu.Unlock()
	return current, fixture.limits
}

func firstTenant(current state) Tenant {
	for _, value := range current.tenants {
		return value
	}
	panic("missing tenant")
}

func firstNode(current state) Node {
	for _, value := range current.nodes {
		return value
	}
	panic("missing node")
}

func firstOperatorCredential(current state) controlauth.Credential {
	for _, value := range current.credentials {
		if value.Kind == controlauth.KindOperator {
			return value
		}
	}
	panic("missing operator credential")
}

func firstNodeCredential(current state) controlauth.Credential {
	for _, value := range current.credentials {
		if value.Kind == controlauth.KindNode {
			return value
		}
	}
	panic("missing node credential")
}

func firstEnrollment(current state) controlauth.Enrollment {
	for _, value := range current.enrollments {
		return value
	}
	panic("missing enrollment")
}

func firstCommand(current state) Command {
	for _, value := range current.commands {
		return cloneCommand(value)
	}
	panic("missing command")
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := parseTimestamp(value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}
