package controlplane

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

func TestDeploymentHTTPContractAppliesProjectsListsAndRemoves(t *testing.T) {
	fixture := newServerFixture(t)
	admin, err := fixture.store.AuthenticateOperator(fixture.server.auth, fixture.adminToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, created, err := fixture.store.CreateTenant(admin, "tenant-a", fixture.now); err != nil || !created {
		t.Fatalf("create tenant = (%v, %v)", created, err)
	}
	if _, _, _, err := fixture.store.CreateEnrollment(
		admin, fixture.server.auth, "node-1", []string{"tenant-a"},
		fixture.now.Add(time.Hour), fixture.now,
	); err != nil {
		t.Fatal(err)
	}
	input := deploymentHTTPFixture(t, fixture.now, "research")
	response := fixture.request(
		t, http.MethodPut, "/v1/tenants/tenant-a/deployments/research", fixture.adminToken,
		mustJSON(t, input),
	)
	requireStatus(t, response, http.StatusCreated)
	var created deploymentResponse
	decodeResponse(t, response, &created)
	if created.DeploymentID != "research" || created.Revision != 1 || created.Generation != 1 ||
		created.DesiredState != controlstore.DeploymentRunning || len(created.Instances) != 1 ||
		created.ControllerKeyID != "controller-a" || created.CapsuleDigest == "" ||
		created.DisruptionBudget.MaxUnavailable != 1 ||
		len(created.AllowedNodeIDs) != 1 || created.AllowedNodeIDs[0] != "node-1" {
		t.Fatalf("created deployment response = %+v", created)
	}

	response = fixture.request(
		t, http.MethodPut, "/v1/tenants/tenant-a/deployments/research", fixture.adminToken,
		mustJSON(t, input),
	)
	requireStatus(t, response, http.StatusOK)
	response = fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/deployments/research", fixture.adminToken, "",
	)
	requireStatus(t, response, http.StatusOK)
	var projected deploymentResponse
	decodeResponse(t, response, &projected)
	if projected.DeploymentID != created.DeploymentID || projected.DelegationDigest != created.DelegationDigest {
		t.Fatalf("projected deployment = %+v", projected)
	}
	requireError(t, fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/deployments/missing", fixture.adminToken, "",
	), http.StatusNotFound, "not_found")
	response = fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/deployments?limit=1", fixture.adminToken, "",
	)
	requireStatus(t, response, http.StatusOK)
	var list deploymentListResponse
	decodeResponse(t, response, &list)
	if len(list.Deployments) != 1 || list.Deployments[0].DeploymentID != "research" || list.NextAfter != "" {
		t.Fatalf("deployment list = %+v", list)
	}
	secondInput := deploymentHTTPFixture(t, fixture.now, "writer")
	response = fixture.request(
		t, http.MethodPut, "/v1/tenants/tenant-a/deployments/writer", fixture.adminToken,
		mustJSON(t, secondInput),
	)
	requireStatus(t, response, http.StatusCreated)
	response = fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/deployments?limit=1", fixture.adminToken, "",
	)
	requireStatus(t, response, http.StatusOK)
	list = deploymentListResponse{}
	decodeResponse(t, response, &list)
	if len(list.Deployments) != 1 || list.Deployments[0].DeploymentID != "research" || list.NextAfter != "research" {
		t.Fatalf("first deployment page = %+v", list)
	}
	response = fixture.request(
		t, http.MethodGet, "/v1/tenants/tenant-a/deployments?limit=1&after=research", fixture.adminToken, "",
	)
	requireStatus(t, response, http.StatusOK)
	list = deploymentListResponse{}
	decodeResponse(t, response, &list)
	if len(list.Deployments) != 1 || list.Deployments[0].DeploymentID != "writer" || list.NextAfter != "" {
		t.Fatalf("second deployment page = %+v", list)
	}
	response = fixture.request(
		t, http.MethodDelete, "/v1/tenants/tenant-a/deployments/research", fixture.adminToken,
		`{"expected_revision":1}`,
	)
	requireStatus(t, response, http.StatusAccepted)
	var removed deploymentResponse
	decodeResponse(t, response, &removed)
	if removed.DesiredState != controlstore.DeploymentAbsent || removed.Revision != 2 ||
		removed.Phase != controlstore.DeploymentStopping {
		t.Fatalf("removed deployment = %+v", removed)
	}
}

func TestDeploymentHTTPContractFailsClosedAtRoutingAndEncodingBoundaries(t *testing.T) {
	fixture := newServerFixture(t)
	for _, test := range []struct {
		method string
		path   string
		body   string
		status int
		code   string
	}{
		{http.MethodPost, "/v1/tenants/tenant-a/deployments", `{}`, http.StatusMethodNotAllowed, "method_not_allowed"},
		{http.MethodGet, "/v1/tenants/tenant-a/deployments/x?unexpected=1", "", http.StatusBadRequest, "invalid_request"},
		{http.MethodPut, "/v1/tenants/tenant-a/deployments/x", `{}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodPut, "/v1/tenants/tenant-a/deployments/x", `{"generation":1,"agent_name":"a","bundle_digest":"x","capsule_dsse_base64":"Zh","delegation_dsse_base64":"Zh"}`, http.StatusBadRequest, "invalid_request"},
		{http.MethodDelete, "/v1/tenants/tenant-a/deployments/x", `{"expected_revision":0}`, http.StatusBadRequest, "invalid_request"},
	} {
		requireError(t, fixture.request(t, test.method, test.path, fixture.adminToken, test.body), test.status, test.code)
	}
	oversized := `{"generation":1,"agent_name":"a","bundle_digest":"x","capsule_dsse_base64":"` +
		strings.Repeat("a", maxRequestBytes) + `","delegation_dsse_base64":"a"}`
	requireError(
		t, fixture.request(t, http.MethodPut, "/v1/tenants/tenant-a/deployments/x", fixture.adminToken, oversized),
		http.StatusRequestEntityTooLarge, "payload_too_large",
	)
}

func TestDeploymentViewProjectsRolloutDigestsWithoutAuthorityEnvelopes(t *testing.T) {
	now := time.Date(2026, 7, 20, 18, 0, 0, 0, time.UTC)
	input := deploymentHTTPFixture(t, now, "research")
	capsule, err := base64.StdEncoding.DecodeString(input.CapsuleDSSEBase64)
	if err != nil {
		t.Fatal(err)
	}
	delegation, err := base64.StdEncoding.DecodeString(input.DelegationDSSEBase64)
	if err != nil {
		t.Fatal(err)
	}
	value := controlstore.Deployment{
		TenantID: "tenant-a", ID: "research", Generation: 2, Revision: 9,
		AgentName: "research-agent", BundleDigest: input.BundleDigest,
		CapsuleDSSE: capsule, DelegationDSSE: delegation,
		DesiredState:     controlstore.DeploymentRunning,
		DisruptionBudget: controlstore.DeploymentDisruptionBudget{MaxUnavailable: 1},
		Phase:            controlstore.DeploymentReconciling, Instances: []controlstore.DeploymentInstance{},
		Rollout: &controlstore.DeploymentRollout{
			SourceGeneration: 1, SourceAgentName: "research-agent",
			SourceBundleDigest: input.BundleDigest,
			SourceCapsuleDSSE:  capsule, SourceDelegationDSSE: delegation,
			StartedAt: now.Format(time.RFC3339Nano),
		},
		CreatedAt: now.Format(time.RFC3339Nano), UpdatedAt: now.Format(time.RFC3339Nano),
	}
	view, err := deploymentView(value)
	if err != nil || view.Rollout == nil || view.Rollout.SourceCapsuleDigest != dsse.Digest(capsule) ||
		view.Rollout.SourceDelegationDigest != dsse.Digest(delegation) {
		t.Fatalf("rollout projection = (%+v, %v)", view.Rollout, err)
	}
	raw, err := json.Marshal(view)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), base64.StdEncoding.EncodeToString(capsule)) ||
		strings.Contains(string(raw), base64.StdEncoding.EncodeToString(delegation)) {
		t.Fatal("rollout projection exposed retained authority envelope")
	}
}

func deploymentHTTPFixture(t *testing.T, now time.Time, deploymentID string) deploymentApplyRequest {
	t.Helper()
	_, publisherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	capsuleEnvelope, err := dsse.Sign(
		admission.CapsulePayloadType, []byte(`{"schema_version":"steward.capsule.v1"}`),
		"publisher-a", publisherPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	capsuleRaw, err := dsse.Marshal(capsuleEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegation := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1,
		DelegationID:  deploymentID + "-authority", TenantID: "tenant-a",
		ControllerKeyID: "controller-a", ControllerPublicKey: base64.StdEncoding.EncodeToString(controllerPublic),
		Operations: []string{"admit", "destroy", "renew", "start", "stop"}, NodeIDs: []string{"node-1"},
		Instances: []admission.CommandDelegationInstance{{
			InstanceID: deploymentID + "-0", LineageID: deploymentID + "-lineage-0",
			MinInstanceGeneration: 1, MaxInstanceGeneration: 3,
		}},
		ClaimGeneration: 1,
		Admission: &admission.CommandDelegationAdmissionTemplate{
			CapsuleDigest:    dsse.Digest(capsuleRaw),
			Resources:        admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
			StateDisposition: "none",
		},
		IssuedAt: now.Format(time.RFC3339Nano), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(delegation)
	if err != nil {
		t.Fatal(err)
	}
	_, tenantPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	delegationEnvelope, err := dsse.Sign(
		admission.CommandDelegationPayloadType, payload, "tenant-command-a", tenantPrivate,
	)
	if err != nil {
		t.Fatal(err)
	}
	delegationRaw, err := dsse.Marshal(delegationEnvelope)
	if err != nil {
		t.Fatal(err)
	}
	return deploymentApplyRequest{
		Generation: 1, AgentName: "research-agent",
		BundleDigest:         "sha256:" + strings.Repeat("a", 64),
		CapsuleDSSEBase64:    base64.StdEncoding.EncodeToString(capsuleRaw),
		DelegationDSSEBase64: base64.StdEncoding.EncodeToString(delegationRaw),
	}
}
