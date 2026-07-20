package controlclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

func TestDeploymentClientPreservesSignedBindingsAndRevisionIntent(t *testing.T) {
	capsule := []byte(`{"payloadType":"capsule"}`)
	delegation := []byte(`{"payloadType":"delegation"}`)
	want := validClientDeployment()
	want.CapsuleDigest = dsse.Digest(capsule)
	want.DelegationDigest = dsse.Digest(delegation)
	want.Fork = &controlstore.DeploymentFork{
		SnapshotID: "checkpoint-a", SourceLineageID: "source-lineage",
		SourceNodeID: "node-1", ExpiresAt: "2026-07-13T20:30:00Z",
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.Header.Get("Authorization") != "Bearer operator" {
			t.Fatal("deployment request omitted operator bearer")
		}
		writer.Header().Set("Content-Type", "application/json")
		switch {
		case request.Method == http.MethodPut:
			var body struct {
				Generation           uint64                                   `json:"generation"`
				ExpectedRevision     uint64                                   `json:"expected_revision"`
				CapsuleDSSEBase64    string                                   `json:"capsule_dsse_base64"`
				DelegationDSSEBase64 string                                   `json:"delegation_dsse_base64"`
				DisruptionBudget     *controlstore.DeploymentDisruptionBudget `json:"disruption_budget"`
				Fork                 *controlstore.DeploymentFork             `json:"fork"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.Generation != 1 ||
				body.ExpectedRevision != 7 || body.CapsuleDSSEBase64 != base64.StdEncoding.EncodeToString(capsule) ||
				body.DelegationDSSEBase64 != base64.StdEncoding.EncodeToString(delegation) ||
				body.DisruptionBudget == nil || body.DisruptionBudget.MaxUnavailable != 1 ||
				body.Fork == nil || *body.Fork != *want.Fork {
				t.Fatalf("deployment apply body = (%+v, %v)", body, err)
			}
			_ = json.NewEncoder(writer).Encode(want)
		case request.Method == http.MethodGet && request.URL.RawQuery != "":
			if request.URL.Query().Get("after") != "before" || request.URL.Query().Get("limit") != "10" {
				t.Fatalf("deployment page query = %q", request.URL.RawQuery)
			}
			_ = json.NewEncoder(writer).Encode(DeploymentList{Deployments: []Deployment{want}})
		case request.Method == http.MethodGet:
			_ = json.NewEncoder(writer).Encode(want)
		case request.Method == http.MethodDelete:
			var body struct {
				ExpectedRevision uint64 `json:"expected_revision"`
			}
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil || body.ExpectedRevision != 1 {
				t.Fatalf("deployment removal body = (%+v, %v)", body, err)
			}
			removed := want
			removed.DesiredState = controlstore.DeploymentAbsent
			removed.Phase = controlstore.DeploymentStopping
			removed.Revision = 2
			_ = json.NewEncoder(writer).Encode(removed)
		default:
			t.Fatalf("unexpected deployment request %s %s", request.Method, request.URL.String())
		}
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	budget := controlstore.DeploymentDisruptionBudget{MaxUnavailable: 1}
	applied, err := client.ApplyDeployment(ctx, "tenant-a", "research", DeploymentApply{
		Generation: 1, ExpectedRevision: 7, AgentName: "research-agent",
		BundleDigest: want.BundleDigest, CapsuleDSSE: capsule, DelegationDSSE: delegation,
		DisruptionBudget: &budget,
		Fork:             want.Fork,
	})
	if err != nil || applied.DeploymentID != "research" {
		t.Fatalf("apply deployment = (%+v, %v)", applied, err)
	}
	if loaded, err := client.GetDeployment(ctx, "tenant-a", "research"); err != nil || loaded.Revision != 1 {
		t.Fatalf("get deployment = (%+v, %v)", loaded, err)
	}
	if page, err := client.ListDeployments(ctx, "tenant-a", "before", 10); err != nil || len(page.Deployments) != 1 {
		t.Fatalf("list deployments = (%+v, %v)", page, err)
	}
	if removed, err := client.RemoveDeployment(ctx, "tenant-a", "research", 1); err != nil ||
		removed.DesiredState != controlstore.DeploymentAbsent {
		t.Fatalf("remove deployment = (%+v, %v)", removed, err)
	}
	if requests != 4 {
		t.Fatalf("deployment request count = %d", requests)
	}
}

func TestDeploymentClientRejectsInvalidLocalInputAndUntrustedProjection(t *testing.T) {
	requests := 0
	invalid := validClientDeployment()
	invalid.Instances = nil
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(writer).Encode(invalid)
	}))
	defer server.Close()
	client, err := New(server.URL, "operator", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := client.GetDeployment(ctx, "tenant-a", "research"); err == nil {
		t.Fatal("client accepted deployment with a missing instance collection")
	}
	for _, call := range []func() error{
		func() error { _, err := client.GetDeployment(ctx, "bad tenant", "research"); return err },
		func() error {
			_, err := client.ListDeployments(ctx, "tenant-a", strings.Repeat("x", 129), 1)
			return err
		},
		func() error { _, err := client.RemoveDeployment(ctx, "tenant-a", "research", 0); return err },
	} {
		if err := call(); err == nil {
			t.Fatal("invalid local deployment input reached transport")
		}
	}
	if requests != 1 {
		t.Fatalf("invalid local input made %d requests", requests-1)
	}
}

func TestDeploymentClientValidatesRolloutProjection(t *testing.T) {
	deployment := validClientDeployment()
	deployment.Generation = 2
	deployment.Phase = controlstore.DeploymentReconciling
	deployment.Rollout = &DeploymentRollout{
		SourceGeneration: 1, SourceAgentName: deployment.AgentName,
		SourceBundleDigest:     "sha256:" + strings.Repeat("d", 64),
		SourceCapsuleDigest:    "sha256:" + strings.Repeat("e", 64),
		SourceDelegationDigest: "sha256:" + strings.Repeat("f", 64),
		StartedAt:              deployment.UpdatedAt,
	}
	deployment.Instances[0].Intent = nil
	deployment.Instances[0].Rollout = &controlstore.DeploymentInstanceRollout{
		Stage: "draining", StartedAt: deployment.UpdatedAt,
	}
	if err := validateDeploymentResponse(deployment, "tenant-a", "research"); err != nil {
		t.Fatalf("valid rollout projection was rejected: %v", err)
	}
	deployment.Instances[0].Rollout.Stage = "unknown"
	if err := validateDeploymentResponse(deployment, "tenant-a", "research"); err == nil {
		t.Fatal("unknown rollout stage was accepted")
	}
	deployment.Instances[0].Rollout.Stage = "draining"
	deployment.Rollout.StartedAt = "not-a-time"
	if err := validateDeploymentResponse(deployment, "tenant-a", "research"); err == nil {
		t.Fatal("malformed rollout time was accepted")
	}
	deployment.Rollout.StartedAt = deployment.UpdatedAt
	deployment.Rollout.SourceGeneration = deployment.Generation
	if err := validateDeploymentResponse(deployment, "tenant-a", "research"); err == nil {
		t.Fatal("non-forward rollout generation was accepted")
	}
	deployment.Rollout.SourceGeneration = 1
	deployment.Instances[0].Rollout.StartedAt = "not-a-time"
	if err := validateDeploymentResponse(deployment, "tenant-a", "research"); err == nil {
		t.Fatal("malformed instance rollout time was accepted")
	}
	deployment.Instances[0].Rollout.StartedAt = deployment.UpdatedAt
	deployment.Rollout = nil
	if err := validateDeploymentResponse(deployment, "tenant-a", "research"); err == nil {
		t.Fatal("instance rollout without deployment rollout was accepted")
	}
}

func TestDeploymentClientRejectsMalformedProjectionFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Deployment)
	}{
		{"disruption budget", func(value *Deployment) {
			value.DisruptionBudget.MaxUnavailable = len(value.Instances) + 1
		}},
		{"node scope", func(value *Deployment) { value.AllowedNodeIDs = []string{"bad node"} }},
		{"instance identity", func(value *Deployment) { value.Instances[0].InstanceID = "bad instance" }},
		{"intent", func(value *Deployment) { value.Instances[0].Intent = &admission.InstanceIntent{} }},
		{"admission", func(value *Deployment) {
			value.Instances[0].Admission = &controlprotocol.ExecutorAdmissionProjectionV1{}
		}},
		{"timestamps", func(value *Deployment) { value.UpdatedAt = "not-a-time" }},
		{"desired state", func(value *Deployment) { value.DesiredState = "unknown" }},
		{"phase", func(value *Deployment) { value.Phase = "unknown" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			deployment := validClientDeployment()
			test.mutate(&deployment)
			if err := validateDeploymentResponse(deployment, "tenant-a", "research"); err == nil {
				t.Fatal("malformed deployment projection was accepted")
			}
		})
	}
}

func validClientDeployment() Deployment {
	created := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	return Deployment{
		TenantID: "tenant-a", DeploymentID: "research", Generation: 1, Revision: 1,
		AgentName: "research-agent", BundleDigest: "sha256:" + strings.Repeat("a", 64),
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64), DelegationDigest: "sha256:" + strings.Repeat("c", 64),
		DelegationID: "research-authority", ControllerKeyID: "controller-a", ClaimGeneration: 1,
		AllowedNodeIDs: []string{"node-1"}, DelegationExpiresAt: created.Add(6 * time.Hour).Format(time.RFC3339Nano),
		DesiredState: controlstore.DeploymentRunning, Phase: controlstore.DeploymentPending,
		DisruptionBudget: controlstore.DeploymentDisruptionBudget{MaxUnavailable: 1},
		Instances: []controlstore.DeploymentInstance{{
			InstanceID: "research-0", LineageID: "research-lineage-0", Generation: 1,
			Phase: controlstore.DeploymentInstancePending, TransitionedAt: created.Format(time.RFC3339Nano),
		}},
		CreatedAt: created.Format(time.RFC3339Nano), UpdatedAt: created.Format(time.RFC3339Nano),
	}
}
