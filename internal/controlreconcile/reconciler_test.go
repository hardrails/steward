package controlreconcile

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
)

type reconcileFixture struct {
	store      *controlstore.Store
	auth       *controlauth.Manager
	admin      controlauth.Identity
	node       controlauth.NodeIdentity
	now        time.Time
	dir        string
	controller ed25519.PrivateKey
	limits     controlstore.Limits
}

func TestReconcilerConvergesLifecycleWithoutDuplicateEffectAcrossRestart(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)

	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Enqueued != 1 {
		t.Fatalf("enqueue admit = (%+v, %v)", report, err)
	}
	deployment := getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentReconciling ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceAdmitting ||
		deployment.Instances[0].CommandOperation != "admit" {
		t.Fatalf("admit cursor = %+v", deployment)
	}
	firstCommand := deployment.Instances[0].CommandID

	// Restart after durable enqueue but before a node report. The new
	// reconciler observes the same pending command and does not create another.
	if err := fixture.store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := controlstore.Open(fixture.dir, fixture.limits)
	if err != nil {
		t.Fatal(err)
	}
	fixture.store = reopened
	t.Cleanup(func() { _ = reopened.Close() })
	reconciler = fixture.reconciler(t)
	report, err = reconciler.Reconcile(context.Background())
	if err != nil || report.Enqueued != 0 || report.Observed != 0 {
		t.Fatalf("restart pending reconciliation = (%+v, %v)", report, err)
	}
	if deployment = getControlDeployment(t, fixture); deployment.Instances[0].CommandID != firstCommand ||
		deployment.Instances[0].Attempts != 1 {
		t.Fatalf("restart duplicated command = %+v", deployment.Instances[0])
	}

	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe admit", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue start", 0, 1)
	completeDeploymentCommand(t, fixture, "start", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe start", 1, 0)
	deployment = getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentReady ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceRunning {
		t.Fatalf("running deployment = %+v", deployment)
	}

	removed, changed, err := fixture.store.SetDeploymentDesiredState(
		fixture.admin, "tenant-a", "research", deployment.Revision,
		controlstore.DeploymentAbsent, fixture.now.Add(20*time.Minute),
	)
	if err != nil || !changed || removed.Phase != controlstore.DeploymentStopping {
		t.Fatalf("set absent = (%+v, %v, %v)", removed, changed, err)
	}
	fixture.now = fixture.now.Add(20 * time.Minute)
	assertReconcileCount(t, reconciler, "enqueue stop", 0, 1)
	completeDeploymentCommand(t, fixture, "stop", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe stop", 1, 0)
	assertReconcileCount(t, reconciler, "enqueue destroy", 0, 1)
	completeDeploymentCommand(t, fixture, "destroy", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, reconciler, "observe destroy", 1, 0)
	deployment = getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentRemoved ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceRemoved ||
		deployment.Instances[0].Attempts != 4 {
		t.Fatalf("removed deployment = %+v", deployment)
	}
}

func TestReconcilerDegradesAmbiguousOutcomeWithoutRetry(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	assertReconcileCount(t, reconciler, "enqueue admit", 0, 1)
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusOutcomeUnknown)
	assertReconcileCount(t, reconciler, "observe unknown", 1, 0)
	deployment := getControlDeployment(t, fixture)
	if deployment.Phase != controlstore.DeploymentDegraded ||
		deployment.Instances[0].Phase != controlstore.DeploymentInstanceFailed ||
		!strings.Contains(deployment.Instances[0].LastError, controlprotocol.ExecutorStatusOutcomeUnknown) {
		t.Fatalf("ambiguous deployment = %+v", deployment)
	}
	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Enqueued != 0 || report.Observed != 0 ||
		getControlDeployment(t, fixture).Instances[0].Attempts != 1 {
		t.Fatalf("ambiguous outcome retried = (%+v, %v)", report, err)
	}
}

func TestConcurrentReconcilersCannotDoubleEnqueueOrWidenAuthority(t *testing.T) {
	fixture := newControlReconcileFixture(t)
	applyControlDeployment(t, fixture, 1)
	reconciler := fixture.reconciler(t)
	start := make(chan struct{})
	reports := make(chan Report, 2)
	errors := make(chan error, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			report, err := reconciler.Reconcile(context.Background())
			reports <- report
			errors <- err
		}()
	}
	close(start)
	workers.Wait()
	close(reports)
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	enqueued := 0
	for report := range reports {
		enqueued += report.Enqueued
	}
	if status, err := fixture.store.Status(); err != nil || enqueued != 1 || status.Commands != 1 ||
		getControlDeployment(t, fixture).Instances[0].Attempts != 1 {
		t.Fatalf("concurrent reconciliation = enqueued %d status %+v err %v", enqueued, status, err)
	}

	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := New(Config{
		Store: fixture.store, KeyID: "controller-a", PrivateKey: wrongKey,
		Interval: time.Second, Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	// The pending command is observed, not re-signed. After admission succeeds,
	// the wrong key cannot produce the next effect.
	completeDeploymentCommand(t, fixture, "admit", controlprotocol.ExecutorStatusDone)
	assertReconcileCount(t, wrong, "observe admit with wrong key", 1, 0)
	report, err := wrong.Reconcile(context.Background())
	if err != nil || report.Blocked != 1 || report.Enqueued != 0 {
		t.Fatalf("wrong controller key widened authority = (%+v, %v)", report, err)
	}
}

func newControlReconcileFixture(t *testing.T) *reconcileFixture {
	t.Helper()
	limits := controlstore.DefaultLimits()
	dir := filepath.Join(t.TempDir(), "control")
	store, err := controlstore.Initialize(dir, limits)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	auth, err := controlauth.New(bytes.Repeat([]byte{0x44}, controlauth.KeyBytes))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 19, 12, 0, 0, 0, time.UTC)
	adminRaw, _, _, err := store.BootstrapSiteAdmin(auth, now)
	if err != nil {
		t.Fatal(err)
	}
	admin, err := store.AuthenticateOperator(auth, adminRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := store.CreateTenant(admin, "tenant-a", now); err != nil {
		t.Fatal(err)
	}
	enrollmentRaw, enrollment, _, err := store.CreateEnrollment(
		admin, auth, "node-1", []string{"tenant-a"}, now.Add(time.Hour), now,
	)
	if err != nil {
		t.Fatal(err)
	}
	public, receiptPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := controlprotocol.NewExecutorEvidenceIdentityClaimV1(
		auth.InstanceID(), enrollment.ID, "node-1", "node-1", 1, public,
	)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := controlprotocol.SignExecutorEvidenceIdentityClaimV1(claim, receiptPrivate)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := store.ExchangeEnrollment(auth, enrollmentRaw, "enroll-node-1", proof, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	node, err := store.AuthenticateNode(auth, credential.Credential)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := []string{
		controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
		controlprotocol.ExecutorCapabilityControllerDelegationV1,
	}
	if deliveries, err := store.PollV4(node, capabilities, now.Add(2*time.Minute), time.Minute, 1); err != nil || len(deliveries) != 0 {
		t.Fatalf("prime node capabilities = (%+v, %v)", deliveries, err)
	}
	_, controller, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &reconcileFixture{
		store: store, auth: auth, admin: admin, node: node, now: now.Add(3 * time.Minute),
		dir: dir, controller: controller, limits: limits,
	}
}

func (fixture *reconcileFixture) reconciler(t *testing.T) *Reconciler {
	t.Helper()
	reconciler, err := New(Config{
		Store: fixture.store, KeyID: "controller-a", PrivateKey: fixture.controller,
		Interval: time.Second, Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	return reconciler
}

func applyControlDeployment(t *testing.T, fixture *reconcileFixture, generation uint64) {
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
	delegation := admission.CommandDelegation{
		SchemaVersion: admission.CommandDelegationSchemaV1,
		DelegationID:  "research-authority", TenantID: "tenant-a",
		ControllerKeyID:     "controller-a",
		ControllerPublicKey: base64.StdEncoding.EncodeToString(fixture.controller.Public().(ed25519.PublicKey)),
		Operations:          []string{"admit", "destroy", "start", "stop"}, NodeIDs: []string{"node-1"},
		Instances: []admission.CommandDelegationInstance{{
			InstanceID: "research-0", LineageID: "research-lineage-0",
			MinInstanceGeneration: generation, MaxInstanceGeneration: generation + 4,
		}},
		ClaimGeneration: generation,
		Admission: &admission.CommandDelegationAdmissionTemplate{
			CapsuleDigest:    dsse.Digest(capsuleRaw),
			Resources:        admission.ResourceLimits{MemoryBytes: 128 << 20, CPUMillis: 250, PIDs: 32},
			StateDisposition: "none",
		},
		IssuedAt:  fixture.now.Add(-time.Minute).Format(time.RFC3339Nano),
		ExpiresAt: fixture.now.Add(23 * time.Hour).Format(time.RFC3339Nano),
	}
	payload, err := json.Marshal(delegation)
	if err != nil {
		t.Fatal(err)
	}
	_, tenantPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := dsse.Sign(admission.CommandDelegationPayloadType, payload, "tenant-command-a", tenantPrivate)
	if err != nil {
		t.Fatal(err)
	}
	delegationRaw, err := dsse.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if _, changed, err := fixture.store.ApplyDeployment(fixture.admin, controlstore.DeploymentApply{
		TenantID: "tenant-a", ID: "research", Generation: generation,
		AgentName: "research-agent", BundleDigest: "sha256:" + strings.Repeat("a", 64),
		CapsuleDSSE: capsuleRaw, DelegationDSSE: delegationRaw,
	}, fixture.now); err != nil || !changed {
		t.Fatalf("apply deployment = (%v, %v)", changed, err)
	}
}

func completeDeploymentCommand(t *testing.T, fixture *reconcileFixture, operation, status string) {
	t.Helper()
	fixture.now = fixture.now.Add(time.Minute)
	capabilities := []string{
		controlprotocol.ExecutorCapabilityAdmissionProjectionV1,
		controlprotocol.ExecutorCapabilityControllerDelegationV1,
	}
	deliveries, err := fixture.store.PollV4(fixture.node, capabilities, fixture.now, time.Minute, 1)
	if err != nil || len(deliveries) != 1 {
		t.Fatalf("poll %s = (%+v, %v)", operation, deliveries, err)
	}
	deployment := getControlDeployment(t, fixture)
	instance := deployment.Instances[0]
	if instance.CommandOperation != operation || instance.CommandID != deliveries[0].CommandID {
		t.Fatalf("%s delivery differs from cursor: delivery=%+v instance=%+v", operation, deliveries[0], instance)
	}
	runtimeDigest := sha256.Sum256([]byte(deployment.TenantID + "\x00" + instance.InstanceID))
	runtimeRef := "executor-" + hex.EncodeToString(runtimeDigest[:])
	reported := "stopped"
	if operation == "start" {
		reported = "running"
	}
	report := controlprotocol.ExecutorReportV4{
		ProtocolVersion: controlprotocol.ExecutorProtocolV4,
		DeliveryID:      deliveries[0].DeliveryID, DeliveryGeneration: deliveries[0].DeliveryGeneration,
		CommandID: deliveries[0].CommandID, CommandDigest: deliveries[0].CommandDigest,
		Status: status, ReportedStatus: reported, ClaimGeneration: 1,
		Result: controlprotocol.ExecutorReportResultV4{RuntimeRef: runtimeRef},
	}
	if status == controlprotocol.ExecutorStatusDone && operation == "admit" {
		report.Result.Admission = &controlprotocol.ExecutorAdmissionProjectionV1{
			SchemaVersion: controlprotocol.ExecutorAdmissionProjectionSchemaV1,
			RuntimeRef:    runtimeRef, Status: "created",
			CapsuleDigest: dsse.Digest(deployment.CapsuleDSSE),
			PolicyDigest:  "sha256:" + strings.Repeat("b", 64),
			Generation:    instance.Generation, EvidenceKeyID: strings.Repeat("d", 32),
		}
	}
	if status == controlprotocol.ExecutorStatusOutcomeUnknown {
		report.ReportedStatus = "failed"
		report.ErrorCode = "local_outcome_unknown"
		report.Result.Error = "executor response was lost after dispatch"
	}
	if operation == "destroy" && status == controlprotocol.ExecutorStatusDone {
		report.Result.Absent = true
	}
	if applied, err := fixture.store.ApplyReportV4(fixture.node, report, fixture.now.Add(time.Second)); err != nil || !applied {
		t.Fatalf("report %s = (%v, %v)", operation, applied, err)
	}
	fixture.now = fixture.now.Add(2 * time.Second)
}

func assertReconcileCount(t *testing.T, reconciler *Reconciler, label string, observed, enqueued int) {
	t.Helper()
	report, err := reconciler.Reconcile(context.Background())
	if err != nil || report.Observed != observed || report.Enqueued != enqueued {
		t.Fatalf("%s = (%+v, %v)", label, report, err)
	}
}

func getControlDeployment(t *testing.T, fixture *reconcileFixture) controlstore.Deployment {
	t.Helper()
	deployment, found, err := fixture.store.GetDeployment(fixture.admin, "tenant-a", "research")
	if err != nil || !found {
		t.Fatalf("get deployment = (%+v, %v, %v)", deployment, found, err)
	}
	return deployment
}
