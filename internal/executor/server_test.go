package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/journal"
)

type fakeDocker struct {
	created  []Workload
	observed *ObservedWorkload
	err      error
	total    int
	tenant   int
	starts   int
	removes  int
}

type secureDocker struct {
	fakeDocker
	name      string
	imageID   string
	createErr error
	startErr  error
	stopErr   error
	removeErr error
	onCreate  func()
	onStart   func()
	onStop    func()
	onRemove  func()
	startNoop bool
}

func (d *secureDocker) Create(_ context.Context, name string, workload Workload) error {
	d.name = name
	d.created = append(d.created, workload)
	imageID := d.imageID
	if imageID == "" {
		imageID = "sha256:" + strings.Repeat("b", 64)
	}
	d.observed = &ObservedWorkload{
		Workload: workload, ImageID: imageID, Fingerprint: workloadFingerprint(workload),
		Managed: true, Hardened: true, Status: "created",
	}
	if d.onCreate != nil {
		d.onCreate()
	}
	return d.createErr
}

func (d *secureDocker) Start(context.Context, string) error {
	if d.startErr != nil {
		return d.startErr
	}
	d.starts++
	if !d.startNoop {
		d.observed.Status = "running"
	}
	if d.onStart != nil {
		d.onStart()
	}
	return nil
}

func (d *secureDocker) Stop(context.Context, string) error {
	if d.stopErr != nil {
		return d.stopErr
	}
	d.observed.Status = "exited"
	if d.onStop != nil {
		d.onStop()
	}
	return nil
}

func (d *secureDocker) Remove(context.Context, string) error {
	if d.removeErr != nil {
		return d.removeErr
	}
	d.removes++
	d.observed = nil
	if d.onRemove != nil {
		d.onRemove()
	}
	return nil
}

func TestSecureAdmissionRejectsLocalConfigDigestMismatch(t *testing.T) {
	docker := &secureDocker{imageID: "sha256:" + strings.Repeat("c", 64)}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError || docker.removes != 1 || len(config.Journal.Pending()) != 0 {
		t.Fatalf("status=%d removes=%d pending=%#v body=%s", response.Code, docker.removes, config.Journal.Pending(), response.Body.String())
	}
}

func TestSecureAdmissionLeavesJournalPendingWhenRejectedContainerCannotBeRemoved(t *testing.T) {
	docker := &secureDocker{
		imageID:   "sha256:" + strings.Repeat("c", 64),
		removeErr: errors.New("remove failed"),
	}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 1 || docker.observed == nil {
		t.Fatalf("status=%d pending=%#v observed=%#v body=%s", response.Code, config.Journal.Pending(), docker.observed, response.Body.String())
	}
}

func TestSecureAdmissionDoesNotAdoptLegacyLookalike(t *testing.T) {
	capsule, intent, config := secureAdmissionFixture(t)
	workload := Workload{
		InstanceID: "agent-1", TenantID: "tenant-a", ProfileID: "generic-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32}, Egress: Egress{},
	}
	docker := &secureDocker{fakeDocker: fakeDocker{observed: &ObservedWorkload{
		Workload: workload, ImageID: "sha256:" + strings.Repeat("b", 64),
		Fingerprint: workloadFingerprint(workload), Managed: true, Hardened: true, Status: "created",
	}}}
	server, _ := NewServer(docker, "secret", nil)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSecureAdmissionDoesNotReplayConsumedAbsentGeneration(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	if err := config.Fences.Commit(admission.FenceRecord{
		TenantID: intent.TenantID, InstanceID: intent.InstanceID,
		Generation: intent.Generation, CapsuleDigest: intent.CapsuleDigest,
		PolicyDigest: dsse.Digest(config.PolicyEnvelope), LineageID: intent.LineageID, Present: false,
		WorkloadDigest:    "sha256:" + strings.Repeat("c", 64),
		ImageConfigDigest: "sha256:" + strings.Repeat("b", 64),
	}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Evidence.Append(evidence.Event{
		Type: evidence.LifecycleDestroy, TenantID: intent.TenantID,
		RuntimeRef: RuntimeRef(intent.TenantID, intent.InstanceID), CapsuleDigest: intent.CapsuleDigest,
		PolicyDigest: dsse.Digest(config.PolicyEnvelope), Generation: intent.Generation,
		GrantID: "workload", Outcome: evidence.Committed,
	}); err != nil {
		t.Fatal(err)
	}
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusConflict || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d body=%s", response.Code, len(docker.created), response.Body.String())
	}
}

func (d *fakeDocker) Inspect(context.Context, string) (ObservedWorkload, error) {
	if d.observed != nil {
		return *d.observed, d.err
	}
	if d.err != nil {
		return ObservedWorkload{}, d.err
	}
	return ObservedWorkload{}, ErrNotFound
}

func (d *fakeDocker) RuntimeAvailable(context.Context, string) (bool, error) { return true, d.err }
func (d *fakeDocker) WorkloadCounts(context.Context, string) (int, int, error) {
	return d.total, d.tenant, d.err
}
func (d *fakeDocker) Create(_ context.Context, _ string, w Workload) error {
	d.created = append(d.created, w)
	return d.err
}

type capacityDocker struct {
	mu       sync.Mutex
	created  int
	tenantID string
}

func (d *capacityDocker) RuntimeAvailable(context.Context, string) (bool, error) { return true, nil }
func (d *capacityDocker) Inspect(context.Context, string) (ObservedWorkload, error) {
	return ObservedWorkload{}, ErrNotFound
}
func (d *capacityDocker) WorkloadCounts(_ context.Context, tenantID string) (int, int, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	tenant := 0
	if tenantID == d.tenantID {
		tenant = d.created
	}
	return d.created, tenant, nil
}
func (d *capacityDocker) Create(_ context.Context, _ string, _ Workload) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.created++
	return nil
}
func (d *capacityDocker) Start(context.Context, string) error          { return nil }
func (d *capacityDocker) Stop(context.Context, string) error           { return nil }
func (d *capacityDocker) Remove(context.Context, string) error         { return nil }
func (d *capacityDocker) Logs(context.Context, string) (string, error) { return "", nil }
func (d *fakeDocker) Start(context.Context, string) error {
	d.starts++
	return d.err
}
func (d *fakeDocker) Stop(context.Context, string) error { return d.err }
func (d *fakeDocker) Remove(context.Context, string) error {
	d.removes++
	return d.err
}
func (d *fakeDocker) Logs(context.Context, string) (string, error) { return "hello\n", d.err }

func validWorkload() string {
	return `{"instance_id":"tenant-a/agent-1","tenant_id":"tenant-a","profile_id":"openclaw-v1","image":"registry.local/openclaw@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","command":["agent"],"resources":{"memory_bytes":1048576,"cpu_millis":100,"pids":64},"egress":{}}`
}

func TestSecureAdmissionCreatesOnlyFromSignedIntersection(t *testing.T) {
	docker := &secureDocker{}
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	capsuleEnvelope, intent, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(secureProvisionRequest{
		CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsuleEnvelope), Intent: intent,
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if len(docker.created) != 1 || docker.created[0].TenantID != "tenant-a" ||
		docker.created[0].Image != "registry.local/agent@sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("created=%#v", docker.created)
	}
	if fences := config.Fences.Fences("tenant-a", "agent-1"); fences.Generation != 1 || fences.PolicyEpoch != 1 {
		t.Fatalf("fences=%#v", fences)
	}
	if pending := config.Journal.Pending(); len(pending) != 0 {
		t.Fatalf("pending=%#v", pending)
	}
	var decoded secureProvisionResponse
	if err := json.NewDecoder(response.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Generation != 1 || decoded.CapsuleDigest != intent.CapsuleDigest || decoded.EvidenceKeyID == "" {
		t.Fatalf("response=%#v", decoded)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(docker.created) != 1 {
		t.Fatalf("idempotent status=%d creates=%d body=%s", response.Code, len(docker.created), response.Body.String())
	}
}

func TestSecureLifecycleIsJournaledReceiptedAndTombstoned(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("admit status=%d body=%s", response.Code, response.Body.String())
	}
	runtimeRef := RuntimeRef(intent.TenantID, intent.InstanceID)
	for _, target := range []string{"/v1/workloads/" + runtimeRef + "/start", "/v1/workloads/" + runtimeRef + "/stop"} {
		request = httptest.NewRequest(http.MethodPost, target, nil)
		request.Header.Set("Authorization", "Bearer secret")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("%s status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
	request = httptest.NewRequest(http.MethodDelete, "/v1/workloads/"+runtimeRef, nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("destroy status=%d body=%s", response.Code, response.Body.String())
	}
	record, ok := config.Fences.Record(intent.TenantID, intent.InstanceID)
	if !ok || record.Present || len(config.Journal.Pending()) != 0 {
		t.Fatalf("record=%#v pending=%#v", record, config.Journal.Pending())
	}
	// Destroy remains idempotent through the signed tombstone.
	request = httptest.NewRequest(http.MethodDelete, "/v1/workloads/"+runtimeRef, nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("repeated destroy status=%d body=%s", response.Code, response.Body.String())
	}
	// The consumed generation cannot recreate the absent workload.
	request = httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("replay status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSecureAdmissionRejectsTamperAndCapabilitiesBeforeDocker(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(*[]byte, *admission.InstanceIntent)
		status int
	}{
		{name: "tampered capsule", status: http.StatusForbidden, mutate: func(raw *[]byte, _ *admission.InstanceIntent) {
			(*raw)[len(*raw)-2] ^= 1
		}},
		{name: "unimplemented capability", status: http.StatusNotImplemented, mutate: func(_ *[]byte, intent *admission.InstanceIntent) {
			intent.Capabilities.State = true
			intent.StateDisposition = "new"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			docker := &secureDocker{}
			server, _ := NewServer(docker, "secret", nil)
			capsule, intent, config := secureAdmissionFixture(t)
			test.mutate(&capsule, &intent)
			if err := server.EnableSecureAdmission(config); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
			request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.status || len(docker.created) != 0 {
				t.Fatalf("status=%d creates=%d body=%s", response.Code, len(docker.created), response.Body.String())
			}
		})
	}
}

func TestSecureAdmissionRequiresNonForgeablePrincipalByDefault(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	config.AllowHostAdminIntent = false
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(docker.created) != 0 {
		t.Fatalf("unbound status=%d creates=%d", response.Code, len(docker.created))
	}
	ctx := WithAdmissionPrincipal(context.Background(), "tenant-a", "node-a", 1)
	request = httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body))).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("bound status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSecureModeDisablesLegacyProvisioning(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	_, _, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d body=%s", response.Code, len(docker.created), response.Body.String())
	}
}

func TestSecureAdmissionUnavailableAndStrictRequestErrors(t *testing.T) {
	server, _ := NewServer(&secureDocker{}, "secret", nil)
	for _, body := range []string{
		`{}`,
		`{"capsule_dsse_base64":"%%%","intent":{}}`,
		`{"capsule_dsse_base64":"x","capsule_dsse_base64":"y","intent":{}}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusServiceUnavailable {
			t.Fatalf("unconfigured status=%d body=%s", response.Code, response.Body.String())
		}
	}
	_, _, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{}`,
		`{"capsule_dsse_base64":"%%%","intent":{"tenant_id":"t","node_id":"node-a","instance_id":"i","lineage_id":"l","generation":1,"capsule_digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resources":{"memory_bytes":1,"cpu_millis":1,"pids":1},"capabilities":{"state":false,"inference":false,"service":false},"state_disposition":"none"}}`,
		`{"capsule_dsse_base64":"x","capsule_dsse_base64":"y","intent":{}}`,
	} {
		request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("configured status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func TestEnableSecureAdmissionRejectsBrokenAuthorityState(t *testing.T) {
	server, _ := NewServer(&secureDocker{}, "secret", nil)
	if err := server.EnableSecureAdmission(SecureAdmissionConfig{}); err == nil {
		t.Fatal("incomplete secure configuration accepted")
	}
	t.Run("pending journal", func(t *testing.T) {
		_, _, config := secureAdmissionFixture(t)
		if _, err := config.Journal.Prepare("pending", "target", 1); err != nil {
			t.Fatal(err)
		}
		if err := server.EnableSecureAdmission(config); err == nil {
			t.Fatal("pending journal accepted")
		}
	})
	t.Run("empty evidence with fences", func(t *testing.T) {
		_, intent, config := secureAdmissionFixture(t)
		if err := config.Fences.Commit(admission.FenceRecord{
			TenantID: intent.TenantID, InstanceID: intent.InstanceID, Generation: 1,
			CapsuleDigest: intent.CapsuleDigest, PolicyDigest: dsse.Digest(config.PolicyEnvelope),
			LineageID: intent.LineageID, WorkloadDigest: "sha256:" + strings.Repeat("c", 64),
			ImageConfigDigest: "sha256:" + strings.Repeat("b", 64), Present: true,
		}, 1); err != nil {
			t.Fatal(err)
		}
		if err := server.EnableSecureAdmission(config); err == nil {
			t.Fatal("missing evidence history accepted")
		}
	})
	t.Run("bad policy signature", func(t *testing.T) {
		_, _, config := secureAdmissionFixture(t)
		config.PolicyEnvelope[len(config.PolicyEnvelope)-2] ^= 1
		if err := server.EnableSecureAdmission(config); err == nil {
			t.Fatal("tampered policy accepted")
		}
	})
}

func TestSecureAdmissionFailsClosedWhenDurabilityCloses(t *testing.T) {
	for _, target := range []string{"evidence", "journal"} {
		t.Run(target, func(t *testing.T) {
			docker := &secureDocker{}
			server, _ := NewServer(docker, "secret", nil)
			capsule, intent, config := secureAdmissionFixture(t)
			if err := server.EnableSecureAdmission(config); err != nil {
				t.Fatal(err)
			}
			if target == "evidence" {
				_ = config.Evidence.Close()
			} else {
				_ = config.Journal.Close()
			}
			body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
			request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable || len(docker.created) != 0 {
				t.Fatalf("status=%d creates=%d body=%s", response.Code, len(docker.created), response.Body.String())
			}
		})
	}
}

func TestSecureLifecycleRequiresMatchingPrincipal(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	server.secure.allowHostAdmin = false
	target := "/v1/workloads/" + RuntimeRef(intent.TenantID, intent.InstanceID) + "/start"
	for _, ctx := range []context.Context{
		context.Background(),
		WithAdmissionPrincipal(context.Background(), "tenant-b", "node-a", 1),
		WithAdmissionPrincipal(context.Background(), "tenant-a", "node-a", 2),
	} {
		request = httptest.NewRequest(http.MethodPost, target, nil).WithContext(ctx)
		request.Header.Set("Authorization", "Bearer secret")
		response = httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	}
	ctx := WithAdmissionPrincipal(context.Background(), "tenant-a", "node-a", 1)
	request = httptest.NewRequest(http.MethodPost, target, nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("authorized status=%d body=%s", response.Code, response.Body.String())
	}
	// The already-running transition is an authenticated idempotent no-op.
	request = httptest.NewRequest(http.MethodPost, target, nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || docker.starts != 1 {
		t.Fatalf("idempotent status=%d starts=%d", response.Code, docker.starts)
	}
}

func TestSecureDestroyRejectsUnknownAndInvalidRefs(t *testing.T) {
	server, _ := NewServer(&secureDocker{}, "secret", nil)
	_, _, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	for target, want := range map[string]int{
		"/v1/workloads/not-a-ref":                           http.StatusBadRequest,
		"/v1/workloads/executor-" + strings.Repeat("a", 64): http.StatusNotFound,
	} {
		request := httptest.NewRequest(http.MethodDelete, target, nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != want {
			t.Fatalf("%s status=%d body=%s", target, response.Code, response.Body.String())
		}
	}
}

func TestSecureProvisionLeavesAmbiguousDockerCreatePrepared(t *testing.T) {
	docker := &secureDocker{createErr: errors.New("create transport lost")}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || len(config.Journal.Pending()) != 1 {
		t.Fatalf("status=%d pending=%#v body=%s", response.Code, config.Journal.Pending(), response.Body.String())
	}
}

func TestSecureProvisionCapacityAndCommitFailures(t *testing.T) {
	for _, test := range []struct {
		name   string
		docker *secureDocker
		want   int
	}{
		{"host capacity", &secureDocker{fakeDocker: fakeDocker{total: 32}}, http.StatusServiceUnavailable},
		{"tenant capacity", &secureDocker{fakeDocker: fakeDocker{tenant: 4}}, http.StatusServiceUnavailable},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := NewServer(test.docker, "secret", nil)
			capsule, intent, config := secureAdmissionFixture(t)
			if err := server.EnableSecureAdmission(config); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
			request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.want || len(test.docker.created) != 0 {
				t.Fatalf("status=%d creates=%d body=%s", response.Code, len(test.docker.created), response.Body.String())
			}
		})
	}
	for _, target := range []string{"evidence", "journal"} {
		t.Run("commit "+target, func(t *testing.T) {
			docker := &secureDocker{}
			server, _ := NewServer(docker, "secret", nil)
			capsule, intent, config := secureAdmissionFixture(t)
			if target == "evidence" {
				docker.onCreate = func() { _ = config.Evidence.Close() }
			} else {
				docker.onCreate = func() { _ = config.Journal.Close() }
			}
			if err := server.EnableSecureAdmission(config); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
			request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusServiceUnavailable {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestSecureTransitionFailureModes(t *testing.T) {
	t.Run("pending journal", func(t *testing.T) {
		server, _, config, runtimeRef := admittedSecureServer(t, &secureDocker{})
		if _, err := config.Journal.Prepare("other", "target", 1); err != nil {
			t.Fatal(err)
		}
		assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusServiceUnavailable)
	})
	t.Run("closed evidence", func(t *testing.T) {
		server, _, config, runtimeRef := admittedSecureServer(t, &secureDocker{})
		_ = config.Evidence.Close()
		assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusServiceUnavailable)
	})
	t.Run("closed journal", func(t *testing.T) {
		server, _, config, runtimeRef := admittedSecureServer(t, &secureDocker{})
		_ = config.Journal.Close()
		assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusServiceUnavailable)
	})
	t.Run("observed drift", func(t *testing.T) {
		docker := &secureDocker{}
		server, _, _, runtimeRef := admittedSecureServer(t, docker)
		docker.observed.Hardened = false
		assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusConflict)
	})
	t.Run("signed fingerprint drift", func(t *testing.T) {
		docker := &secureDocker{}
		server, _, _, runtimeRef := admittedSecureServer(t, docker)
		docker.observed.Fingerprint = strings.Repeat("c", 64)
		assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusForbidden)
	})
	t.Run("docker start failure", func(t *testing.T) {
		docker := &secureDocker{startErr: errors.New("start failed")}
		server, _, config, runtimeRef := admittedSecureServer(t, docker)
		assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusBadGateway)
		if len(config.Journal.Pending()) != 0 {
			t.Fatal("unchanged failed start was not compensated")
		}
	})
	t.Run("unexpected final state", func(t *testing.T) {
		docker := &secureDocker{startNoop: true}
		server, _, config, runtimeRef := admittedSecureServer(t, docker)
		assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusInternalServerError)
		if len(config.Journal.Pending()) != 0 {
			t.Fatal("unexpected state was not compensated")
		}
	})
	t.Run("failed rollback remains pending", func(t *testing.T) {
		docker := &secureDocker{startNoop: true}
		docker.onStop = func() { docker.err = errors.New("inspect failed") }
		server, _, config, runtimeRef := admittedSecureServer(t, docker)
		assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusServiceUnavailable)
		if len(config.Journal.Pending()) != 1 {
			t.Fatal("ambiguous lifecycle rollback did not remain pending")
		}
	})
	for _, target := range []string{"evidence", "journal"} {
		t.Run("commit "+target, func(t *testing.T) {
			docker := &secureDocker{}
			server, _, config, runtimeRef := admittedSecureServer(t, docker)
			if target == "evidence" {
				docker.onStart = func() { _ = config.Evidence.Close() }
			} else {
				docker.onStart = func() { _ = config.Journal.Close() }
			}
			assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", context.Background(), http.StatusServiceUnavailable)
		})
	}
	assertLifecycleStatus(t, mustSecureServer(t), http.MethodPost, "/v1/workloads/not-a-ref/start", context.Background(), http.StatusBadRequest)
}

func TestSecureDestroyFailureModes(t *testing.T) {
	t.Run("docker remove failure", func(t *testing.T) {
		docker := &secureDocker{removeErr: errors.New("remove failed")}
		server, _, config, runtimeRef := admittedSecureServer(t, docker)
		assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+runtimeRef, context.Background(), http.StatusBadGateway)
		if len(config.Journal.Pending()) != 0 {
			t.Fatal("unchanged failed destroy was not compensated")
		}
	})
	t.Run("closed evidence", func(t *testing.T) {
		server, _, config, runtimeRef := admittedSecureServer(t, &secureDocker{})
		_ = config.Evidence.Close()
		assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+runtimeRef, context.Background(), http.StatusServiceUnavailable)
	})
	t.Run("wrong principal", func(t *testing.T) {
		server, _, _, runtimeRef := admittedSecureServer(t, &secureDocker{})
		server.secure.allowHostAdmin = false
		ctx := WithAdmissionPrincipal(context.Background(), "tenant-b", "node-a", 1)
		assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+runtimeRef, ctx, http.StatusForbidden)
	})
	t.Run("drift", func(t *testing.T) {
		docker := &secureDocker{}
		server, _, _, runtimeRef := admittedSecureServer(t, docker)
		docker.observed.Hardened = false
		assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+runtimeRef, context.Background(), http.StatusConflict)
	})
	for _, target := range []string{"evidence", "journal"} {
		t.Run("commit "+target, func(t *testing.T) {
			docker := &secureDocker{}
			server, _, config, runtimeRef := admittedSecureServer(t, docker)
			if target == "evidence" {
				docker.onRemove = func() { _ = config.Evidence.Close() }
			} else {
				docker.onRemove = func() { _ = config.Journal.Close() }
			}
			assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+runtimeRef, context.Background(), http.StatusServiceUnavailable)
		})
	}
}

func admittedSecureServer(t *testing.T, docker *secureDocker) (*Server, admission.InstanceIntent, SecureAdmissionConfig, string) {
	t.Helper()
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	capsule, intent, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("admit status=%d body=%s", response.Code, response.Body.String())
	}
	return server, intent, config, RuntimeRef(intent.TenantID, intent.InstanceID)
}

func mustSecureServer(t *testing.T) *Server {
	t.Helper()
	server, _ := NewServer(&secureDocker{}, "secret", nil)
	_, _, config := secureAdmissionFixture(t)
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	return server
}

func assertLifecycleStatus(t *testing.T, server *Server, method, target string, ctx context.Context, want int) {
	t.Helper()
	request := httptest.NewRequest(method, target, nil).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", method, target, response.Code, want, response.Body.String())
	}
}

func secureAdmissionFixture(t *testing.T) ([]byte, admission.InstanceIntent, SecureAdmissionConfig) {
	t.Helper()
	_, sitePrivate, _ := ed25519.GenerateKey(rand.Reader)
	publisherPublic, publisherPrivate, _ := ed25519.GenerateKey(rand.Reader)
	policy := admission.SitePolicy{
		SchemaVersion: admission.SchemaV1, PolicyID: "site-a", PolicyEpoch: 1,
		Publishers: []admission.PublisherRule{{
			KeyID: "publisher-a", PublicKey: base64.StdEncoding.EncodeToString(publisherPublic),
			AllowedProfiles:        []admission.ProfileRef{{ID: "generic-v1", Version: "v1"}},
			AllowedRepositories:    []string{"registry.local/agent"},
			AllowedManifestDigests: []string{"sha256:" + strings.Repeat("a", 64)},
			ResourceCeiling:        admission.ResourceLimits{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
		}},
		Tenants: []admission.TenantRule{{
			TenantID: "tenant-a", PublisherKeyIDs: []string{"publisher-a"},
			ResourceCeiling: admission.ResourceLimits{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
		}},
	}
	policyPayload, _ := json.Marshal(policy)
	policySigned, _ := dsse.Sign(admission.PolicyPayloadType, policyPayload, "site-root", sitePrivate)
	policyEnvelope, _ := dsse.Marshal(policySigned)
	capsule := admission.ProfileCapsule{
		SchemaVersion: admission.SchemaV1, CapsuleID: "capsule-a", PublisherKeyID: "publisher-a",
		Profile: admission.ProfileRef{ID: "generic-v1", Version: "v1"},
		Image: admission.ImageIdentity{
			Repository: "registry.local/agent", ManifestDigest: "sha256:" + strings.Repeat("a", 64),
			ConfigDigest: "sha256:" + strings.Repeat("b", 64),
			Platform:     admission.Platform{OS: "linux", Architecture: "amd64"},
		},
		Command: []string{"agent"}, Resources: admission.ResourceLimits{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
		Capabilities: admission.Capabilities{State: true},
		State:        admission.StateShape{SchemaVersion: "v1", Path: "/state"},
	}
	capsulePayload, _ := json.Marshal(capsule)
	capsuleSigned, _ := dsse.Sign(admission.CapsulePayloadType, capsulePayload, "publisher-a", publisherPrivate)
	capsuleEnvelope, _ := dsse.Marshal(capsuleSigned)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-1", LineageID: "lineage-a",
		Generation: 1, CapsuleDigest: dsse.Digest(capsuleEnvelope),
		Resources:        admission.ResourceLimits{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
		StateDisposition: "none",
	}
	dir := t.TempDir()
	if err := admission.InitializeFenceStore(filepath.Join(dir, "fences.bin")); err != nil {
		t.Fatal(err)
	}
	fences, err := admission.OpenFenceStore(filepath.Join(dir, "fences.bin"))
	if err != nil {
		t.Fatal(err)
	}
	operations, err := journal.Open(filepath.Join(dir, "journal.bin"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = operations.Close() })
	_, evidencePrivate, _ := ed25519.GenerateKey(rand.Reader)
	receipts, err := evidence.Open(filepath.Join(dir, "evidence.bin"), evidencePrivate, "node-a", 1)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = receipts.Close() })
	return capsuleEnvelope, intent, SecureAdmissionConfig{
		PolicyEnvelope: policyEnvelope, SiteRoots: map[string]ed25519.PublicKey{"site-root": sitePrivate.Public().(ed25519.PublicKey)},
		NodeID: "node-a", Fences: fences, Journal: operations, Evidence: receipts, AllowHostAdminIntent: true,
	}
}

func TestProvisionRejectsMutableImageBeforeDocker(t *testing.T) {
	docker := &fakeDocker{}
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(strings.Replace(validWorkload(), "@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", ":latest", 1)))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", res.Code)
	}
	if len(docker.created) != 0 {
		t.Fatal("Docker Create ran for a rejected policy")
	}
	var body map[string]string
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "policy_rejected" {
		t.Fatalf("error = %#v", body)
	}
}

func TestProvisionRejectsEgressUntilTenantProxyExists(t *testing.T) {
	docker := &fakeDocker{}
	server, _ := NewServer(docker, "secret", nil)
	payload := strings.Replace(validWorkload(), `"egress":{}`, `"egress":{"allowed_hosts":["api.example.test"]}`, 1)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d", res.Code, len(docker.created))
	}
}

func TestProvisionRejectsEnvironmentInjection(t *testing.T) {
	docker := &fakeDocker{}
	server, _ := NewServer(docker, "secret", nil)
	payload := strings.Replace(
		validWorkload(), `"egress":{}`, `"env":["API_KEY=secret"],"egress":{}`, 1,
	)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d", res.Code, len(docker.created))
	}
}

func TestProvisionRejectsUnknownEscapeHatchFields(t *testing.T) {
	docker := &fakeDocker{}
	server, _ := NewServer(docker, "secret", nil)
	payload := strings.Replace(validWorkload(), `"egress":{}`, `"egress":{},"privileged":true`, 1)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d", res.Code, len(docker.created))
	}
}

func TestProvisionRejectsOversizedCommandBeforeDocker(t *testing.T) {
	docker := &fakeDocker{}
	server, _ := NewServer(docker, "secret", nil)
	payload := strings.Replace(validWorkload(), `"egress":{}`, `"command":["`+strings.Repeat("x", 4097)+`"],"egress":{}`, 1)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d", res.Code, len(docker.created))
	}
}

func TestProvisionRequiresHostControlCredential(t *testing.T) {
	server, _ := NewServer(&fakeDocker{}, "secret", nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", res.Code)
	}
}

func TestProvisionCreatesValidatedWorkload(t *testing.T) {
	docker := &fakeDocker{}
	server, _ := NewServer(docker, "secret", nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
	if len(docker.created) != 1 || docker.created[0].ProfileID != "openclaw-v1" {
		t.Fatalf("creates = %#v", docker.created)
	}
	if !strings.Contains(res.Body.String(), `"status":"created"`) {
		t.Fatalf("created response = %s", res.Body.String())
	}
}

func TestProvisionIsIdempotentOnlyForTheSameImmutableWorkload(t *testing.T) {
	w := Workload{
		InstanceID: "tenant-a/agent-1", TenantID: "tenant-a", ProfileID: "openclaw-v1",
		Image:     "registry.local/openclaw@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Command:   []string{"agent"},
		Resources: Resources{MemoryBytes: 1048576, CPUMillis: 100, PIDs: 64},
	}
	docker := &fakeDocker{observed: &ObservedWorkload{
		Workload: w, Fingerprint: workloadFingerprint(w), Managed: true, Hardened: true, Status: "created",
	}}
	server, _ := NewServer(docker, "secret", nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d body=%s", res.Code, len(docker.created), res.Body.String())
	}
	// Docker may normalize Config.Image during create/inspect. The immutable
	// admission fingerprint label remains authoritative while mutable resources
	// and fixed hardening are independently checked by Inspect.
	docker.observed.Workload.Image = "sha256:normalized-content-id"
	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
	req.Header.Set("Authorization", "Bearer secret")
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("normalized image caused false drift: status=%d body=%s", res.Code, res.Body.String())
	}

	docker.observed.Fingerprint = workloadFingerprint(Workload{ProfileID: "other-profile"})
	res = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
	req.Header.Set("Authorization", "Bearer secret")
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusConflict {
		t.Fatalf("conflicting replay status=%d body=%s", res.Code, res.Body.String())
	}
}

func TestNewServerRejectsInvalidHostPolicy(t *testing.T) {
	policy := DefaultHostPolicy()
	policy.MaxWorkloadsPerTenant = policy.MaxWorkloads + 1
	if _, err := NewServerWithPolicy(&fakeDocker{}, "secret", policy, nil); err == nil {
		t.Fatal("NewServerWithPolicy accepted a tenant cap above the global cap")
	}
}

func TestProvisionRejectsResourcesAboveHostCeilings(t *testing.T) {
	docker := &fakeDocker{}
	policy := HostPolicy{
		MaxMemoryBytes:        1 << 20,
		MaxCPUMillis:          100,
		MaxPIDs:               64,
		MaxWorkloads:          4,
		MaxWorkloadsPerTenant: 2,
	}
	server, err := NewServerWithPolicy(docker, "secret", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := strings.Replace(validWorkload(), `"cpu_millis":100`, `"cpu_millis":101`, 1)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(payload))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d", res.Code, len(docker.created))
	}
}

func TestProvisionGlobalCapacityIsAtomicUnderConcurrency(t *testing.T) {
	docker := &capacityDocker{tenantID: "tenant-a"}
	policy := HostPolicy{
		MaxMemoryBytes:        1 << 20,
		MaxCPUMillis:          100,
		MaxPIDs:               64,
		MaxWorkloads:          1,
		MaxWorkloadsPerTenant: 1,
	}
	server, err := NewServerWithPolicy(docker, "secret", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	const attempts = 8
	statuses := make(chan int, attempts)
	var wg sync.WaitGroup
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
			req.Header.Set("Authorization", "Bearer secret")
			res := httptest.NewRecorder()
			handler.ServeHTTP(res, req)
			statuses <- res.Code
		}()
	}
	wg.Wait()
	close(statuses)
	created, rejected := 0, 0
	for status := range statuses {
		switch status {
		case http.StatusCreated:
			created++
		case http.StatusServiceUnavailable:
			rejected++
		default:
			t.Fatalf("unexpected status %d", status)
		}
	}
	if created != 1 || rejected != attempts-1 || docker.created != 1 {
		t.Fatalf("created=%d rejected=%d docker=%d", created, rejected, docker.created)
	}
}

func TestProvisionEnforcesTenantCapacitySeparatelyFromGlobalCapacity(t *testing.T) {
	docker := &fakeDocker{total: 1, tenant: 1}
	policy := HostPolicy{
		MaxMemoryBytes:        1 << 20,
		MaxCPUMillis:          100,
		MaxPIDs:               64,
		MaxWorkloads:          4,
		MaxWorkloadsPerTenant: 1,
	}
	server, err := NewServerWithPolicy(docker, "secret", policy, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusServiceUnavailable || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d", res.Code, len(docker.created))
	}
	var body map[string]string
	if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body["error"] != "capacity_exceeded" || body["message"] != "tenant workload capacity is exhausted" {
		t.Fatalf("body=%#v", body)
	}
}

func TestUnknownDockerWorkloadMapsTo404(t *testing.T) {
	server, _ := NewServer(&fakeDocker{err: ErrNotFound}, "secret", nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/workloads/"+RuntimeRef("tenant-a", "missing"), nil)
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusNotFound {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestRuntimeRefsAreTenantScopedAndOpaque(t *testing.T) {
	first := RuntimeRef("tenant-a", "agent-1")
	second := RuntimeRef("tenant-b", "agent-1")
	if first == second {
		t.Fatalf("different tenants received one runtime ref %q", first)
	}
	if got, ok := runtimeRef(first); !ok || got != first {
		t.Fatalf("runtimeRef(%q) = %q, %v", first, got, ok)
	}
	if _, ok := runtimeRef("other-container"); ok {
		t.Fatal("arbitrary Docker name was accepted as a runtime ref")
	}
}

func TestLifecycleNeverTouchesAnUnmanagedExecutorPrefixedContainer(t *testing.T) {
	docker := &fakeDocker{observed: &ObservedWorkload{Status: "running"}}
	server, _ := NewServer(docker, "secret", nil)
	ref := RuntimeRef("tenant-a", "agent-1")
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/workloads/" + ref + "/start"},
		{http.MethodDelete, "/v1/workloads/" + ref},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		res := httptest.NewRecorder()
		server.Handler().ServeHTTP(res, req)
		if tc.method == http.MethodPost && res.Code != http.StatusNotFound {
			t.Fatalf("unmanaged start status=%d body=%s", res.Code, res.Body.String())
		}
		if tc.method == http.MethodDelete && res.Code != http.StatusNoContent {
			t.Fatalf("unmanaged destroy status=%d body=%s", res.Code, res.Body.String())
		}
	}
	if docker.starts != 0 || docker.removes != 0 {
		t.Fatalf("unmanaged container mutated: starts=%d removes=%d", docker.starts, docker.removes)
	}
}

func TestLifecycleQuarantinesManagedContainerAfterPolicyDrift(t *testing.T) {
	docker := &fakeDocker{observed: &ObservedWorkload{
		Managed: true, Hardened: false, Fingerprint: "stale", Status: "running",
	}}
	server, _ := NewServer(docker, "secret", nil)
	ref := RuntimeRef("tenant-a", "agent-1")
	for _, tc := range []struct{ method, path string }{
		{http.MethodPost, "/v1/workloads/" + ref + "/start"},
		{http.MethodDelete, "/v1/workloads/" + ref},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		res := httptest.NewRecorder()
		server.Handler().ServeHTTP(res, req)
		if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "workload_drift") {
			t.Fatalf("drifted %s status=%d body=%s", tc.method, res.Code, res.Body.String())
		}
	}
	if docker.starts != 0 || docker.removes != 0 {
		t.Fatalf("drifted container mutated: starts=%d removes=%d", docker.starts, docker.removes)
	}
}

func TestDockerErrorsMapToBoundedGatewayError(t *testing.T) {
	server, _ := NewServer(&fakeDocker{err: errors.New("socket down")}, "secret", nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/workloads/"+RuntimeRef("tenant-a", "a"), nil)
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadGateway {
		t.Fatalf("status = %d body=%s", res.Code, res.Body.String())
	}
}

func TestLogsAreAvailableOnlyForExecutorRuntimeRefs(t *testing.T) {
	server, _ := NewServer(&fakeDocker{observed: &ObservedWorkload{
		Fingerprint: workloadFingerprint(Workload{}), Managed: true, Hardened: true, Status: "running",
	}}, "secret", nil)
	ref := RuntimeRef("tenant-a", "agent-1")
	req := httptest.NewRequest(http.MethodGet, "/v1/workloads/"+ref+"/logs", nil)
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusOK || !strings.Contains(res.Body.String(), "hello") {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
}

func TestDefault404And405UseTheExecutorErrorEnvelope(t *testing.T) {
	server, _ := NewServer(&fakeDocker{}, "secret", nil)
	for _, tc := range []struct {
		method, path, code string
		status             int
	}{
		{http.MethodGet, "/v1/missing", "not_found", http.StatusNotFound},
		{http.MethodGet, "/v1/workloads", "method_not_allowed", http.StatusMethodNotAllowed},
	} {
		req := httptest.NewRequest(tc.method, tc.path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		res := httptest.NewRecorder()
		server.Handler().ServeHTTP(res, req)
		var body map[string]string
		if err := json.NewDecoder(res.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if res.Code != tc.status || body["error"] != tc.code {
			t.Fatalf("%s %s: status=%d body=%#v", tc.method, tc.path, res.Code, body)
		}
	}
}
