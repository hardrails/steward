package executor

import (
	"bytes"
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
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/journal"
)

type fakeDocker struct {
	created   []Workload
	observed  *ObservedWorkload
	err       error
	createErr error
	total     int
	tenant    int
	starts    int
	removes   int
	logs      string
}

type secureDocker struct {
	fakeDocker
	name      string
	imageID   string
	imageErr  error
	volumes   []string
	createErr error
	startErr  error
	stopErr   error
	removeErr error
	onCreate  func()
	onStart   func()
	onStop    func()
	onRemove  func()
	startNoop bool
	stopNoop  bool
	stopCalls int
	// stopAppliesOnError models Docker applying a stop before its response is
	// lost. Lifecycle code must trust the exact reinspection, not the error alone.
	stopAppliesOnError bool
	volume             *ObservedStateVolume
	volumeErr          error
	network            *ObservedNetwork
	relay              *ObservedRelay
}

func (d *secureDocker) InspectImage(context.Context, string) (ObservedImage, error) {
	if d.imageErr != nil {
		return ObservedImage{}, d.imageErr
	}
	imageID := d.imageID
	if imageID == "" {
		imageID = "sha256:" + strings.Repeat("b", 64)
	}
	return ObservedImage{
		ID: imageID, OS: "linux", Architecture: "amd64", ConfigPresent: true,
		DeclaredVolumes: append([]string(nil), d.volumes...),
	}, nil
}

func (d *secureDocker) InspectNetwork(context.Context, string) (ObservedNetwork, error) {
	if d.network == nil {
		return ObservedNetwork{}, ErrNotFound
	}
	return *d.network, nil
}
func (d *secureDocker) CreateNetwork(_ context.Context, spec NetworkSpec) error {
	allocated := testNetworkSpec(spec.TenantID, spec.InstanceID, spec.Generation)
	d.network = &ObservedNetwork{NetworkSpec: allocated, Managed: true, Internal: true}
	return nil
}
func (d *secureDocker) RemoveNetwork(context.Context, string) error { d.network = nil; return nil }
func (d *secureDocker) CreateRelay(_ context.Context, spec RelaySpec) error {
	d.relay = &ObservedRelay{Spec: spec, Fingerprint: relayFingerprint(spec), Managed: true, Hardened: true, Status: "created"}
	return nil
}
func (d *secureDocker) InspectRelay(context.Context, string) (ObservedRelay, error) {
	if d.relay == nil {
		return ObservedRelay{}, ErrNotFound
	}
	return *d.relay, nil
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
		if d.relay != nil && d.observed != nil && d.relay.Spec.Name != d.name && d.relay.Status != "running" {
			d.relay.Status, d.relay.IPAddress = "running", d.relay.Spec.RelayIP
		} else if d.observed != nil {
			d.observed.Status = "running"
		}
	}
	if d.onStart != nil {
		d.onStart()
	}
	return nil
}

func (d *secureDocker) Stop(context.Context, string) error {
	d.stopCalls++
	if d.stopErr != nil && !d.stopAppliesOnError {
		return d.stopErr
	}
	if !d.stopNoop {
		if d.relay != nil && d.observed != nil && d.relay.Status == "running" && d.observed.Status != "running" {
			d.relay.Status, d.relay.IPAddress = "exited", ""
		} else if d.observed != nil {
			d.observed.Status = "exited"
		}
	}
	if d.onStop != nil {
		d.onStop()
	}
	return d.stopErr
}

func (d *secureDocker) Remove(context.Context, string) error {
	if d.removeErr != nil {
		return d.removeErr
	}
	d.removes++
	if d.relay != nil && d.observed == nil {
		d.relay = nil
	} else {
		d.observed = nil
	}
	if d.onRemove != nil {
		d.onRemove()
	}
	return nil
}

func (d *secureDocker) InspectStateVolume(context.Context, string) (ObservedStateVolume, error) {
	if d.volume != nil {
		return *d.volume, d.volumeErr
	}
	if d.volumeErr != nil {
		return ObservedStateVolume{}, d.volumeErr
	}
	return ObservedStateVolume{}, ErrNotFound
}

func (d *secureDocker) CreateStateVolume(_ context.Context, spec StateVolumeSpec) error {
	if d.volumeErr != nil {
		return d.volumeErr
	}
	d.volume = &ObservedStateVolume{StateVolumeSpec: spec, Managed: true}
	return nil
}

func (d *secureDocker) RemoveStateVolume(context.Context, string) error {
	if d.volumeErr != nil {
		return d.volumeErr
	}
	d.volume = nil
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
	if response.Code != http.StatusConflict || len(docker.created) != 0 || docker.removes != 0 || len(config.Journal.Pending()) != 0 {
		t.Fatalf("status=%d creates=%d removes=%d pending=%#v body=%s", response.Code, len(docker.created), docker.removes, config.Journal.Pending(), response.Body.String())
	}
}

func TestSecureAdmissionRejectsDeclaredImageVolumesBeforeMutation(t *testing.T) {
	docker := &secureDocker{volumes: []string{"/hidden-state"}}
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
	if response.Code != http.StatusConflict || len(config.Journal.Pending()) != 0 || len(docker.created) != 0 || docker.observed != nil {
		t.Fatalf("status=%d pending=%#v creates=%d observed=%#v body=%s", response.Code, config.Journal.Pending(), len(docker.created), docker.observed, response.Body.String())
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
	return d.createErr
}

type capacityDocker struct {
	mu       sync.Mutex
	created  int
	tenantID string
}

type aggregateCapacityDocker struct {
	fakeDocker
	usage CapacityUsage
}

func (d *aggregateCapacityDocker) CapacityUsage(context.Context, string) (CapacityUsage, error) {
	return d.usage, d.err
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
func (d *fakeDocker) Logs(context.Context, string) (string, error) {
	if d.logs != "" {
		return d.logs, d.err
	}
	return "hello\n", d.err
}

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

func TestSecureAdmissionRuntimeCapabilitiesDriveFullTopologyLifecycle(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixtureFor(t, admission.Capabilities{Inference: true, Service: true, Egress: true})
	grants := &gatewayFixture{grants: map[string]gateway.Grant{}}
	config.Topology, config.Gateway = docker, grants
	config.RelayImage = "sha256:" + strings.Repeat("d", 64)
	config.GrantRoot, config.RelayGID = "/run/steward-gateway/grants", 1234
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated || docker.network == nil || docker.relay == nil || len(grants.grants) != 1 {
		t.Fatalf("admit status=%d network=%#v relay=%#v grants=%#v body=%s", response.Code, docker.network, docker.relay, grants.grants, response.Body.String())
	}
	var admitted secureProvisionResponse
	if err := json.NewDecoder(response.Body).Decode(&admitted); err != nil || admitted.EgressProxy != "http://steward-relay:8082" ||
		len(admitted.EgressRouteIDs) != 1 || admitted.EgressRouteIDs[0] != "public-web" || !docker.relay.Spec.Egress ||
		admitted.RoutePolicyDigest != "sha256:"+strings.Repeat("e", 64) || len(docker.observed.Workload.Runtime.EgressRouteIDs) != 1 {
		t.Fatalf("egress admission=%#v relay=%#v workload=%#v err=%v", admitted, docker.relay, docker.observed.Workload, err)
	}
	committedFence, ok := config.Fences.Record(intent.TenantID, intent.InstanceID)
	if !ok || committedFence.RoutePolicyDigest != admitted.RoutePolicyDigest {
		t.Fatalf("committed route policy=%q response=%q", committedFence.RoutePolicyDigest, admitted.RoutePolicyDigest)
	}
	ref := RuntimeRef(intent.TenantID, intent.InstanceID)
	grants.policyDigest = "sha256:" + strings.Repeat("f", 64)
	assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+ref+"/start", context.Background(), http.StatusConflict)
	if docker.observed.Status == "running" || docker.relay.Status == "running" || grants.grants[docker.observed.Workload.Runtime.GrantID].Active {
		t.Fatal("route policy mismatch did not fail closed before lifecycle mutation")
	}
	grants.policyDigest = admitted.RoutePolicyDigest
	assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+ref+"/start", context.Background(), http.StatusOK)
	if !grants.grants[docker.observed.Workload.Runtime.GrantID].Active || docker.observed.Status != "running" || docker.relay.Status != "running" {
		t.Fatalf("runtime not activated: agent=%#v relay=%#v grants=%#v", docker.observed, docker.relay, grants.grants)
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/workloads/"+ref+"/egress", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"allowed":1`) {
		t.Fatalf("egress stats status=%d body=%s", response.Code, response.Body.String())
	}
	request = httptest.NewRequest(http.MethodGet, "/v1/workloads/"+ref, nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"egress_proxy":"http://steward-relay:8082"`) || !strings.Contains(response.Body.String(), `"public-web"`) {
		t.Fatalf("egress status=%d body=%s", response.Code, response.Body.String())
	}
	grants.inspectErr = errors.New("gateway offline")
	request = httptest.NewRequest(http.MethodGet, "/v1/workloads/"+ref+"/egress", nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "gateway_unavailable") {
		t.Fatalf("offline stats status=%d body=%s", response.Code, response.Body.String())
	}
	grants.inspectErr = nil
	assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+ref+"/stop", context.Background(), http.StatusOK)
	assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+ref, context.Background(), http.StatusNoContent)
	if docker.network != nil || docker.relay != nil || len(grants.grants) != 0 {
		t.Fatalf("runtime topology retained: network=%#v relay=%#v grants=%#v", docker.network, docker.relay, grants.grants)
	}
}

func TestSecureAdmissionRejectsUnquotaedStateByDefault(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixtureFor(t, admission.Capabilities{State: true})
	intent.Capabilities.State = true
	intent.StateDisposition = "new"
	config.AllowUnquotaedStateOnDedicatedHost = false
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{
		CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent,
	})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented || !strings.Contains(response.Body.String(), "no hard byte or inode quota") ||
		len(docker.created) != 0 || len(config.Journal.Pending()) != 0 || config.Evidence.NextSequence() != 1 {
		t.Fatalf("status=%d creates=%d pending=%#v next_receipt=%d body=%s", response.Code, len(docker.created), config.Journal.Pending(), config.Evidence.NextSequence(), response.Body.String())
	}
}

func TestEgressStatsRejectsInvalidUnmanagedAndUngrantableWorkloads(t *testing.T) {
	request := func(t *testing.T, docker Docker, path string) *httptest.ResponseRecorder {
		t.Helper()
		server, err := NewServer(docker, "secret", nil)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, req)
		return response
	}

	response := request(t, &fakeDocker{}, "/v1/workloads/not-a-runtime-ref/egress")
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_runtime_ref") {
		t.Fatalf("invalid ref status=%d body=%s", response.Code, response.Body.String())
	}

	path := "/v1/workloads/" + RuntimeRef("tenant-a", "agent-1") + "/egress"
	response = request(t, &fakeDocker{err: ErrNotFound}, path)
	if response.Code != http.StatusNotFound {
		t.Fatalf("missing workload status=%d body=%s", response.Code, response.Body.String())
	}

	response = request(t, &fakeDocker{observed: &ObservedWorkload{
		Workload: Workload{InstanceID: "tenant-a/agent-1", TenantID: "tenant-a"},
		Managed:  true,
		Hardened: true,
	}}, path)
	if response.Code != http.StatusNotFound {
		t.Fatalf("unsigned workload status=%d body=%s", response.Code, response.Body.String())
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

func TestPolicyRotationRevokesStartButNeverBricksCleanup(t *testing.T) {
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
	ref := RuntimeRef(intent.TenantID, intent.InstanceID)
	assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+ref+"/start", context.Background(), http.StatusOK)

	// A newly installed policy has not reauthorized this exact admission record.
	// Starting must fail closed, while stop and destroy remain available so a
	// policy rotation can never strand a running workload.
	server.secure.policyEnvelope = append(append([]byte(nil), server.secure.policyEnvelope...), '\n')
	assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+ref+"/stop", context.Background(), http.StatusOK)
	assertLifecycleStatus(t, server, http.MethodPost, "/v1/workloads/"+ref+"/start", context.Background(), http.StatusForbidden)
	assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+ref, context.Background(), http.StatusNoContent)
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

func TestSecureAdmissionRejectsStateWithoutCapableDockerBackend(t *testing.T) {
	docker := &fakeDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State = true
	intent.StateDisposition = "new"
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusNotImplemented || len(docker.created) != 0 {
		t.Fatalf("status=%d creates=%d body=%s", response.Code, len(docker.created), response.Body.String())
	}
}

func TestSecureAdmissionCreatesAndResumesTenantLineageState(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State = true
	intent.StateDisposition = "new"
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated || docker.volume == nil || docker.observed.Workload.State == nil {
		t.Fatalf("status=%d volume=%#v observed=%#v body=%s", response.Code, docker.volume, docker.observed, response.Body.String())
	}
	wantName := StateVolumeName(intent.TenantID, intent.LineageID)
	if docker.volume.Name != wantName || docker.observed.Workload.State.VolumeName != wantName {
		t.Fatalf("volume=%#v workload=%#v", docker.volume, docker.observed.Workload.State)
	}
	// Exact replay remains idempotent even though the original disposition was new.
	request = httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("replay status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSecureAdmissionExclusivelyLeasesWritableStateLineage(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	intent.InstanceID = "agent-2"
	intent.Capabilities.State = true
	intent.StateDisposition = "resume"
	docker.volume = &ObservedStateVolume{Managed: true, StateVolumeSpec: StateVolumeSpec{
		Name: StateVolumeName(intent.TenantID, intent.LineageID), TenantID: intent.TenantID, LineageID: intent.LineageID,
	}}
	if err := config.Fences.Commit(admission.FenceRecord{
		TenantID: intent.TenantID, InstanceID: "agent-1", Generation: 1,
		CapsuleDigest: intent.CapsuleDigest, PolicyDigest: dsse.Digest(config.PolicyEnvelope),
		LineageID: intent.LineageID, WorkloadDigest: "sha256:" + strings.Repeat("c", 64),
		ImageConfigDigest: "sha256:" + strings.Repeat("b", 64), Present: true,
	}, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Evidence.Append(evidence.Event{
		Type: evidence.AdmissionAllow, TenantID: intent.TenantID, RuntimeRef: RuntimeRef(intent.TenantID, "agent-1"),
		CapsuleDigest: intent.CapsuleDigest, PolicyDigest: dsse.Digest(config.PolicyEnvelope), Generation: 1,
		GrantID: "workload", Outcome: evidence.Allowed,
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
	if response.Code != http.StatusConflict || len(docker.created) != 0 || len(config.Journal.Pending()) != 0 {
		t.Fatalf("status=%d creates=%d pending=%#v body=%s", response.Code, len(docker.created), config.Journal.Pending(), response.Body.String())
	}
}

func TestSecureStateSurvivesDestroyAndRequiresExplicitReceiptedPurge(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State = true
	intent.StateDisposition = "new"
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
	ref := RuntimeRef(intent.TenantID, intent.InstanceID)
	request = httptest.NewRequest(http.MethodDelete, "/v1/workloads/"+ref, nil)
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || docker.volume == nil {
		t.Fatalf("destroy status=%d volume=%#v body=%s", response.Code, docker.volume, response.Body.String())
	}
	purge, _ := json.Marshal(purgeStateRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation,
	})
	request = httptest.NewRequest(http.MethodPost, "/v1/state/purge", strings.NewReader(string(purge)))
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent || docker.volume != nil || len(config.Journal.Pending()) != 0 {
		t.Fatalf("purge status=%d volume=%#v pending=%#v body=%s", response.Code, docker.volume, config.Journal.Pending(), response.Body.String())
	}
	// Purge is idempotent for the already-authorized absent lineage.
	request = httptest.NewRequest(http.MethodPost, "/v1/state/purge", strings.NewReader(string(purge)))
	request.Header.Set("Authorization", "Bearer secret")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("repeat purge status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestSecureStatePurgeRejectsLiveOrCrossTenantLineage(t *testing.T) {
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State = true
	intent.StateDisposition = "new"
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatal(response.Body.String())
	}
	for _, purge := range []purgeStateRequest{
		{TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: 1},
		{TenantID: "tenant-b", NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: 1},
	} {
		raw, _ := json.Marshal(purge)
		request = httptest.NewRequest(http.MethodPost, "/v1/state/purge", strings.NewReader(string(raw)))
		request.Header.Set("Authorization", "Bearer secret")
		response = httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusConflict && response.Code != http.StatusNotFound {
			t.Fatalf("purge=%#v status=%d body=%s", purge, response.Code, response.Body.String())
		}
	}
}

func TestStatePurgeRechecksLineageUnderProvisionLock(t *testing.T) {
	server, docker, intent, config := destroyedStateServer(t)
	purge, _ := json.Marshal(purgeStateRequest{
		TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation,
	})
	server.provisionMu.Lock()
	responseDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		request := httptest.NewRequest(http.MethodPost, "/v1/state/purge", bytes.NewReader(purge))
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		responseDone <- response
	}()

	// A concurrent resume/provision commits its live lease while holding the
	// same host-mutation lock. Purge must not have snapshotted the absent lineage
	// before waiting for that lock.
	time.Sleep(20 * time.Millisecond)
	record, ok := config.Fences.Record(intent.TenantID, intent.InstanceID)
	if !ok {
		server.provisionMu.Unlock()
		t.Fatal("destroyed lineage fence is missing")
	}
	record.Present = true
	if err := config.Fences.Commit(record, config.Fences.Fences(intent.TenantID, intent.InstanceID).PolicyEpoch); err != nil {
		server.provisionMu.Unlock()
		t.Fatal(err)
	}
	server.provisionMu.Unlock()

	response := <-responseDone
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "state_in_use") || docker.volume == nil {
		t.Fatalf("purge raced live lineage: status=%d volume=%#v body=%s", response.Code, docker.volume, response.Body.String())
	}
}

func TestStatePurgeFailsClosedAcrossBoundaryErrors(t *testing.T) {
	t.Run("secure admission unavailable", func(t *testing.T) {
		server, _ := NewServer(&secureDocker{}, "secret", nil)
		assertStatePurge(t, server, purgeStateRequest{TenantID: "t", NodeID: "n", LineageID: "l", Generation: 1}, context.Background(), http.StatusServiceUnavailable)
	})
	t.Run("state backend unavailable", func(t *testing.T) {
		server, _ := NewServer(&fakeDocker{}, "secret", nil)
		_, _, config := secureAdmissionFixture(t)
		if err := server.EnableSecureAdmission(config); err != nil {
			t.Fatal(err)
		}
		assertStatePurge(t, server, purgeStateRequest{TenantID: "t", NodeID: "node-a", LineageID: "l", Generation: 1}, context.Background(), http.StatusNotImplemented)
	})
	t.Run("invalid body", func(t *testing.T) {
		server := mustSecureServer(t)
		request := httptest.NewRequest(http.MethodPost, "/v1/state/purge", strings.NewReader(`{"tenant_id":"t"}`))
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})
	for _, test := range []struct {
		name   string
		mutate func(*Server, *secureDocker, admission.InstanceIntent, SecureAdmissionConfig) (purgeStateRequest, context.Context)
		want   int
	}{
		{name: "wrong node", want: http.StatusForbidden, mutate: func(_ *Server, _ *secureDocker, intent admission.InstanceIntent, _ SecureAdmissionConfig) (purgeStateRequest, context.Context) {
			return purgeStateRequest{TenantID: intent.TenantID, NodeID: "other", LineageID: intent.LineageID, Generation: intent.Generation}, context.Background()
		}},
		{name: "principal required", want: http.StatusForbidden, mutate: func(server *Server, _ *secureDocker, intent admission.InstanceIntent, _ SecureAdmissionConfig) (purgeStateRequest, context.Context) {
			server.secure.allowHostAdmin = false
			return purgeStateRequest{TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation}, context.Background()
		}},
		{name: "principal mismatch", want: http.StatusForbidden, mutate: func(server *Server, _ *secureDocker, intent admission.InstanceIntent, _ SecureAdmissionConfig) (purgeStateRequest, context.Context) {
			server.secure.allowHostAdmin = false
			request := purgeStateRequest{TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation}
			return request, WithAdmissionPrincipal(context.Background(), intent.TenantID, intent.NodeID, intent.Generation+1)
		}},
		{name: "pending mutation", want: http.StatusServiceUnavailable, mutate: func(_ *Server, _ *secureDocker, intent admission.InstanceIntent, config SecureAdmissionConfig) (purgeStateRequest, context.Context) {
			_, _ = config.Journal.Prepare("pending-purge-test", "other", intent.Generation)
			return purgeStateRequest{TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation}, context.Background()
		}},
		{name: "inspect failure", want: http.StatusBadGateway, mutate: func(_ *Server, docker *secureDocker, intent admission.InstanceIntent, _ SecureAdmissionConfig) (purgeStateRequest, context.Context) {
			docker.volumeErr = errors.New("volume inspect failed")
			return purgeStateRequest{TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation}, context.Background()
		}},
		{name: "volume drift", want: http.StatusConflict, mutate: func(_ *Server, docker *secureDocker, intent admission.InstanceIntent, _ SecureAdmissionConfig) (purgeStateRequest, context.Context) {
			docker.volume.TenantID = "other"
			return purgeStateRequest{TenantID: intent.TenantID, NodeID: intent.NodeID, LineageID: intent.LineageID, Generation: intent.Generation}, context.Background()
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, docker, intent, config := destroyedStateServer(t)
			request, ctx := test.mutate(server, docker, intent, config)
			assertStatePurge(t, server, request, ctx, test.want)
		})
	}
}

func destroyedStateServer(t *testing.T) (*Server, *secureDocker, admission.InstanceIntent, SecureAdmissionConfig) {
	t.Helper()
	docker := &secureDocker{}
	server, _ := NewServer(docker, "secret", nil)
	capsule, intent, config := secureAdmissionFixture(t)
	intent.Capabilities.State = true
	intent.StateDisposition = "new"
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
	assertLifecycleStatus(t, server, http.MethodDelete, "/v1/workloads/"+RuntimeRef(intent.TenantID, intent.InstanceID), context.Background(), http.StatusNoContent)
	return server, docker, intent, config
}

func assertStatePurge(t *testing.T, server *Server, purge purgeStateRequest, ctx context.Context, want int) {
	t.Helper()
	raw, _ := json.Marshal(purge)
	request := httptest.NewRequest(http.MethodPost, "/v1/state/purge", bytes.NewReader(raw)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("purge status=%d want=%d body=%s", response.Code, want, response.Body.String())
	}
}

func TestSecureAdmissionStateDispositionAndOwnershipFailures(t *testing.T) {
	for _, test := range []struct {
		name        string
		disposition string
		volume      *ObservedStateVolume
		want        int
	}{
		{name: "resume missing", disposition: "resume", want: http.StatusConflict},
		{name: "new exists", disposition: "new", want: http.StatusConflict, volume: &ObservedStateVolume{Managed: true}},
		{name: "wrong owner", disposition: "resume", want: http.StatusConflict, volume: &ObservedStateVolume{Managed: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			docker := &secureDocker{volume: test.volume}
			server, _ := NewServer(docker, "secret", nil)
			capsule, intent, config := secureAdmissionFixture(t)
			intent.Capabilities.State = true
			intent.StateDisposition = test.disposition
			if docker.volume != nil && test.name == "new exists" {
				docker.volume.StateVolumeSpec = StateVolumeSpec{Name: StateVolumeName(intent.TenantID, intent.LineageID), TenantID: intent.TenantID, LineageID: intent.LineageID}
			}
			if docker.volume != nil && test.name == "wrong owner" {
				docker.volume.StateVolumeSpec = StateVolumeSpec{Name: StateVolumeName(intent.TenantID, intent.LineageID), TenantID: "other", LineageID: intent.LineageID}
			}
			if err := server.EnableSecureAdmission(config); err != nil {
				t.Fatal(err)
			}
			body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
			request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(string(body)))
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.want || len(docker.created) != 0 {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestStateRollbackHelpersConfirmAbsence(t *testing.T) {
	if got := (&stateAdmissionError{Message: "state error"}).Error(); got != "state error" {
		t.Fatalf("error=%q", got)
	}
	docker := &secureDocker{volume: &ObservedStateVolume{Managed: true}}
	if !removeAndConfirmStateAbsent(context.Background(), docker, "state") || docker.volume != nil {
		t.Fatal("successful removal was not confirmed")
	}
	docker = &secureDocker{volumeErr: errors.New("remove failed")}
	if removeAndConfirmStateAbsent(context.Background(), docker, "state") {
		t.Fatal("ambiguous removal accepted")
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

func TestSecureAdmissionBoundaryAndCapabilityFailures(t *testing.T) {
	t.Run("oversized body", func(t *testing.T) {
		server := mustSecureServer(t)
		request := httptest.NewRequest(http.MethodPost, "/v1/admissions", strings.NewReader(strings.Repeat("x", maxBodyBytes+1)))
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
		}
	})
	for _, test := range []struct {
		name   string
		mutate func(*admission.InstanceIntent) context.Context
	}{
		{name: "wrong node", mutate: func(intent *admission.InstanceIntent) context.Context {
			intent.NodeID = "other"
			return context.Background()
		}},
		{name: "principal generation", mutate: func(intent *admission.InstanceIntent) context.Context {
			return WithAdmissionPrincipal(context.Background(), intent.TenantID, intent.NodeID, intent.Generation+1)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, _ := NewServer(&secureDocker{}, "secret", nil)
			capsule, intent, config := secureAdmissionFixture(t)
			if err := server.EnableSecureAdmission(config); err != nil {
				t.Fatal(err)
			}
			ctx := test.mutate(&intent)
			body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
			request := httptest.NewRequest(http.MethodPost, "/v1/admissions", bytes.NewReader(body)).WithContext(ctx)
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != http.StatusForbidden {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
	t.Run("runtime topology unavailable", func(t *testing.T) {
		server, _ := NewServer(&secureDocker{}, "secret", nil)
		capsule, intent, config := secureAdmissionFixtureFor(t, admission.Capabilities{Inference: true, Service: true})
		if err := server.EnableSecureAdmission(config); err != nil {
			t.Fatal(err)
		}
		assertAdmissionResponse(t, server, capsule, intent, context.Background(), http.StatusNotImplemented)
	})
	t.Run("state backend unavailable", func(t *testing.T) {
		server, _ := NewServer(&fakeDocker{}, "secret", nil)
		capsule, intent, config := secureAdmissionFixture(t)
		intent.Capabilities.State, intent.StateDisposition = true, "new"
		if err := server.EnableSecureAdmission(config); err != nil {
			t.Fatal(err)
		}
		assertAdmissionResponse(t, server, capsule, intent, context.Background(), http.StatusNotImplemented)
	})
	t.Run("pending host mutation", func(t *testing.T) {
		server, _ := NewServer(&secureDocker{}, "secret", nil)
		capsule, intent, config := secureAdmissionFixture(t)
		if err := server.EnableSecureAdmission(config); err != nil {
			t.Fatal(err)
		}
		_, _ = config.Journal.Prepare("pending-admission-test", "other", 1)
		assertAdmissionResponse(t, server, capsule, intent, context.Background(), http.StatusServiceUnavailable)
	})
	t.Run("docker inspect unavailable", func(t *testing.T) {
		docker := &secureDocker{fakeDocker: fakeDocker{err: errors.New("inspect unavailable")}}
		server, _ := NewServer(docker, "secret", nil)
		capsule, intent, config := secureAdmissionFixture(t)
		if err := server.EnableSecureAdmission(config); err != nil {
			t.Fatal(err)
		}
		assertAdmissionResponse(t, server, capsule, intent, context.Background(), http.StatusBadGateway)
	})
}

func assertAdmissionResponse(t *testing.T, server *Server, capsule []byte, intent admission.InstanceIntent, ctx context.Context, want int) {
	t.Helper()
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", bytes.NewReader(body)).WithContext(ctx)
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != want {
		t.Fatalf("admission status=%d want=%d body=%s", response.Code, want, response.Body.String())
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
		if err := server.EnableSecureAdmission(config); err != nil {
			t.Fatalf("pending journal must permit degraded startup: %v", err)
		}
		report, err := server.Reconcile(context.Background())
		if !errors.Is(err, ErrReconciliationIncomplete) || report.Ready || len(report.Failures) != 1 || report.Failures[0].Code != "journal_pending" {
			t.Fatalf("report=%#v err=%v", report, err)
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

func TestSecureProvisionMapsMissingCreateDependencyToConflict(t *testing.T) {
	docker := &secureDocker{createErr: ErrNotFound}
	docker.onCreate = func() { docker.observed = nil }
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
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "workload_dependency_unavailable") || len(config.Journal.Pending()) != 0 {
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

func TestFailedStartActivationResponseLossUsesMonotonicContainment(t *testing.T) {
	for _, test := range []struct {
		name              string
		deactivationFails bool
		wantStatus        int
		wantPending       int
	}{
		{name: "contained", wantStatus: http.StatusBadGateway},
		{name: "containment unprovable", deactivationFails: true, wantStatus: http.StatusServiceUnavailable, wantPending: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			server, docker, grants, config, runtimeRef := admittedRuntimeCapabilityServer(t)
			grants.activateErr = errors.New("activation response lost")
			grants.activateApplies = true
			if test.deactivationFails {
				grants.deactivateErr = errors.New("deactivation unavailable")
			}

			request := httptest.NewRequest(http.MethodPost, "/v1/workloads/"+runtimeRef+"/start", nil)
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", response.Code, test.wantStatus, response.Body.String())
			}
			if pending := config.Journal.Pending(); len(pending) != test.wantPending {
				t.Fatalf("pending=%#v want=%d", pending, test.wantPending)
			}
			grant := grants.grants[docker.observed.Workload.Runtime.GrantID]
			if !stoppedStatus(docker.observed.Status) || !stoppedStatus(docker.relay.Status) || grant.Active != test.deactivationFails {
				t.Fatalf("agent=%q relay=%q grant=%#v", docker.observed.Status, docker.relay.Status, grant)
			}
			if docker.starts != 2 {
				t.Fatalf("failed-start recovery issued a widening start; starts=%d", docker.starts)
			}
			server.reconcileMu.RLock()
			report := cloneReconcileReport(server.reconcileReport)
			attempted := server.reconcileAttempted
			server.reconcileMu.RUnlock()
			if test.deactivationFails {
				if !attempted || report.Ready || len(report.Failures) == 0 || report.Failures[len(report.Failures)-1].Code != "containment_incomplete" {
					t.Fatalf("degraded report=%#v attempted=%t", report, attempted)
				}
			} else if attempted {
				t.Fatalf("exactly contained ordinary start failure degraded readiness: %#v", report)
			}
		})
	}
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

func admittedRuntimeCapabilityServer(
	t *testing.T,
) (*Server, *secureDocker, *gatewayFixture, SecureAdmissionConfig, string) {
	t.Helper()
	docker := &secureDocker{}
	server, err := NewServer(docker, "secret", nil)
	if err != nil {
		t.Fatal(err)
	}
	capsule, intent, config := secureAdmissionFixtureFor(t, admission.Capabilities{Inference: true})
	grants := &gatewayFixture{grants: map[string]gateway.Grant{}}
	config.Topology, config.Gateway = docker, grants
	config.RelayImage = "sha256:" + strings.Repeat("d", 64)
	config.GrantRoot, config.RelayGID = "/run/steward-gateway/grants", 1234
	if err := server.EnableSecureAdmission(config); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(secureProvisionRequest{CapsuleDSSEBase64: base64.StdEncoding.EncodeToString(capsule), Intent: intent})
	request := httptest.NewRequest(http.MethodPost, "/v1/admissions", bytes.NewReader(body))
	request.Header.Set("Authorization", "Bearer secret")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("admit status=%d body=%s", response.Code, response.Body.String())
	}
	return server, docker, grants, config, RuntimeRef(intent.TenantID, intent.InstanceID)
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
	return secureAdmissionFixtureFor(t, admission.Capabilities{State: true})
}

func secureAdmissionFixtureFor(t *testing.T, capabilities admission.Capabilities) ([]byte, admission.InstanceIntent, SecureAdmissionConfig) {
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
			ResourceCeiling:   admission.ResourceLimits{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
			InferenceRouteIDs: []string{"local"}, InferenceModelAliases: []string{"private-model"},
			ServiceIDs: []string{"agent-api"}, EgressRouteIDs: []string{"public-web"},
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
		Capabilities: capabilities,
	}
	capsule.State = admission.StateShape{SchemaVersion: "v1", Path: "/state"}
	if capabilities.Service {
		capsule.Service = admission.ServiceShape{ID: "agent-api", Port: 8080}
	}
	capsulePayload, _ := json.Marshal(capsule)
	capsuleSigned, _ := dsse.Sign(admission.CapsulePayloadType, capsulePayload, "publisher-a", publisherPrivate)
	capsuleEnvelope, _ := dsse.Marshal(capsuleSigned)
	intent := admission.InstanceIntent{
		TenantID: "tenant-a", NodeID: "node-a", InstanceID: "agent-1", LineageID: "lineage-a",
		Generation: 1, CapsuleDigest: dsse.Digest(capsuleEnvelope),
		Resources:        admission.ResourceLimits{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 32},
		Capabilities:     capabilities,
		StateDisposition: "none",
	}
	if capabilities.State {
		intent.Capabilities.State = false
	}
	if capabilities.Inference {
		intent.InferenceRouteID, intent.ModelAlias = "local", "private-model"
	}
	if capabilities.Service {
		intent.ServiceID = "agent-api"
	}
	if capabilities.Egress {
		intent.EgressRouteIDs = []string{"public-web"}
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
		AllowUnquotaedStateOnDedicatedHost: true,
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

func TestProvisionMapsMissingCreateDependencyToConflict(t *testing.T) {
	docker := &fakeDocker{createErr: ErrNotFound}
	server, _ := NewServer(docker, "secret", nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads", strings.NewReader(validWorkload()))
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusConflict || !strings.Contains(res.Body.String(), "workload_dependency_unavailable") {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
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
	policy = DefaultHostPolicy()
	policy.MaxTenantMemoryBytes = policy.MaxTotalMemoryBytes + 1
	if _, err := NewServerWithPolicy(&fakeDocker{}, "secret", policy, nil); err == nil {
		t.Fatal("NewServerWithPolicy accepted a tenant resource cap above the host cap")
	}
}

func TestAggregateCapacityEnforcesHostTenantAndRelayReservations(t *testing.T) {
	workload := Workload{TenantID: "tenant-a", Resources: Resources{MemoryBytes: 10, CPUMillis: 20, PIDs: 30}}
	for _, test := range []struct {
		name    string
		usage   CapacityUsage
		runtime bool
		adjust  func(*HostPolicy)
		want    string
	}{
		{"host memory", CapacityUsage{Host: CapacityReservation{MemoryBytes: 91}}, false, func(policy *HostPolicy) { policy.MaxTotalMemoryBytes = 100 }, "host memory capacity is exhausted"},
		{"host CPU", CapacityUsage{Host: CapacityReservation{CPUMillis: 81}}, false, func(policy *HostPolicy) { policy.MaxTotalCPUMillis = 100 }, "host CPU capacity is exhausted"},
		{"host PIDs", CapacityUsage{Host: CapacityReservation{PIDs: 71}}, false, func(policy *HostPolicy) { policy.MaxTotalPIDs = 100 }, "host process capacity is exhausted"},
		{"tenant memory", CapacityUsage{Tenant: CapacityReservation{MemoryBytes: 91}}, false, func(policy *HostPolicy) { policy.MaxTenantMemoryBytes = 100 }, "tenant memory capacity is exhausted"},
		{"tenant CPU", CapacityUsage{Tenant: CapacityReservation{CPUMillis: 81}}, false, func(policy *HostPolicy) { policy.MaxTenantCPUMillis = 100 }, "tenant CPU capacity is exhausted"},
		{"tenant PIDs", CapacityUsage{Tenant: CapacityReservation{PIDs: 71}}, false, func(policy *HostPolicy) { policy.MaxTenantPIDs = 100 }, "tenant process capacity is exhausted"},
		{"relay overhead", CapacityUsage{}, true, func(policy *HostPolicy) {
			policy.MaxTotalMemoryBytes = workload.Resources.MemoryBytes + defaultRelayMemory - 1
		}, "host memory capacity is exhausted"},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := workload
			if test.runtime {
				candidate.Runtime = &RuntimeGrant{}
			}
			policy := DefaultHostPolicy()
			test.adjust(&policy)
			// Keep tenant ceilings within any lowered host ceiling unless this
			// case intentionally tests a tenant-specific limit.
			if policy.MaxTenantMemoryBytes > policy.MaxTotalMemoryBytes {
				policy.MaxTenantMemoryBytes = policy.MaxTotalMemoryBytes
			}
			if policy.MaxTenantCPUMillis > policy.MaxTotalCPUMillis {
				policy.MaxTenantCPUMillis = policy.MaxTotalCPUMillis
			}
			if policy.MaxTenantPIDs > policy.MaxTotalPIDs {
				policy.MaxTenantPIDs = policy.MaxTotalPIDs
			}
			server, err := NewServerWithPolicy(&aggregateCapacityDocker{usage: test.usage}, "secret", policy, nil)
			if err != nil {
				t.Fatal(err)
			}
			message, err := server.capacityMessage(context.Background(), candidate)
			if err != nil || message != test.want {
				t.Fatalf("message=%q want=%q err=%v", message, test.want, err)
			}
		})
	}
}

func TestProvisionRejectsResourcesAboveHostCeilings(t *testing.T) {
	docker := &fakeDocker{}
	policy := DefaultHostPolicy()
	policy.MaxMemoryBytes, policy.MaxCPUMillis, policy.MaxPIDs = 1<<20, 100, 64
	policy.MaxWorkloads, policy.MaxWorkloadsPerTenant = 4, 2
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
	policy := DefaultHostPolicy()
	policy.MaxMemoryBytes, policy.MaxCPUMillis, policy.MaxPIDs = 1<<20, 100, 64
	policy.MaxWorkloads, policy.MaxWorkloadsPerTenant = 1, 1
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
	policy := DefaultHostPolicy()
	policy.MaxMemoryBytes, policy.MaxCPUMillis, policy.MaxPIDs = 1<<20, 100, 64
	policy.MaxWorkloads, policy.MaxWorkloadsPerTenant = 4, 1
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

func TestLogsRejectJSONExpansionBeyondResponseLimit(t *testing.T) {
	docker := &fakeDocker{observed: &ObservedWorkload{
		Fingerprint: workloadFingerprint(Workload{}), Managed: true, Hardened: true, Status: "running",
	}, logs: strings.Repeat("\x00", maxLogBytes/2)}
	server, _ := NewServer(docker, "secret", nil)
	ref := RuntimeRef("tenant-a", "agent-1")
	req := httptest.NewRequest(http.MethodGet, "/v1/workloads/"+ref+"/logs", nil)
	req.Header.Set("Authorization", "Bearer secret")
	res := httptest.NewRecorder()
	server.Handler().ServeHTTP(res, req)
	if res.Code != http.StatusBadGateway || !strings.Contains(res.Body.String(), "encoded Docker log response exceeds") {
		t.Fatalf("status=%d body=%s", res.Code, res.Body.String())
	}
	if res.Body.Len() > maxLogBytes {
		t.Fatalf("error response exceeded cap: %d", res.Body.Len())
	}
}

func TestLegacyLifecycleStatusLogsAndIdempotency(t *testing.T) {
	ref := RuntimeRef("tenant-a", "agent-1")
	docker := &secureDocker{fakeDocker: fakeDocker{observed: &ObservedWorkload{
		Workload: Workload{TenantID: "tenant-a", InstanceID: "agent-1"}, Managed: true, Hardened: true, Status: "created",
	}}}
	server, _ := NewServer(docker, "secret", nil)
	handler := server.Handler()
	requests := []struct {
		method string
		path   string
		want   int
	}{
		{http.MethodGet, "/v1/workloads/" + ref, http.StatusOK},
		{http.MethodPost, "/v1/workloads/" + ref + "/start", http.StatusOK},
		{http.MethodPost, "/v1/workloads/" + ref + "/start", http.StatusOK},
		{http.MethodGet, "/v1/workloads/" + ref + "/logs", http.StatusOK},
		{http.MethodPost, "/v1/workloads/" + ref + "/stop", http.StatusOK},
		{http.MethodPost, "/v1/workloads/" + ref + "/stop", http.StatusOK},
		{http.MethodDelete, "/v1/workloads/" + ref, http.StatusNoContent},
		{http.MethodDelete, "/v1/workloads/" + ref, http.StatusNoContent},
	}
	for _, test := range requests {
		request := httptest.NewRequest(test.method, test.path, nil)
		request.Header.Set("Authorization", "Bearer secret")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != test.want {
			t.Fatalf("%s %s status=%d body=%s", test.method, test.path, response.Code, response.Body.String())
		}
	}
	if docker.starts != 1 || docker.removes != 1 {
		t.Fatalf("starts=%d removes=%d", docker.starts, docker.removes)
	}
}

func TestLegacyLifecycleDockerFailuresAndInvalidRefs(t *testing.T) {
	ref := RuntimeRef("tenant-a", "agent-1")
	for _, test := range []struct {
		name   string
		method string
		path   string
		docker *secureDocker
		want   int
	}{
		{name: "invalid start", method: http.MethodPost, path: "/v1/workloads/not-a-ref/start", docker: &secureDocker{}, want: http.StatusBadRequest},
		{name: "invalid stop", method: http.MethodPost, path: "/v1/workloads/not-a-ref/stop", docker: &secureDocker{}, want: http.StatusBadRequest},
		{name: "invalid status", method: http.MethodGet, path: "/v1/workloads/not-a-ref", docker: &secureDocker{}, want: http.StatusBadRequest},
		{name: "invalid logs", method: http.MethodGet, path: "/v1/workloads/not-a-ref/logs", docker: &secureDocker{}, want: http.StatusBadRequest},
		{name: "start failure", method: http.MethodPost, path: "/v1/workloads/" + ref + "/start", docker: &secureDocker{startErr: errors.New("start")}, want: http.StatusBadGateway},
		{name: "stop failure", method: http.MethodPost, path: "/v1/workloads/" + ref + "/stop", docker: &secureDocker{stopErr: errors.New("stop")}, want: http.StatusBadGateway},
		{name: "remove failure", method: http.MethodDelete, path: "/v1/workloads/" + ref, docker: &secureDocker{removeErr: errors.New("remove")}, want: http.StatusBadGateway},
	} {
		t.Run(test.name, func(t *testing.T) {
			if strings.Contains(test.name, "failure") {
				status := "created"
				if test.name == "stop failure" {
					status = "running"
				}
				test.docker.observed = &ObservedWorkload{Managed: true, Hardened: true, Status: status}
			}
			server, _ := NewServer(test.docker, "secret", nil)
			request := httptest.NewRequest(test.method, test.path, nil)
			request.Header.Set("Authorization", "Bearer secret")
			response := httptest.NewRecorder()
			server.Handler().ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
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
