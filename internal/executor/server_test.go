package executor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
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
