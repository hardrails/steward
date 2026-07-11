package executor

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
)

func dockerTestClient(t *testing.T, handler http.HandlerFunc) *DockerHTTP {
	t.Helper()
	file, err := os.CreateTemp("/tmp", "se-docker-")
	if err != nil {
		t.Fatal(err)
	}
	socket := file.Name()
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(socket); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(socket) })
	server := &http.Server{Handler: handler}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close() })
	return NewDockerHTTP(socket)
}

func TestCreateSendsNonEscapableDockerPolicy(t *testing.T) {
	var payload map[string]any
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.41/containers/create" || r.URL.Query().Get("name") != "executor-x" {
			t.Fatalf("unexpected target %s", r.URL.String())
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	w := Workload{
		InstanceID: "x", TenantID: "tenant-a", ProfileID: "openclaw-v1",
		Image:     "registry.local/openclaw@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 250, PIDs: 32},
	}
	if err := docker.Create(context.Background(), "executor-x", w); err != nil {
		t.Fatal(err)
	}
	host := payload["HostConfig"].(map[string]any)
	if payload["User"] != "65532:65532" {
		t.Fatalf("workload was not forced to an unprivileged user: %#v", payload)
	}
	if payload["WorkingDir"] != "/workspace" {
		t.Fatalf("fixed writable workspace missing: %#v", payload)
	}
	if host["Runtime"] != "runsc" || host["NetworkMode"] != "none" || host["ReadonlyRootfs"] != true {
		t.Fatalf("unsafe host config: %#v", host)
	}
	if host["Memory"] != float64(1<<20) || host["NanoCPUs"] != float64(250_000_000) || host["PidsLimit"] != float64(32) {
		t.Fatalf("resource limits missing: %#v", host)
	}
	if got := host["CapDrop"].([]any); len(got) != 1 || got[0] != "ALL" {
		t.Fatalf("capabilities not dropped: %#v", host)
	}
	tmpfs := host["Tmpfs"].(map[string]any)
	if tmpfs["/tmp"] != tempTmpfs || tmpfs["/workspace"] != workspaceTmpfs {
		t.Fatalf("fixed tmpfs policy missing: %#v", tmpfs)
	}
	labels := payload["Labels"].(map[string]any)
	if labels[managedWorkloadLabel] != "true" || labels["io.hardrails.tenant"] != "tenant-a" {
		t.Fatalf("managed workload labels missing: %#v", labels)
	}
	if labels[workloadFingerprintLabel] != workloadFingerprint(w) {
		t.Fatalf("workload fingerprint label missing: %#v", labels)
	}
	if labels[workloadMemoryLabel] != "1048576" || labels[workloadCPULabel] != "250" || labels[workloadPIDsLabel] != "32" {
		t.Fatalf("resource drift labels missing: %#v", labels)
	}
}

func TestRuntimeAvailableReadsDockerRegistry(t *testing.T) {
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.41/info" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"Runtimes": map[string]any{"runsc": map[string]any{}}})
	})
	available, err := docker.RuntimeAvailable(context.Background(), "runsc")
	if err != nil || !available {
		t.Fatalf("RuntimeAvailable = %v, %v", available, err)
	}
}

func TestInspectProjectsOnlyExecutorOwnedWorkloadState(t *testing.T) {
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Config": map[string]any{
				"Image": "registry.local/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
				"Cmd":   []string{"agent", "serve"}, "User": "65532:65532",
				"Env": []string{"HOME=/workspace", "TMPDIR=/tmp"}, "WorkingDir": "/workspace",
				"Labels": map[string]string{
					managedWorkloadLabel: "true", "io.hardrails.tenant": "tenant-a",
					"io.hardrails.instance": "agent-1", "io.hardrails.profile": "hermes-v1",
					workloadFingerprintLabel: strings.Repeat("a", 64),
					workloadMemoryLabel:      "1048576", workloadCPULabel: "250", workloadPIDsLabel: "32",
				},
			},
			"HostConfig": map[string]any{
				"Memory": 1048576, "NanoCpus": 250000000, "PidsLimit": 32,
				"Runtime": "runsc", "NetworkMode": "none", "ReadonlyRootfs": true,
				"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"},
				"Tmpfs": map[string]string{"/tmp": tempTmpfs, "/workspace": workspaceTmpfs},
			},
			"State": map[string]any{"Status": "running"},
		})
	})
	observed, err := docker.Inspect(context.Background(), "executor-x")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Status != "running" || observed.Workload.TenantID != "tenant-a" ||
		observed.Workload.Resources.CPUMillis != 250 || !observed.Hardened {
		t.Fatalf("observed = %#v", observed)
	}
}

func TestWorkloadCountsUseManagedDockerLabels(t *testing.T) {
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.41/containers/json" || r.URL.Query().Get("all") != "true" {
			t.Fatalf("unexpected target %s", r.URL.String())
		}
		var filters map[string][]string
		if err := json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters); err != nil {
			t.Fatal(err)
		}
		if got := filters["label"]; len(got) != 1 || got[0] != managedWorkloadLabel+"=true" {
			t.Fatalf("filters = %#v", filters)
		}
		_ = json.NewEncoder(w).Encode([]map[string]map[string]string{
			{"Labels": {managedWorkloadLabel: "true", "io.hardrails.tenant": "tenant-a"}},
			{"Labels": {managedWorkloadLabel: "true", "io.hardrails.tenant": "tenant-b"}},
			{"Labels": {managedWorkloadLabel: "true", "io.hardrails.tenant": "tenant-a"}},
		})
	})
	total, tenant, err := docker.WorkloadCounts(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || tenant != 2 {
		t.Fatalf("counts = %d, %d", total, tenant)
	}
}

func TestUnframeDockerLogs(t *testing.T) {
	frame := make([]byte, 8)
	frame[0] = 1
	binary.BigEndian.PutUint32(frame[4:], uint32(len("stdout\n")))
	raw := append(frame, []byte("stdout\n")...)
	if got := string(unframeDockerLogs(raw)); got != "stdout\n" {
		t.Fatalf("unframeDockerLogs = %q", got)
	}
}

func TestDockerLifecycleAndLogsUseOnlyBoundedManagedPaths(t *testing.T) {
	var calls []string
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.RequestURI())
		switch {
		case strings.HasSuffix(r.URL.Path, "/start"):
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/stop"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case strings.HasSuffix(r.URL.Path, "/logs"):
			frame := make([]byte, 8)
			frame[0] = 1
			binary.BigEndian.PutUint32(frame[4:], uint32(len("hello\n")))
			_, _ = w.Write(append(frame, []byte("hello\n")...))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	ctx := context.Background()
	if err := docker.Start(ctx, "executor-x"); err != nil {
		t.Fatal(err)
	}
	if err := docker.Stop(ctx, "executor-x"); err != nil {
		t.Fatal(err)
	}
	if err := docker.Remove(ctx, "executor-x"); err != nil {
		t.Fatal(err)
	}
	logs, err := docker.Logs(ctx, "executor-x")
	if err != nil || logs != "hello\n" {
		t.Fatalf("logs=%q err=%v", logs, err)
	}
	if len(calls) != 4 {
		t.Fatalf("calls=%#v", calls)
	}
}

func TestDockerErrorIsBoundedAndNamesHTTPStatus(t *testing.T) {
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("x", 8192)))
	})
	err := docker.Start(context.Background(), "executor-x")
	if err == nil || !strings.Contains(err.Error(), "HTTP 500") || len(err.Error()) > 4200 {
		t.Fatalf("error=%q", err)
	}
}
