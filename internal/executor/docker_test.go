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

func TestCreateWithStateUsesOnlyExecutorDerivedVolume(t *testing.T) {
	var payload map[string]any
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	state := &StateMount{VolumeName: StateVolumeName("tenant-a", "lineage-a"), Path: "/state"}
	workload := Workload{
		InstanceID: "agent", TenantID: "tenant-a", ProfileID: "generic-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 16}, State: state,
	}
	if err := docker.Create(context.Background(), "executor-state", workload); err != nil {
		t.Fatal(err)
	}
	if payload["WorkingDir"] != "/state" {
		t.Fatalf("payload=%#v", payload)
	}
	host := payload["HostConfig"].(map[string]any)
	tmpfs := host["Tmpfs"].(map[string]any)
	if _, exists := tmpfs["/workspace"]; exists {
		t.Fatal("state workload retained ephemeral workspace")
	}
	mounts := host["Mounts"].([]any)
	mount := mounts[0].(map[string]any)
	if mount["Type"] != "volume" || mount["Source"] != state.VolumeName || mount["Target"] != "/state" || mount["ReadOnly"] != false {
		t.Fatalf("mount=%#v", mount)
	}
	labels := payload["Labels"].(map[string]any)
	if labels[stateVolumeLabel] != state.VolumeName || labels[statePathLabel] != "/state" {
		t.Fatalf("labels=%#v", labels)
	}
}

func TestStateVolumeLifecycleUsesManagedTenantLabels(t *testing.T) {
	spec := StateVolumeSpec{Name: StateVolumeName("tenant-a", "lineage-a"), TenantID: "tenant-a", LineageID: "lineage-a"}
	var calls []string
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		switch r.Method {
		case http.MethodPost:
			var payload struct {
				Name   string            `json:"Name"`
				Labels map[string]string `json:"Labels"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload.Name != spec.Name || payload.Labels[managedStateLabel] != "true" || payload.Labels[stateLineageLabel] != spec.LineageID {
				t.Fatalf("payload=%#v", payload)
			}
			w.WriteHeader(http.StatusCreated)
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{"Name": spec.Name, "Labels": map[string]string{
				managedStateLabel: "true", "io.hardrails.tenant": spec.TenantID, stateLineageLabel: spec.LineageID,
			}})
		case http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		}
	})
	ctx := context.Background()
	if err := docker.CreateStateVolume(ctx, spec); err != nil {
		t.Fatal(err)
	}
	observed, err := docker.InspectStateVolume(ctx, spec.Name)
	if err != nil || !observed.Managed || observed.StateVolumeSpec != spec {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	if err := docker.RemoveStateVolume(ctx, spec.Name); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 3 {
		t.Fatalf("calls=%#v", calls)
	}
}

func TestStateVolumeNameSeparatesTenantsAndLineages(t *testing.T) {
	a := StateVolumeName("tenant-a", "lineage")
	if a == StateVolumeName("tenant-b", "lineage") || a == StateVolumeName("tenant-a", "other") || len(a) != len("steward-state-")+64 {
		t.Fatalf("unexpected state name %q", a)
	}
}

func TestStateMountPathIsDerivedFromBuiltInProfile(t *testing.T) {
	for _, test := range []struct{ profile, path string }{
		{"generic-v1@v1", "/state"},
		{"hermes-v1@v1", "/opt/data"},
		{"openclaw-v1@v1", "/home/node/.openclaw"},
	} {
		workload := Workload{
			InstanceID: "agent", TenantID: "tenant", ProfileID: test.profile,
			Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent"},
			Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 16},
			State:     &StateMount{VolumeName: StateVolumeName("tenant", "lineage"), Path: test.path},
		}
		if err := workload.Validate(); err != nil {
			t.Fatalf("%s rejected: %v", test.profile, err)
		}
		workload.State.Path = "/caller-selected"
		if err := workload.Validate(); err == nil {
			t.Fatalf("%s accepted arbitrary state path", test.profile)
		}
	}
}

func TestCreateRelayUsesOnlyFixedHardenedTopology(t *testing.T) {
	var payload map[string]any
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.41/containers/create" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	spec := RelaySpec{
		TenantID: "tenant-a", InstanceID: "agent-a", Generation: 3,
		GrantID: "grant-" + strings.Repeat("a", 64), GrantDir: "/run/steward-gateway/grants/grant-" + strings.Repeat("a", 64),
		Image: "sha256:" + strings.Repeat("b", 64), RelayGID: 1234, Inference: true, ServicePort: 8080,
		MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32,
	}
	spec.Name = RelayName(spec.TenantID, spec.InstanceID, spec.Generation)
	addresses := NetworkSpecFor(spec.TenantID, spec.InstanceID, spec.Generation)
	spec.NetworkName, spec.RelayIP, spec.AgentIP = addresses.Name, addresses.RelayIP, addresses.AgentIP
	if err := docker.CreateRelay(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	host := payload["HostConfig"].(map[string]any)
	if host["Runtime"] != "runc" || host["NetworkMode"] != spec.NetworkName || host["ReadonlyRootfs"] != true {
		t.Fatalf("host=%#v", host)
	}
	if _, published := host["PortBindings"]; published {
		t.Fatalf("relay published a raw Docker port: %#v", host)
	}
	extraHosts := host["ExtraHosts"].([]any)
	if len(extraHosts) != 1 || extraHosts[0] != "agent:"+spec.AgentIP {
		t.Fatalf("extra hosts=%#v", extraHosts)
	}
	mount := host["Mounts"].([]any)[0].(map[string]any)
	if mount["Source"] != spec.GrantDir || mount["Target"] != "/run/steward-grant" || mount["ReadOnly"] != false {
		t.Fatalf("grant mount=%#v", mount)
	}
	endpoint := payload["NetworkingConfig"].(map[string]any)["EndpointsConfig"].(map[string]any)[spec.NetworkName].(map[string]any)
	if endpoint["IPAMConfig"].(map[string]any)["IPv4Address"] != spec.RelayIP {
		t.Fatalf("endpoint=%#v", endpoint)
	}
	labels := payload["Labels"].(map[string]any)
	if labels["io.hardrails.tenant"] != spec.TenantID || labels[runtimeGrantLabel] != spec.GrantID {
		t.Fatalf("labels=%#v", labels)
	}
	bad := spec
	bad.Image = "steward-relay:latest"
	if err := docker.CreateRelay(context.Background(), bad); err == nil {
		t.Fatal("mutable relay image accepted")
	}
}

func TestNetworkSpecUsesDeterministicPrivatePerInstanceSubnet(t *testing.T) {
	a := NetworkSpecFor("tenant-a", "agent-a", 1)
	b := NetworkSpecFor("tenant-a", "agent-a", 2)
	if a == b || !strings.HasSuffix(a.Subnet, "/29") || !strings.HasPrefix(a.AgentIP, "10.") || a.AgentIP == a.RelayIP {
		t.Fatalf("a=%#v b=%#v", a, b)
	}
	if a.Name != NetworkName("tenant-a", "agent-a", 1) {
		t.Fatalf("name=%s", a.Name)
	}
}

func TestNetworkLifecycleAndRelayInspectionVerifyObservedTopology(t *testing.T) {
	network := NetworkSpecFor("tenant-a", "agent-a", 7)
	relay := RelaySpec{
		Name: RelayName("tenant-a", "agent-a", 7), Image: "sha256:" + strings.Repeat("a", 64),
		NetworkName: network.Name, GrantID: "grant-" + strings.Repeat("b", 64),
		GrantDir: "/run/steward-gateway/grants/" + strings.Repeat("b", 32), TenantID: "tenant-a", InstanceID: "agent-a", Generation: 7,
		RelayGID: 1234, Inference: true, ServicePort: 8080, RelayIP: network.RelayIP, AgentIP: network.AgentIP,
		MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32,
	}
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1.41/networks/create":
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.41/networks/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Name": network.Name, "Internal": true, "Attachable": false,
				"Labels": map[string]string{managedNetworkLabel: "true", "io.hardrails.tenant": network.TenantID, "io.hardrails.instance": network.InstanceID, networkGenerationLabel: "7"},
				"IPAM":   map[string]any{"Config": []map[string]string{{"Subnet": network.Subnet, "Gateway": network.Gateway}}},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1.41/networks/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.41/containers/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Image": relay.Image,
				"Config": map[string]any{"Image": relay.Image, "User": "65532:1234", "WorkingDir": "/",
					"Cmd":    []string{"-inference-socket=/run/steward-grant/i.sock", "-service-target=http://agent:8080"},
					"Labels": map[string]string{managedRelayLabel: "true", relayFingerprintLabel: relayFingerprint(relay), "io.hardrails.tenant": relay.TenantID, "io.hardrails.instance": relay.InstanceID, networkGenerationLabel: "7", runtimeNetworkLabel: relay.NetworkName, runtimeGrantLabel: relay.GrantID}},
				"HostConfig": map[string]any{"Memory": relay.MemoryBytes, "NanoCpus": relay.CPUMillis * 1_000_000, "PidsLimit": relay.PIDs,
					"Runtime": "runc", "NetworkMode": relay.NetworkName, "ReadonlyRootfs": true, "CapDrop": []string{"ALL"},
					"SecurityOpt": []string{"no-new-privileges:true"}, "Tmpfs": map[string]string{"/tmp": tempTmpfs}, "ExtraHosts": []string{"agent:" + relay.AgentIP}},
				"Mounts":          []map[string]any{{"Type": "bind", "Source": relay.GrantDir, "Destination": "/run/steward-grant", "RW": true}},
				"NetworkSettings": map[string]any{"Networks": map[string]any{relay.NetworkName: map[string]string{"IPAddress": relay.RelayIP}}},
				"State":           map[string]string{"Status": "running"},
			})
		default:
			t.Fatalf("unexpected Docker request %s %s", r.Method, r.URL.Path)
		}
	})
	ctx := context.Background()
	if err := docker.CreateNetwork(ctx, network); err != nil {
		t.Fatal(err)
	}
	observedNetwork, err := docker.InspectNetwork(ctx, network.Name)
	if err != nil || !networkEqual(observedNetwork, network) {
		t.Fatalf("network=%#v err=%v", observedNetwork, err)
	}
	observedRelay, err := docker.InspectRelay(ctx, relay.Name)
	if err != nil || !relayEqual(observedRelay, relay) || observedRelay.IPAddress != relay.RelayIP {
		t.Fatalf("relay=%#v err=%v", observedRelay, err)
	}
	if err := docker.RemoveNetwork(ctx, network.Name); err != nil {
		t.Fatal(err)
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

func TestInspectProjectsPersistentStateAndRuntimeGrant(t *testing.T) {
	addresses := NetworkSpecFor("tenant-a", "agent-1", 3)
	state := &StateMount{VolumeName: StateVolumeName("tenant-a", "lineage-a"), Path: "/home/node/.openclaw"}
	runtime := &RuntimeGrant{
		NetworkName: addresses.Name, GrantID: "grant-" + strings.Repeat("b", 64), Generation: 3,
		Inference: true, RouteID: "local", ModelAlias: "private-model", ServicePort: 8080,
		RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP,
	}
	workload := Workload{
		InstanceID: "agent-1", TenantID: "tenant-a", ProfileID: "openclaw-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent", "serve"},
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 250, PIDs: 32}, State: state, Runtime: runtime,
	}
	fingerprint := workloadFingerprint(workload)
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Image": "sha256:" + strings.Repeat("c", 64),
			"Config": map[string]any{
				"Image": workload.Image, "Cmd": workload.Command, "User": "65532:65532",
				"Env": []string{
					"HOME=/home/node", "TMPDIR=/tmp", "OPENAI_BASE_URL=http://steward-relay:8080/v1",
					"OPENAI_API_BASE=http://steward-relay:8080/v1", "OPENAI_API_KEY=steward-local", "OPENAI_MODEL=private-model",
				},
				"WorkingDir": "/home/node/.openclaw/workspace",
				"Labels": map[string]string{
					managedWorkloadLabel: "true", workloadFingerprintLabel: fingerprint,
					"io.hardrails.tenant": "tenant-a", "io.hardrails.instance": "agent-1", "io.hardrails.profile": "openclaw-v1@v1",
					workloadMemoryLabel: "1048576", workloadCPULabel: "250", workloadPIDsLabel: "32",
					stateVolumeLabel: state.VolumeName, statePathLabel: state.Path,
					runtimeNetworkLabel: addresses.Name, runtimeGrantLabel: runtime.GrantID, runtimeGenerationLabel: "3",
					runtimeInferenceLabel: "true", runtimeModelLabel: "private-model", runtimeRouteLabel: "local",
					runtimeServicePortLabel: "8080", runtimeRelayIPLabel: addresses.RelayIP, runtimeAgentIPLabel: addresses.AgentIP,
				},
			},
			"HostConfig": map[string]any{
				"Memory": 1048576, "NanoCpus": 250000000, "PidsLimit": 32,
				"Runtime": "runsc", "NetworkMode": addresses.Name, "ReadonlyRootfs": true,
				"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"},
				"Tmpfs": map[string]string{"/tmp": tempTmpfs}, "ExtraHosts": []string{"steward-relay:" + addresses.RelayIP},
			},
			"Mounts":          []map[string]any{{"Type": "volume", "Name": state.VolumeName, "Destination": state.Path, "RW": true}},
			"NetworkSettings": map[string]any{"Networks": map[string]any{addresses.Name: map[string]string{"IPAddress": addresses.AgentIP}}},
			"State":           map[string]string{"Status": "running"},
		})
	})
	observed, err := docker.Inspect(context.Background(), "executor-state-runtime")
	if err != nil || !observed.Hardened || observed.Workload.State == nil || observed.Workload.Runtime == nil {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	if *observed.Workload.State != *state || *observed.Workload.Runtime != *runtime || observed.Fingerprint != fingerprint {
		t.Fatalf("projected workload=%#v", observed.Workload)
	}
}

func TestDockerInspectAndVolumeErrorResponses(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "not found", status: http.StatusNotFound},
		{name: "daemon error", status: http.StatusInternalServerError, body: "broken"},
		{name: "invalid json", status: http.StatusOK, body: "{"},
	} {
		t.Run(test.name, func(t *testing.T) {
			docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})
			if _, err := docker.Inspect(context.Background(), "executor-x"); err == nil {
				t.Fatal("inspect accepted error response")
			}
			if _, err := docker.InspectStateVolume(context.Background(), "state-x"); err == nil {
				t.Fatal("volume inspect accepted error response")
			}
		})
	}
	if hasExactStateMount([]dockerMount{{Type: "bind", Name: "x", Destination: "/state", RW: true}}, StateMount{VolumeName: "x", Path: "/state"}) {
		t.Fatal("bind mount accepted as state volume")
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
