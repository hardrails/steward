package executor

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"math"
	"net"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/gateway"
)

func TestLoadImageUsesNativeDockerImportAndRejectsDaemonErrors(t *testing.T) {
	for _, test := range []struct {
		name     string
		response string
		wantErr  bool
	}{
		{name: "success", response: "{\"stream\":\"Loaded image\"}\n"},
		{name: "daemon error", response: "{\"errorDetail\":{\"message\":\"invalid layer\"},\"error\":\"invalid layer\"}\n", wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodPost || r.URL.Path != "/v1.41/images/load" || r.URL.Query().Get("quiet") != "1" {
					t.Fatalf("unexpected image import target %s %s", r.Method, r.URL.String())
				}
				if r.Header.Get("Content-Type") != "application/x-tar" {
					t.Fatalf("content type=%q", r.Header.Get("Content-Type"))
				}
				body, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				if string(body) != "verified archive" {
					t.Fatalf("body=%q", body)
				}
				_, _ = w.Write([]byte(test.response))
			})
			err := docker.LoadImage(context.Background(), strings.NewReader("verified archive"))
			if (err != nil) != test.wantErr {
				t.Fatalf("LoadImage error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

func TestCachedImageConfigDigestsReturnsCanonicalBoundedInventory(t *testing.T) {
	images := make([]map[string]string, 0, controlprotocol.MaxExecutorSchedulingImages+2)
	for index := controlprotocol.MaxExecutorSchedulingImages + 1; index >= 0; index-- {
		images = append(images, map[string]string{"Id": fmt.Sprintf("sha256:%064x", index)})
	}
	images = append(images, images[0])
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1.41/images/json" || r.URL.Query().Get("all") != "1" {
			t.Fatalf("unexpected image inventory target %s %s", r.Method, r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(images)
	})
	digests, err := docker.CachedImageConfigDigests(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(digests) != controlprotocol.MaxExecutorSchedulingImages ||
		digests[0] != "sha256:"+strings.Repeat("0", 64) ||
		digests[len(digests)-1] != fmt.Sprintf("sha256:%064x", controlprotocol.MaxExecutorSchedulingImages-1) {
		t.Fatalf("canonical bounded inventory = %#v", digests)
	}
}

func TestCachedImageConfigDigestsRejectsUntrustedDockerResponses(t *testing.T) {
	for _, test := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "daemon status", status: http.StatusServiceUnavailable, body: `{"message":"unavailable"}`},
		{name: "invalid digest", status: http.StatusOK, body: `[{"Id":"latest"}]`},
		{name: "invalid json", status: http.StatusOK, body: `[`},
		{name: "oversized", status: http.StatusOK, body: `"` + strings.Repeat("x", (1<<20)+1) + `"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.body))
			})
			if _, err := docker.CachedImageConfigDigests(context.Background()); err == nil {
				t.Fatal("untrusted Docker image inventory was accepted")
			}
		})
	}
}

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

func assertClosedDockerCreatePolicy(t *testing.T, host map[string]any) {
	t.Helper()
	for key, want := range map[string]any{
		"PidMode": "", "IpcMode": "private", "UTSMode": "", "CgroupnsMode": "private",
		"UsernsMode": "", "Cgroup": "", "AutoRemove": false, "OomKillDisable": false,
		"OomScoreAdj": float64(0), "ContainerIDFile": "", "CgroupParent": "", "VolumeDriver": "",
		"ShmSize": float64(privateShmBytes),
	} {
		got, ok := host[key]
		if !ok || got != want {
			t.Fatalf("closed Docker policy %s=%#v want %#v (present=%v): %#v", key, got, want, ok, host)
		}
	}
	restart, ok := host["RestartPolicy"].(map[string]any)
	if !ok || restart["Name"] != "no" || restart["MaximumRetryCount"] != float64(0) {
		t.Fatalf("restart policy is not explicitly disabled: %#v", host["RestartPolicy"])
	}
	for _, key := range []string{"VolumesFrom", "Links", "GroupAdd", "DeviceCgroupRules", "DnsOptions", "DnsSearch"} {
		values, ok := host[key].([]any)
		if !ok || len(values) != 0 {
			t.Fatalf("closed Docker policy %s=%#v", key, host[key])
		}
	}
	for _, key := range []string{"StorageOpt", "Sysctls"} {
		values, ok := host[key].(map[string]any)
		if !ok || len(values) != 0 {
			t.Fatalf("closed Docker policy %s=%#v", key, host[key])
		}
	}
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
	assertClosedDockerCreatePolicy(t, host)
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
	if host["MemorySwap"] != float64(1<<20) {
		t.Fatalf("swap exceeded memory ceiling: %#v", host)
	}
	logConfig := host["LogConfig"].(map[string]any)
	logOptions := logConfig["Config"].(map[string]any)
	if logConfig["Type"] != dockerLogDriver || logOptions["max-size"] != dockerLogMaxSize ||
		logOptions["max-file"] != dockerLogMaxFiles || logOptions["compress"] != dockerLogCompress {
		t.Fatalf("bounded local logging missing: %#v", logConfig)
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

func TestCreateRunsSecureWorkloadByExactConfigDigest(t *testing.T) {
	var payload map[string]any
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	workload := Workload{
		InstanceID: "agent", TenantID: "tenant-a", ProfileID: "generic-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), ImageConfigDigest: "sha256:" + strings.Repeat("b", 64),
		Command: []string{"agent"}, Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 16},
	}
	if err := workload.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := docker.Create(context.Background(), "executor-image-id", workload); err != nil {
		t.Fatal(err)
	}
	if payload["Image"] != workload.ImageConfigDigest {
		t.Fatalf("Docker create image=%v want exact config %s", payload["Image"], workload.ImageConfigDigest)
	}
	labels := payload["Labels"].(map[string]any)
	if labels[workloadImageReferenceLabel] != workload.Image || labels[workloadImageConfigLabel] != workload.ImageConfigDigest {
		t.Fatalf("signed image identity labels=%#v", labels)
	}
}

func TestCreateRunsContainerdStoreWorkloadByExactManifestDigest(t *testing.T) {
	var payload map[string]any
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	workload := Workload{
		InstanceID: "agent", TenantID: "tenant-a", ProfileID: "generic-v1@v1",
		Image: "registry.local/agent@" + manifestDigest, ImageConfigDigest: configDigest,
		ImageRuntimeDigest: manifestDigest, Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 16},
	}
	if err := workload.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := docker.Create(context.Background(), "executor-image-manifest", workload); err != nil {
		t.Fatal(err)
	}
	if payload["Image"] != manifestDigest {
		t.Fatalf("Docker create image=%v want exact manifest %s", payload["Image"], manifestDigest)
	}
	labels := payload["Labels"].(map[string]any)
	if labels[workloadImageReferenceLabel] != workload.Image || labels[workloadImageConfigLabel] != configDigest ||
		labels[workloadImageRuntimeLabel] != manifestDigest {
		t.Fatalf("signed image identity labels=%#v", labels)
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
	assertClosedDockerCreatePolicy(t, host)
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

func TestCreateWithSignedEgressInjectsOnlyFixedProxyAndDisablesDNS(t *testing.T) {
	var payload map[string]any
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	addresses := testNetworkSpec("tenant-a", "agent-a", 4)
	workload := Workload{InstanceID: "agent-a", TenantID: "tenant-a", ProfileID: "generic-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 16}, Runtime: &RuntimeGrant{
			NetworkName: addresses.Name, GrantID: "grant-" + strings.Repeat("b", 64), Generation: 4,
			Subnet: addresses.Subnet, Gateway: addresses.Gateway,
			RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP, EgressRouteIDs: []string{"package-mirrors", "public-web"},
		}}
	if err := workload.Validate(); err != nil {
		t.Fatal(err)
	}
	if err := docker.Create(context.Background(), "executor-egress", workload); err != nil {
		t.Fatal(err)
	}
	host := payload["HostConfig"].(map[string]any)
	dns := host["Dns"].([]any)
	if len(dns) != 1 || dns[0] != "127.0.0.1" {
		t.Fatalf("DNS=%#v", dns)
	}
	environment := payload["Env"].([]any)
	for _, expected := range []string{"STEWARD_EGRESS_PROXY=http://steward-relay:8082", "HTTP_PROXY=http://steward-relay:8082",
		"HTTPS_PROXY=http://steward-relay:8082", "NO_PROXY=steward-relay,agent,localhost,127.0.0.1",
		"http_proxy=http://steward-relay:8082", "https_proxy=http://steward-relay:8082"} {
		found := false
		for _, value := range environment {
			if value == expected {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing %q in %#v", expected, environment)
		}
	}
	labels := payload["Labels"].(map[string]any)
	if labels[runtimeEgressRoutesLabel] != "package-mirrors,public-web" {
		t.Fatalf("labels=%#v", labels)
	}
}

func TestCreateWithSignedConnectorInjectsOnlyFixedRelayURLAndAdmissionBindings(t *testing.T) {
	var payload map[string]any
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	addresses := testNetworkSpec("tenant-a", "agent-a", 4)
	secondActionKey := make([]byte, ed25519.PublicKeySize)
	secondActionKey[0] = 1
	actionAuthorities := []gateway.GrantActionAuthority{{
		KeyID: "effects-approver-a", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		ConnectorIDs: []string{"git.read", "issues.create"},
	}, {
		KeyID: "effects-approver-b", PublicKey: base64.StdEncoding.EncodeToString(secondActionKey),
		ConnectorIDs: []string{"git.read", "issues.create"},
	}}
	workload := Workload{InstanceID: "agent-a", TenantID: "tenant-a", ProfileID: "generic-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 16}, Runtime: &RuntimeGrant{
			NetworkName: addresses.Name, GrantID: "grant-" + strings.Repeat("b", 64), NodeID: "node-a", Generation: 4,
			Subnet: addresses.Subnet, Gateway: addresses.Gateway, RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP,
			ConnectorIDs: []string{"git.read", "issues.create"},
			EffectMode:   gateway.EffectModeAuthorized, ActionApprovalThreshold: 2, ActionContextRequired: true, ActionAuthorities: actionAuthorities,
			CapsuleDigest: "sha256:" + strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64),
			ActivationID:          "activation-test",
			ActivationBeginDigest: "sha256:" + strings.Repeat("e", 64),
		}}
	if err := docker.Create(context.Background(), "executor-connector", workload); err != nil {
		t.Fatal(err)
	}
	environment := payload["Env"].([]any)
	wantEnvironment := []any{"HOME=/workspace", "TMPDIR=/tmp", "STEWARD_CONNECTOR_URL=http://steward-relay:8081"}
	if !reflect.DeepEqual(environment, wantEnvironment) {
		t.Fatalf("environment=%#v want=%#v", environment, wantEnvironment)
	}
	labels := payload["Labels"].(map[string]any)
	actionAuthorityRaw, _ := json.Marshal(dockerActionAuthorityLabel{Authorities: actionAuthorities})
	if labels[runtimeConnectorsLabel] != "git.read,issues.create" ||
		labels[runtimeEffectModeLabel] != gateway.EffectModeAuthorized ||
		labels[runtimeActionApprovalThresholdLabel] != "2" ||
		labels[runtimeActionContextRequiredLabel] != "true" ||
		labels[runtimeActionAuthoritiesLabel] != string(actionAuthorityRaw) ||
		labels[runtimeCapsuleDigestLabel] != workload.Runtime.CapsuleDigest ||
		labels[runtimePolicyDigestLabel] != workload.Runtime.PolicyDigest ||
		labels[runtimeActivationIDLabel] != workload.Runtime.ActivationID ||
		labels[runtimeActivationBeginDigestLabel] != workload.Runtime.ActivationBeginDigest {
		t.Fatalf("labels=%#v", labels)
	}
}

func TestRuntimeAdmissionBindingsRequireExactActivationPair(t *testing.T) {
	valid := &RuntimeGrant{
		CapsuleDigest:         "sha256:" + strings.Repeat("a", 64),
		PolicyDigest:          "sha256:" + strings.Repeat("b", 64),
		ActivationID:          "activation-test",
		ActivationBeginDigest: "sha256:" + strings.Repeat("c", 64),
	}
	if !validRuntimeAdmissionBindings(valid) {
		t.Fatal("valid activation admission bindings were rejected")
	}
	for name, mutate := range map[string]func(*RuntimeGrant){
		"missing activation id": func(runtime *RuntimeGrant) {
			runtime.ActivationID = ""
		},
		"missing begin digest": func(runtime *RuntimeGrant) {
			runtime.ActivationBeginDigest = ""
		},
		"missing signed bindings": func(runtime *RuntimeGrant) {
			runtime.CapsuleDigest, runtime.PolicyDigest = "", ""
		},
		"invalid activation id": func(runtime *RuntimeGrant) {
			runtime.ActivationID = "activation/id"
		},
		"invalid begin digest": func(runtime *RuntimeGrant) {
			runtime.ActivationBeginDigest = "sha256:invalid"
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := *valid
			mutate(&candidate)
			if validRuntimeAdmissionBindings(&candidate) {
				t.Fatal("invalid activation admission bindings were accepted")
			}
		})
	}
}

func TestCreateDisablesDNSForEveryPositiveCapabilityRuntime(t *testing.T) {
	for _, runtime := range []*RuntimeGrant{
		{Inference: true, RouteID: "local", ModelAlias: "model"},
		{ServicePort: 8080},
	} {
		t.Run(fmt.Sprintf("inference=%t-service=%d", runtime.Inference, runtime.ServicePort), func(t *testing.T) {
			var payload map[string]any
			docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatal(err)
				}
				w.WriteHeader(http.StatusCreated)
			})
			addresses := testNetworkSpec("tenant-a", "agent-a", 5)
			runtime.NetworkName, runtime.GrantID, runtime.Generation = addresses.Name, "grant-"+strings.Repeat("b", 64), 5
			runtime.Subnet, runtime.Gateway = addresses.Subnet, addresses.Gateway
			runtime.RelayIP, runtime.AgentIP = addresses.RelayIP, addresses.AgentIP
			workload := Workload{InstanceID: "agent-a", TenantID: "tenant-a", ProfileID: "generic-v1@v1",
				Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent"},
				Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 16}, Runtime: runtime}
			if err := docker.Create(context.Background(), "executor-runtime", workload); err != nil {
				t.Fatal(err)
			}
			dns := payload["HostConfig"].(map[string]any)["Dns"].([]any)
			if len(dns) != 1 || dns[0] != "127.0.0.1" {
				t.Fatalf("DNS=%#v", dns)
			}
		})
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
		Image: "sha256:" + strings.Repeat("b", 64), RelayGID: 1234, Inference: true, Connector: true, ServicePort: 8080,
		MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32,
	}
	spec.Name = RelayName(spec.TenantID, spec.InstanceID, spec.Generation)
	addresses := testNetworkSpec(spec.TenantID, spec.InstanceID, spec.Generation)
	spec.NetworkName, spec.RelayIP, spec.AgentIP = addresses.Name, addresses.RelayIP, addresses.AgentIP
	if err := docker.CreateRelay(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	host := payload["HostConfig"].(map[string]any)
	assertClosedDockerCreatePolicy(t, host)
	if host["Runtime"] != "runc" || host["NetworkMode"] != spec.NetworkName || host["ReadonlyRootfs"] != true {
		t.Fatalf("host=%#v", host)
	}
	if host["MemorySwap"] != float64(spec.MemoryBytes) || host["Dns"].([]any)[0] != "127.0.0.1" {
		t.Fatalf("relay resource/DNS fence missing: %#v", host)
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
	command := payload["Cmd"].([]any)
	wantCommand := []string{
		"-inference-socket=/run/steward-grant/i.sock",
		"-connector-socket=/run/steward-grant/c.sock",
		"-service-socket=/run/steward-grant/s.sock",
		"-service-target=http://agent:8080",
	}
	if len(command) != len(wantCommand) {
		t.Fatalf("command=%#v", command)
	}
	for index := range wantCommand {
		if command[index] != wantCommand[index] {
			t.Fatalf("command=%#v", command)
		}
	}
	bad := spec
	bad.Image = "steward-relay:latest"
	if err := docker.CreateRelay(context.Background(), bad); err == nil {
		t.Fatal("mutable relay image accepted")
	}
}

func TestCreateServiceOnlyRelayMountsItsGrantSocket(t *testing.T) {
	var payload map[string]any
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusCreated)
	})
	spec := RelaySpec{
		TenantID: "tenant-a", InstanceID: "service-only", Generation: 1,
		GrantID: "grant-" + strings.Repeat("a", 64), GrantDir: "/run/steward-gateway/grants/" + strings.Repeat("a", 32),
		Image: "sha256:" + strings.Repeat("b", 64), RelayGID: 1234, ServicePort: 8080,
		MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32,
	}
	spec.Name = RelayName(spec.TenantID, spec.InstanceID, spec.Generation)
	addresses := testNetworkSpec(spec.TenantID, spec.InstanceID, spec.Generation)
	spec.NetworkName, spec.RelayIP, spec.AgentIP = addresses.Name, addresses.RelayIP, addresses.AgentIP
	if err := docker.CreateRelay(context.Background(), spec); err != nil {
		t.Fatal(err)
	}
	command := payload["Cmd"].([]any)
	wantCommand := []string{"-service-socket=/run/steward-grant/s.sock", "-service-target=http://agent:8080"}
	if len(command) != len(wantCommand) {
		t.Fatalf("command=%#v", command)
	}
	for index := range wantCommand {
		if command[index] != wantCommand[index] {
			t.Fatalf("command=%#v", command)
		}
	}
	mounts := payload["HostConfig"].(map[string]any)["Mounts"].([]any)
	if len(mounts) != 1 || mounts[0].(map[string]any)["Source"] != spec.GrantDir {
		t.Fatalf("mounts=%#v", mounts)
	}
}

func TestNetworkSpecBindsDockerAllocatedPrivateAddresses(t *testing.T) {
	identity := NetworkSpecFor("tenant-a", "agent-a", 1)
	if identity.Name != NetworkName("tenant-a", "agent-a", 1) || identity.Subnet != "" || identity.RelayIP != "" || identity.AgentIP != "" {
		t.Fatalf("identity=%#v", identity)
	}
	allocated, err := networkSpecFromIPAM(identity, "172.30.8.0/29", "")
	if err != nil {
		t.Fatal(err)
	}
	if allocated.Subnet != "172.30.8.0/29" || allocated.Gateway != "" ||
		allocated.RelayIP != "172.30.8.1" || allocated.AgentIP != "172.30.8.2" {
		t.Fatalf("allocated=%#v", allocated)
	}
	observed := ObservedNetwork{NetworkSpec: allocated, Managed: true, Internal: true}
	if !networkEqual(observed, identity) {
		t.Fatal("gateway-less isolated Docker allocation did not match its identity")
	}
	observed.AgentIP = "172.30.8.3"
	if networkEqual(observed, identity) {
		t.Fatal("network equality accepted an endpoint that was not derived from Docker IPAM")
	}
	if !runtimeAllocationMatches(identity, allocated.Subnet, allocated.Gateway, allocated.RelayIP, allocated.AgentIP) {
		t.Fatal("canonical gateway-less allocation did not match")
	}
	if runtimeAllocationMatches(identity, "172.30.8.1/29", allocated.Gateway, allocated.RelayIP, allocated.AgentIP) {
		t.Fatal("non-canonical subnet matched the recorded runtime allocation")
	}
	withGateway, err := networkSpecFromIPAM(identity, "172.30.8.0/29", "172.30.8.1")
	if err != nil {
		t.Fatal(err)
	}
	if withGateway.Gateway != "172.30.8.1" || withGateway.RelayIP != "172.30.8.2" || withGateway.AgentIP != "172.30.8.3" {
		t.Fatalf("allocation with gateway=%#v", withGateway)
	}
	for _, test := range []struct {
		name, subnet, gateway string
	}{
		{"too small", "172.30.8.0/30", ""},
		{"public gateway", "192.0.2.0/29", "192.0.2.1"},
		{"outside gateway", "172.30.8.0/29", "172.30.9.1"},
		{"invalid gateway", "172.30.8.0/29", "not-an-address"},
		{"network address gateway", "172.30.8.0/29", "172.30.8.0"},
		{"broadcast gateway", "172.30.8.0/29", "172.30.8.7"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := networkSpecFromIPAM(identity, test.subnet, test.gateway); err == nil {
				t.Fatal("invalid Docker allocation accepted")
			}
		})
	}
}

func TestNetworkLifecycleAndRelayInspectionVerifyObservedTopology(t *testing.T) {
	network := testNetworkSpec("tenant-a", "agent-a", 7)
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
			var create map[string]any
			if err := json.NewDecoder(r.Body).Decode(&create); err != nil {
				t.Fatal(err)
			}
			if create["Driver"] != "bridge" || create["Internal"] != true ||
				create["Options"].(map[string]any)[isolatedGatewayOption] != isolatedGatewayMode {
				t.Fatalf("network create=%#v", create)
			}
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.41/networks/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Name": network.Name, "Driver": "bridge", "Internal": true, "Attachable": false,
				"Options": map[string]string{isolatedGatewayOption: isolatedGatewayMode},
				"Labels":  map[string]string{managedNetworkLabel: "true", "io.hardrails.tenant": network.TenantID, "io.hardrails.instance": network.InstanceID, networkGenerationLabel: "7"},
				"IPAM":    map[string]any{"Config": []map[string]string{{"Subnet": network.Subnet, "Gateway": network.Gateway}}},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1.41/networks/"):
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1.41/containers/"):
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Image": relay.Image,
				"Config": map[string]any{"Image": relay.Image, "User": "65532:1234", "WorkingDir": "/",
					"Cmd":    []string{"-inference-socket=/run/steward-grant/i.sock", "-service-socket=/run/steward-grant/s.sock", "-service-target=http://agent:8080"},
					"Labels": map[string]string{managedRelayLabel: "true", relayFingerprintLabel: relayFingerprint(relay), "io.hardrails.tenant": relay.TenantID, "io.hardrails.instance": relay.InstanceID, networkGenerationLabel: "7", runtimeNetworkLabel: relay.NetworkName, runtimeGrantLabel: relay.GrantID}},
				"HostConfig": enforceClosedDockerHostPolicy(map[string]any{"Memory": relay.MemoryBytes, "MemorySwap": relay.MemoryBytes, "NanoCpus": relay.CPUMillis * 1_000_000, "PidsLimit": relay.PIDs,
					"Runtime": "runc", "NetworkMode": relay.NetworkName, "ReadonlyRootfs": true, "CapDrop": []string{"ALL"},
					"SecurityOpt": []string{"no-new-privileges:true"}, "Tmpfs": map[string]string{"/tmp": tempTmpfs}, "ExtraHosts": []string{"agent:" + relay.AgentIP},
					"Dns": []string{"127.0.0.1"}, "LogConfig": map[string]any{"Type": dockerLogDriver, "Config": map[string]string{
						"max-size": dockerLogMaxSize, "max-file": dockerLogMaxFiles, "compress": dockerLogCompress}}}),
				"Mounts": []map[string]any{{"Type": "bind", "Source": relay.GrantDir, "Destination": "/run/steward-grant", "RW": true}},
				"NetworkSettings": map[string]any{"Networks": map[string]any{relay.NetworkName: map[string]any{
					"IPAddress": relay.RelayIP, "IPAMConfig": map[string]string{"IPv4Address": relay.RelayIP},
				}}},
				"State": map[string]string{"Status": "running"},
			})
		default:
			t.Fatalf("unexpected Docker request %s %s", r.Method, r.URL.Path)
		}
	})
	ctx := context.Background()
	if err := docker.CreateNetwork(ctx, NetworkSpecFor(network.TenantID, network.InstanceID, network.Generation)); err != nil {
		t.Fatal(err)
	}
	observedNetwork, err := docker.InspectNetwork(ctx, network.Name)
	if err != nil || !observedNetwork.Managed || !observedNetwork.Internal || observedNetwork.NetworkSpec != network {
		t.Fatalf("network=%#v err=%v", observedNetwork, err)
	}
	observedRelay, err := docker.InspectRelay(ctx, relay.Name)
	if err != nil || !observedRelay.Managed || !observedRelay.Hardened || observedRelay.Spec != relay ||
		observedRelay.Fingerprint != relayFingerprint(relay) || observedRelay.IPAddress != relay.RelayIP {
		t.Fatalf("relay=%#v err=%v", observedRelay, err)
	}
	if err := docker.RemoveNetwork(ctx, network.Name); err != nil {
		t.Fatal(err)
	}
}

func TestInspectRelayRejectsClosedEnvelopeDrift(t *testing.T) {
	network := testNetworkSpec("tenant-a", "agent-a", 9)
	relay := RelaySpec{
		Name: RelayName("tenant-a", "agent-a", 9), Image: "sha256:" + strings.Repeat("a", 64),
		NetworkName: network.Name, GrantID: "grant-" + strings.Repeat("b", 64),
		GrantDir: "/run/steward-gateway/grants/" + strings.Repeat("b", 32), TenantID: "tenant-a", InstanceID: "agent-a", Generation: 9,
		RelayGID: 1234, Inference: true, ServicePort: 8080, RelayIP: network.RelayIP, AgentIP: network.AgentIP,
		MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32,
	}
	tests := []struct {
		name   string
		field  string
		mutate func(map[string]any)
	}{
		{"extra mount", "mounts", func(p map[string]any) {
			p["Mounts"] = append(p["Mounts"].([]map[string]any), map[string]any{"Type": "bind", "Source": "/host", "Destination": "/host", "RW": true})
		}},
		{"extra network", "networks", func(p map[string]any) {
			p["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)["hostile"] = map[string]string{"IPAddress": "10.0.0.2"}
		}},
		{"privileged", "privileged", func(p map[string]any) { p["HostConfig"].(map[string]any)["Privileged"] = true }},
		{"device", "devices", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["Devices"] = []map[string]string{{"PathOnHost": "/dev/kvm"}}
		}},
		{"port binding", "published_ports", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{"8080/tcp": []map[string]string{{"HostPort": "8080"}}}
		}},
		{"unsafe logs", "log_config", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["LogConfig"] = map[string]any{"Type": "json-file", "Config": map[string]string{}}
		}},
		{"host PID namespace", "namespace_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["PidMode"] = "host" }},
		{"shared IPC namespace", "namespace_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["IpcMode"] = "shareable" }},
		{"host UTS namespace", "namespace_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["UTSMode"] = "host" }},
		{"host cgroup namespace", "namespace_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["CgroupnsMode"] = "host" }},
		{"host user namespace", "namespace_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["UsernsMode"] = "host" }},
		{"shared container cgroup", "namespace_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["Cgroup"] = "container:peer" }},
		{"restart policy", "lifecycle_policy", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["RestartPolicy"] = map[string]any{"Name": "always", "MaximumRetryCount": 0}
		}},
		{"automatic removal", "lifecycle_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["AutoRemove"] = true }},
		{"OOM killer disabled", "lifecycle_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["OomKillDisable"] = true }},
		{"protected from host OOM", "lifecycle_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["OomScoreAdj"] = -1000 }},
		{"custom cgroup parent", "host_attachment_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["CgroupParent"] = "/system.slice" }},
		{"device cgroup rule", "host_attachment_policy", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["DeviceCgroupRules"] = []string{"c 1:3 rwm"}
		}},
		{"volumes from peer", "host_attachment_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["VolumesFrom"] = []string{"peer"} }},
		{"supplemental host group", "host_attachment_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["GroupAdd"] = []string{"docker"} }},
		{"legacy container link", "host_attachment_policy", func(p map[string]any) { p["HostConfig"].(map[string]any)["Links"] = []string{"/peer:/agent/peer"} }},
		{"namespaced sysctl", "host_attachment_policy", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["Sysctls"] = map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := hardenedRelayInspectPayload(relay)
			test.mutate(payload)
			docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(payload)
			})
			observed, err := docker.InspectRelay(context.Background(), relay.Name)
			if err != nil {
				t.Fatal(err)
			}
			if observed.Hardened || !strings.Contains(observed.Drift, test.field) {
				t.Fatalf("drift accepted or not explained: %#v", observed)
			}
		})
	}
}

func hardenedRelayInspectPayload(relay RelaySpec) map[string]any {
	return map[string]any{
		"Image": relay.Image,
		"Config": map[string]any{
			"Image": relay.Image, "User": "65532:1234", "WorkingDir": "/",
			"Cmd": relayCommand(relay),
			"Labels": map[string]string{
				managedRelayLabel: "true", relayFingerprintLabel: relayFingerprint(relay),
				"io.hardrails.tenant": relay.TenantID, "io.hardrails.instance": relay.InstanceID,
				networkGenerationLabel: "9", runtimeNetworkLabel: relay.NetworkName, runtimeGrantLabel: relay.GrantID,
			},
		},
		"HostConfig": enforceClosedDockerHostPolicy(map[string]any{
			"Memory": relay.MemoryBytes, "MemorySwap": relay.MemoryBytes, "NanoCpus": relay.CPUMillis * 1_000_000, "PidsLimit": relay.PIDs,
			"Runtime": "runc", "NetworkMode": relay.NetworkName, "ReadonlyRootfs": true,
			"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"}, "Tmpfs": map[string]string{"/tmp": tempTmpfs},
			"ExtraHosts": []string{"agent:" + relay.AgentIP}, "Dns": []string{"127.0.0.1"},
			"LogConfig": map[string]any{"Type": dockerLogDriver, "Config": map[string]string{
				"max-size": dockerLogMaxSize, "max-file": dockerLogMaxFiles, "compress": dockerLogCompress}},
		}),
		"Mounts": []map[string]any{{"Type": "bind", "Source": relay.GrantDir, "Destination": "/run/steward-grant", "RW": true}},
		"NetworkSettings": map[string]any{"Networks": map[string]any{
			relay.NetworkName: map[string]any{
				"IPAddress": relay.RelayIP, "IPAMConfig": map[string]string{"IPv4Address": relay.RelayIP},
			},
		}},
		"State": map[string]string{"Status": "running"},
	}
}

func TestInspectRelayUsesConfiguredStaticIPBeforeFirstStart(t *testing.T) {
	network := testNetworkSpec("tenant-a", "agent-a", 9)
	relay := RelaySpec{
		Name: RelayName("tenant-a", "agent-a", 9), Image: "sha256:" + strings.Repeat("a", 64),
		NetworkName: network.Name, GrantID: "grant-" + strings.Repeat("b", 64),
		GrantDir: "/run/steward-gateway/grants/" + strings.Repeat("b", 32), TenantID: "tenant-a", InstanceID: "agent-a", Generation: 9,
		RelayGID: 1234, Inference: true, Connector: true, ServicePort: 8080, RelayIP: network.RelayIP, AgentIP: network.AgentIP,
		MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32,
	}
	payload := hardenedRelayInspectPayload(relay)
	endpoint := payload["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)[relay.NetworkName].(map[string]any)
	endpoint["IPAddress"] = ""
	payload["State"] = map[string]string{"Status": "created"}
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	})
	observed, err := docker.InspectRelay(context.Background(), relay.Name)
	if err != nil || !observed.Hardened || observed.Spec != relay || observed.IPAddress != "" {
		t.Fatalf("created relay=%#v err=%v", observed, err)
	}
}

func TestInspectNetworkRejectsInternalBridgeWithoutIsolatedGatewayMode(t *testing.T) {
	network := testNetworkSpec("tenant-a", "agent-a", 7)
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Name": network.Name, "Driver": "bridge", "Internal": true, "Attachable": false,
			"Options": map[string]string{isolatedGatewayOption: "nat"},
			"Labels": map[string]string{managedNetworkLabel: "true", "io.hardrails.tenant": network.TenantID,
				"io.hardrails.instance": network.InstanceID, networkGenerationLabel: "7"},
			"IPAM": map[string]any{"Config": []map[string]string{{"Subnet": network.Subnet, "Gateway": network.Gateway}}},
		})
	})
	observed, err := docker.InspectNetwork(context.Background(), network.Name)
	if err != nil {
		t.Fatal(err)
	}
	if observed.Internal {
		t.Fatalf("host-reachable internal bridge accepted: %#v", observed)
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

func TestInspectImageProjectsExactConfigPlatformAndVolumes(t *testing.T) {
	configDigest := "sha256:" + strings.Repeat("b", 64)
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, "/v1.41/images/") {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.String())
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id": "sha256:" + strings.Repeat("b", 64), "Os": "linux", "Architecture": "arm64", "Variant": "v8",
			"Config": map[string]any{"Volumes": map[string]any{"/z": map[string]any{}, "/a": map[string]any{}}},
		})
	})
	observed, err := docker.InspectImage(context.Background(), configDigest)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ID != configDigest || observed.ConfigDigest != configDigest || observed.Identity != imageIdentityConfig ||
		observed.ManifestDigest != "" || observed.OS != "linux" || observed.Architecture != "arm64" ||
		observed.Variant != "v8" || !observed.ConfigPresent || !reflect.DeepEqual(observed.DeclaredVolumes, []string{"/a", "/z"}) {
		t.Fatalf("observed=%#v", observed)
	}
}

func TestInspectSignedImageUsesClassicConfigIdentityWithoutManifestFallback(t *testing.T) {
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	requests := 0
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1.41/images/"+configDigest+"/json" {
			t.Fatalf("unexpected classic lookup %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Id": configDigest, "Os": "linux", "Architecture": "amd64", "Config": map[string]any{},
		})
	})
	observed, err := docker.InspectSignedImage(context.Background(), "registry.local/agent@"+manifestDigest, configDigest)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 1 || observed.Identity != imageIdentityConfig || observed.ID != configDigest ||
		observed.ConfigDigest != configDigest || observed.ManifestDigest != "" {
		t.Fatalf("requests=%d observed=%#v", requests, observed)
	}
	if err := ValidateImage(observed, ImageRequirement{
		ManifestDigest: manifestDigest, ConfigDigest: configDigest, OS: "linux", Architecture: "amd64",
	}); err != nil {
		t.Fatalf("classic signed identity rejected: %v", err)
	}
}

func TestInspectSignedImageFallsBackToContainerdManifestIdentity(t *testing.T) {
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	var paths []string
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/v1.41/images/" + configDigest + "/json":
			w.WriteHeader(http.StatusNotFound)
		case "/v1.48/images/" + manifestDigest + "/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": manifestDigest, "Os": "linux", "Architecture": "amd64", "Config": map[string]any{},
				"Descriptor": map[string]any{
					"digest": manifestDigest, "annotations": map[string]string{"config.digest": configDigest},
				},
			})
		default:
			t.Fatalf("unexpected containerd lookup %s", r.URL.Path)
		}
	})
	observed, err := docker.InspectSignedImage(context.Background(), "registry.local/agent@"+manifestDigest, configDigest)
	if err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{"/v1.41/images/" + configDigest + "/json", "/v1.48/images/" + manifestDigest + "/json"}
	if !reflect.DeepEqual(paths, wantPaths) || observed.Identity != imageIdentityManifest || observed.ID != manifestDigest ||
		observed.ManifestDigest != manifestDigest || observed.ConfigDigest != configDigest {
		t.Fatalf("paths=%#v observed=%#v", paths, observed)
	}
	if err := ValidateImage(observed, ImageRequirement{
		ManifestDigest: manifestDigest, ConfigDigest: configDigest, OS: "linux", Architecture: "amd64",
	}); err != nil {
		t.Fatalf("containerd signed identity rejected: %v", err)
	}
}

func TestInspectSignedImageUsesSignedConfigWhenContainerdOmitsAnnotation(t *testing.T) {
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.41/images/" + configDigest + "/json":
			w.WriteHeader(http.StatusNotFound)
		case "/v1.48/images/" + manifestDigest + "/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": manifestDigest, "Os": "linux", "Architecture": "amd64", "Config": map[string]any{},
				"Descriptor": map[string]any{"digest": manifestDigest},
			})
		default:
			t.Fatalf("unexpected containerd lookup %s", r.URL.Path)
		}
	})

	observed, err := docker.InspectSignedImage(context.Background(), "registry.local/agent@"+manifestDigest, configDigest)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ConfigDigest != configDigest {
		t.Fatalf("config digest=%q want signed %q", observed.ConfigDigest, configDigest)
	}
	if err := ValidateImage(observed, ImageRequirement{
		ManifestDigest: manifestDigest, ConfigDigest: configDigest, OS: "linux", Architecture: "amd64",
	}); err != nil {
		t.Fatalf("containerd image without optional annotation rejected: %v", err)
	}
}

func TestInspectSignedImageDoesNotReplaceConflictingContainerdConfigAnnotation(t *testing.T) {
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	conflictingDigest := "sha256:" + strings.Repeat("c", 64)
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1.41/images/" + configDigest + "/json":
			w.WriteHeader(http.StatusNotFound)
		case "/v1.48/images/" + manifestDigest + "/json":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"Id": manifestDigest, "Os": "linux", "Architecture": "amd64", "Config": map[string]any{},
				"Descriptor": map[string]any{
					"digest": manifestDigest, "annotations": map[string]string{"config.digest": conflictingDigest},
				},
			})
		default:
			t.Fatalf("unexpected containerd lookup %s", r.URL.Path)
		}
	})

	observed, err := docker.InspectSignedImage(context.Background(), "registry.local/agent@"+manifestDigest, configDigest)
	if err != nil {
		t.Fatal(err)
	}
	if observed.ConfigDigest != conflictingDigest {
		t.Fatalf("config digest=%q want observed conflict %q", observed.ConfigDigest, conflictingDigest)
	}
	if err := ValidateImage(observed, ImageRequirement{
		ManifestDigest: manifestDigest, ConfigDigest: configDigest, OS: "linux", Architecture: "amd64",
	}); err == nil {
		t.Fatal("conflicting config annotation accepted")
	}
}

func TestInspectSignedImageDoesNotInferConfigBeforeExactManifestMatch(t *testing.T) {
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	otherDigest := "sha256:" + strings.Repeat("c", 64)
	tests := []struct {
		name             string
		id               string
		descriptorDigest string
	}{
		{name: "image id mismatch", id: otherDigest, descriptorDigest: manifestDigest},
		{name: "descriptor mismatch", id: manifestDigest, descriptorDigest: otherDigest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1.41/images/" + configDigest + "/json":
					w.WriteHeader(http.StatusNotFound)
				case "/v1.48/images/" + manifestDigest + "/json":
					_ = json.NewEncoder(w).Encode(map[string]any{
						"Id": tt.id, "Os": "linux", "Architecture": "amd64", "Config": map[string]any{},
						"Descriptor": map[string]any{"digest": tt.descriptorDigest},
					})
				default:
					t.Fatalf("unexpected containerd lookup %s", r.URL.Path)
				}
			})

			observed, err := docker.InspectSignedImage(context.Background(), "registry.local/agent@"+manifestDigest, configDigest)
			if err != nil {
				t.Fatal(err)
			}
			if observed.ConfigDigest != "" {
				t.Fatalf("config digest inferred before exact manifest match: %q", observed.ConfigDigest)
			}
			if err := ValidateImage(observed, ImageRequirement{
				ManifestDigest: manifestDigest, ConfigDigest: configDigest, OS: "linux", Architecture: "amd64",
			}); err == nil {
				t.Fatal("mismatched manifest identity accepted")
			}
		})
	}
}

func TestInspectSignedImageDoesNotHideConfigLookupFailure(t *testing.T) {
	requests := 0
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"message":"store unavailable"}`))
	})
	_, err := docker.InspectSignedImage(context.Background(),
		"registry.local/agent@sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("b", 64))
	if err == nil || requests != 1 {
		t.Fatalf("err=%v requests=%d", err, requests)
	}
}

func TestInspectRejectsClosedEnvelopeDrift(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"anonymous volume", func(p map[string]any) {
			p["Mounts"] = []map[string]any{{"Type": "volume", "Name": "anonymous", "Destination": "/data", "RW": true}}
		}},
		{"extra network", func(p map[string]any) {
			p["NetworkSettings"].(map[string]any)["Networks"].(map[string]any)["hostile"] = map[string]string{"IPAddress": "10.0.0.2"}
		}},
		{"privileged", func(p map[string]any) { p["HostConfig"].(map[string]any)["Privileged"] = true }},
		{"device", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["Devices"] = []map[string]string{{"PathOnHost": "/dev/kvm"}}
		}},
		{"port binding", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["PortBindings"] = map[string]any{"8080/tcp": []map[string]string{{"HostPort": "8080"}}}
		}},
		{"unsafe logs", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["LogConfig"] = map[string]any{"Type": "json-file", "Config": map[string]string{}}
		}},
		{"swap growth", func(p map[string]any) { p["HostConfig"].(map[string]any)["MemorySwap"] = 2 << 20 }},
		{"host PID namespace", func(p map[string]any) { p["HostConfig"].(map[string]any)["PidMode"] = "host" }},
		{"shared IPC namespace", func(p map[string]any) { p["HostConfig"].(map[string]any)["IpcMode"] = "container:peer" }},
		{"host UTS namespace", func(p map[string]any) { p["HostConfig"].(map[string]any)["UTSMode"] = "host" }},
		{"host cgroup namespace", func(p map[string]any) { p["HostConfig"].(map[string]any)["CgroupnsMode"] = "host" }},
		{"host user namespace", func(p map[string]any) { p["HostConfig"].(map[string]any)["UsernsMode"] = "host" }},
		{"shared container cgroup", func(p map[string]any) { p["HostConfig"].(map[string]any)["Cgroup"] = "container:peer" }},
		{"restart policy", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["RestartPolicy"] = map[string]any{"Name": "unless-stopped", "MaximumRetryCount": 0}
		}},
		{"automatic removal", func(p map[string]any) { p["HostConfig"].(map[string]any)["AutoRemove"] = true }},
		{"OOM killer disabled", func(p map[string]any) { p["HostConfig"].(map[string]any)["OomKillDisable"] = true }},
		{"protected from host OOM", func(p map[string]any) { p["HostConfig"].(map[string]any)["OomScoreAdj"] = -1000 }},
		{"custom cgroup parent", func(p map[string]any) { p["HostConfig"].(map[string]any)["CgroupParent"] = "/system.slice" }},
		{"device cgroup rule", func(p map[string]any) { p["HostConfig"].(map[string]any)["DeviceCgroupRules"] = []string{"c 1:3 rwm"} }},
		{"volumes from peer", func(p map[string]any) { p["HostConfig"].(map[string]any)["VolumesFrom"] = []string{"peer"} }},
		{"supplemental host group", func(p map[string]any) { p["HostConfig"].(map[string]any)["GroupAdd"] = []string{"docker"} }},
		{"legacy container link", func(p map[string]any) { p["HostConfig"].(map[string]any)["Links"] = []string{"/peer:/agent/peer"} }},
		{"namespaced sysctl", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["Sysctls"] = map[string]string{"net.ipv4.ip_unprivileged_port_start": "0"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := hardenedWorkloadInspectPayload()
			test.mutate(payload)
			docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(payload)
			})
			observed, err := docker.Inspect(context.Background(), "executor-agent")
			if err != nil {
				t.Fatal(err)
			}
			if observed.Hardened {
				t.Fatalf("%s drift was accepted", test.name)
			}
		})
	}
}

func hardenedWorkloadInspectPayload() map[string]any {
	return map[string]any{
		"Image": "sha256:" + strings.Repeat("b", 64),
		"Config": map[string]any{
			"Image": "registry.local/agent@sha256:" + strings.Repeat("a", 64), "Cmd": []string{"agent"},
			"User": "65532:65532", "Env": []string{"HOME=/workspace", "TMPDIR=/tmp"}, "WorkingDir": "/workspace",
			"Labels": map[string]string{
				managedWorkloadLabel: "true", workloadFingerprintLabel: strings.Repeat("c", 64),
				"io.hardrails.tenant": "tenant-a", "io.hardrails.instance": "agent", "io.hardrails.profile": "generic-v1@v1",
				workloadMemoryLabel: "1048576", workloadCPULabel: "100", workloadPIDsLabel: "16",
			},
		},
		"HostConfig": enforceClosedDockerHostPolicy(map[string]any{
			"Memory": 1048576, "MemorySwap": 1048576, "NanoCpus": 100000000, "PidsLimit": 16,
			"Runtime": "runsc", "NetworkMode": "none", "ReadonlyRootfs": true,
			"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"},
			"Tmpfs": map[string]string{"/tmp": tempTmpfs, "/workspace": workspaceTmpfs},
			"LogConfig": map[string]any{"Type": dockerLogDriver, "Config": map[string]string{
				"max-size": dockerLogMaxSize, "max-file": dockerLogMaxFiles, "compress": dockerLogCompress}},
		}),
		"Mounts":          []map[string]any{},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"none": map[string]string{"IPAddress": ""}}},
		"State":           map[string]string{"Status": "created"},
	}
}

func TestInspectReconstructsSignedImageIdentityAndRequiresExactConfigID(t *testing.T) {
	reference := "registry.local/agent@sha256:" + strings.Repeat("a", 64)
	configID := "sha256:" + strings.Repeat("b", 64)
	payload := hardenedWorkloadInspectPayload()
	payload["Image"] = configID
	config := payload["Config"].(map[string]any)
	config["Image"] = configID
	labels := config["Labels"].(map[string]string)
	labels[workloadImageReferenceLabel] = reference
	labels[workloadImageConfigLabel] = configID
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	})
	observed, err := docker.Inspect(context.Background(), "executor-image")
	if err != nil || !observed.Hardened {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	if observed.Workload.Image != reference || observed.Workload.ImageConfigDigest != configID || observed.ImageID != configID {
		t.Fatalf("image identity=%#v imageID=%s", observed.Workload, observed.ImageID)
	}

	payload["Image"] = "sha256:" + strings.Repeat("c", 64)
	observed, err = docker.Inspect(context.Background(), "executor-image")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Hardened {
		t.Fatal("container running a different config ID was accepted")
	}
}

func TestInspectReconstructsContainerdRuntimeAndExposesSignedConfigIdentity(t *testing.T) {
	manifestID := "sha256:" + strings.Repeat("a", 64)
	configID := "sha256:" + strings.Repeat("b", 64)
	reference := "registry.local/agent@" + manifestID
	payload := hardenedWorkloadInspectPayload()
	payload["Image"] = manifestID
	config := payload["Config"].(map[string]any)
	config["Image"] = manifestID
	labels := config["Labels"].(map[string]string)
	labels[workloadImageReferenceLabel] = reference
	labels[workloadImageConfigLabel] = configID
	labels[workloadImageRuntimeLabel] = manifestID
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(payload)
	})
	observed, err := docker.Inspect(context.Background(), "executor-image")
	if err != nil || !observed.Hardened {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	if observed.ImageID != configID || observed.RuntimeImageID != manifestID || observed.Workload.ImageConfigDigest != configID ||
		observed.Workload.ImageRuntimeDigest != manifestID || observed.Workload.Image != reference {
		t.Fatalf("image identity=%#v imageID=%s", observed.Workload, observed.ImageID)
	}

	payload["Image"] = configID
	observed, err = docker.Inspect(context.Background(), "executor-image")
	if err != nil {
		t.Fatal(err)
	}
	if observed.Hardened {
		t.Fatal("container running a different runtime digest was accepted")
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
			"HostConfig": enforceClosedDockerHostPolicy(map[string]any{
				"Memory": 1048576, "MemorySwap": 1048576, "NanoCpus": 250000000, "PidsLimit": 32,
				"Runtime": "runsc", "NetworkMode": "none", "ReadonlyRootfs": true,
				"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"},
				"Tmpfs": map[string]string{"/tmp": tempTmpfs, "/workspace": workspaceTmpfs},
				"LogConfig": map[string]any{"Type": dockerLogDriver, "Config": map[string]string{
					"max-size": dockerLogMaxSize, "max-file": dockerLogMaxFiles, "compress": dockerLogCompress}},
			}),
			"NetworkSettings": map[string]any{"Networks": map[string]any{"none": map[string]string{"IPAddress": ""}}},
			"State":           map[string]any{"Status": "running"},
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
	addresses := testNetworkSpec("tenant-a", "agent-1", 3)
	state := &StateMount{VolumeName: StateVolumeName("tenant-a", "lineage-a"), Path: "/home/node/.openclaw"}
	taskAuthorities := []gateway.TaskAuthority{{
		KeyID: "task-approver", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}}
	secondActionKey := make([]byte, ed25519.PublicKeySize)
	secondActionKey[0] = 1
	actionAuthorities := []gateway.GrantActionAuthority{{
		KeyID: "effects-approver-a", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		ConnectorIDs: []string{"git.read", "issues.create"},
	}, {
		KeyID: "effects-approver-b", PublicKey: base64.StdEncoding.EncodeToString(secondActionKey),
		ConnectorIDs: []string{"git.read", "issues.create"},
	}}
	runtime := &RuntimeGrant{
		NetworkName: addresses.Name, GrantID: "grant-" + strings.Repeat("b", 64), NodeID: "node-a", Generation: 3,
		Inference: true, RouteID: "local", ModelAlias: "private-model", ServicePort: 8080, ServiceID: "hermes-api",
		TaskAuthorities: taskAuthorities,
		Subnet:          addresses.Subnet, Gateway: addresses.Gateway,
		RelayIP: addresses.RelayIP, AgentIP: addresses.AgentIP, ConnectorIDs: []string{"git.read", "issues.create"},
		EffectMode: gateway.EffectModeAuthorized, ActionApprovalThreshold: 2, ActionContextRequired: true, ActionAuthorities: actionAuthorities,
		CapsuleDigest: "sha256:" + strings.Repeat("d", 64), PolicyDigest: "sha256:" + strings.Repeat("e", 64),
		ActivationID:          "activation-test",
		ActivationBeginDigest: "sha256:" + strings.Repeat("f", 64),
	}
	workload := Workload{
		InstanceID: "agent-1", TenantID: "tenant-a", ProfileID: "openclaw-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent", "serve"},
		Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 250, PIDs: 32}, State: state, Runtime: runtime,
	}
	fingerprint := workloadFingerprint(workload)
	authorityLabel, err := json.Marshal(dockerTaskAuthorityLabel{Authorities: taskAuthorities})
	if err != nil {
		t.Fatal(err)
	}
	actionAuthorityLabel, err := json.Marshal(dockerActionAuthorityLabel{Authorities: actionAuthorities})
	if err != nil {
		t.Fatal(err)
	}
	docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"Image": "sha256:" + strings.Repeat("c", 64),
			"Config": map[string]any{
				"Image": workload.Image, "Cmd": workload.Command, "User": "65532:65532",
				"Env": []string{
					"HOME=/home/node", "TMPDIR=/tmp", "OPENAI_BASE_URL=http://steward-relay:8080/v1",
					"OPENAI_API_BASE=http://steward-relay:8080/v1", "OPENAI_API_KEY=steward-local", "OPENAI_MODEL=private-model",
					"STEWARD_CONNECTOR_URL=http://steward-relay:8081",
				},
				"WorkingDir": "/home/node/.openclaw/workspace",
				"Labels": map[string]string{
					managedWorkloadLabel: "true", workloadFingerprintLabel: fingerprint,
					"io.hardrails.tenant": "tenant-a", "io.hardrails.instance": "agent-1", "io.hardrails.profile": "openclaw-v1@v1",
					workloadMemoryLabel: "1048576", workloadCPULabel: "250", workloadPIDsLabel: "32",
					stateVolumeLabel: state.VolumeName, statePathLabel: state.Path,
					runtimeNetworkLabel: addresses.Name, runtimeGrantLabel: runtime.GrantID, runtimeGenerationLabel: "3",
					runtimeNodeIDLabel:    "node-a",
					runtimeInferenceLabel: "true", runtimeModelLabel: "private-model", runtimeRouteLabel: "local",
					runtimeServiceIDLabel: "hermes-api", runtimeTaskAuthoritiesLabel: string(authorityLabel),
					runtimeEffectModeLabel: gateway.EffectModeAuthorized, runtimeActionApprovalThresholdLabel: "2",
					runtimeActionContextRequiredLabel: "true",
					runtimeActionAuthoritiesLabel:     string(actionAuthorityLabel),
					runtimeSubnetLabel:                addresses.Subnet, runtimeGatewayLabel: addresses.Gateway,
					runtimeServicePortLabel: "8080", runtimeRelayIPLabel: addresses.RelayIP, runtimeAgentIPLabel: addresses.AgentIP,
					runtimeConnectorsLabel: "git.read,issues.create", runtimeCapsuleDigestLabel: runtime.CapsuleDigest,
					runtimePolicyDigestLabel:          runtime.PolicyDigest,
					runtimeActivationIDLabel:          runtime.ActivationID,
					runtimeActivationBeginDigestLabel: runtime.ActivationBeginDigest,
				},
			},
			"HostConfig": enforceClosedDockerHostPolicy(map[string]any{
				"Memory": 1048576, "MemorySwap": 1048576, "NanoCpus": 250000000, "PidsLimit": 32,
				"Runtime": "runsc", "NetworkMode": addresses.Name, "ReadonlyRootfs": true,
				"CapDrop": []string{"ALL"}, "SecurityOpt": []string{"no-new-privileges:true"},
				"Tmpfs": map[string]string{"/tmp": tempTmpfs}, "ExtraHosts": []string{"steward-relay:" + addresses.RelayIP}, "Dns": []string{"127.0.0.1"},
				"LogConfig": map[string]any{"Type": dockerLogDriver, "Config": map[string]string{
					"max-size": dockerLogMaxSize, "max-file": dockerLogMaxFiles, "compress": dockerLogCompress}},
			}),
			"Mounts": []map[string]any{{"Type": "volume", "Name": state.VolumeName, "Destination": state.Path, "RW": true}},
			"NetworkSettings": map[string]any{"Networks": map[string]any{addresses.Name: map[string]any{
				"IPAddress": addresses.AgentIP, "IPAMConfig": map[string]string{"IPv4Address": addresses.AgentIP},
			}}},
			"State": map[string]string{"Status": "running"},
		})
	})
	observed, err := docker.Inspect(context.Background(), "executor-state-runtime")
	if err != nil || !observed.Hardened || observed.Workload.State == nil || observed.Workload.Runtime == nil {
		t.Fatalf("observed=%#v err=%v", observed, err)
	}
	if *observed.Workload.State != *state || !reflect.DeepEqual(*observed.Workload.Runtime, *runtime) || observed.Fingerprint != fingerprint {
		t.Fatalf("projected workload=%#v", observed.Workload)
	}
}

func TestActionAuthorityDockerLabelSupportsMaximumAdmittedScope(t *testing.T) {
	connectors := make([]string, 32)
	for index := range connectors {
		connectors[index] = fmt.Sprintf("connector-%02d-%s", index, strings.Repeat("x", 115))
	}
	authorities := make([]gateway.GrantActionAuthority, 8)
	for index := range authorities {
		public := make([]byte, ed25519.PublicKeySize)
		public[0] = byte(index + 1)
		authorities[index] = gateway.GrantActionAuthority{
			KeyID:        fmt.Sprintf("effects-%02d", index),
			PublicKey:    base64.StdEncoding.EncodeToString(public),
			ConnectorIDs: append([]string(nil), connectors...),
		}
	}
	raw, err := json.Marshal(dockerActionAuthorityLabel{Authorities: authorities})
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) <= 16<<10 || len(raw) > maxRuntimeActionAuthorityLabelBytes {
		t.Fatalf("maximum admitted authority label has unexpected size %d", len(raw))
	}
	decoded, err := decodeActionAuthorityLabel(string(raw), connectors)
	if err != nil || !reflect.DeepEqual(decoded, authorities) {
		t.Fatalf("decoded=%#v err=%v", decoded, err)
	}
	if _, err := decodeActionAuthorityLabel(strings.Repeat("x", maxRuntimeActionAuthorityLabelBytes+1), connectors); err == nil {
		t.Fatal("oversized action authority label accepted")
	}
}

func TestTaskAuthorityDockerLabelRoundTripsAndRejectsAmbiguity(t *testing.T) {
	want := []gateway.TaskAuthority{{
		KeyID: "task-approver", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	}}
	raw, err := json.Marshal(dockerTaskAuthorityLabel{Authorities: want})
	if err != nil {
		t.Fatal(err)
	}
	got, err := decodeTaskAuthorityLabel(string(raw))
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("decoded=%#v err=%v", got, err)
	}
	if got, err := decodeTaskAuthorityLabel(""); err != nil || got != nil {
		t.Fatalf("empty decoded=%#v err=%v", got, err)
	}

	secondPublic := append([]byte(nil), make([]byte, 32)...)
	secondPublic[0] = 1
	unsorted, err := json.Marshal(dockerTaskAuthorityLabel{Authorities: []gateway.TaskAuthority{
		{KeyID: "z-key", PublicKey: base64.StdEncoding.EncodeToString(secondPublic)},
		{KeyID: "a-key", PublicKey: want[0].PublicKey},
	}})
	if err != nil {
		t.Fatal(err)
	}
	legacyArray, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]string{
		"legacy array":        string(legacyArray),
		"missing member":      `{}`,
		"null authorities":    `{"authorities":null}`,
		"empty authorities":   `{"authorities":[]}`,
		"unknown member":      `{"authorities":[],"extra":true}`,
		"duplicate member":    `{"authorities":[],"authorities":[]}`,
		"duplicate key field": `{"authorities":[{"key_id":"task-approver","key_id":"other","public_key":"` + want[0].PublicKey + `"}]}`,
		"invalid public key":  `{"authorities":[{"key_id":"task-approver","public_key":"not-base64"}]}`,
		"unsorted keys":       string(unsorted),
		"oversized":           strings.Repeat("x", 16<<10+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeTaskAuthorityLabel(value); err == nil {
				t.Fatal("invalid task authority label accepted")
			}
		})
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
	if hasExactStateMount([]dockerMount{
		{Type: "volume", Name: "x", Destination: "/state", RW: true},
		{Type: "volume", Name: "extra", Destination: "/extra", RW: true},
	}, StateMount{VolumeName: "x", Path: "/state"}) {
		t.Fatal("state mount helper accepted an extra mount")
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

func TestCapacityUsageIncludesStoppedWorkloadsAndRelayReservations(t *testing.T) {
	managedNetwork := "steward-net-" + strings.Repeat("a", 64)
	docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("all") != "true" || !strings.Contains(r.URL.Query().Get("filters"), managedWorkloadLabel) {
			t.Fatalf("query=%s", r.URL.RawQuery)
		}
		_ = json.NewEncoder(w).Encode([]map[string]any{
			{"State": "exited", "Labels": map[string]string{
				managedWorkloadLabel: "true", "io.hardrails.tenant": "tenant-a",
				workloadMemoryLabel: "1048576", workloadCPULabel: "100", workloadPIDsLabel: "16",
				runtimeNetworkLabel: managedNetwork,
			}},
			{"State": "running", "Labels": map[string]string{
				managedWorkloadLabel: "true", "io.hardrails.tenant": "tenant-b",
				workloadMemoryLabel: "2097152", workloadCPULabel: "200", workloadPIDsLabel: "32",
			}},
		})
	})
	usage, err := docker.CapacityUsage(context.Background(), "tenant-a")
	if err != nil {
		t.Fatal(err)
	}
	wantTenant := CapacityReservation{
		Workloads: 1, MemoryBytes: (1 << 20) + defaultRelayMemory,
		CPUMillis: 100 + defaultRelayCPU, PIDs: 16 + defaultRelayPIDs,
	}
	wantHost := wantTenant
	wantHost.Workloads++
	wantHost.MemoryBytes += 2 << 20
	wantHost.CPUMillis += 200
	wantHost.PIDs += 32
	if usage.Host != wantHost || usage.Tenant != wantTenant {
		t.Fatalf("usage=%#v want host=%#v tenant=%#v", usage, wantHost, wantTenant)
	}
}

func TestCapacityUsageRejectsMalformedAndOverflowingLabels(t *testing.T) {
	valid := map[string]string{
		managedWorkloadLabel: "true", "io.hardrails.tenant": "tenant-a",
		workloadMemoryLabel: "1", workloadCPULabel: "1", workloadPIDsLabel: "1",
	}
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"missing tenant", func(labels map[string]string) { delete(labels, "io.hardrails.tenant") }},
		{"missing resource", func(labels map[string]string) { delete(labels, workloadMemoryLabel) }},
		{"negative resource", func(labels map[string]string) { labels[workloadPIDsLabel] = "-1" }},
		{"partial runtime", func(labels map[string]string) { labels[runtimeGrantLabel] = "grant" }},
		{"overflow relay", func(labels map[string]string) {
			labels[workloadMemoryLabel] = strconv.FormatInt(math.MaxInt64, 10)
			labels[runtimeNetworkLabel] = "steward-net-" + strings.Repeat("a", 64)
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			labels := maps.Clone(valid)
			test.mutate(labels)
			docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode([]map[string]any{{"Labels": labels}})
			})
			if _, err := docker.CapacityUsage(context.Background(), "tenant-a"); err == nil {
				t.Fatal("invalid capacity labels accepted")
			}
		})
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

func TestEgressRouteLabelValidationRejectsNoncanonicalSets(t *testing.T) {
	tooMany := make([]string, 33)
	for index := range tooMany {
		tooMany[index] = fmt.Sprintf("route-%02d", index)
	}
	if validEgressRouteIDs(tooMany) {
		t.Fatal("more than 32 egress routes accepted")
	}
	for _, routes := range [][]string{{"bad route"}, {"route-b", "route-a"}, {"route-a", "route-a"}} {
		if validEgressRouteIDs(routes) {
			t.Fatalf("noncanonical route set accepted: %#v", routes)
		}
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
	if !strings.Contains(calls[2], "force=true") || !strings.Contains(calls[2], "v=true") {
		t.Fatalf("remove did not clean anonymous volumes: %q", calls[2])
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
