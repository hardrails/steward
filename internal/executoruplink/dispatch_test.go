package executoruplink

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/admission"
)

func TestDispatcherOverridesTenantAndInstanceAndFencesReplay(t *testing.T) {
	var provisions int
	var workload map[string]any
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer local-token" {
			t.Fatal("missing local executor authentication")
		}
		provisions++
		if err := json.NewDecoder(r.Body).Decode(&workload); err != nil {
			t.Fatal(err)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"runtime_ref":"executor-x","status":"created"}`))
	})
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	d := dispatcher{handler: handler, token: "local-token", tenantID: "tenant-a", nodeID: "node-1", state: store}
	cmd := command{
		CommandID: "c1", TenantID: "tenant-a", NodeID: "node-1",
		RuntimeRef: "uplink:6:node-1:agent-1", Kind: "provision",
		Payload:         json.RawMessage(`{"profile_id":"hermes-v1","image":"registry/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resources":{"memory_bytes":1048576,"cpu_millis":100,"pids":32},"egress":{}}`),
		ClaimGeneration: 1, InstanceGeneration: 2, CommandSequence: 7,
	}
	rep := d.execute(context.Background(), cmd)
	if rep.Status != "done" || rep.ReportedStatus != "stopped" {
		t.Fatalf("report = %#v", rep)
	}
	if workload["tenant_id"] != "tenant-a" || workload["instance_id"] != "agent-1" {
		t.Fatalf("workload identity = %#v", workload)
	}
	replay := d.execute(context.Background(), cmd)
	if replay.Status != "done" || replay.Result["replayed"] != true || provisions != 1 {
		t.Fatalf("replay=%#v provisions=%d", replay, provisions)
	}
}

func TestDispatcherRejectsCrossTenantAndUnknownPayloadFields(t *testing.T) {
	mutations := 0
	handler := http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mutations++ })
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	d := dispatcher{handler: handler, token: "token", tenantID: "tenant-a", nodeID: "node-1", state: store}
	base := command{
		CommandID: "c1", TenantID: "tenant-b", NodeID: "node-1",
		RuntimeRef: "uplink:6:node-1:agent-1", Kind: "provision", Payload: json.RawMessage(`{}`),
		ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
	}
	if rep := d.execute(context.Background(), base); rep.Status != "failed" {
		t.Fatalf("cross-tenant report = %#v", rep)
	}
	base.TenantID = "tenant-a"
	base.Payload = json.RawMessage(`{"profile_id":"p","image":"x@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","resources":{"memory_bytes":1,"cpu_millis":1,"pids":1},"egress":{},"privileged":true}`)
	if rep := d.execute(context.Background(), base); rep.Status != "failed" {
		t.Fatalf("unknown-field report = %#v", rep)
	}
	if mutations != 0 {
		t.Fatalf("rejected commands mutated executor %d times", mutations)
	}
}

func TestDispatcherRoutesOnlyIdentityBoundSignedAdmission(t *testing.T) {
	var path string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]string{"runtime_ref": "executor-x", "status": "created"})
	})
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	d := dispatcher{handler: handler, token: "token", tenantID: "tenant-a", nodeID: "node-1", state: store}
	payload := admissionPayload{
		CapsuleDSSEBase64: "opaque",
		Intent: admission.InstanceIntent{
			TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1", LineageID: "lineage-1",
			Generation: 2, CapsuleDigest: "sha256:" + strings.Repeat("a", 64),
			Resources: admission.ResourceLimits{MemoryBytes: 1, CPUMillis: 1, PIDs: 1}, StateDisposition: "none",
		},
	}
	raw, _ := json.Marshal(payload)
	cmd := command{
		CommandID: "signed-1", TenantID: "tenant-a", NodeID: "node-1",
		RuntimeRef: "uplink:6:node-1:agent-1", Kind: "admit", Payload: raw,
		ClaimGeneration: 1, InstanceGeneration: 2, CommandSequence: 1,
	}
	if report := d.execute(context.Background(), cmd); report.Status != "done" || path != "/v1/admissions" {
		t.Fatalf("report=%#v path=%q", report, path)
	}
	store = newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	d.state = store
	payload.Intent.TenantID = "tenant-b"
	cmd.Payload, _ = json.Marshal(payload)
	path = ""
	if report := d.execute(context.Background(), cmd); report.Status != "failed" || path != "" {
		t.Fatalf("mismatched identity report=%#v path=%q", report, path)
	}
}

func TestDispatcherAppliesLifecycleCommandsAndRejectsHibernate(t *testing.T) {
	var paths []string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.Method == http.MethodDelete {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		status := "running"
		if strings.HasSuffix(r.URL.Path, "/stop") {
			status = "created"
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"runtime_ref": "executor-x", "status": status})
	})
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	d := dispatcher{handler: handler, token: "token", tenantID: "tenant-a", nodeID: "node-1", state: store}
	base := command{
		TenantID: "tenant-a", NodeID: "node-1", RuntimeRef: "uplink:6:node-1:agent-1",
		ClaimGeneration: 1, InstanceGeneration: 1,
	}
	for index, kind := range []string{"start", "stop", "destroy"} {
		cmd := base
		cmd.CommandID, cmd.Kind, cmd.CommandSequence = kind, kind, uint64(index+1)
		if rep := d.execute(context.Background(), cmd); rep.Status != "done" {
			t.Fatalf("%s report=%#v", kind, rep)
		} else if kind == "destroy" && rep.Result["absent"] != true {
			t.Fatalf("destroy did not report absence: %#v", rep)
		}
	}
	destroyReplay := base
	destroyReplay.CommandID, destroyReplay.Kind, destroyReplay.CommandSequence = "destroy", "destroy", 3
	if rep := d.execute(context.Background(), destroyReplay); rep.Result["absent"] != true || rep.Result["replayed"] != true {
		t.Fatalf("destroy replay lost absence evidence: %#v", rep)
	}
	hibernate := base
	hibernate.CommandID, hibernate.Kind, hibernate.CommandSequence = "hibernate", "hibernate", 4
	if rep := d.execute(context.Background(), hibernate); rep.Status != "failed" {
		t.Fatalf("hibernate report=%#v", rep)
	}
	if len(paths) != 3 {
		t.Fatalf("paths=%#v", paths)
	}
}

func TestLocalDockerStatesMapToControlPlaneLifecycleStates(t *testing.T) {
	want := map[string]string{
		"restarting": "provisioning", "removing": "stopping",
		"paused": "hibernated", "dead": "failed",
	}
	for dockerStatus, reported := range want {
		t.Run(dockerStatus, func(t *testing.T) {
			handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{
					"runtime_ref": "executor-x", "status": dockerStatus,
				})
			})
			d := dispatcher{handler: handler, token: "token"}
			got, err := d.call(context.Background(), http.MethodPost, "/v1/workloads/executor-x/start", nil)
			if err != nil || got != reported {
				t.Fatalf("reported=%q err=%v, want %q", got, err, reported)
			}
		})
	}
}

func TestNodeScopedDispatcherSupportsReadAndReceiptedPurge(t *testing.T) {
	var paths []string
	var purge map[string]any
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.Method+" "+r.URL.Path)
		if r.URL.Path == "/v1/state/purge" {
			if err := json.NewDecoder(r.Body).Decode(&purge); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"runtime_ref": "executor-x", "status": "running"})
	})
	store := newStateStore(t, filepath.Join(t.TempDir(), "state.json"))
	if err := store.advance("tenant-a", "agent-1", position{
		ClaimGeneration: 1, Generation: 4, Sequence: 1, ReportedStatus: "running",
	}); err != nil {
		t.Fatal(err)
	}
	d := dispatcher{handler: handler, token: "token", nodeID: "node-1", nodeScoped: true, state: store}
	ref, err := RuntimeRefV2("tenant-a", "node-1", "agent-1")
	if err != nil {
		t.Fatal(err)
	}
	base := command{
		TenantID: "tenant-a", NodeID: "node-1", InstanceID: "agent-1", RuntimeRef: ref,
		ClaimGeneration: 1, InstanceGeneration: 4, signed: true,
	}
	poison := base
	poison.CommandID, poison.Kind, poison.CommandSequence, poison.Payload = "read-future", "read", 9999, json.RawMessage(`{}`)
	poison.ClaimGeneration, poison.InstanceGeneration = 99, 99
	if rep := d.execute(context.Background(), poison); rep.Status != "failed" || len(paths) != 0 {
		t.Fatalf("future-generation read report=%#v paths=%#v", rep, paths)
	}
	read := base
	read.CommandID, read.Kind, read.CommandSequence, read.Payload = "read", "read", 1000, json.RawMessage(`{}`)
	if rep := d.execute(context.Background(), read); rep.Status != "done" || rep.ReportedStatus != "running" {
		t.Fatalf("read report = %#v", rep)
	}
	purgeCommand := base
	purgeCommand.CommandID, purgeCommand.Kind, purgeCommand.CommandSequence = "purge", "purge", 2
	purgeCommand.Payload = json.RawMessage(`{"lineage_id":"lineage-1"}`)
	if rep := d.execute(context.Background(), purgeCommand); rep.Status != "done" {
		t.Fatalf("purge report = %#v", rep)
	}
	if current, ok := store.position("tenant-a", "agent-1"); !ok || current.Sequence != 2 {
		t.Fatalf("read-only command advanced lifecycle fence: %#v %t", current, ok)
	}
	if len(paths) != 2 || !strings.HasPrefix(paths[0], "GET /v1/workloads/") || paths[1] != "POST /v1/state/purge" {
		t.Fatalf("paths = %#v", paths)
	}
	if purge["tenant_id"] != "tenant-a" || purge["node_id"] != "node-1" || purge["lineage_id"] != "lineage-1" || purge["generation"] != float64(4) {
		t.Fatalf("purge body = %#v", purge)
	}
}

func TestRuntimeRefV2UsesTenantAwareUTF8ByteLengths(t *testing.T) {
	ref, err := RuntimeRefV2("té", "节点", "agent:one")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := parseRuntimeRef(ref)
	if err != nil {
		t.Fatal(err)
	}
	if identity.Version != 2 || identity.TenantID != "té" || identity.NodeID != "节点" || identity.InstanceID != "agent:one" {
		t.Fatalf("identity = %#v, ref=%q", identity, ref)
	}
	// "té" is three UTF-8 bytes. A rune-count prefix of two must not parse.
	tampered := strings.Replace(ref, "uplink:v2:3:", "uplink:v2:2:", 1)
	if _, err := parseRuntimeRef(tampered); err == nil {
		t.Fatal("rune-count-prefixed v2 runtime reference was accepted")
	}
}

func TestNodeScopedDispatcherRejectsTenantRuntimeRefMismatch(t *testing.T) {
	mutations := 0
	d := dispatcher{
		handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) { mutations++ }),
		token:   "token", nodeID: "node-1", nodeScoped: true,
		state: newStateStore(t, filepath.Join(t.TempDir(), "state.json")),
	}
	ref, _ := RuntimeRefV2("tenant-a", "node-1", "agent-1")
	cmd := command{
		CommandID: "cross-tenant", TenantID: "tenant-b", NodeID: "node-1", InstanceID: "agent-1",
		RuntimeRef: ref, Kind: "read", Payload: json.RawMessage(`{}`), signed: true,
		ClaimGeneration: 1, InstanceGeneration: 1, CommandSequence: 1,
	}
	if rep := d.execute(context.Background(), cmd); rep.Status != "failed" || mutations != 0 {
		t.Fatalf("report=%#v mutations=%d", rep, mutations)
	}
}
