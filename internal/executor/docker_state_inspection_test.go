package executor

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestInspectStateUsesOpaqueBackendHandleAndExactMount(t *testing.T) {
	for _, handle := range []string{
		"steward-state-" + strings.Repeat("a", 64),
		"steward-zfs-" + strings.Repeat("b", 64),
		"qualified_backend.volume-3",
	} {
		t.Run(handle, func(t *testing.T) {
			payload := stateInspectPayload(handle)
			docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(payload)
			})
			observed, err := docker.Inspect(context.Background(), "executor-state")
			if err != nil || !observed.Hardened || observed.Workload.State == nil || observed.Workload.State.VolumeName != handle {
				t.Fatalf("exact backend mount not retained: observed=%#v error=%v", observed, err)
			}
		})
	}
}

func TestInspectStateRejectsUnboundOrUnsafeMounts(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"substituted handle", func(p map[string]any) { p["Mounts"].([]map[string]any)[0]["Name"] = "another-volume" }},
		{"wrong path", func(p map[string]any) { p["Mounts"].([]map[string]any)[0]["Destination"] = "/other" }},
		{"bind mount", func(p map[string]any) { p["Mounts"].([]map[string]any)[0]["Type"] = "bind" }},
		{"read only", func(p map[string]any) { p["Mounts"].([]map[string]any)[0]["RW"] = false }},
		{"missing mount", func(p map[string]any) { p["Mounts"] = []map[string]any{} }},
		{"extra mount", func(p map[string]any) {
			p["Mounts"] = append(p["Mounts"].([]map[string]any), map[string]any{"Type": "bind", "Destination": "/extra"})
		}},
		{"invalid opaque handle", func(p map[string]any) {
			p["Config"].(map[string]any)["Labels"].(map[string]string)[stateVolumeLabel] = "../../host"
			p["Mounts"].([]map[string]any)[0]["Name"] = "../../host"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := stateInspectPayload("steward-zfs-" + strings.Repeat("b", 64))
			test.mutate(payload)
			docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
				_ = json.NewEncoder(w).Encode(payload)
			})
			observed, err := docker.Inspect(context.Background(), "executor-state")
			if err != nil || observed.Hardened {
				t.Fatalf("unsafe mount must fail closed: hardened=%t error=%v", observed.Hardened, err)
			}
		})
	}
}

func stateInspectPayload(handle string) map[string]any {
	payload := hardenedWorkloadInspectPayload()
	config := payload["Config"].(map[string]any)
	labels := config["Labels"].(map[string]string)
	layout := profileLayoutFor(labels["io.hardrails.profile"])
	labels[stateVolumeLabel], labels[statePathLabel] = handle, layout.StatePath
	config["WorkingDir"] = layout.WorkDir
	config["Env"] = []string{"HOME=" + layout.Home, "TMPDIR=/tmp"}
	payload["HostConfig"].(map[string]any)["Tmpfs"] = map[string]string{"/tmp": tempTmpfs}
	payload["Mounts"] = []map[string]any{{"Type": "volume", "Name": handle, "Destination": layout.StatePath, "RW": true}}
	return payload
}

func TestQualifiedStateCopyPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
		valid  bool
	}{
		{"exact no-copy mount", func(map[string]any) {}, true},
		{"missing host mount", func(p map[string]any) { p["HostConfig"].(map[string]any)["Mounts"] = nil }, false},
		{"copy enabled", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["Mounts"].([]map[string]any)[0]["VolumeOptions"] = map[string]any{"NoCopy": false}
		}, false},
		{"wrong source", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["Mounts"].([]map[string]any)[0]["Source"] = "other-volume"
		}, false},
		{"wrong target", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["Mounts"].([]map[string]any)[0]["Target"] = "/other"
		}, false},
		{"bind type", func(p map[string]any) {
			p["HostConfig"].(map[string]any)["Mounts"].([]map[string]any)[0]["Type"] = "bind"
		}, false},
		{"missing label", func(p map[string]any) {
			delete(p["Config"].(map[string]any)["Labels"].(map[string]string), stateNoCopyLabel)
		}, false},
		{"invalid label", func(p map[string]any) {
			p["Config"].(map[string]any)["Labels"].(map[string]string)[stateNoCopyLabel] = "yes"
		}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := stateInspectPayload("qualified-volume")
			labels := payload["Config"].(map[string]any)["Labels"].(map[string]string)
			labels[stateNoCopyLabel] = "true"
			payload["HostConfig"].(map[string]any)["Mounts"] = []map[string]any{{"Type": "volume", "Source": labels[stateVolumeLabel], "Target": labels[statePathLabel], "VolumeOptions": map[string]any{"NoCopy": true}}}
			test.mutate(payload)
			docker := dockerTestClient(t, func(w http.ResponseWriter, _ *http.Request) { _ = json.NewEncoder(w).Encode(payload) })
			observed, err := docker.Inspect(context.Background(), "executor-state")
			if err != nil || observed.Hardened != test.valid {
				t.Fatalf("hardened=%t want %t, error=%v", observed.Hardened, test.valid, err)
			}
		})
	}
}

func TestStateCopyPolicyPreservesRetainedWorkloadIdentity(t *testing.T) {
	w := Workload{State: &StateMount{VolumeName: "qualified-volume", Path: "/state"}}
	before := workloadFingerprint(w)
	w.State.NoCopy = true
	if workloadFingerprint(w) != before {
		t.Fatal("creation policy invalidated an existing retained workload fingerprint")
	}
}

func TestCreateStateCopyPolicy(t *testing.T) {
	for _, noCopy := range []bool{false, true} {
		docker := dockerTestClient(t, func(w http.ResponseWriter, r *http.Request) {
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			mount := payload["HostConfig"].(map[string]any)["Mounts"].([]any)[0].(map[string]any)
			options, exists := mount["VolumeOptions"].(map[string]any)
			if exists != noCopy || (noCopy && options["NoCopy"] != true) {
				t.Fatalf("copy policy=%#v want no-copy=%t", mount, noCopy)
			}
			label := payload["Labels"].(map[string]any)[stateNoCopyLabel]
			if (noCopy && label != "true") || (!noCopy && label != nil) {
				t.Fatalf("copy policy label=%v", label)
			}
			w.WriteHeader(http.StatusCreated)
		})
		w := Workload{TenantID: "tenant-a", InstanceID: "agent-a", ProfileID: "generic-v1@v1", Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), Command: []string{"agent"}, Resources: Resources{MemoryBytes: 1 << 20, CPUMillis: 100, PIDs: 16}, State: &StateMount{VolumeName: "qualified-volume", Path: "/state", NoCopy: noCopy}}
		if err := docker.Create(context.Background(), "executor-state", w); err != nil {
			t.Fatal(err)
		}
	}
}
