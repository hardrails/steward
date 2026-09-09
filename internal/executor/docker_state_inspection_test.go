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
