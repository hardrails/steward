package controlprotocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestExecutorSchedulingObservationV1ValidatesCanonicalBoundedProfile(t *testing.T) {
	valid := schedulingObservationFixture()
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid scheduling observation: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ExecutorSchedulingObservationV1)
	}{
		{"schema", func(value *ExecutorSchedulingObservationV1) { value.SchemaVersion = "v2" }},
		{"scope", func(value *ExecutorSchedulingObservationV1) { value.CredentialScope = "tenant" }},
		{"os", func(value *ExecutorSchedulingObservationV1) { value.OS = "darwin" }},
		{"isolation", func(value *ExecutorSchedulingObservationV1) { value.Isolation = "runc" }},
		{"nil labels", func(value *ExecutorSchedulingObservationV1) { value.Labels = nil }},
		{"unsorted labels", func(value *ExecutorSchedulingObservationV1) {
			value.Labels = []ExecutorSchedulingLabelV1{{Key: "zone", Value: "b"}, {Key: "region", Value: "a"}}
		}},
		{"duplicate labels", func(value *ExecutorSchedulingObservationV1) {
			value.Labels = []ExecutorSchedulingLabelV1{{Key: "zone", Value: "a"}, {Key: "zone", Value: "b"}}
		}},
		{"nil taints", func(value *ExecutorSchedulingObservationV1) { value.Taints = nil }},
		{"unsorted taints", func(value *ExecutorSchedulingObservationV1) { value.Taints = []string{"z", "a"} }},
		{"unsorted images", func(value *ExecutorSchedulingObservationV1) {
			value.CachedImageConfigDigests = []string{
				"sha256:" + strings.Repeat("b", 64),
				"sha256:" + strings.Repeat("a", 64),
			}
		}},
		{"duplicate images", func(value *ExecutorSchedulingObservationV1) {
			digest := "sha256:" + strings.Repeat("a", 64)
			value.CachedImageConfigDigests = []string{digest, digest}
		}},
		{"invalid image", func(value *ExecutorSchedulingObservationV1) {
			value.CachedImageConfigDigests = []string{"sha256:not-a-digest"}
		}},
		{"too many images", func(value *ExecutorSchedulingObservationV1) {
			value.CachedImageConfigDigests = make([]string, MaxExecutorSchedulingImages+1)
		}},
		{"oversized attribute", func(value *ExecutorSchedulingObservationV1) {
			value.Architecture = strings.Repeat("a", MaxExecutorSchedulingAttribute+1)
		}},
		{"zero host", func(value *ExecutorSchedulingObservationV1) { value.Policy.Host.MemoryBytes = 0 }},
		{"tenant above host", func(value *ExecutorSchedulingObservationV1) {
			value.Policy.Tenant.Workloads = value.Policy.Host.Workloads + 1
		}},
		{"runtime slot", func(value *ExecutorSchedulingObservationV1) { value.Policy.RuntimeOverhead.Workloads = 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := schedulingObservationFixture()
			test.mutate(&candidate)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid scheduling observation was accepted")
			}
		})
	}
}

func TestExecutorSchedulingObservationPreservesReportedEmptyImageInventory(t *testing.T) {
	observation := schedulingObservationFixture()
	observation.CachedImageConfigDigests = []string{}
	raw, err := json.Marshal(observation)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ExecutorSchedulingObservationV1
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CachedImageConfigDigests == nil {
		t.Fatalf("reported empty image inventory was lost: %s", raw)
	}
}

func schedulingObservationFixture() ExecutorSchedulingObservationV1 {
	return ExecutorSchedulingObservationV1{
		SchemaVersion: ExecutorSchedulingSchemaV1,
		NodeID:        "node-1", CredentialScope: "node", OS: "linux", Architecture: "amd64",
		Isolation: ExecutorSchedulingIsolationGVisor,
		Labels:    []ExecutorSchedulingLabelV1{{Key: "region", Value: "west"}},
		Taints:    []string{"dedicated"},
		Policy: ExecutorSchedulingPolicyV1{
			PerWorkload:     ExecutorSchedulingResourcesV1{MemoryBytes: 512 << 20, CPUMillis: 1000, PIDs: 128, Workloads: 1},
			Host:            ExecutorSchedulingResourcesV1{MemoryBytes: 8 << 30, CPUMillis: 8000, PIDs: 2048, Workloads: 32},
			Tenant:          ExecutorSchedulingResourcesV1{MemoryBytes: 2 << 30, CPUMillis: 2000, PIDs: 512, Workloads: 4},
			RuntimeOverhead: ExecutorSchedulingResourcesV1{MemoryBytes: 64 << 20, CPUMillis: 100, PIDs: 32},
		},
	}
}
