package executor

import (
	"strings"
	"testing"
)

func TestValidateImageRequiresExactSafeLocalImage(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	expected := ImageRequirement{ConfigDigest: digest, OS: "linux", Architecture: "arm64", Variant: "v8"}
	valid := ObservedImage{ID: digest, OS: "linux", Architecture: "arm64", Variant: "v8", ConfigPresent: true}
	if err := ValidateImage(valid, expected); err != nil {
		t.Fatalf("valid image rejected: %v", err)
	}
	tests := []struct {
		name     string
		observed ObservedImage
		expected ImageRequirement
	}{
		{"declared volume", ObservedImage{ID: digest, OS: "linux", Architecture: "arm64", Variant: "v8", ConfigPresent: true, DeclaredVolumes: []string{"/data"}}, expected},
		{"wrong config", ObservedImage{ID: "sha256:" + strings.Repeat("b", 64), OS: "linux", Architecture: "arm64", Variant: "v8", ConfigPresent: true}, expected},
		{"wrong os", ObservedImage{ID: digest, OS: "windows", Architecture: "arm64", Variant: "v8", ConfigPresent: true}, expected},
		{"wrong architecture", ObservedImage{ID: digest, OS: "linux", Architecture: "amd64", Variant: "v8", ConfigPresent: true}, expected},
		{"wrong variant", ObservedImage{ID: digest, OS: "linux", Architecture: "arm64", Variant: "v7", ConfigPresent: true}, expected},
		{"missing config", ObservedImage{ID: digest, OS: "linux", Architecture: "arm64", Variant: "v8"}, expected},
		{"unsupported signed os", valid, ImageRequirement{ConfigDigest: digest, OS: "windows", Architecture: "arm64", Variant: "v8"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateImage(test.observed, test.expected); err == nil {
				t.Fatal("unsafe image accepted")
			}
		})
	}
}

func TestWorkloadValidatesOptionalExactConfigDigest(t *testing.T) {
	workload := Workload{
		InstanceID: "agent", TenantID: "tenant", ProfileID: "generic-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("a", 64), ImageConfigDigest: "sha256:" + strings.Repeat("b", 64),
		Command: []string{"agent"}, Resources: Resources{MemoryBytes: 1, CPUMillis: 1, PIDs: 1},
	}
	if err := workload.Validate(); err != nil {
		t.Fatal(err)
	}
	workload.ImageConfigDigest = "sha256:not-a-digest"
	if err := workload.Validate(); err == nil {
		t.Fatal("invalid internal config digest accepted")
	}
}
