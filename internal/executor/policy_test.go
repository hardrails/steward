package executor

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/gateway"
)

func TestValidateImageRequiresExactSafeLocalImage(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	expected := ImageRequirement{ConfigDigest: digest, OS: "linux", Architecture: "arm64", Variant: "v8"}
	valid := ObservedImage{ID: digest, ConfigDigest: digest, Identity: imageIdentityConfig, OS: "linux", Architecture: "arm64", Variant: "v8", ConfigPresent: true}
	if err := ValidateImage(valid, expected); err != nil {
		t.Fatalf("valid image rejected: %v", err)
	}
	tests := []struct {
		name     string
		observed ObservedImage
		expected ImageRequirement
	}{
		{"declared volume", ObservedImage{ID: digest, ConfigDigest: digest, Identity: imageIdentityConfig, OS: "linux", Architecture: "arm64", Variant: "v8", ConfigPresent: true, DeclaredVolumes: []string{"/data"}}, expected},
		{"wrong config", ObservedImage{ID: "sha256:" + strings.Repeat("b", 64), ConfigDigest: "sha256:" + strings.Repeat("b", 64), Identity: imageIdentityConfig, OS: "linux", Architecture: "arm64", Variant: "v8", ConfigPresent: true}, expected},
		{"wrong os", ObservedImage{ID: digest, ConfigDigest: digest, Identity: imageIdentityConfig, OS: "windows", Architecture: "arm64", Variant: "v8", ConfigPresent: true}, expected},
		{"wrong architecture", ObservedImage{ID: digest, ConfigDigest: digest, Identity: imageIdentityConfig, OS: "linux", Architecture: "amd64", Variant: "v8", ConfigPresent: true}, expected},
		{"wrong variant", ObservedImage{ID: digest, ConfigDigest: digest, Identity: imageIdentityConfig, OS: "linux", Architecture: "arm64", Variant: "v7", ConfigPresent: true}, expected},
		{"missing config", ObservedImage{ID: digest, ConfigDigest: digest, Identity: imageIdentityConfig, OS: "linux", Architecture: "arm64", Variant: "v8"}, expected},
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

func TestValidateImageRequiresExactContainerdManifestAndConfigPair(t *testing.T) {
	manifestDigest := "sha256:" + strings.Repeat("a", 64)
	configDigest := "sha256:" + strings.Repeat("b", 64)
	expected := ImageRequirement{
		ManifestDigest: manifestDigest, ConfigDigest: configDigest,
		OS: "linux", Architecture: "amd64",
	}
	valid := ObservedImage{
		ID: manifestDigest, ManifestDigest: manifestDigest, ConfigDigest: configDigest,
		Identity: imageIdentityManifest, OS: "linux", Architecture: "amd64", ConfigPresent: true,
	}
	if err := ValidateImage(valid, expected); err != nil {
		t.Fatalf("valid manifest/config pair rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*ObservedImage)
	}{
		{"runtime manifest", func(image *ObservedImage) { image.ID = "sha256:" + strings.Repeat("c", 64) }},
		{"descriptor manifest", func(image *ObservedImage) { image.ManifestDigest = "sha256:" + strings.Repeat("c", 64) }},
		{"descriptor config", func(image *ObservedImage) { image.ConfigDigest = "sha256:" + strings.Repeat("c", 64) }},
		{"missing descriptor", func(image *ObservedImage) { image.ManifestDigest = "" }},
		{"wrong identity mode", func(image *ObservedImage) { image.Identity = imageIdentityConfig }},
	} {
		t.Run(test.name, func(t *testing.T) {
			observed := valid
			test.mutate(&observed)
			if err := ValidateImage(observed, expected); err == nil {
				t.Fatal("mismatched manifest/config identity accepted")
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
	workload.ImageConfigDigest = "sha256:" + strings.Repeat("b", 64)
	workload.ImageRuntimeDigest = "sha256:not-a-digest"
	if err := workload.Validate(); err == nil {
		t.Fatal("invalid internal runtime digest accepted")
	}
	workload.ImageRuntimeDigest = "sha256:" + strings.Repeat("a", 64)
	workload.ImageConfigDigest = ""
	if err := workload.Validate(); err == nil {
		t.Fatal("runtime digest without config digest accepted")
	}
	workload.ImageConfigDigest = "sha256:" + strings.Repeat("b", 64)
	workload.ImageRuntimeDigest = "sha256:" + strings.Repeat("c", 64)
	if err := workload.Validate(); err == nil {
		t.Fatal("runtime digest unrelated to the signed manifest/config pair accepted")
	}
}

func TestWorkloadValidatesBoundedConnectorRuntimeGrant(t *testing.T) {
	connectorIDs := make([]string, 32)
	for index := range connectorIDs {
		connectorIDs[index] = fmt.Sprintf("connector.%02d", index)
	}
	network := NetworkSpecFor("tenant", "agent", 1)
	runtime := RuntimeGrant{
		NetworkName: network.Name, GrantID: "grant-" + strings.Repeat("b", 64), Generation: 1,
		ConnectorIDs: connectorIDs, CapsuleDigest: "sha256:" + strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64),
	}
	workload := Workload{
		InstanceID: "agent", TenantID: "tenant", ProfileID: "generic-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("e", 64), Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1, CPUMillis: 1, PIDs: 1}, Runtime: &runtime,
	}
	if err := workload.Validate(); err != nil {
		t.Fatalf("valid 32-connector runtime rejected: %v", err)
	}

	for _, test := range []struct {
		name   string
		mutate func(*RuntimeGrant)
	}{
		{name: "too many", mutate: func(runtime *RuntimeGrant) { runtime.ConnectorIDs = append(runtime.ConnectorIDs, "connector.32") }},
		{name: "not sorted", mutate: func(runtime *RuntimeGrant) {
			runtime.ConnectorIDs[0], runtime.ConnectorIDs[1] = runtime.ConnectorIDs[1], runtime.ConnectorIDs[0]
		}},
		{name: "duplicate", mutate: func(runtime *RuntimeGrant) { runtime.ConnectorIDs[1] = runtime.ConnectorIDs[0] }},
		{name: "invalid ID", mutate: func(runtime *RuntimeGrant) { runtime.ConnectorIDs[0] = "bad connector" }},
		{name: "missing bindings", mutate: func(runtime *RuntimeGrant) { runtime.CapsuleDigest, runtime.PolicyDigest = "", "" }},
		{name: "partial binding", mutate: func(runtime *RuntimeGrant) { runtime.PolicyDigest = "" }},
		{name: "invalid binding", mutate: func(runtime *RuntimeGrant) { runtime.PolicyDigest = "sha256:not-a-digest" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := workload
			clonedRuntime := runtime
			clonedRuntime.ConnectorIDs = append([]string(nil), runtime.ConnectorIDs...)
			candidate.Runtime = &clonedRuntime
			test.mutate(candidate.Runtime)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid connector runtime accepted")
			}
		})
	}

	legacy := workload
	legacyRuntime := runtime
	legacyRuntime.ConnectorIDs = nil
	legacyRuntime.CapsuleDigest, legacyRuntime.PolicyDigest = "", ""
	legacyRuntime.Inference, legacyRuntime.RouteID, legacyRuntime.ModelAlias = true, "local", "model"
	legacy.Runtime = &legacyRuntime
	if err := legacy.Validate(); err != nil {
		t.Fatalf("legacy connector-free runtime rejected: %v", err)
	}
}

func TestWorkloadValidatesTaskAuthorityRuntimeGrant(t *testing.T) {
	network := NetworkSpecFor("tenant", "agent", 1)
	runtime := RuntimeGrant{
		NetworkName: network.Name, GrantID: "grant-" + strings.Repeat("b", 64), NodeID: "node-a", Generation: 1,
		ServicePort: 8080, ServiceID: "hermes-api", TaskAuthorities: []gateway.TaskAuthority{{
			KeyID: "task-approver", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
		}},
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64),
	}
	workload := Workload{
		InstanceID: "agent", TenantID: "tenant", ProfileID: "hermes-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("e", 64), Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1, CPUMillis: 1, PIDs: 1}, Runtime: &runtime,
	}
	if err := workload.Validate(); err != nil {
		t.Fatalf("valid task-authorized runtime rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*RuntimeGrant)
	}{
		{"missing node", func(value *RuntimeGrant) { value.NodeID = "" }},
		{"invalid service", func(value *RuntimeGrant) { value.ServiceID = "bad service" }},
		{"missing service port", func(value *RuntimeGrant) { value.ServicePort = 0 }},
		{"missing admission bindings", func(value *RuntimeGrant) { value.CapsuleDigest, value.PolicyDigest = "", "" }},
		{"invalid authority", func(value *RuntimeGrant) { value.TaskAuthorities[0].PublicKey = "not-base64" }},
		{"authority removed but identity retained", func(value *RuntimeGrant) { value.TaskAuthorities = nil }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := workload
			candidateRuntime := runtime
			candidateRuntime.TaskAuthorities = append([]gateway.TaskAuthority(nil), runtime.TaskAuthorities...)
			candidate.Runtime = &candidateRuntime
			test.mutate(candidate.Runtime)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid task-authorized runtime accepted")
			}
		})
	}
}

func TestWorkloadValidatesAuthorizedEffectsRuntimeGrant(t *testing.T) {
	network := NetworkSpecFor("tenant", "agent", 1)
	runtime := RuntimeGrant{
		NetworkName: network.Name, GrantID: "grant-" + strings.Repeat("b", 64),
		NodeID: "node-a", Generation: 1, ConnectorIDs: []string{"issues"},
		EffectMode: gateway.EffectModeAuthorized,
		ActionAuthorities: []gateway.GrantActionAuthority{{
			KeyID: "effects-approver", PublicKey: base64.StdEncoding.EncodeToString(make([]byte, ed25519.PublicKeySize)),
			ConnectorIDs: []string{"issues"},
		}},
		CapsuleDigest: "sha256:" + strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64),
	}
	workload := Workload{
		InstanceID: "agent", TenantID: "tenant", ProfileID: "hermes-v1@v1",
		Image: "registry.local/agent@sha256:" + strings.Repeat("e", 64), Command: []string{"agent"},
		Resources: Resources{MemoryBytes: 1, CPUMillis: 1, PIDs: 1}, Runtime: &runtime,
	}
	if err := workload.Validate(); err != nil {
		t.Fatalf("valid authorized-effects runtime rejected: %v", err)
	}
	for _, test := range []struct {
		name   string
		mutate func(*RuntimeGrant)
	}{
		{"mode removed", func(value *RuntimeGrant) { value.EffectMode = "" }},
		{"mode changed", func(value *RuntimeGrant) { value.EffectMode = gateway.EffectModeStandard }},
		{"node removed", func(value *RuntimeGrant) { value.NodeID = "" }},
		{"generic egress added", func(value *RuntimeGrant) { value.EgressRouteIDs = []string{"public-web"} }},
		{"authority removed", func(value *RuntimeGrant) { value.ActionAuthorities = nil }},
		{"authority malformed", func(value *RuntimeGrant) { value.ActionAuthorities[0].PublicKey = "not-base64" }},
		{"scope removed", func(value *RuntimeGrant) { value.ActionAuthorities[0].ConnectorIDs = nil }},
		{"bindings removed", func(value *RuntimeGrant) { value.CapsuleDigest, value.PolicyDigest = "", "" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			candidate := workload
			candidateRuntime := runtime
			candidateRuntime.ConnectorIDs = append([]string(nil), runtime.ConnectorIDs...)
			candidateRuntime.ActionAuthorities = cloneGrantActionAuthorities(runtime.ActionAuthorities)
			candidate.Runtime = &candidateRuntime
			test.mutate(candidate.Runtime)
			if err := candidate.Validate(); err == nil {
				t.Fatal("invalid authorized-effects runtime accepted")
			}
		})
	}
}
