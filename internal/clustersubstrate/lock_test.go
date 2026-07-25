package clustersubstrate

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCurrentLockIsExactAndComplete(t *testing.T) {
	lock, err := CurrentLock()
	if err != nil {
		t.Fatal(err)
	}
	if lock.Version != "v1.35.6+rke2r1" {
		t.Fatalf("unexpected version %q", lock.Version)
	}
	for _, arch := range SupportedArchitectures() {
		for _, kind := range []string{"bundle", "images", "checksums"} {
			artifact, err := lock.Artifact(arch, kind)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(artifact.URL, lock.Version[:7]) || artifact.Size <= 0 || len(artifact.SHA256) != 64 {
				t.Fatalf("invalid %s/%s artifact: %#v", arch, kind, artifact)
			}
		}
	}
}

func TestLockRejectsUnknownAndMovedMetadata(t *testing.T) {
	lock, err := CurrentLock()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(lock)
	cases := []string{
		strings.Replace(string(raw), `"schema_version":`, `"unknown":true,"schema_version":`, 1),
		strings.Replace(string(raw), "https://github.com/rancher/rke2/releases/download/", "https://example.com/", 1),
		strings.Replace(string(raw), lock.Version, "v1.35.7+rke2r1", 1),
		strings.Replace(string(raw), `"size":40463856`, `"size":0`, 1),
	}
	for _, candidate := range cases {
		if _, err := ParseLock([]byte(candidate)); err == nil {
			t.Fatal("malformed lock was accepted")
		}
	}
}

func TestBuildPlanRendersHardenedServerAndWorker(t *testing.T) {
	server, err := BuildPlan(PlanRequest{
		Operation: OperationInit, ClusterName: "research", NodeName: "server-1",
		Arch: "amd64", AirGap: true, Start: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"profile: cis", "secrets-encryption: true", "cni: canal",
		"rke2-ingress-nginx", "etcd-snapshot-retention: 12",
	} {
		if !strings.Contains(server.Config, want) {
			t.Fatalf("server config is missing %q:\n%s", want, server.Config)
		}
	}
	if server.Images == nil || !strings.Contains(server.Baseline, "kind: RuntimeClass") ||
		!strings.Contains(server.Baseline, "kind: NetworkPolicy") {
		t.Fatal("server plan lacks the air-gap artifact or baseline")
	}

	worker, err := BuildPlan(PlanRequest{
		Operation: OperationJoinWorker, ClusterName: "research", NodeName: "worker-1",
		ServerURL: "https://10.0.0.10:9345", TokenFile: "/run/steward/join-token",
		Arch: "arm64", Start: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if worker.Service != "rke2-agent" || worker.Baseline != "" ||
		!strings.Contains(worker.Config, "profile: cis") ||
		!strings.Contains(worker.Config, `token-file: "/run/steward/join-token"`) ||
		strings.Contains(worker.Config, "secrets-encryption") {
		t.Fatalf("unexpected worker plan: %#v", worker)
	}
}

func TestBuildPlanRejectsUnsafeInputs(t *testing.T) {
	base := PlanRequest{
		Operation: OperationJoinWorker, ClusterName: "research", NodeName: "worker-1",
		ServerURL: "https://10.0.0.10:9345", TokenFile: "/run/steward/join-token",
		Arch: "amd64",
	}
	cases := []PlanRequest{
		func() PlanRequest { value := base; value.ClusterName = "Bad_Name"; return value }(),
		func() PlanRequest { value := base; value.NodeName = "node\ninject"; return value }(),
		func() PlanRequest { value := base; value.ServerURL = "https://user@host:9345"; return value }(),
		func() PlanRequest { value := base; value.ServerURL = "https://host:6443"; return value }(),
		func() PlanRequest { value := base; value.TokenFile = "../token"; return value }(),
		func() PlanRequest { value := base; value.Arch = "386"; return value }(),
	}
	for _, request := range cases {
		if _, err := BuildPlan(request); err == nil {
			t.Fatalf("unsafe plan was accepted: %#v", request)
		}
	}
}
