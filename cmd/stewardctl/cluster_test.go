package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/clustersubstrate"
)

func TestClusterPlanOutputsHumanJSONAndConfig(t *testing.T) {
	for _, output := range []string{"human", "json", "config"} {
		var stdout bytes.Buffer
		err := run([]string{"cluster", "plan", "init", "-cluster", "research", "-node", "server-1", "-arch", "amd64", "-output", output}, &stdout, &bytes.Buffer{})
		if err != nil {
			t.Fatalf("%s: %v", output, err)
		}
		switch output {
		case "human":
			if !strings.Contains(stdout.String(), "No host changes were made.") ||
				!strings.Contains(stdout.String(), "RKE2 v1.35.6+rke2r1") {
				t.Fatalf("unexpected human output:\n%s", stdout.String())
			}
		case "json":
			var plan clustersubstrate.Plan
			if err := json.Unmarshal(stdout.Bytes(), &plan); err != nil || plan.Operation != "init" {
				t.Fatalf("unexpected JSON output: %v %#v", err, plan)
			}
		case "config":
			if !strings.Contains(stdout.String(), "profile: cis") {
				t.Fatalf("unexpected config:\n%s", stdout.String())
			}
		}
	}
}

func TestClusterArtifactIsMachineSafe(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"cluster", "artifact", "bundle", "-arch", "arm64"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	fields := strings.Split(strings.TrimSpace(stdout.String()), "\t")
	if len(fields) != 4 || fields[0] != "rke2.linux-arm64.tar.gz" ||
		fields[2] != "36237481" || len(fields[3]) != 64 {
		t.Fatalf("unexpected artifact output %q", stdout.String())
	}
}

func TestClusterPlanRejectsUnsafeJoin(t *testing.T) {
	for _, arguments := range [][]string{
		{"cluster", "plan", "join-worker", "-server", "http://node:9345"},
		{"cluster", "plan", "join-worker", "-server", "https://node:6443"},
		{"cluster", "plan", "join-worker", "-server", "https://node:9345", "-token-file", "relative"},
		{"cluster", "plan", "unknown"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("unsafe cluster plan was accepted: %v", arguments)
		}
	}
}

func TestClusterBaselineIsDefaultDenyRunsc(t *testing.T) {
	var stdout bytes.Buffer
	if err := run([]string{"cluster", "baseline"}, &stdout, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"name: runsc", "name: steward-agents", "name: default-deny",
		"automountServiceAccountToken: false",
	} {
		if !strings.Contains(stdout.String(), want) {
			t.Fatalf("baseline is missing %q", want)
		}
	}
}
