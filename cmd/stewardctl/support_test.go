package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSupportMatrixJSONIsStableAndHonest(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"support", "matrix", "-output", "json"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	var matrix supportMatrix
	if err := json.Unmarshal(output.Bytes(), &matrix); err != nil {
		t.Fatal(err)
	}
	if matrix.SchemaVersion != supportMatrixSchemaV1 || matrix.StewardVersion == "" || len(matrix.Platforms) != 3 {
		t.Fatalf("support matrix identity = %+v", matrix)
	}
	if matrix.Platforms[1].Role != "executor" || matrix.Platforms[1].Status != "production" ||
		matrix.Isolation.ProductionSandbox != "gvisor-runsc" || matrix.Isolation.ControlAuthorityOnNodes {
		t.Fatalf("executor support contract = %+v isolation=%+v", matrix.Platforms[1], matrix.Isolation)
	}
	if len(matrix.AgentRuntimes) != 2 || matrix.AgentRuntimes[0].Name != "hermes-agent" ||
		matrix.AgentRuntimes[0].Status != "qualified" || matrix.AgentRuntimes[1].Status != "not_supported" {
		t.Fatalf("runtime support contract = %+v", matrix.AgentRuntimes)
	}
	if matrix.Compatibility.NodeManifest != "release.json" || matrix.Compatibility.SupportSchema != supportMatrixSchemaV1 || len(matrix.KnownLimits) < 5 {
		t.Fatalf("compatibility or limits = %+v %+v", matrix.Compatibility, matrix.KnownLimits)
	}
}

func TestSupportMatrixHumanOutputAndBoundaries(t *testing.T) {
	var output bytes.Buffer
	if err := supportCommand([]string{"matrix"}, &output); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"support matrix", "executor: production", "Hermes (qualified", "Known limits", "-output json"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("human support matrix missing %q: %s", expected, output.String())
		}
	}
	for _, arguments := range [][]string{nil, {"unknown"}, {"matrix", "extra"}, {"matrix", "-output", "yaml"}} {
		if err := supportCommand(arguments, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid support command accepted: %#v", arguments)
		}
	}
}
