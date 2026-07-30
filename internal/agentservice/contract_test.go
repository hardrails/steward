package agentservice

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestV1IsStableAndReturnsIndependentValues(t *testing.T) {
	first := V1()
	second := V1()
	first.Runtime.Command[0] = "changed"
	if second.Runtime.Command[0] != Command {
		t.Fatal("contract descriptor returned mutable shared state")
	}
	raw, err := json.Marshal(second)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`"schema_version":"steward.agent-service-contract.v1"`,
		`"adapter_contract":"steward.agent-service.v1"`,
		`"profile_id":"agent-service-v1"`,
		`"health_path":"/v1/healthz"`,
		`"invocation_path":"/v1/invocations"`,
		`"task_protocol":"steward.task-lifecycle.v1"`,
		`"max_request_bytes":65536`,
		`"max_response_bytes":1048576`,
	} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("descriptor %s does not contain %s", raw, required)
		}
	}
}

func TestOpenAPIContainsEveryFixedV1Value(t *testing.T) {
	raw, err := os.ReadFile("../../openapi/steward-agent-service.v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		AdapterContractV1,
		HealthSchemaV1,
		InvocationSchemaV1,
		HealthPath,
		InvocationPath,
		StatusPathPrefix,
		"agent-api:8080",
		"x-steward-max-body-bytes: 65536",
		"x-steward-max-body-bytes: 1048576",
	} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("agent service OpenAPI is missing fixed contract value %q", required)
		}
	}
	for _, forbidden := range []string{"deployment_id", "release_digest"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("agent service health requires uninjected worker metadata %q", forbidden)
		}
	}
}

func TestAuthoringSchemaIncludesTheExactRuntimePair(t *testing.T) {
	raw, err := os.ReadFile("../../schemas/agent.cue")
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		`engine: "agent-service"`,
		`adapter_contract: "steward.agent-service.v1"`,
		`if runtime.engine == "agent-service"`,
		`tool_profile?: "workspace"`,
	} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("agent authoring schema is missing %q", required)
		}
	}
}
