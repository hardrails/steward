package agentservice

import (
	"encoding/json"
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
