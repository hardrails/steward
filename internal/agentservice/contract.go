// Package agentservice defines Steward's fixed, runtime-neutral agent service
// contract. It contains no workflow, prompt, tool, or result semantics: those
// remain the responsibility of the hosted agent and its caller.
package agentservice

const (
	DescriptorSchemaV1 = "steward.agent-service-contract.v1"
	AdapterContractV1  = "steward.agent-service.v1"
	HealthSchemaV1     = "steward.agent-health.v1"
	InvocationSchemaV1 = "steward.agent-invocation.v1"

	RuntimeEngine  = "agent-service"
	ProfileID      = "agent-service-v1"
	ProfileVersion = "v1"
	StatePath      = "/state"
	Command        = "serve"

	ServiceID          = "agent-api"
	ServicePort        = 8080
	OperationID        = "agent.invoke"
	HealthPath         = "/v1/healthz"
	InvocationPath     = "/v1/invocations"
	StatusPathPrefix   = "/v1/invocations/"
	TaskProtocol       = "steward.task-lifecycle.v1"
	MaxRequestBytes    = int64(64 << 10)
	MaxResponseBytes   = int64(1 << 20)
	MaxDispatchSeconds = 120
	MaxPermitSeconds   = 900
	MaxStatusSeconds   = 30
	MaxPollSeconds     = 60
)

// Descriptor is the immutable compatibility surface a portable agent image
// implements. Limits are ceilings; node policy may select smaller values.
type Descriptor struct {
	SchemaVersion string            `json:"schema_version"`
	Runtime       RuntimeDescriptor `json:"runtime"`
	Service       ServiceDescriptor `json:"service"`
	Limits        Limits            `json:"limits"`
}

type RuntimeDescriptor struct {
	Engine          string   `json:"engine"`
	AdapterContract string   `json:"adapter_contract"`
	ProfileID       string   `json:"profile_id"`
	ProfileVersion  string   `json:"profile_version"`
	Command         []string `json:"command"`
	StatePath       string   `json:"state_path"`
}

type ServiceDescriptor struct {
	ID               string `json:"id"`
	Port             int    `json:"port"`
	OperationID      string `json:"operation_id"`
	HealthPath       string `json:"health_path"`
	InvocationPath   string `json:"invocation_path"`
	StatusPathPrefix string `json:"status_path_prefix"`
	TaskProtocol     string `json:"task_protocol"`
}

type Limits struct {
	MaxRequestBytes    int64 `json:"max_request_bytes"`
	MaxResponseBytes   int64 `json:"max_response_bytes"`
	MaxDispatchSeconds int   `json:"max_dispatch_seconds"`
	MaxPermitSeconds   int   `json:"max_permit_seconds"`
	MaxStatusSeconds   int   `json:"max_status_seconds"`
	MaxPollSeconds     int   `json:"max_poll_seconds"`
}

func V1() Descriptor {
	return Descriptor{
		SchemaVersion: DescriptorSchemaV1,
		Runtime: RuntimeDescriptor{
			Engine: RuntimeEngine, AdapterContract: AdapterContractV1,
			ProfileID: ProfileID, ProfileVersion: ProfileVersion,
			Command: []string{Command}, StatePath: StatePath,
		},
		Service: ServiceDescriptor{
			ID: ServiceID, Port: ServicePort, OperationID: OperationID,
			HealthPath: HealthPath, InvocationPath: InvocationPath,
			StatusPathPrefix: StatusPathPrefix, TaskProtocol: TaskProtocol,
		},
		Limits: Limits{
			MaxRequestBytes: MaxRequestBytes, MaxResponseBytes: MaxResponseBytes,
			MaxDispatchSeconds: MaxDispatchSeconds, MaxPermitSeconds: MaxPermitSeconds,
			MaxStatusSeconds: MaxStatusSeconds, MaxPollSeconds: MaxPollSeconds,
		},
	}
}
