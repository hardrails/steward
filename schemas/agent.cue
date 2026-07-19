// Agent application schema for authoring-time `cue vet`. Steward still applies
// its own strict validation after `cue export`; this file is an ergonomic aid,
// not an enforcement replacement.
#Agent: {
  schema: "steward.agent.v1"
  name: =~"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$"
  runtime: {
    engine: "hermes" | "openclaw"
    image: string & =~"@sha256:[0-9a-f]{64}$"
    adapter_contract: string
  }
  model: route: string & !=""
  skills?: [...string]
  mcp_servers?: [...string]
  resources: {
    cpu_millis: int & >=10 & <=128000
    memory_mib: int & >=64 & <=1048576
    disk_mib: int & >=64 & <=10485760
    pids: int & >=16 & <=1048576
  }
  placement: {
    architectures: [string, ...string]
    isolation: "development" | "hardened"
    required_labels?: [...{key: string, value: string}]
    preferred_labels?: [...{key: string, value: string}]
    tolerations?: [...string]
    spread_by?: string
  }
  state: {
    persistent: bool
    snapshot_id?: string
  }
  lifetime: {
    mode: "task" | "service" | "temporary"
    ttl_seconds?: int
    on_expiry?: "destroy" | "hibernate"
  }
}
