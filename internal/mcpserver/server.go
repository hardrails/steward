// Package mcpserver implements Steward's deliberately narrow MCP stdio tools
// adapter. It supports the MCP 2025-11-25 lifecycle and tools capability,
// delegates operations to Steward's public node and control-plane contracts,
// and can optionally expose Gateway's bounded task-lifecycle client.
package mcpserver

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/nodeclient"
)

const ProtocolVersion = "2025-11-25"
const maxMessageBytes = 1 << 20
const maxToolResultBytes = 1 << 20
const nodeOperationTimeout = 30 * time.Second

type Node interface {
	Admit(context.Context, []byte, admission.InstanceIntent) (nodeclient.State, error)
	Status(context.Context, string) (nodeclient.State, error)
	Logs(context.Context, string) (nodeclient.State, error)
	Start(context.Context, string) (nodeclient.State, error)
	Stop(context.Context, string) (nodeclient.State, error)
	Destroy(context.Context, string) error
	PurgeState(context.Context, nodeclient.StatePurge) error
	SnapshotState(context.Context, nodeclient.StateSnapshotRequest) (nodeclient.StateSnapshot, error)
	CloneState(context.Context, nodeclient.StateCloneRequest) (nodeclient.StateClone, error)
	DeleteStateSnapshot(context.Context, nodeclient.StateSnapshotRequest) error
}

type Server struct {
	node        Node
	control     Control
	tasks       TaskGateway
	resultStore *taskResultStore
	version     string
}

// Config selects the independently optional MCP operation surfaces.
type Config struct {
	Node                Node
	Control             Control
	Tasks               TaskGateway
	TaskResultDirectory string
	Version             string
}

func New(node Node, version string) (*Server, error) {
	return NewConfigured(Config{Node: node, Version: version})
}

// NewWithTasks adds the optional Gateway-backed task lifecycle tools. The
// result directory is fixed for the process lifetime and must already be an
// owner-only directory; terminal agent bytes are written there and never
// returned over MCP stdio.
func NewWithTasks(node Node, tasks TaskGateway, resultDirectory, version string) (*Server, error) {
	return NewConfigured(Config{
		Node: node, Tasks: tasks, TaskResultDirectory: resultDirectory, Version: version,
	})
}

// NewConfigured builds an MCP surface from independently optional node and
// control-plane clients. Gateway task tools require a node configuration so a
// controller-only process cannot acquire an ambient path to agent execution.
func NewConfigured(config Config) (*Server, error) {
	if strings.TrimSpace(config.Version) == "" {
		return nil, errors.New("MCP server version is required")
	}
	if config.Node == nil && config.Control == nil {
		return nil, errors.New("MCP node or control client is required")
	}
	if config.Tasks != nil && config.Node == nil {
		return nil, errors.New("MCP Gateway task tools require a node client")
	}
	if config.Tasks == nil && config.TaskResultDirectory != "" {
		return nil, errors.New("MCP task result directory requires a Gateway task client")
	}
	server := &Server{node: config.Node, control: config.Control, tasks: config.Tasks, version: config.Version}
	if config.Tasks == nil {
		return server, nil
	}
	store, err := newTaskResultStore(config.TaskResultDirectory)
	if err != nil {
		return nil, err
	}
	server.resultStore = store
	return server, nil
}

type request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (s *Server) Serve(ctx context.Context, input io.Reader, output, logWriter io.Writer) error {
	if input == nil || output == nil || logWriter == nil {
		return errors.New("MCP input, output, and log writer are required")
	}
	if s.resultStore != nil {
		defer s.resultStore.close()
	}
	scanner := bufio.NewScanner(input)
	scanner.Buffer(make([]byte, 64<<10), maxMessageBytes)
	encoder := json.NewEncoder(output)
	encoder.SetEscapeHTML(false)
	initializedResponse := false
	initialized := false
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		var message request
		if err := dsse.DecodeStrictInto(line, maxMessageBytes, &message); err != nil {
			if err := encoder.Encode(response{JSONRPC: "2.0", ID: json.RawMessage("null"), Error: &rpcError{Code: -32700, Message: "Parse error"}}); err != nil {
				return err
			}
			continue
		}
		if message.JSONRPC != "2.0" || strings.TrimSpace(message.Method) == "" || !validID(message.ID) {
			if len(message.ID) != 0 {
				if err := encoder.Encode(response{JSONRPC: "2.0", ID: normalizedID(message.ID), Error: &rpcError{Code: -32600, Message: "Invalid Request"}}); err != nil {
					return err
				}
			}
			continue
		}
		isNotification := len(message.ID) == 0
		if isNotification {
			if message.Method == "notifications/initialized" && initializedResponse {
				initialized = true
			}
			continue
		}
		var result any
		var callErr *rpcError
		switch message.Method {
		case "initialize":
			if initializedResponse {
				callErr = &rpcError{Code: -32600, Message: "initialize may only be called once"}
				break
			}
			if err := validateInitialize(message.Params); err != nil {
				callErr = &rpcError{Code: -32602, Message: err.Error()}
				break
			}
			initializedResponse = true
			serverTitle, serverDescription, instructions := s.initializationMetadata()
			result = map[string]any{
				"protocolVersion": ProtocolVersion,
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo": map[string]any{
					"name": "steward-mcp", "title": serverTitle, "version": s.version,
					"description": serverDescription,
				},
				"instructions": instructions,
			}
		case "ping":
			result = map[string]any{}
		case "tools/list":
			if !initialized {
				callErr = &rpcError{Code: -32002, Message: "MCP session is not initialized"}
				break
			}
			result = map[string]any{"tools": s.configuredTools()}
		case "tools/call":
			if !initialized {
				callErr = &rpcError{Code: -32002, Message: "MCP session is not initialized"}
				break
			}
			result, callErr = s.callTool(ctx, message.Params)
		default:
			callErr = &rpcError{Code: -32601, Message: "Method not found"}
		}
		if callErr != nil {
			if err := encoder.Encode(response{JSONRPC: "2.0", ID: message.ID, Error: callErr}); err != nil {
				return err
			}
			continue
		}
		if err := encoder.Encode(response{JSONRPC: "2.0", ID: message.ID, Result: result}); err != nil {
			return err
		}
	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(logWriter, "steward-mcp: input exceeds 1 MiB or cannot be read")
		return err
	}
	return nil
}

type initializeParams struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    json.RawMessage `json:"capabilities"`
	ClientInfo      clientInfo      `json:"clientInfo"`
	Meta            json.RawMessage `json:"_meta,omitempty"`
}

type clientInfo struct {
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Version     string          `json:"version"`
	Description string          `json:"description,omitempty"`
	Icons       json.RawMessage `json:"icons,omitempty"`
	WebsiteURL  string          `json:"websiteUrl,omitempty"`
}

func validateInitialize(raw []byte) error {
	var params initializeParams
	if err := dsse.DecodeStrictInto(raw, maxMessageBytes, &params); err != nil {
		return errors.New("invalid initialize parameters")
	}
	if params.ProtocolVersion == "" || params.ClientInfo.Name == "" || params.ClientInfo.Version == "" || len(params.Capabilities) == 0 {
		return errors.New("initialize requires protocolVersion, capabilities, and clientInfo")
	}
	return nil
}

type toolCall struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
	Meta      json.RawMessage `json:"_meta,omitempty"`
}

type runtimeArgs struct {
	RuntimeRef string `json:"runtime_ref"`
}

type admitArgs struct {
	CapsuleDSSEBase64 string `json:"capsule_dsse_base64"`
	IntentJSON        string `json:"intent_json"`
}

type purgeStateArgs struct {
	TenantID   string `json:"tenant_id"`
	NodeID     string `json:"node_id"`
	LineageID  string `json:"lineage_id"`
	Generation uint64 `json:"generation"`
}

type snapshotStateArgs struct {
	TenantID   string `json:"tenant_id"`
	NodeID     string `json:"node_id"`
	InstanceID string `json:"instance_id"`
	LineageID  string `json:"lineage_id"`
	Generation uint64 `json:"generation"`
	SnapshotID string `json:"snapshot_id"`
}

type cloneStateArgs struct {
	TenantID        string `json:"tenant_id"`
	NodeID          string `json:"node_id"`
	InstanceID      string `json:"instance_id"`
	LineageID       string `json:"lineage_id"`
	Generation      uint64 `json:"generation"`
	SnapshotID      string `json:"snapshot_id"`
	SourceLineageID string `json:"source_lineage_id"`
}

func (s *Server) callTool(ctx context.Context, raw []byte) (any, *rpcError) {
	var call toolCall
	if err := dsse.DecodeStrictInto(raw, maxMessageBytes, &call); err != nil || call.Name == "" {
		return nil, &rpcError{Code: -32602, Message: "invalid tool call parameters"}
	}
	var value any
	var err error
	switch call.Name {
	case "steward_admit":
		if s.node == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		var arguments admitArgs
		if decodeArguments(call.Arguments, &arguments) != nil || arguments.CapsuleDSSEBase64 == "" || arguments.IntentJSON == "" {
			return toolFailure("steward_admit requires capsule_dsse_base64 and intent_json"), nil
		}
		capsule, decodeErr := base64.StdEncoding.DecodeString(arguments.CapsuleDSSEBase64)
		if decodeErr != nil || len(capsule) == 0 || len(capsule) > 512<<10 {
			return toolFailure("capsule_dsse_base64 is invalid or exceeds 512 KiB"), nil
		}
		var intent admission.InstanceIntent
		if decodeErr := dsse.DecodeStrictInto([]byte(arguments.IntentJSON), maxMessageBytes, &intent); decodeErr != nil {
			return toolFailure("intent_json must be one strict instance intent"), nil
		}
		nodeCtx, cancel := context.WithTimeout(ctx, nodeOperationTimeout)
		defer cancel()
		value, err = s.node.Admit(nodeCtx, capsule, intent)
	case "steward_status", "steward_logs", "steward_egress", "steward_start", "steward_stop", "steward_destroy":
		if s.node == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		var arguments runtimeArgs
		if decodeArguments(call.Arguments, &arguments) != nil || arguments.RuntimeRef == "" {
			return toolFailure(call.Name + " requires runtime_ref"), nil
		}
		nodeCtx, cancel := context.WithTimeout(ctx, nodeOperationTimeout)
		defer cancel()
		switch call.Name {
		case "steward_status":
			value, err = s.node.Status(nodeCtx, arguments.RuntimeRef)
		case "steward_logs":
			value, err = s.node.Logs(nodeCtx, arguments.RuntimeRef)
		case "steward_egress":
			egress, ok := s.node.(interface {
				EgressStats(context.Context, string) (nodeclient.EgressStats, error)
			})
			if !ok {
				return toolFailure("egress statistics are unavailable"), nil
			}
			value, err = egress.EgressStats(nodeCtx, arguments.RuntimeRef)
		case "steward_start":
			value, err = s.node.Start(nodeCtx, arguments.RuntimeRef)
		case "steward_stop":
			value, err = s.node.Stop(nodeCtx, arguments.RuntimeRef)
		case "steward_destroy":
			err = s.node.Destroy(nodeCtx, arguments.RuntimeRef)
			value = map[string]any{"runtime_ref": arguments.RuntimeRef, "destroyed": err == nil}
		}
	case "steward_purge_state":
		if s.node == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		var arguments purgeStateArgs
		if decodeArguments(call.Arguments, &arguments) != nil || arguments.TenantID == "" || arguments.NodeID == "" || arguments.LineageID == "" || arguments.Generation == 0 {
			return toolFailure("steward_purge_state requires tenant_id, node_id, lineage_id, and generation"), nil
		}
		nodeCtx, cancel := context.WithTimeout(ctx, nodeOperationTimeout)
		defer cancel()
		err = s.node.PurgeState(nodeCtx, nodeclient.StatePurge{
			TenantID: arguments.TenantID, NodeID: arguments.NodeID, LineageID: arguments.LineageID, Generation: arguments.Generation,
		})
		value = map[string]any{"tenant_id": arguments.TenantID, "lineage_id": arguments.LineageID, "purged": err == nil}
	case "steward_snapshot_state":
		if s.node == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		var arguments snapshotStateArgs
		if decodeArguments(call.Arguments, &arguments) != nil || arguments.TenantID == "" || arguments.NodeID == "" ||
			arguments.InstanceID == "" || arguments.LineageID == "" || arguments.Generation == 0 || arguments.SnapshotID == "" {
			return toolFailure("steward_snapshot_state requires tenant_id, node_id, instance_id, lineage_id, generation, and snapshot_id"), nil
		}
		nodeCtx, cancel := context.WithTimeout(ctx, nodeOperationTimeout)
		defer cancel()
		value, err = s.node.SnapshotState(nodeCtx, nodeclient.StateSnapshotRequest{
			TenantID: arguments.TenantID, NodeID: arguments.NodeID, InstanceID: arguments.InstanceID,
			LineageID: arguments.LineageID, Generation: arguments.Generation, SnapshotID: arguments.SnapshotID,
		})
	case "steward_clone_state":
		if s.node == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		var arguments cloneStateArgs
		if decodeArguments(call.Arguments, &arguments) != nil || arguments.TenantID == "" || arguments.NodeID == "" ||
			arguments.InstanceID == "" || arguments.LineageID == "" || arguments.Generation == 0 || arguments.SnapshotID == "" ||
			arguments.SourceLineageID == "" || arguments.SourceLineageID == arguments.LineageID {
			return toolFailure("steward_clone_state requires tenant_id, node_id, instance_id, lineage_id, generation, snapshot_id, and a different source_lineage_id"), nil
		}
		nodeCtx, cancel := context.WithTimeout(ctx, nodeOperationTimeout)
		defer cancel()
		value, err = s.node.CloneState(nodeCtx, nodeclient.StateCloneRequest{
			TenantID: arguments.TenantID, NodeID: arguments.NodeID, InstanceID: arguments.InstanceID,
			LineageID: arguments.LineageID, Generation: arguments.Generation, SnapshotID: arguments.SnapshotID,
			SourceLineageID: arguments.SourceLineageID,
		})
	case "steward_delete_snapshot":
		if s.node == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		var arguments snapshotStateArgs
		if decodeArguments(call.Arguments, &arguments) != nil || arguments.TenantID == "" || arguments.NodeID == "" ||
			arguments.InstanceID == "" || arguments.LineageID == "" || arguments.Generation == 0 || arguments.SnapshotID == "" {
			return toolFailure("steward_delete_snapshot requires tenant_id, node_id, instance_id, lineage_id, generation, and snapshot_id"), nil
		}
		nodeCtx, cancel := context.WithTimeout(ctx, nodeOperationTimeout)
		defer cancel()
		err = s.node.DeleteStateSnapshot(nodeCtx, nodeclient.StateSnapshotRequest{
			TenantID: arguments.TenantID, NodeID: arguments.NodeID, InstanceID: arguments.InstanceID,
			LineageID: arguments.LineageID, Generation: arguments.Generation, SnapshotID: arguments.SnapshotID,
		})
		value = map[string]any{"tenant_id": arguments.TenantID, "snapshot_id": arguments.SnapshotID, "deleted": err == nil}
	case "steward_task_submit":
		if s.tasks == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		value, err = s.submitTask(ctx, call.Arguments)
	case "steward_task_status":
		if s.tasks == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		value, err = s.taskStatus(ctx, call.Arguments)
	case "steward_task_observe":
		if s.tasks == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		value, err = s.observeTask(ctx, call.Arguments)
	case "steward_control_tenant_list", "steward_control_tenant_create",
		"steward_control_node_list", "steward_control_node_status", "steward_control_node_revoke",
		"steward_control_command_submit", "steward_control_command_status",
		"steward_control_operations_summary", "steward_control_attention_list",
		"steward_control_agent_list", "steward_control_command_list", "steward_control_credential_list",
		"steward_control_evidence_status":
		if s.control == nil {
			return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
		}
		value, err = s.callControlTool(ctx, call.Name, call.Arguments)
	default:
		return nil, &rpcError{Code: -32602, Message: "unknown tool " + call.Name}
	}
	if err != nil {
		return toolFailure(err.Error()), nil
	}
	encoded, marshalErr := json.Marshal(value)
	if marshalErr != nil {
		return toolFailure("encode tool result"), nil
	}
	if len(encoded) > maxToolResultBytes {
		return toolFailure("tool result exceeds 1 MiB"), nil
	}
	return map[string]any{
		"content":           []any{map[string]any{"type": "text", "text": string(encoded)}},
		"structuredContent": value,
		"isError":           false,
	}, nil
}

func decodeArguments(raw []byte, target any) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	return dsse.DecodeStrictInto(raw, maxMessageBytes, target)
}

func toolFailure(message string) any {
	if len(message) > 4096 {
		message = message[:4096]
	}
	return map[string]any{
		"content": []any{map[string]any{"type": "text", "text": message}},
		"isError": true,
	}
}

func tools(includeTasks bool) []any {
	result := nodeTools()
	if includeTasks {
		result = append(result, taskTools()...)
	}
	return result
}

func nodeTools() []any {
	runtimeSchema := map[string]any{
		"type": "object", "additionalProperties": false, "required": []string{"runtime_ref"},
		"properties": map[string]any{"runtime_ref": map[string]any{"type": "string", "pattern": "^executor-[a-f0-9]{64}$"}},
	}
	return []any{
		tool("steward_admit", "Admit signed agent", "Admit one publisher-signed capsule and tenant-bound intent on the configured Steward node.", map[string]any{
			"type": "object", "additionalProperties": false, "required": []string{"capsule_dsse_base64", "intent_json"},
			"properties": map[string]any{
				"capsule_dsse_base64": map[string]any{"type": "string", "description": "Base64 of the exact signed capsule envelope."},
				"intent_json":         map[string]any{"type": "string", "description": "Strict JSON instance intent authenticated by the configured node path."},
			},
		}, false, false, true, false),
		tool("steward_status", "Inspect agent", "Read the current bounded runtime status.", runtimeSchema, true, false, true, false),
		tool("steward_logs", "Read agent logs", "Read the bounded tail of agent stdout and stderr.", runtimeSchema, true, false, true, false),
		tool("steward_egress", "Inspect agent egress", "Read bounded allow/deny counters and the last destination for the signed egress grant.", runtimeSchema, true, false, true, false),
		tool("steward_start", "Start agent", "Start an admitted agent workload.", runtimeSchema, false, false, true, false),
		tool("steward_stop", "Stop agent", "Stop an admitted agent workload.", runtimeSchema, false, true, true, false),
		tool("steward_destroy", "Destroy agent", "Destroy the admitted workload while retaining separately managed lineage state.", runtimeSchema, false, true, true, false),
		tool("steward_purge_state", "Purge agent state", "Permanently remove one absent, signed tenant lineage state volume.", map[string]any{
			"type": "object", "additionalProperties": false,
			"required": []string{"tenant_id", "node_id", "lineage_id", "generation"},
			"properties": map[string]any{
				"tenant_id":  map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
				"node_id":    map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
				"lineage_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 256},
				"generation": map[string]any{"type": "integer", "minimum": 1},
			},
		}, false, true, true, false),
		tool("steward_snapshot_state", "Snapshot agent state", "Create an immutable snapshot after the complete signed source lineage is destroyed.", stateSnapshotToolSchema(), false, false, true, false),
		tool("steward_clone_state", "Clone agent state", "Create a new quota-enforced copy-on-write lineage from an immutable same-tenant snapshot.", stateCloneToolSchema(), false, false, true, false),
		tool("steward_delete_snapshot", "Delete state snapshot", "Delete an immutable snapshot after every dependent clone is purged.", stateSnapshotToolSchema(), false, true, true, false),
	}
}

func stateSnapshotToolSchema() map[string]any {
	return map[string]any{
		"type": "object", "additionalProperties": false,
		"required": []string{"tenant_id", "node_id", "instance_id", "lineage_id", "generation", "snapshot_id"},
		"properties": map[string]any{
			"tenant_id":   map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"node_id":     map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
			"instance_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 256},
			"lineage_id":  map[string]any{"type": "string", "minLength": 1, "maxLength": 256},
			"generation":  map[string]any{"type": "integer", "minimum": 1},
			"snapshot_id": map[string]any{"type": "string", "minLength": 1, "maxLength": 128},
		},
	}
}

func stateCloneToolSchema() map[string]any {
	schema := stateSnapshotToolSchema()
	required := append(schema["required"].([]string), "source_lineage_id")
	properties := schema["properties"].(map[string]any)
	properties["source_lineage_id"] = map[string]any{"type": "string", "minLength": 1, "maxLength": 256}
	schema["required"] = required
	return schema
}

func (s *Server) configuredTools() []any {
	result := make([]any, 0, 16)
	if s.node != nil {
		result = append(result, nodeTools()...)
	}
	if s.control != nil {
		result = append(result, controlTools()...)
	}
	if s.tasks != nil {
		result = append(result, taskTools()...)
	}
	return result
}

func (s *Server) initializationMetadata() (string, string, string) {
	var title, description string
	switch {
	case s.node != nil && s.control != nil && s.tasks != nil:
		title = "Steward Node, Control Plane, and Task Operations"
		description = "Manage a locally authorized Steward node, its bundled control plane, and bounded Gateway task lifecycle through their public enforcement boundaries."
	case s.node != nil && s.control != nil:
		title = "Steward Node and Control Plane Operations"
		description = "Manage a locally authorized Steward node and its bundled control plane through their public enforcement boundaries."
	case s.node != nil && s.tasks != nil:
		title = "Steward Node and Task Operations"
		description = "Manage one locally authorized Steward node and bounded Gateway task lifecycle through their public enforcement boundaries."
	case s.control != nil:
		title = "Steward Control Plane Operations"
		description = "Manage tenants, node inventory, and exact signed-command delivery through Steward's bundled control plane."
	default:
		title = "Steward Node Operations"
		description = "Manage one locally authorized Steward node through its public enforcement boundary."
	}
	instructions := "Use read tools freely."
	if s.node != nil {
		instructions += " Confirm create, stop, destroy, and other node lifecycle mutations with the operator before invoking them."
	}
	if s.control != nil {
		instructions += " Control-plane MCP never issues operator or enrollment secrets. Mutation acknowledgments are model-visible safety checks, not authority; the configured operator credential and exact signed command remain authoritative."
	}
	if s.tasks != nil {
		instructions += " Task submission starts signed real-world work. The acknowledgment argument is not proof of human approval; signed permits and Gateway policy authorize the exact work. Terminal agent output is saved only in the configured owner-only, quota-bounded result directory."
	}
	return title, description, instructions
}

func tool(name, title, description string, schema map[string]any, readOnly, destructive, idempotent, openWorld bool) map[string]any {
	return map[string]any{
		"name": name, "title": title, "description": description, "inputSchema": schema,
		"annotations": map[string]any{
			"title": title, "readOnlyHint": readOnly, "destructiveHint": destructive,
			"idempotentHint": idempotent, "openWorldHint": openWorld,
		},
	}
}

func validID(raw []byte) bool {
	if len(raw) == 0 {
		return true
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return false
	}
	switch value.(type) {
	case string, json.Number, nil:
		return true
	default:
		return false
	}
}

func normalizedID(raw []byte) json.RawMessage {
	if validID(raw) && len(raw) != 0 {
		return raw
	}
	return json.RawMessage("null")
}
