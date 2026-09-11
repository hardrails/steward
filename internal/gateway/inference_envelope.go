package gateway

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// This closed request profile constrains one OpenAI-compatible text chat call.
// It is not a tokenizer or pricing implementation. A consumer must still bind
// the exact provider/model context ceiling and tariff to its admitted allowance.
const boundedTextChatProfile = "openai-text-chat.v1"

var boundedChatFields = func() map[string]bool {
	fields := make(map[string]bool)
	for _, name := range strings.Fields(`model messages tools tool_choice parallel_tool_calls
		stop max_tokens max_completion_tokens n service_tier stream stream_options
		temperature top_p top_k min_p frequency_penalty presence_penalty repetition_penalty
		seed logprobs top_logprobs response_format reasoning_effort reasoning_history thinking
		user prompt_cache_key prompt_cache_isolation_key`) {
		fields[name] = true
	}
	return fields
}()

var errInferenceEnvelope = errors.New("request is outside the admitted text-chat envelope")

func boundedChatRequest(raw []byte, path string, cap int) ([]byte, error) {
	if path != "/v1/chat/completions" || cap < 1 {
		return nil, errInferenceEnvelope
	}
	var document map[string]json.RawMessage
	if err := json.Unmarshal(raw, &document); err != nil {
		return nil, errInferenceEnvelope
	}
	for key := range document {
		if !boundedChatFields[key] {
			return nil, errInferenceEnvelope
		}
	}
	if value, exists := document["n"]; exists && string(value) != "1" {
		return nil, errInferenceEnvelope
	}
	if value, exists := document["service_tier"]; exists && !jsonStringIs(value, "default") {
		return nil, errInferenceEnvelope
	}
	document["n"] = json.RawMessage("1")
	document["service_tier"] = json.RawMessage(`"default"`)
	maximum, hasMaximum := document["max_tokens"]
	alias, hasAlias := document["max_completion_tokens"]
	if hasMaximum && hasAlias {
		return nil, errInferenceEnvelope
	}
	if hasAlias {
		maximum = alias
	}
	limit := int64(cap)
	if hasMaximum || hasAlias {
		var requested int64
		if err := json.Unmarshal(maximum, &requested); err != nil || requested < 1 {
			return nil, errInferenceEnvelope
		}
		if requested < limit {
			limit = requested
		}
	}
	delete(document, "max_completion_tokens")
	document["max_tokens"] = json.RawMessage(fmt.Sprintf("%d", limit))
	var messages []map[string]json.RawMessage
	if err := json.Unmarshal(document["messages"], &messages); err != nil || len(messages) == 0 {
		return nil, errInferenceEnvelope
	}
	for _, message := range messages {
		for key := range message {
			switch key {
			case "role", "content", "name", "tool_calls", "tool_call_id", "reasoning_content":
			default:
				return nil, errInferenceEnvelope
			}
		}
		if !textChatContent(message["content"]) {
			return nil, errInferenceEnvelope
		}
		if calls, exists := message["tool_calls"]; exists && !functionToolsOnly(calls) {
			return nil, errInferenceEnvelope
		}
	}
	if tools, exists := document["tools"]; exists && !functionToolsOnly(tools) {
		return nil, errInferenceEnvelope
	}
	rewritten, err := json.Marshal(document)
	if err != nil || len(rewritten) > maxProxyBody {
		return nil, errInferenceEnvelope
	}
	return rewritten, nil
}

func jsonStringIs(raw json.RawMessage, want string) bool {
	var value string
	return json.Unmarshal(raw, &value) == nil && value == want
}

func textChatContent(raw json.RawMessage) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return true // Assistant tool calls can have no text content.
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		return true
	}
	var blocks []map[string]json.RawMessage
	if json.Unmarshal(raw, &blocks) != nil {
		return false
	}
	for _, block := range blocks {
		if len(block) != 2 || !jsonStringIs(block["type"], "text") || json.Unmarshal(block["text"], &text) != nil || string(block["text"]) == "null" {
			return false
		}
	}
	return true
}

func functionToolsOnly(raw json.RawMessage) bool {
	var tools []map[string]json.RawMessage
	if json.Unmarshal(raw, &tools) != nil {
		return false
	}
	for _, tool := range tools {
		if !jsonStringIs(tool["type"], "function") {
			return false
		}
		for key := range tool {
			if key != "type" && key != "function" && key != "id" {
				return false
			}
		}
	}
	return true
}
