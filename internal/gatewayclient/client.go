// Package gatewayclient provides the narrow, bounded Gateway task-lifecycle
// client shared by Steward operator tools. It intentionally exposes only the
// fixed status and observation operations, not an ambient HTTP capability.
package gatewayclient

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskprotocol"
)

const (
	taskStatusSchemaV1       = "steward.task-status.v1"
	maxTaskStatusWireBytes   = 2 << 20
	maxObservationBytes      = 1 << 20
	maxGatewayResponseHeader = 64 << 10
)

// ErrRedirect means Gateway tried to redirect a task-lifecycle request. The
// client never follows redirects, so its bearer token cannot cross origins.
var ErrRedirect = errors.New("gateway redirect refused")

// Phase identifies the latest durable task-lifecycle evidence phase.
type Phase string

const (
	PhaseAuthorize Phase = "authorize"
	PhaseDispatch  Phase = "dispatch"
	PhaseTerminal  Phase = "terminal"
)

// AgentTaskStatus is the terminal state reported by an agent service. It is
// evidence of what Gateway observed, not proof that the work was correct.
type AgentTaskStatus string

const (
	AgentReportedCompleted AgentTaskStatus = "agent_reported_completed"
	AgentReportedFailed    AgentTaskStatus = "agent_reported_failed"
	AgentReportedCancelled AgentTaskStatus = "agent_reported_cancelled"
)

// ObservedStatus is the agent-neutral state returned by one live observation.
type ObservedStatus string

const (
	ObservedQueued    ObservedStatus = "queued"
	ObservedRunning   ObservedStatus = "running"
	ObservedCompleted ObservedStatus = "completed"
	ObservedFailed    ObservedStatus = "failed"
	ObservedCancelled ObservedStatus = "cancelled"
)

const (
	StateAuthorizationRecorded = "authorization_recorded"
	StateDispatchAccepted      = "dispatch_accepted"
	StateFailedBeforeDispatch  = "failed_before_dispatch"
	StateObservationFailed     = "observation_failed"
)

// TaskLifecycleStatus mirrors Steward Gateway's steward.task-status.v1 wire
// response without importing Gateway's server implementation package.
// ObservationBase64 is present only on the request that first records a live
// terminal observation; Gateway does not retain or replay those raw bytes.
type TaskLifecycleStatus struct {
	SchemaVersion     string          `json:"schema_version"`
	TaskDigest        string          `json:"task_digest"`
	PermitDigest      string          `json:"permit_digest"`
	Phase             Phase           `json:"phase"`
	State             string          `json:"state"`
	RunID             string          `json:"run_id,omitempty"`
	TaskStatus        AgentTaskStatus `json:"task_status,omitempty"`
	ResultDigest      string          `json:"result_digest,omitempty"`
	ResponseBytes     int64           `json:"response_bytes,omitempty"`
	ErrorCode         string          `json:"error_code,omitempty"`
	ObservedStatus    ObservedStatus  `json:"observed_status,omitempty"`
	ObservationBase64 string          `json:"observation_base64,omitempty"`
}

// APIError is a valid structured error returned by Gateway. RetryAfter is set
// when Gateway supplies a valid delta-seconds Retry-After header.
type APIError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("gateway HTTP %d %s: %s", e.Status, e.Code, e.Message)
}

// Client calls one explicit literal-loopback Gateway origin.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

type taskLifecycleOperation uint8

const (
	taskLifecycleStatus taskLifecycleOperation = iota
	taskLifecycleObserve
)

// New creates a hardened task-lifecycle client. Gateway's service listener is
// loopback-only; remote operators reach it through an authenticated private
// management path such as an SSH tunnel.
func New(baseURL, token string) (*Client, error) {
	canonical, err := loopbackOrigin(baseURL)
	if err != nil {
		return nil, err
	}
	if !validToken(token) {
		return nil, errors.New("gateway token must contain 1 to 4096 visible ASCII bytes without whitespace")
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second, KeepAlive: 30 * time.Second}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		DisableCompression:     true,
		ResponseHeaderTimeout:  45 * time.Second,
		MaxResponseHeaderBytes: maxGatewayResponseHeader,
		IdleConnTimeout:        30 * time.Second,
		MaxIdleConns:           4,
		MaxIdleConnsPerHost:    2,
	}
	return &Client{
		baseURL: canonical,
		token:   token,
		http: &http.Client{
			Transport: transport,
			Timeout:   60 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrRedirect
			},
		},
	}, nil
}

// Status returns Gateway's durable lifecycle evidence without contacting the
// agent service.
func (c *Client) Status(ctx context.Context, taskDigest, permitDigest string) (TaskLifecycleStatus, error) {
	return c.do(ctx, taskLifecycleStatus, taskDigest, permitDigest)
}

// Observe asks Gateway to make one policy-bounded, bodyless status observation.
// Gateway, not the caller, selects the agent-service origin and status path.
func (c *Client) Observe(ctx context.Context, taskDigest, permitDigest string) (TaskLifecycleStatus, error) {
	return c.do(ctx, taskLifecycleObserve, taskDigest, permitDigest)
}

func (c *Client) do(ctx context.Context, operation taskLifecycleOperation, taskDigest, permitDigest string) (TaskLifecycleStatus, error) {
	if !validDigest(taskDigest) || !validDigest(permitDigest) {
		return TaskLifecycleStatus{}, errors.New("task and permit digests must each be sha256 followed by 64 lowercase hexadecimal characters")
	}
	method, suffix := http.MethodGet, ""
	if operation == taskLifecycleObserve {
		method, suffix = http.MethodPost, "/observe"
	} else if operation != taskLifecycleStatus {
		return TaskLifecycleStatus{}, errors.New("unsupported Gateway task lifecycle operation")
	}
	target := c.baseURL + "/v1/tasks/" + taskDigest + "/permits/" + permitDigest + suffix
	request, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return TaskLifecycleStatus{}, err
	}
	request.Header = http.Header{
		"Accept":          {"application/json"},
		"Accept-Encoding": {"identity"},
		"Authorization":   {"Bearer " + c.token},
		"User-Agent":      {"steward"},
	}
	response, err := c.http.Do(request)
	if err != nil {
		return TaskLifecycleStatus{}, fmt.Errorf("call Gateway task lifecycle: %w", err)
	}
	defer response.Body.Close()
	raw, err := readResponse(response)
	if err != nil {
		return TaskLifecycleStatus{}, err
	}
	if response.StatusCode != http.StatusOK {
		return TaskLifecycleStatus{}, decodeAPIError(response, raw)
	}
	status, fields, err := decodeTaskLifecycleStatus(raw)
	if err != nil {
		return TaskLifecycleStatus{}, fmt.Errorf("invalid Gateway task status response: %w", err)
	}
	if err := validateStatus(status, fields, operation, taskDigest, permitDigest); err != nil {
		return TaskLifecycleStatus{}, fmt.Errorf("invalid Gateway task status response: %w", err)
	}
	return status, nil
}

func decodeTaskLifecycleStatus(raw []byte) (TaskLifecycleStatus, map[string]json.RawMessage, error) {
	var status TaskLifecycleStatus
	if err := dsse.DecodeStrictInto(raw, maxTaskStatusWireBytes, &status); err != nil {
		return TaskLifecycleStatus{}, nil, err
	}
	// Strict decoding above has already rejected unknown and duplicate members.
	// Retain the member set as a separate wire concern so an explicit zero value
	// cannot masquerade as an omitted optional field in the public value type.
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		return TaskLifecycleStatus{}, nil, errors.New("task status response is not a JSON object")
	}
	return status, fields, nil
}

func readResponse(response *http.Response) ([]byte, error) {
	if len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" {
		return nil, errors.New("Gateway task lifecycle response has invalid content type")
	}
	encodings := response.Header.Values("Content-Encoding")
	if len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return nil, errors.New("Gateway task lifecycle response has invalid content encoding")
	}
	if response.ContentLength > maxTaskStatusWireBytes {
		return nil, errors.New("Gateway task lifecycle response exceeds 2 MiB")
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxTaskStatusWireBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Gateway task lifecycle response: %w", err)
	}
	if len(raw) > maxTaskStatusWireBytes {
		return nil, errors.New("Gateway task lifecycle response exceeds 2 MiB")
	}
	if response.ContentLength >= 0 && response.ContentLength != int64(len(raw)) {
		return nil, errors.New("Gateway task lifecycle response length is inconsistent")
	}
	return raw, nil
}

func decodeAPIError(response *http.Response, raw []byte) error {
	var payload struct {
		Code    string `json:"error"`
		Message string `json:"message"`
	}
	if err := dsse.DecodeStrictInto(raw, maxTaskStatusWireBytes, &payload); err != nil ||
		!identifier(payload.Code, 128) || len(payload.Message) == 0 || len(payload.Message) > 4096 || hasControl(payload.Message) {
		return fmt.Errorf("Gateway HTTP %d returned an invalid error response", response.StatusCode)
	}
	retryAfter, err := parseRetryAfter(response.Header)
	if err != nil {
		return fmt.Errorf("Gateway HTTP %d returned an invalid Retry-After header", response.StatusCode)
	}
	return &APIError{Status: response.StatusCode, Code: payload.Code, Message: payload.Message, RetryAfter: retryAfter}
}

func parseRetryAfter(header http.Header) (time.Duration, error) {
	values := header.Values("Retry-After")
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, errors.New("multiple Retry-After values")
	}
	seconds, err := strconv.Atoi(values[0])
	if err != nil || seconds < 1 || seconds > 3600 || strconv.Itoa(seconds) != values[0] {
		return 0, errors.New("invalid Retry-After delta-seconds")
	}
	return time.Duration(seconds) * time.Second, nil
}

func validateStatus(
	status TaskLifecycleStatus,
	fields map[string]json.RawMessage,
	operation taskLifecycleOperation,
	expectedTaskDigest, expectedPermitDigest string,
) error {
	if err := validateStatusFieldPresence(status, fields); err != nil {
		return err
	}
	if status.SchemaVersion != taskStatusSchemaV1 {
		return errors.New("unsupported schema version")
	}
	if status.TaskDigest != expectedTaskDigest {
		return errors.New("task digest does not match the request")
	}
	if status.PermitDigest != expectedPermitDigest {
		return errors.New("permit digest does not match the request")
	}
	if !validPhase(status.Phase) || !validState(status.State) {
		return errors.New("phase or state is unsupported")
	}
	if status.RunID != "" && !identifier(status.RunID, 128) {
		return errors.New("run ID is invalid")
	}
	if status.TaskStatus != "" && !validAgentTaskStatus(status.TaskStatus) {
		return errors.New("agent-reported status is unsupported")
	}
	if status.ResultDigest != "" && !validDigest(status.ResultDigest) {
		return errors.New("result digest is invalid")
	}
	if status.ResponseBytes < 0 || status.ResponseBytes > maxObservationBytes ||
		status.ErrorCode != "" && !identifier(status.ErrorCode, 128) {
		return errors.New("response length or error code is invalid")
	}
	if status.ObservedStatus != "" && !validObservedStatus(status.ObservedStatus) {
		return errors.New("observed status is unsupported")
	}
	if err := validateStatusOperation(status, fields, operation); err != nil {
		return err
	}
	if err := validateStatusShape(status); err != nil {
		return err
	}
	return validateObservation(status)
}

func validateStatusFieldPresence(status TaskLifecycleStatus, fields map[string]json.RawMessage) error {
	for _, name := range []string{"schema_version", "task_digest", "permit_digest", "phase", "state"} {
		if _, present := fields[name]; !present {
			return fmt.Errorf("required field %q is absent", name)
		}
	}
	optionalStrings := []struct {
		name  string
		value string
	}{
		{name: "run_id", value: status.RunID},
		{name: "task_status", value: string(status.TaskStatus)},
		{name: "result_digest", value: status.ResultDigest},
		{name: "error_code", value: status.ErrorCode},
		{name: "observed_status", value: string(status.ObservedStatus)},
		{name: "observation_base64", value: status.ObservationBase64},
	}
	for _, field := range optionalStrings {
		if _, present := fields[field.name]; present && field.value == "" {
			return fmt.Errorf("optional field %q is present but empty", field.name)
		}
	}
	if _, present := fields["response_bytes"]; present && status.ResponseBytes <= 0 {
		return errors.New("optional field \"response_bytes\" is present but not positive")
	}
	return nil
}

func validateStatusOperation(status TaskLifecycleStatus, fields map[string]json.RawMessage, operation taskLifecycleOperation) error {
	_, observed := fields["observed_status"]
	_, raw := fields["observation_base64"]
	switch operation {
	case taskLifecycleStatus:
		if observed || raw {
			return errors.New("durable status response includes live observation fields")
		}
	case taskLifecycleObserve:
		if status.State == StateAuthorizationRecorded {
			return errors.New("observation response contains authorization-only state")
		}
		if status.State == StateDispatchAccepted && !observed {
			return errors.New("nonterminal observation response has no observed status")
		}
	default:
		return errors.New("unsupported Gateway task lifecycle operation")
	}
	return nil
}

func validateStatusShape(status TaskLifecycleStatus) error {
	switch status.State {
	case StateAuthorizationRecorded:
		if status.Phase != PhaseAuthorize || hasTaskResult(status) {
			return errors.New("authorization status fields are inconsistent")
		}
	case StateDispatchAccepted:
		if status.Phase != PhaseDispatch || status.RunID == "" || status.TaskStatus != "" ||
			status.ResultDigest != "" || status.ResponseBytes != 0 || status.ErrorCode != "" {
			return errors.New("dispatch status fields are inconsistent")
		}
		if status.ObservedStatus != "" && status.ObservedStatus != ObservedQueued && status.ObservedStatus != ObservedRunning {
			return errors.New("dispatch has a terminal observed status")
		}
	case string(AgentReportedCompleted), string(AgentReportedFailed), string(AgentReportedCancelled):
		if status.Phase != PhaseTerminal || status.RunID == "" || string(status.TaskStatus) != status.State ||
			status.ResultDigest == "" || status.ResponseBytes < 1 || status.ErrorCode != "" {
			return errors.New("agent-reported terminal status fields are inconsistent")
		}
		wantObserved := observedForAgentStatus(status.TaskStatus)
		if status.ObservedStatus != "" && status.ObservedStatus != wantObserved {
			return errors.New("terminal observation does not match durable status")
		}
		if (status.ObservedStatus == "") != (status.ObservationBase64 == "") {
			return errors.New("terminal observation bytes and status must appear together")
		}
	case StateFailedBeforeDispatch:
		if status.Phase != PhaseTerminal || status.RunID != "" || status.TaskStatus != "" || status.ResultDigest != "" ||
			status.ObservedStatus != "" || status.ObservationBase64 != "" || status.ErrorCode == "" {
			return errors.New("pre-dispatch failure fields are inconsistent")
		}
	case StateObservationFailed:
		if status.Phase != PhaseTerminal || status.RunID == "" || status.TaskStatus != "" || status.ResultDigest != "" ||
			status.ObservedStatus != "" || status.ObservationBase64 != "" || status.ErrorCode == "" {
			return errors.New("observation failure fields are inconsistent")
		}
	}
	return nil
}

func validateObservation(status TaskLifecycleStatus) error {
	if status.ObservationBase64 == "" {
		return nil
	}
	if status.ObservedStatus != ObservedCompleted && status.ObservedStatus != ObservedFailed && status.ObservedStatus != ObservedCancelled {
		return errors.New("raw observation is not terminal")
	}
	if len(status.ObservationBase64) > base64.StdEncoding.EncodedLen(maxObservationBytes) {
		return errors.New("raw observation exceeds 1 MiB")
	}
	raw, err := base64.StdEncoding.DecodeString(status.ObservationBase64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != status.ObservationBase64 || len(raw) > maxObservationBytes {
		return errors.New("raw observation is not canonical bounded base64")
	}
	if int64(len(raw)) != status.ResponseBytes {
		return errors.New("raw observation length does not match durable metadata")
	}
	report, err := taskprotocol.ParseReport(raw, len(raw), status.RunID)
	if err != nil || string(report.Status) != string(status.ObservedStatus) || !report.Status.Terminal() {
		return errors.New("raw observation does not match the reported terminal state")
	}
	if status.ResultDigest != dsse.Digest(raw) {
		return errors.New("raw observation digest does not match durable metadata")
	}
	return nil
}

func hasTaskResult(status TaskLifecycleStatus) bool {
	return status.RunID != "" || status.TaskStatus != "" || status.ResultDigest != "" || status.ResponseBytes != 0 ||
		status.ErrorCode != "" || status.ObservedStatus != "" || status.ObservationBase64 != ""
}

func validPhase(value Phase) bool {
	return value == PhaseAuthorize || value == PhaseDispatch || value == PhaseTerminal
}

func validState(value string) bool {
	switch value {
	case StateAuthorizationRecorded, StateDispatchAccepted, StateFailedBeforeDispatch, StateObservationFailed,
		string(AgentReportedCompleted), string(AgentReportedFailed), string(AgentReportedCancelled):
		return true
	default:
		return false
	}
}

func validAgentTaskStatus(value AgentTaskStatus) bool {
	return value == AgentReportedCompleted || value == AgentReportedFailed || value == AgentReportedCancelled
}

func validObservedStatus(value ObservedStatus) bool {
	switch value {
	case ObservedQueued, ObservedRunning, ObservedCompleted, ObservedFailed, ObservedCancelled:
		return true
	default:
		return false
	}
}

func observedForAgentStatus(value AgentTaskStatus) ObservedStatus {
	switch value {
	case AgentReportedCompleted:
		return ObservedCompleted
	case AgentReportedFailed:
		return ObservedFailed
	case AgentReportedCancelled:
		return ObservedCancelled
	default:
		return ""
	}
}

func loopbackOrigin(value string) (string, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "http" || parsed.Opaque != "" || parsed.User != nil || parsed.Host == "" ||
		parsed.Path != "" || parsed.RawPath != "" || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", errors.New("Gateway URL must be an HTTP literal-loopback origin with an explicit port and no path")
	}
	host, portText, err := net.SplitHostPort(parsed.Host)
	port, portErr := strconv.Atoi(portText)
	address := net.ParseIP(host)
	if err != nil || portErr != nil || port < 1 || port > 65535 || strconv.Itoa(port) != portText || address == nil || !address.IsLoopback() {
		return "", errors.New("Gateway URL must be an HTTP literal-loopback origin with an explicit port and no path")
	}
	return parsed.String(), nil
}

func validToken(value string) bool {
	if len(value) < 1 || len(value) > 4096 {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for index := len("sha256:"); index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' && value[index] < 'a' || value[index] > 'f' {
			return false
		}
	}
	return true
}

func identifier(value string, maximum int) bool {
	if len(value) < 1 || len(value) > maximum {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func hasControl(value string) bool {
	for _, character := range value {
		if character < 0x20 || character == 0x7f {
			return true
		}
	}
	return false
}
