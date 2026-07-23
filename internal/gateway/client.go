package gateway

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
	"unicode/utf8"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	maxControlResponse          = 1 << 20
	maxControlErrorCodeBytes    = 128
	maxControlErrorMessageBytes = 4096
	maxControlRetryAfterSeconds = 3600
	maxControlReceiptNodeBytes  = 256
)

// ControlAPIError is one strictly decoded error from Gateway's host-local
// control API. RetryAfter is nonzero only when Gateway supplied one canonical,
// positive delta-seconds value within the control client's retry bound.
type ControlAPIError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

// Error preserves the text returned by the control client before structured
// errors were exposed. Callers should use errors.As instead of parsing it.
func (e *ControlAPIError) Error() string {
	return fmt.Sprintf("gateway %s: %s", e.Code, e.Message)
}

// ControlClient is the Executor's narrow, host-local client for the gateway
// Unix socket. It deliberately exposes grants rather than a generic HTTP
// method so an Executor bug cannot turn it into an ambient proxy capability.
type ControlClient struct {
	client *http.Client
}

func NewControlClient(socket string) (*ControlClient, error) {
	if !validAbsolutePath(socket) {
		return nil, errors.New("gateway control socket must be a clean absolute path")
	}
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "unix", socket)
		},
		ResponseHeaderTimeout:  35 * time.Second,
		MaxResponseHeaderBytes: maxHTTPHeaderBytes,
		IdleConnTimeout:        30 * time.Second,
	}
	return &ControlClient{client: &http.Client{Transport: transport, Timeout: 40 * time.Second}}, nil
}

func (c *ControlClient) Register(ctx context.Context, grant Grant) error {
	return c.call(ctx, http.MethodPost, "/v1/grants", grant, http.StatusCreated)
}

// ListInstanceEvents returns the durable, bounded Gateway outbox. Delivery is
// at least once: callers acknowledge only after the controller commits the
// entire returned batch.
func (c *ControlClient) ListInstanceEvents(ctx context.Context) ([]InstanceEvent, error) {
	var batch eventBatch
	if err := c.callInto(ctx, http.MethodGet, "/v1/events", nil, http.StatusOK, &batch); err != nil {
		return nil, err
	}
	if len(batch.Events) > maxInstanceEvents || validateRetainedEvents(batch.Events) != nil {
		return nil, errors.New("gateway controller event response is invalid")
	}
	events := make([]InstanceEvent, len(batch.Events))
	for index, event := range batch.Events {
		events[index] = cloneEvent(event)
	}
	return events, nil
}

// AckInstanceEvents durably removes only controller-committed event IDs.
func (c *ControlClient) AckInstanceEvents(ctx context.Context, eventIDs []string) error {
	if len(eventIDs) == 0 || len(eventIDs) > maxInstanceEvents {
		return errors.New("gateway controller event acknowledgement is invalid")
	}
	seen := make(map[string]struct{}, len(eventIDs))
	for _, id := range eventIDs {
		if !validInstanceEventID(id) {
			return errors.New("gateway controller event acknowledgement is invalid")
		}
		if _, duplicate := seen[id]; duplicate {
			return errors.New("gateway controller event acknowledgement contains a duplicate")
		}
		seen[id] = struct{}{}
	}
	return c.call(ctx, http.MethodPost, "/v1/events/ack", eventAck{EventIDs: eventIDs}, http.StatusNoContent)
}

// ListInteractionOutbox returns agent-authored requests not yet acknowledged by
// Control. The caller must commit the whole batch before acknowledging it.
func (c *ControlClient) ListInteractionOutbox(ctx context.Context) ([]Interaction, error) {
	var batch interactionBatch
	if err := c.callInto(ctx, http.MethodGet, "/v1/interactions/outbox", nil, http.StatusOK, &batch); err != nil {
		return nil, err
	}
	if validateRetainedInteractions(batch.Interactions) != nil {
		return nil, errors.New("gateway interaction outbox is invalid")
	}
	result := make([]Interaction, len(batch.Interactions))
	for index, interaction := range batch.Interactions {
		result[index] = cloneInteraction(interaction)
	}
	return result, nil
}

func (c *ControlClient) AckInteractions(ctx context.Context, interactionIDs []string) error {
	if len(interactionIDs) == 0 || len(interactionIDs) > maxInteractions {
		return errors.New("gateway interaction acknowledgement is invalid")
	}
	seen := make(map[string]struct{}, len(interactionIDs))
	for _, id := range interactionIDs {
		if !validInteractionID(id) {
			return errors.New("gateway interaction acknowledgement is invalid")
		}
		if _, duplicate := seen[id]; duplicate {
			return errors.New("gateway interaction acknowledgement contains a duplicate")
		}
		seen[id] = struct{}{}
	}
	return c.call(ctx, http.MethodPost, "/v1/interactions/ack",
		interactionAck{InteractionIDs: interactionIDs}, http.StatusNoContent)
}

func (c *ControlClient) ResolveInteraction(
	ctx context.Context,
	interactionID string,
	permitRaw, responseRaw []byte,
) (Interaction, error) {
	if !validInteractionID(interactionID) || len(permitRaw) == 0 ||
		len(permitRaw) > interactionpermit.MaxEnvelopeBytes ||
		len(responseRaw) == 0 || len(responseRaw) > interactionpermit.MaxResponseBytes {
		return Interaction{}, errors.New("gateway interaction response is invalid")
	}
	var result Interaction
	if err := c.callInto(ctx, http.MethodPost, "/v1/interactions/responses",
		interactionCourier(interactionID, permitRaw, responseRaw), http.StatusOK, &result); err != nil {
		return Interaction{}, err
	}
	if validateRetainedInteractions([]Interaction{result}) != nil || result.InteractionID != interactionID {
		return Interaction{}, errors.New("gateway interaction response result is invalid")
	}
	return result, nil
}

func (c *ControlClient) Inspect(ctx context.Context, grantID string) (Grant, error) {
	inspection, err := c.InspectWithPolicy(ctx, grantID)
	return inspection.Grant, err
}

// InspectWithPolicy returns the retained grant together with the deterministic,
// non-secret digest of its effective inference and egress route policy.
func (c *ControlClient) InspectWithPolicy(ctx context.Context, grantID string) (GrantInspection, error) {
	if !validGrantID(grantID) {
		return GrantInspection{}, errors.New("invalid gateway grant ID")
	}
	var inspection GrantInspection
	if err := c.callInto(ctx, http.MethodGet, "/v1/grants/"+url.PathEscape(grantID), nil, http.StatusOK, &inspection); err != nil {
		return GrantInspection{}, err
	}
	return inspection, nil
}

func (c *ControlClient) EgressStats(ctx context.Context, grantID string) (EgressStats, error) {
	if !validGrantID(grantID) {
		return EgressStats{}, errors.New("invalid gateway grant ID")
	}
	var stats EgressStats
	if err := c.callInto(ctx, http.MethodGet, "/v1/grants/"+url.PathEscape(grantID)+"/egress", nil, http.StatusOK, &stats); err != nil {
		return EgressStats{}, err
	}
	return stats, nil
}

func (c *ControlClient) Activate(ctx context.Context, grantID string) error {
	return c.grantAction(ctx, grantID, "activate")
}

func (c *ControlClient) Deactivate(ctx context.Context, grantID string) error {
	return c.grantAction(ctx, grantID, "deactivate")
}

func (c *ControlClient) Unregister(ctx context.Context, grantID string) error {
	if !validGrantID(grantID) {
		return errors.New("invalid gateway grant ID")
	}
	return c.call(ctx, http.MethodDelete, "/v1/grants/"+url.PathEscape(grantID), nil, http.StatusNoContent)
}

// SubmitTask dispatches one exact configured service operation using a
// canonical tenant-signed permit and the exact request bytes bound by it.
func (c *ControlClient) SubmitTask(
	ctx context.Context,
	grantID string,
	operationID string,
	taskPermit string,
	requestBody []byte,
) (ControlTaskSubmission, error) {
	if !validGrantID(grantID) || !routeID(operationID) ||
		len(requestBody) == 0 || int64(len(requestBody)) > taskpermit.MaxRequestBytes ||
		!validTaskJSON(requestBody, int(taskpermit.MaxRequestBytes)) {
		return ControlTaskSubmission{}, errors.New("invalid gateway control task submission")
	}
	rawPermit, err := taskpermit.DecodeHeader(taskPermit)
	if err != nil {
		return ControlTaskSubmission{}, errors.New("invalid gateway control task permit")
	}
	request := controlTaskSubmitRequest{
		SchemaVersion: controlTaskSubmitSchemaV1,
		GrantID:       grantID,
		OperationID:   operationID,
		TaskPermit:    taskPermit,
		RequestBase64: base64.StdEncoding.EncodeToString(requestBody),
	}
	var submission ControlTaskSubmission
	if err := c.callStrictInto(ctx, http.MethodPost, "/v1/tasks", request, http.StatusOK, &submission); err != nil {
		return ControlTaskSubmission{}, err
	}
	if submission.SchemaVersion != ControlTaskSubmissionSchemaV1 ||
		!serviceTaskDigestPattern.MatchString(submission.TaskDigest) ||
		submission.PermitDigest != dsse.Digest(rawPermit) ||
		!serviceRunIDPattern.MatchString(submission.RunID) ||
		!validControlReceiptNodeID(submission.ReceiptNodeID) ||
		submission.ReceiptEpoch == 0 ||
		!canonicalControlReceiptPublicKey(submission.ReceiptPublicKey) {
		return ControlTaskSubmission{}, errors.New("gateway control task submission response is invalid")
	}
	return submission, nil
}

// TaskStatus reads only the durable lifecycle state for one exact task and
// permit identity. It does not contact the managed agent.
func (c *ControlClient) TaskStatus(
	ctx context.Context,
	taskDigest string,
	permitDigest string,
) (TaskLifecycleStatus, error) {
	return c.taskLifecycle(ctx, http.MethodGet, taskDigest, permitDigest, "")
}

// ObserveTask performs one policy-throttled live status observation for one
// exact dispatched task. Gateway retains the existing grant-revocation and
// terminal-evidence rules used by its service interface.
func (c *ControlClient) ObserveTask(
	ctx context.Context,
	taskDigest string,
	permitDigest string,
) (TaskLifecycleStatus, error) {
	return c.taskLifecycle(ctx, http.MethodPost, taskDigest, permitDigest, "observe")
}

func (c *ControlClient) taskLifecycle(
	ctx context.Context,
	method string,
	taskDigest string,
	permitDigest string,
	action string,
) (TaskLifecycleStatus, error) {
	path, err := controlTaskPath(taskDigest, permitDigest, action)
	if err != nil {
		return TaskLifecycleStatus{}, err
	}
	var status TaskLifecycleStatus
	if err := c.callStrictInto(ctx, method, path, nil, http.StatusOK, &status); err != nil {
		return TaskLifecycleStatus{}, err
	}
	if status.SchemaVersion != TaskStatusSchemaV1 ||
		status.TaskDigest != taskDigest || status.PermitDigest != permitDigest ||
		status.Phase != connectorledger.Authorize &&
			status.Phase != connectorledger.Dispatch &&
			status.Phase != connectorledger.Terminal {
		return TaskLifecycleStatus{}, errors.New("gateway control task status response is invalid")
	}
	if status.ObservationBase64 != "" {
		raw, decodeErr := base64.StdEncoding.DecodeString(status.ObservationBase64)
		if decodeErr != nil || len(raw) == 0 || int64(len(raw)) > maxTaskObservationResponseBytes ||
			base64.StdEncoding.EncodeToString(raw) != status.ObservationBase64 {
			return TaskLifecycleStatus{}, errors.New("gateway control task observation response is invalid")
		}
	}
	return status, nil
}

// ExportTaskEvidence returns only the original signed authorize, dispatch, and
// terminal receipt lines for one complete lifecycle task.
func (c *ControlClient) ExportTaskEvidence(
	ctx context.Context,
	taskDigest string,
	permitDigest string,
) ([]byte, error) {
	path, err := controlTaskPath(taskDigest, permitDigest, "evidence")
	if err != nil {
		return nil, err
	}
	raw, header, err := c.callRaw(
		ctx,
		http.MethodGet,
		path,
		nil,
		http.StatusOK,
		connectorledger.MaxPortableTaskEvidenceBytes,
	)
	if err != nil {
		return nil, err
	}
	contentTypes := header.Values("Content-Type")
	if len(contentTypes) != 1 || contentTypes[0] != controlTaskEvidenceMediaType ||
		len(raw) == 0 || raw[len(raw)-1] != '\n' {
		return nil, errors.New("gateway control task evidence response is invalid")
	}
	return raw, nil
}

func controlTaskPath(taskDigest, permitDigest, action string) (string, error) {
	if !serviceTaskDigestPattern.MatchString(taskDigest) ||
		!serviceTaskDigestPattern.MatchString(permitDigest) ||
		action != "" && action != "observe" && action != "evidence" {
		return "", errors.New("invalid gateway control task identity")
	}
	path := "/v1/tasks/" + taskDigest + "/permits/" + permitDigest
	if action != "" {
		path += "/" + action
	}
	return path, nil
}

func (c *ControlClient) grantAction(ctx context.Context, grantID, action string) error {
	if !validGrantID(grantID) {
		return errors.New("invalid gateway grant ID")
	}
	return c.call(ctx, http.MethodPost, "/v1/grants/"+url.PathEscape(grantID)+"/"+action, nil, http.StatusOK)
}

func (c *ControlClient) call(ctx context.Context, method, path string, body any, want int) error {
	return c.callInto(ctx, method, path, body, want, nil)
}

func (c *ControlClient) callInto(ctx context.Context, method, path string, body any, want int, target any) error {
	raw, _, err := c.callRaw(ctx, method, path, body, want, maxControlResponse)
	if err != nil {
		return err
	}
	if target != nil {
		if len(raw) == 0 || json.Unmarshal(raw, target) != nil {
			return errors.New("gateway control response is invalid")
		}
	}
	return nil
}

func (c *ControlClient) callStrictInto(ctx context.Context, method, path string, body any, want int, target any) error {
	raw, _, err := c.callRaw(ctx, method, path, body, want, maxControlResponse)
	if err != nil {
		return err
	}
	if len(raw) == 0 || dsse.DecodeStrictInto(raw, maxControlResponse, target) != nil {
		return errors.New("gateway control response is invalid")
	}
	return nil
}

func (c *ControlClient) callRaw(
	ctx context.Context,
	method string,
	path string,
	body any,
	want int,
	maximum int,
) ([]byte, http.Header, error) {
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, nil, err
		}
		if len(raw) > maxConfigBytes {
			return nil, nil, errors.New("gateway control request exceeds limit")
		}
		reader = bytes.NewReader(raw)
	}
	request, err := http.NewRequestWithContext(ctx, method, "http://gateway"+path, reader)
	if err != nil {
		return nil, nil, err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := c.client.Do(request)
	if err != nil {
		return nil, nil, err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(maximum)+1))
	if err != nil {
		return nil, nil, err
	}
	if len(raw) > maximum {
		return nil, nil, errors.New("gateway control response exceeds limit")
	}
	if response.StatusCode == want {
		return raw, response.Header.Clone(), nil
	}
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if response.StatusCode >= 400 && response.StatusCode <= 599 &&
		dsse.DecodeStrictInto(raw, maximum, &payload) == nil &&
		validControlError(payload.Error, payload.Message) {
		retryAfter, retryErr := parseControlRetryAfter(response.Header)
		if retryErr != nil {
			return nil, nil, fmt.Errorf("gateway returned HTTP %d with invalid Retry-After header", response.StatusCode)
		}
		return nil, nil, &ControlAPIError{
			Status: response.StatusCode, Code: payload.Error, Message: payload.Message, RetryAfter: retryAfter,
		}
	}
	return nil, nil, fmt.Errorf("gateway returned HTTP %d", response.StatusCode)
}

func validControlReceiptNodeID(value string) bool {
	if value == "" || len(value) > maxControlReceiptNodeBytes || !utf8.ValidString(value) ||
		strings.TrimSpace(value) != value || strings.ContainsRune(value, '\x00') ||
		!strings.HasSuffix(value, "/gateway") {
		return false
	}
	return bounded(strings.TrimSuffix(value, "/gateway"), 128)
}

func canonicalControlReceiptPublicKey(value string) bool {
	if len(value) != base64.StdEncoding.EncodedLen(ed25519.PublicKeySize) {
		return false
	}
	public, err := base64.StdEncoding.DecodeString(value)
	return err == nil && len(public) == ed25519.PublicKeySize &&
		base64.StdEncoding.EncodeToString(public) == value
}

func validControlError(code, message string) bool {
	if !routeID(code) || len(code) > maxControlErrorCodeBytes ||
		message == "" || len(message) > maxControlErrorMessageBytes || !utf8.ValidString(message) {
		return false
	}
	for _, character := range message {
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func parseControlRetryAfter(header http.Header) (time.Duration, error) {
	values := header.Values("Retry-After")
	if len(values) == 0 {
		return 0, nil
	}
	if len(values) != 1 {
		return 0, errors.New("multiple Retry-After values")
	}
	seconds, err := strconv.ParseUint(values[0], 10, 64)
	if err != nil || seconds == 0 || seconds > maxControlRetryAfterSeconds ||
		strconv.FormatUint(seconds, 10) != values[0] {
		return 0, errors.New("invalid Retry-After delta-seconds")
	}
	return time.Duration(seconds) * time.Second, nil
}

func validAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.ContainsRune(value, '\x00') && value == strings.TrimSuffix(value, "/")
}
