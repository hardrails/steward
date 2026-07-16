package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

const maxControlResponse = 1 << 20

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
		!serviceRunIDPattern.MatchString(submission.RunID) {
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
	if dsse.DecodeStrictInto(raw, maximum, &payload) == nil && payload.Error != "" && payload.Message != "" {
		return nil, nil, fmt.Errorf("gateway %s: %s", payload.Error, payload.Message)
	}
	return nil, nil, fmt.Errorf("gateway returned HTTP %d", response.StatusCode)
}

func validAbsolutePath(value string) bool {
	return strings.HasPrefix(value, "/") && !strings.ContainsRune(value, '\x00') && value == strings.TrimSuffix(value, "/")
}
