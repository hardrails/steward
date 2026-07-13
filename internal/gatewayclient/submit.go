package gatewayclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	pathpkg "path"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

const maxTaskSubmitResponseBytes = 16 << 10

// TaskSubmission is one exact, already-authorized lifecycle request. The
// caller obtains every field from a verified owner-only task bundle.
type TaskSubmission struct {
	ServicePath   string
	OperationPath string
	ContentType   string
	Request       []byte
	Permit        []byte
}

// TaskReceipt identifies whether Gateway durably recorded this dispatch or
// replayed the previously recorded run identity for the same signed permit.
type TaskReceipt string

const (
	TaskReceiptRecorded TaskReceipt = "recorded"
	TaskReceiptReplayed TaskReceipt = "replayed"
)

// TaskSubmissionResult contains only the durable dispatch identity. It never
// contains an agent result or a copy of the submitted task body.
type TaskSubmissionResult struct {
	RunID   string
	Receipt TaskReceipt
}

// Submit sends one exact lifecycle request through Gateway. It does not expose
// ambient HTTP controls: the method is POST, the origin belongs to Client, and
// query strings, caller-selected headers, and redirects are unavailable.
func (c *Client) Submit(ctx context.Context, submission TaskSubmission) (TaskSubmissionResult, error) {
	if !validServicePath(submission.ServicePath) || !validOperationPath(submission.OperationPath) {
		return TaskSubmissionResult{}, errors.New("task submission has an invalid service or operation path")
	}
	if submission.ContentType != "application/json" || !validTaskRequest(submission.Request) {
		return TaskSubmissionResult{}, errors.New("task submission request must be one exact bounded application/json value")
	}
	permitHeader, err := taskpermit.EncodeHeader(submission.Permit)
	if err != nil {
		return TaskSubmissionResult{}, fmt.Errorf("encode task permit: %w", err)
	}
	target := c.baseURL + strings.TrimSuffix(submission.ServicePath, "/") + submission.OperationPath
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(submission.Request))
	if err != nil {
		return TaskSubmissionResult{}, err
	}
	request.ContentLength = int64(len(submission.Request))
	request.Header = http.Header{
		"Accept":                {"application/json"},
		"Accept-Encoding":       {"identity"},
		"Authorization":         {"Bearer " + c.token},
		"Content-Type":          {submission.ContentType},
		"User-Agent":            {"steward"},
		"X-Steward-Task-Permit": {permitHeader},
	}
	response, err := c.http.Do(request)
	if err != nil {
		return TaskSubmissionResult{}, fmt.Errorf("call Gateway task submit: %w", err)
	}
	defer response.Body.Close()
	raw, err := readTaskSubmitResponse(response)
	if err != nil {
		return TaskSubmissionResult{}, err
	}
	if !successfulTaskSubmitStatus(response.StatusCode) {
		return TaskSubmissionResult{}, decodeAPIError(response, raw)
	}
	receipt, err := taskSubmitHeaders(response.Header)
	if err != nil {
		return TaskSubmissionResult{}, err
	}
	var result struct {
		RunID string `json:"run_id"`
	}
	if err := dsse.DecodeStrictInto(raw, maxTaskSubmitResponseBytes, &result); err != nil || !identifier(result.RunID, 128) {
		return TaskSubmissionResult{}, errors.New("Gateway task submit response has an invalid run ID")
	}
	canonical, err := json.Marshal(result)
	if err != nil || !bytes.Equal(raw, canonical) {
		return TaskSubmissionResult{}, errors.New("Gateway task submit response is not the canonical run ID object")
	}
	return TaskSubmissionResult{RunID: result.RunID, Receipt: receipt}, nil
}

func readTaskSubmitResponse(response *http.Response) ([]byte, error) {
	if len(response.Header.Values("Content-Type")) != 1 || response.Header.Get("Content-Type") != "application/json" {
		return nil, errors.New("Gateway task submit response has invalid content type")
	}
	encodings := response.Header.Values("Content-Encoding")
	if len(encodings) > 1 || len(encodings) == 1 && !strings.EqualFold(strings.TrimSpace(encodings[0]), "identity") {
		return nil, errors.New("Gateway task submit response has invalid content encoding")
	}
	if response.ContentLength < 0 || response.ContentLength > maxTaskSubmitResponseBytes {
		return nil, fmt.Errorf("Gateway task submit response must declare at most %d bytes", maxTaskSubmitResponseBytes)
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxTaskSubmitResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Gateway task submit response: %w", err)
	}
	if len(raw) > maxTaskSubmitResponseBytes {
		return nil, fmt.Errorf("Gateway task submit response exceeds %d bytes", maxTaskSubmitResponseBytes)
	}
	if response.ContentLength != int64(len(raw)) {
		return nil, errors.New("Gateway task submit response length is inconsistent")
	}
	return raw, nil
}

func taskSubmitHeaders(header http.Header) (TaskReceipt, error) {
	if !singleHeaderEquals(header, "X-Steward-Service-Grant", "active") ||
		!singleHeaderEquals(header, "Cache-Control", "no-store") ||
		!singleHeaderEquals(header, "X-Content-Type-Options", "nosniff") {
		return "", errors.New("Gateway task submit response does not prove one active service grant")
	}
	values := header.Values("X-Steward-Task-Receipt")
	if len(values) != 1 {
		return "", errors.New("Gateway task submit response does not contain one durable task receipt marker")
	}
	receipt := TaskReceipt(values[0])
	if receipt != TaskReceiptRecorded && receipt != TaskReceiptReplayed {
		return "", errors.New("Gateway task submit response has an invalid task receipt marker")
	}
	return receipt, nil
}

func singleHeaderEquals(header http.Header, name, value string) bool {
	values := header.Values(name)
	return len(values) == 1 && values[0] == value
}

func successfulTaskSubmitStatus(status int) bool {
	return status == http.StatusOK || status == http.StatusCreated || status == http.StatusAccepted
}

func validTaskRequest(raw []byte) bool {
	if len(raw) == 0 || int64(len(raw)) > taskpermit.MaxRequestBytes {
		return false
	}
	wrapper := make([]byte, 0, len(raw)+10)
	wrapper = append(wrapper, `{"value":`...)
	wrapper = append(wrapper, raw...)
	wrapper = append(wrapper, '}')
	var decoded struct {
		Value json.RawMessage `json:"value"`
	}
	return dsse.DecodeStrictInto(wrapper, int(taskpermit.MaxRequestBytes)+10, &decoded) == nil
}

func validServicePath(value string) bool {
	const prefix = "/v1/services/grant-"
	if len(value) != len(prefix)+64+1 || !strings.HasPrefix(value, prefix) || value[len(value)-1] != '/' {
		return false
	}
	return lowercaseHex(value[len(prefix) : len(value)-1])
}

func validOperationPath(value string) bool {
	if !strings.HasPrefix(value, "/") || len(value) > 2048 || pathpkg.Clean(value) != value || strings.Contains(value, "//") {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' || strings.ContainsRune("/-._~!$&'()*+,;=:@", rune(character)) {
			continue
		}
		return false
	}
	return true
}

func lowercaseHex(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] < '0' || value[index] > '9' && value[index] < 'a' || value[index] > 'f' {
			return false
		}
	}
	return true
}
