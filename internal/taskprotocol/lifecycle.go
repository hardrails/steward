// Package taskprotocol validates the agent-neutral task lifecycle wire format.
// It treats every report as untrusted service output; callers decide what, if
// anything, becomes durable evidence.
package taskprotocol

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hardrails/steward/internal/dsse"
)

type Status string

const (
	MaxReportBytes         = 1 << 20
	StatusQueued    Status = "queued"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

type Report struct {
	RunID  string
	Status Status
}

// ParseReport accepts one strict JSON object, including additional result
// fields, while rejecting duplicate members at every nesting level. The run ID
// must match the already-recorded dispatch; it is never selected by the caller.
func ParseReport(raw []byte, maximum int, expectedRunID string) (Report, error) {
	if maximum < 1 || maximum > MaxReportBytes || !identifier(expectedRunID) {
		return Report{}, errors.New("task status limits or expected run ID are invalid")
	}
	wrapper := make([]byte, 0, len(raw)+10)
	wrapper = append(wrapper, `{"value":`...)
	wrapper = append(wrapper, raw...)
	wrapper = append(wrapper, '}')
	var decoded struct {
		Value json.RawMessage `json:"value"`
	}
	if err := dsse.DecodeStrictInto(wrapper, maximum+10, &decoded); err != nil {
		return Report{}, errors.New("task status response is invalid or ambiguous JSON")
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(decoded.Value, &object); err != nil || object == nil {
		return Report{}, errors.New("task status response is not a JSON object")
	}
	var runID string
	if err := json.Unmarshal(object["run_id"], &runID); err != nil || runID != expectedRunID {
		return Report{}, errors.New("task status response does not match the dispatched run ID")
	}
	var status Status
	if err := json.Unmarshal(object["status"], &status); err != nil {
		return Report{}, errors.New("task status response has no bounded status")
	}
	switch status {
	case StatusQueued, StatusRunning, StatusCompleted, StatusFailed, StatusCancelled:
		return Report{RunID: runID, Status: status}, nil
	default:
		return Report{}, fmt.Errorf("task status response has unsupported status %q", status)
	}
}

func (status Status) Terminal() bool {
	return status == StatusCompleted || status == StatusFailed || status == StatusCancelled
}

func identifier(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}
