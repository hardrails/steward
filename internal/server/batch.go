package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/hardrails/steward/internal/runtime"
)

// batchRequest is the body of POST /v1/instances/batch: an ordered list of
// lifecycle operations to execute one after another, against the live tracker,
// in exactly the order given.
type batchRequest struct {
	Operations []batchOperation `json:"operations"`
}

// batchOperation is one entry in a batchRequest. Op selects which lifecycle
// verb to run and which of the remaining fields apply, mirroring the field
// each single-instance endpoint already accepts for that verb exactly rather
// than inventing a new shape:
//   - "provision" mirrors provisionRequest: InstanceID (required) and Spec
//     (optional) are used; RuntimeRef is ignored.
//   - "start", "stop", and "destroy" mirror the single-instance routes, which
//     address an instance by the `runtime_ref` path parameter: RuntimeRef
//     (required) is used; InstanceID and Spec are ignored.
type batchOperation struct {
	Op         string          `json:"op"`
	InstanceID string          `json:"instance_id,omitempty"`
	RuntimeRef string          `json:"runtime_ref,omitempty"`
	Spec       json.RawMessage `json:"spec,omitempty"`
}

// batchOperationResult is one entry of batchResponse.Results, positionally
// aligned with the batchRequest.Operations entry that produced it. Exactly one
// of Instance or Error is set, mirroring the single-instance endpoints'
// success/error split: Instance is the same body a successful single-op call
// would return, and Error is the same body a failed single-op call would
// return (status is that call's HTTP status). InstanceID/RuntimeRef echo
// whichever identifier the request operation carried, so a result is
// self-describing without cross-referencing the original request by index.
type batchOperationResult struct {
	Op         string            `json:"op"`
	InstanceID string            `json:"instance_id,omitempty"`
	RuntimeRef string            `json:"runtime_ref,omitempty"`
	Status     int               `json:"status"`
	Instance   *runtime.Instance `json:"instance,omitempty"`
	Error      *errorResponse    `json:"error,omitempty"`
}

// batchResponse wraps the per-operation results in a named object under a
// stable `results` key, matching instancesResponse's object-wrapped
// convention (see its doc comment) rather than returning a bare top-level
// array.
type batchResponse struct {
	// Results is one entry per input operation, in the same order, produced by
	// executing every operation in that order against the live tracker and
	// continuing regardless of any individual operation's outcome. A batch is
	// NOT an all-or-nothing transaction: operation 3 of 5 failing does not
	// prevent 1, 2, 4, and 5 from running, and each result reports its own
	// outcome — partial success is always visible per-operation, never
	// silently swallowed. Never null: an empty Operations list yields an
	// empty Results array.
	Results []batchOperationResult `json:"results"`
}

// handleBatch executes an ordered list of lifecycle operations against the
// live tracker, one at a time, in request order, and reports one result per
// operation. It is deliberately NOT a transaction: operations are not rolled
// back on a later failure, so a caller can rely on an earlier operation's
// effect being visible to a later one in the same batch (for example,
// destroying an instance_id and re-provisioning it within one batch). See
// batchResponse's doc comment and docs/batch-instance-operations.md for the
// full partial-success and idempotency discussion.
//
// Each constituent operation is executed by calling straight into the same
// tracker method the matching single-instance endpoint calls (Provision,
// Start, Stop, Destroy) — batching adds no logic of its own on top, so a
// batched operation keeps exactly the idempotency behavior its single-op
// endpoint already has. See handleProvision/handleStart/handleStop/
// handleDestroy in server.go for that per-verb behavior.
func (s *Server) handleBatch(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBodyBytes)

	var req batchRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "request_too_large",
				"request body exceeds the 1MiB limit")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_request", "request body must be a JSON object")
		return
	}

	results := make([]batchOperationResult, len(req.Operations))
	for i, op := range req.Operations {
		results[i] = s.executeBatchOperation(op)
	}
	writeJSON(w, http.StatusOK, batchResponse{Results: results})
}

// executeBatchOperation runs a single batchOperation and reports its result in
// the same shape (and against the same tracker methods, for the same
// idempotency behavior) as the matching single-instance handler in server.go.
func (s *Server) executeBatchOperation(op batchOperation) batchOperationResult {
	switch op.Op {
	case "provision":
		return s.batchProvision(op)
	case "start":
		return s.batchTransition(op, s.tracker.Start)
	case "stop":
		return s.batchTransition(op, s.tracker.Stop)
	case "destroy":
		return s.batchTransition(op, s.tracker.Destroy)
	default:
		return batchOperationResult{
			Op:     op.Op,
			Status: http.StatusBadRequest,
			Error: &errorResponse{
				Error:   "invalid_request",
				Message: fmt.Sprintf("op %q must be one of provision, start, stop, destroy", op.Op),
			},
		}
	}
}

// batchProvision runs one "provision" batch operation. It mirrors
// handleProvision's validation and tracker call exactly (including passing
// generation 0, the same "no fencing" value the direct-REST path always
// uses), so a batched provision is idempotent on instance_id the same way a
// single POST /v1/instances call is.
func (s *Server) batchProvision(op batchOperation) batchOperationResult {
	if op.InstanceID == "" {
		return batchOperationResult{
			Op:     op.Op,
			Status: http.StatusBadRequest,
			Error:  &errorResponse{Error: "invalid_request", Message: "instance_id is required"},
		}
	}

	spec := op.Spec
	if bytes.Equal(bytes.TrimSpace(spec), []byte("null")) {
		spec = nil
	}
	if len(spec) > 0 && !runtime.IsJSONObject(spec) {
		return batchOperationResult{
			Op:         op.Op,
			InstanceID: op.InstanceID,
			Status:     http.StatusBadRequest,
			Error:      &errorResponse{Error: "invalid_request", Message: "spec must be a JSON object"},
		}
	}

	inst, created, err := s.tracker.Provision(op.InstanceID, 0, spec)
	if err != nil {
		if errors.Is(err, runtime.ErrCapacityExceeded) {
			return batchOperationResult{
				Op:         op.Op,
				InstanceID: op.InstanceID,
				Status:     http.StatusServiceUnavailable,
				Error:      &errorResponse{Error: "capacity_exceeded", Message: "instance capacity reached; retry later"},
			}
		}
		s.logger.Error("batch provision failed", "err", err)
		return batchOperationResult{
			Op:         op.Op,
			InstanceID: op.InstanceID,
			Status:     http.StatusInternalServerError,
			Error:      &errorResponse{Error: "internal_error", Message: "operation failed"},
		}
	}

	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	return batchOperationResult{Op: op.Op, InstanceID: op.InstanceID, Status: status, Instance: inst}
}

// batchTransition runs one "start"/"stop"/"destroy" batch operation by calling
// transition (the tracker method for that verb — Start, Stop, or Destroy, all
// of which share the func(string) (*runtime.Instance, error) shape) with the
// operation's runtime_ref, and maps the result the same way s.respond does for
// the single-instance endpoints.
func (s *Server) batchTransition(op batchOperation, transition func(string) (*runtime.Instance, error)) batchOperationResult {
	if op.RuntimeRef == "" {
		return batchOperationResult{
			Op:     op.Op,
			Status: http.StatusBadRequest,
			Error:  &errorResponse{Error: "invalid_request", Message: "runtime_ref is required"},
		}
	}

	inst, err := transition(op.RuntimeRef)
	if err != nil {
		if errors.Is(err, runtime.ErrNotFound) {
			return batchOperationResult{
				Op:         op.Op,
				RuntimeRef: op.RuntimeRef,
				Status:     http.StatusNotFound,
				Error:      &errorResponse{Error: "unknown_runtime_ref", Message: "no instance with that runtime_ref"},
			}
		}
		s.logger.Error("batch operation failed", "op", op.Op, "err", err)
		return batchOperationResult{
			Op:         op.Op,
			RuntimeRef: op.RuntimeRef,
			Status:     http.StatusInternalServerError,
			Error:      &errorResponse{Error: "internal_error", Message: "operation failed"},
		}
	}
	return batchOperationResult{Op: op.Op, RuntimeRef: op.RuntimeRef, Status: http.StatusOK, Instance: inst}
}
