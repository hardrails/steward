package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

type taskRequestSubmit struct {
	TaskPermit    string `json:"task_permit"`
	RequestBase64 string `json:"request_base64"`
}

type taskRequestPage struct {
	Tasks     []controlstore.TaskRequest `json:"tasks"`
	NextAfter string                     `json:"next_after,omitempty"`
}

type taskResultResponse struct {
	TaskID        string `json:"task_id"`
	ResultDigest  string `json:"result_digest"`
	ResponseBytes int64  `json:"response_bytes"`
	ResultBase64  string `json:"result_base64"`
}

func (server *Server) taskRequests(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPost {
		methodNotAllowed(writer, http.MethodGet, http.MethodPost)
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	tenantID := request.PathValue("tenant_id")
	if request.Method == http.MethodPost {
		if !noQuery(writer, request) {
			return
		}
		var input taskRequestSubmit
		if !server.decode(writer, request, &input) {
			return
		}
		body, err := base64.StdEncoding.DecodeString(input.RequestBase64)
		if err != nil || len(body) == 0 || int64(len(body)) > taskpermit.MaxRequestBytes ||
			base64.StdEncoding.EncodeToString(body) != input.RequestBase64 {
			writeError(writer, http.StatusBadRequest, "invalid_request", "request_base64 must be one canonical task body of at most 64 KiB")
			return
		}
		task, created, err := server.store.SubmitTaskRequest(identity, controlstore.TaskRequestInput{
			TenantID: tenantID, TaskPermit: input.TaskPermit, Request: body,
		}, server.now())
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		writeJSON(writer, status, task)
		return
	}
	page, ok := parsePage(writer, request)
	if !ok {
		return
	}
	if page.limit > 100 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "task request limit must be between 1 and 100")
		return
	}
	tasks, err := server.store.ListTaskRequests(identity, tenantID)
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	selected, next, err := pageTaskRequests(tasks, page)
	if err != nil {
		server.logger.Error("control task request page exceeded response bound", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode a bounded task page")
		return
	}
	writeJSON(writer, http.StatusOK, taskRequestPage{Tasks: selected, NextAfter: next})
}

func (server *Server) taskRequest(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodDelete {
		methodNotAllowed(writer, http.MethodGet, http.MethodDelete)
		return
	}
	if !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	tenantID, taskID := request.PathValue("tenant_id"), request.PathValue("task_id")
	if request.Method == http.MethodGet {
		if !emptyTaskRequestBody(writer, request) {
			return
		}
		task, found, err := server.store.GetTaskRequest(identity, tenantID, taskID)
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		if !found {
			writeError(writer, http.StatusNotFound, "not_found", "task request was not found")
			return
		}
		writeJSON(writer, http.StatusOK, task)
		return
	}
	if !emptyTaskRequestBody(writer, request) {
		return
	}
	task, _, err := server.store.CancelTaskRequest(identity, tenantID, taskID, server.now())
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	writeJSON(writer, http.StatusOK, task)
}

func (server *Server) taskResult(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	if !method(writer, request, http.MethodGet) || !noQuery(writer, request) ||
		!emptyTaskRequestBody(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	result, found, err := server.store.GetTaskResult(
		identity, request.PathValue("tenant_id"), request.PathValue("task_id"),
	)
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	if !found {
		writeError(writer, http.StatusNotFound, "not_found", "task request was not found")
		return
	}
	if len(result.Result) == 0 {
		writeError(writer, http.StatusConflict, "task_result_unavailable", "a bounded terminal task result has not been retained")
		return
	}
	writeJSON(writer, http.StatusOK, taskResultResponse{
		TaskID: result.TaskID, ResultDigest: result.ResultDigest, ResponseBytes: result.ResponseBytes,
		ResultBase64: base64.StdEncoding.EncodeToString(result.Result),
	})
}

func (server *Server) executorTaskPoll(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	raw, ok := server.readBody(writer, request)
	if !ok {
		return
	}
	var poll controlprotocol.ExecutorTaskPollRequestV1
	if len(raw) > controlprotocol.MaxExecutorTaskDeliveryBytes ||
		dsse.DecodeStrictInto(raw, controlprotocol.MaxExecutorTaskDeliveryBytes, &poll) != nil ||
		poll.Validate() != nil || poll.NodeID != identity.NodeID {
		writeError(writer, http.StatusBadRequest, "invalid_request", "executor task poll is invalid")
		return
	}
	deliveries, err := server.store.PollTaskRequests(identity, server.now(), server.lease, poll.Limit)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, controlprotocol.ExecutorTaskPollResponseV1{
		SchemaVersion: controlprotocol.ExecutorTaskPollSchemaV1, Deliveries: deliveries,
	})
}

func (server *Server) executorTaskReport(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPost) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	raw, ok := server.readBody(writer, request)
	if !ok {
		return
	}
	var report controlprotocol.ExecutorTaskReportV1
	if len(raw) > controlprotocol.MaxExecutorTaskDeliveryBytes ||
		dsse.DecodeStrictInto(raw, controlprotocol.MaxExecutorTaskDeliveryBytes, &report) != nil ||
		report.Validate() != nil || report.NodeID != identity.NodeID {
		writeError(writer, http.StatusBadRequest, "invalid_request", "executor task report is invalid")
		return
	}
	applied, err := server.store.ApplyTaskReport(identity, report, server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		Applied bool `json:"applied"`
	}{Applied: applied})
}

func pageTaskRequests(values []controlstore.TaskRequest, page pageRequest) ([]controlstore.TaskRequest, string, error) {
	start := 0
	if page.after != "" {
		found := false
		for index, task := range values {
			if task.TaskID == page.after {
				start, found = index+1, true
				break
			}
		}
		if !found {
			return nil, "", controlstore.ErrInvalid
		}
	}
	selected := make([]controlstore.TaskRequest, 0, min(page.limit, len(values)-start))
	for index := start; index < len(values) && len(selected) < page.limit; index++ {
		candidate := append(append([]controlstore.TaskRequest(nil), selected...), values[index])
		next := ""
		if index+1 < len(values) {
			next = values[index].TaskID
		}
		raw, err := json.Marshal(taskRequestPage{Tasks: candidate, NextAfter: next})
		if err != nil {
			return nil, "", err
		}
		if len(raw)+1 > maxResponseBytes {
			if len(selected) == 0 {
				return nil, "", errors.New("one valid task cannot fit the response limit")
			}
			break
		}
		selected = candidate
	}
	next := ""
	if start+len(selected) < len(values) {
		next = selected[len(selected)-1].TaskID
	}
	return selected, next, nil
}

func emptyTaskRequestBody(writer http.ResponseWriter, request *http.Request) bool {
	request.Body = http.MaxBytesReader(writer, request.Body, 1)
	body, err := io.ReadAll(request.Body)
	if err != nil || request.ContentLength != 0 || len(request.TransferEncoding) != 0 || len(body) != 0 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "task request operation must not include a body")
		return false
	}
	return true
}
