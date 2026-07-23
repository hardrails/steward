package controlplane

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/schedulepermit"
	"github.com/hardrails/steward/internal/taskpermit"
)

type taskScheduleSubmit struct {
	SchedulePermitBase64 string `json:"schedule_permit_base64"`
	RequestBase64        string `json:"request_base64"`
}

type taskSchedulePage struct {
	Schedules []controlstore.TaskSchedule `json:"schedules"`
	NextAfter string                      `json:"next_after,omitempty"`
}

func (server *Server) taskSchedules(writer http.ResponseWriter, request *http.Request) {
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
		var input taskScheduleSubmit
		if !server.decode(writer, request, &input) {
			return
		}
		permit, permitErr := base64.StdEncoding.DecodeString(input.SchedulePermitBase64)
		body, bodyErr := base64.StdEncoding.DecodeString(input.RequestBase64)
		if permitErr != nil || len(permit) == 0 || len(permit) > schedulepermit.MaxEnvelopeBytes ||
			base64.StdEncoding.EncodeToString(permit) != input.SchedulePermitBase64 ||
			bodyErr != nil || len(body) == 0 || int64(len(body)) > taskpermit.MaxRequestBytes ||
			base64.StdEncoding.EncodeToString(body) != input.RequestBase64 {
			writeError(writer, http.StatusBadRequest, "invalid_request", "schedule permit and request must use canonical base64 within their documented bounds")
			return
		}
		schedule, created, err := server.store.CreateTaskSchedule(identity, controlstore.TaskScheduleInput{
			TenantID: tenantID, SchedulePermit: permit, Request: body,
		}, server.now())
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		status := http.StatusOK
		if created {
			status = http.StatusCreated
		}
		writeJSON(writer, status, schedule)
		return
	}
	page, ok := parsePage(writer, request)
	if !ok {
		return
	}
	if page.limit > 100 {
		writeError(writer, http.StatusBadRequest, "invalid_request", "task schedule limit must be between 1 and 100")
		return
	}
	schedules, err := server.store.ListTaskSchedules(identity, tenantID)
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	selected, next, err := pageTaskSchedules(schedules, page)
	if err != nil {
		if errors.Is(err, controlstore.ErrInvalid) {
			writeError(writer, http.StatusBadRequest, "invalid_request", "task schedule cursor does not match a retained schedule")
			return
		}
		server.logger.Error("control task schedule page exceeded response bound", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode a bounded schedule page")
		return
	}
	writeJSON(writer, http.StatusOK, taskSchedulePage{Schedules: selected, NextAfter: next})
}

func (server *Server) taskSchedule(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodDelete {
		methodNotAllowed(writer, http.MethodGet, http.MethodDelete)
		return
	}
	if !noQuery(writer, request) || !emptyTaskRequestBody(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	tenantID, scheduleID := request.PathValue("tenant_id"), request.PathValue("schedule_id")
	if request.Method == http.MethodGet {
		schedule, found, err := server.store.GetTaskSchedule(identity, tenantID, scheduleID)
		if err != nil {
			server.storeError(writer, err, true)
			return
		}
		if !found {
			writeError(writer, http.StatusNotFound, "not_found", "task schedule was not found")
			return
		}
		writeJSON(writer, http.StatusOK, schedule)
		return
	}
	schedule, _, err := server.store.CancelTaskSchedule(identity, tenantID, scheduleID, server.now())
	if err != nil {
		server.storeError(writer, err, true)
		return
	}
	writeJSON(writer, http.StatusOK, schedule)
}

func pageTaskSchedules(values []controlstore.TaskSchedule, page pageRequest) ([]controlstore.TaskSchedule, string, error) {
	start := 0
	if page.after != "" {
		found := false
		for index, schedule := range values {
			if schedule.Statement.ScheduleID == page.after {
				start, found = index+1, true
				break
			}
		}
		if !found {
			return nil, "", controlstore.ErrInvalid
		}
	}
	selected := make([]controlstore.TaskSchedule, 0, min(page.limit, len(values)-start))
	for index := start; index < len(values) && len(selected) < page.limit; index++ {
		candidate := append(append([]controlstore.TaskSchedule(nil), selected...), values[index])
		next := ""
		if index+1 < len(values) {
			next = values[index].Statement.ScheduleID
		}
		raw, err := json.Marshal(taskSchedulePage{Schedules: candidate, NextAfter: next})
		if err != nil {
			return nil, "", err
		}
		if len(raw)+1 > maxResponseBytes {
			if len(selected) == 0 {
				return nil, "", errors.New("one valid task schedule cannot fit the response limit")
			}
			break
		}
		selected = candidate
	}
	next := ""
	if start+len(selected) < len(values) {
		next = selected[len(selected)-1].Statement.ScheduleID
	}
	return selected, next, nil
}
