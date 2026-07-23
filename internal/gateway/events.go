package gateway

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	InstanceEventSchemaV1     = "steward.instance-event.v1"
	maxInstanceEventBytes     = 8 << 10
	maxInstanceEvents         = 64
	maxInstanceEventsTenant   = 32
	maxInstanceEventsGrant    = 16
	maxInstanceEventAttrs     = 16
	maxInstanceEventAttrBytes = 4 << 10
)

// InstanceEventInput is the only agent-controlled portion of a controller
// event. Gateway derives every authority and workload identity field.
type InstanceEventInput struct {
	SchemaVersion  string            `json:"schema_version"`
	IdempotencyKey string            `json:"idempotency_key"`
	Kind           string            `json:"kind"`
	Code           string            `json:"code"`
	Severity       string            `json:"severity"`
	Summary        string            `json:"summary"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	TaskID         string            `json:"task_id,omitempty"`
	RunID          string            `json:"run_id,omitempty"`
	ObservedAt     string            `json:"observed_at,omitempty"`
}

// InstanceEvent is a durable, untrusted agent observation bound to the active
// signed grant that accepted it. It carries no authority and cannot mutate
// evidence, reconciliation, policy, or grant state.
type InstanceEvent struct {
	SchemaVersion  string            `json:"schema_version"`
	EventID        string            `json:"event_id"`
	IdempotencyKey string            `json:"idempotency_key"`
	Source         string            `json:"source"`
	TenantID       string            `json:"tenant_id"`
	NodeID         string            `json:"node_id"`
	InstanceID     string            `json:"instance_id"`
	Generation     uint64            `json:"generation"`
	RuntimeRef     string            `json:"runtime_ref"`
	GrantID        string            `json:"grant_id"`
	CapsuleDigest  string            `json:"capsule_digest"`
	PolicyDigest   string            `json:"policy_digest"`
	Kind           string            `json:"kind"`
	Code           string            `json:"code"`
	Severity       string            `json:"severity"`
	Summary        string            `json:"summary"`
	Attributes     map[string]string `json:"attributes,omitempty"`
	TaskID         string            `json:"task_id,omitempty"`
	RunID          string            `json:"run_id,omitempty"`
	ObservedAt     string            `json:"observed_at"`
	AcceptedAt     string            `json:"accepted_at"`
}

type eventBatch struct {
	Events []InstanceEvent `json:"events"`
}

type eventAck struct {
	EventIDs []string `json:"event_ids"`
}

func (input InstanceEventInput) validate() error {
	if input.SchemaVersion != InstanceEventSchemaV1 || !routeID(input.IdempotencyKey) ||
		(input.Kind != "status" && input.Kind != "finding") || !routeID(input.Code) ||
		(input.Severity != "info" && input.Severity != "warning" && input.Severity != "critical") ||
		!eventText(input.Summary, 1024) || input.TaskID != "" && !eventText(input.TaskID, 256) ||
		input.RunID != "" && !eventText(input.RunID, 256) {
		return errors.New("event fields are invalid")
	}
	if input.ObservedAt != "" {
		if parsed, err := time.Parse(time.RFC3339Nano, input.ObservedAt); err != nil || parsed.Format(time.RFC3339Nano) != input.ObservedAt {
			return errors.New("observed_at must be canonical RFC3339Nano")
		}
	}
	if len(input.Attributes) > maxInstanceEventAttrs {
		return errors.New("event has too many attributes")
	}
	total := 0
	for key, value := range input.Attributes {
		if !routeID(key) || !eventText(value, 1024) {
			return errors.New("event attribute is invalid")
		}
		total += len(key) + len(value)
	}
	if total > maxInstanceEventAttrBytes {
		return errors.New("event attributes exceed limit")
	}
	return nil
}

func eventText(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func cloneEvent(event InstanceEvent) InstanceEvent {
	result := event
	if event.Attributes != nil {
		result.Attributes = make(map[string]string, len(event.Attributes))
		for key, value := range event.Attributes {
			result.Attributes[key] = value
		}
	}
	return result
}

func instanceEventID(grantID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte("steward-instance-event-v1\x00" + grantID + "\x00" + idempotencyKey))
	return "event-" + hex.EncodeToString(sum[:])
}

func validInstanceEventID(value string) bool {
	if !strings.HasPrefix(value, "event-") || len(value) != len("event-")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "event-"))
	return err == nil
}

func eventSocketPath(root, grantID string) string {
	return GrantDirectory(root, grantID) + string(os.PathSeparator) + "v.sock"
}

func (s *Server) listenEventGrantLocked(id string) error {
	if listener := s.eventListeners[id]; listener != nil {
		return nil
	}
	directory := GrantDirectory(s.config.GrantRoot, id)
	listener, err := openGrantListener(directory, eventSocketPath(s.config.GrantRoot, id), s.config.RelayGID)
	if err != nil {
		return err
	}
	s.eventListeners[id] = listener
	server := &http.Server{
		Handler: s.interactionAndEventHandler(id), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: maxHTTPHeaderBytes,
	}
	go func() { _ = server.Serve(listener) }()
	return nil
}

func (s *Server) interactionAndEventHandler(grantID string) http.Handler {
	events := s.instanceEventHandler(grantID)
	interactions := s.interactionGrantHandler(grantID)
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasPrefix(request.URL.Path, "/v1/interactions") {
			interactions.ServeHTTP(writer, request)
			return
		}
		events.ServeHTTP(writer, request)
	})
}

func (s *Server) instanceEventHandler(grantID string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/events" || r.URL.RawQuery != "" {
			writeGatewayError(w, http.StatusNotFound, "event_route_not_found", "controller event route not found")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxInstanceEventBytes)
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			writeGatewayError(w, http.StatusRequestEntityTooLarge, "event_too_large", "controller event exceeds limit")
			return
		}
		var input InstanceEventInput
		if err := dsse.DecodeStrictInto(raw, maxInstanceEventBytes, &input); err != nil || input.validate() != nil {
			writeGatewayError(w, http.StatusBadRequest, "invalid_event", "controller event is invalid")
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
		grant, ok := s.grants[grantID]
		if !ok || !grant.Active || !grant.ControllerEvents {
			writeGatewayError(w, http.StatusServiceUnavailable, "event_grant_inactive", "controller event grant is not active")
			return
		}
		eventID := instanceEventID(grantID, input.IdempotencyKey)
		for _, existing := range s.events {
			if existing.EventID == eventID {
				writeJSON(w, http.StatusAccepted, map[string]string{"event_id": eventID, "status": "accepted"})
				return
			}
		}
		tenantCount, grantCount := 0, 0
		for _, existing := range s.events {
			if existing.TenantID == grant.TenantID {
				tenantCount++
			}
			if existing.GrantID == grantID {
				grantCount++
			}
		}
		if len(s.events) >= maxInstanceEvents || tenantCount >= maxInstanceEventsTenant || grantCount >= maxInstanceEventsGrant {
			w.Header().Set("Retry-After", "5")
			writeGatewayError(w, http.StatusTooManyRequests, "event_queue_full", "controller event queue is full")
			return
		}
		now := s.now().UTC().Format(time.RFC3339Nano)
		observedAt := input.ObservedAt
		if observedAt == "" {
			observedAt = now
		}
		event := InstanceEvent{
			SchemaVersion: InstanceEventSchemaV1, EventID: eventID, IdempotencyKey: input.IdempotencyKey,
			Source: "agent", TenantID: grant.TenantID, NodeID: grant.NodeID, InstanceID: grant.InstanceID,
			Generation: grant.Generation, RuntimeRef: grant.RuntimeRef, GrantID: grant.GrantID,
			CapsuleDigest: grant.CapsuleDigest, PolicyDigest: grant.PolicyDigest,
			Kind: input.Kind, Code: input.Code, Severity: input.Severity, Summary: input.Summary,
			Attributes: cloneEvent(InstanceEvent{Attributes: input.Attributes}).Attributes,
			TaskID:     input.TaskID, RunID: input.RunID, ObservedAt: observedAt, AcceptedAt: now,
		}
		s.events = append(s.events, event)
		if err := s.persistLocked(); err != nil {
			s.events = s.events[:len(s.events)-1]
			writeGatewayError(w, http.StatusServiceUnavailable, "event_state_unavailable", "controller event could not be committed")
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]string{"event_id": eventID, "status": "accepted"})
	})
}

func (s *Server) listInstanceEvents(w http.ResponseWriter, r *http.Request) {
	if r.URL.RawQuery != "" {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "event list does not accept query parameters")
		return
	}
	s.mu.Lock()
	events := make([]InstanceEvent, len(s.events))
	for index, event := range s.events {
		events[index] = cloneEvent(event)
	}
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, eventBatch{Events: events})
}

func (s *Server) ackInstanceEvents(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxInstanceEventBytes)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		writeGatewayError(w, http.StatusRequestEntityTooLarge, "invalid_request", "event acknowledgement exceeds limit")
		return
	}
	var request eventAck
	if err := dsse.DecodeStrictInto(raw, maxInstanceEventBytes, &request); err != nil || len(request.EventIDs) == 0 || len(request.EventIDs) > maxInstanceEvents {
		writeGatewayError(w, http.StatusBadRequest, "invalid_request", "event acknowledgement is invalid")
		return
	}
	wanted := make(map[string]struct{}, len(request.EventIDs))
	for _, id := range request.EventIDs {
		if !validInstanceEventID(id) {
			writeGatewayError(w, http.StatusBadRequest, "invalid_request", "event acknowledgement is invalid")
			return
		}
		wanted[id] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	retained := make([]InstanceEvent, 0, len(s.events))
	for _, event := range s.events {
		if _, acknowledged := wanted[event.EventID]; !acknowledged {
			retained = append(retained, event)
		}
	}
	previous := s.events
	s.events = retained
	if err := s.persistLocked(); err != nil {
		s.events = previous
		writeGatewayError(w, http.StatusServiceUnavailable, "event_state_unavailable", "event acknowledgement could not be committed")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validateRetainedEvents(events []InstanceEvent) error {
	if len(events) > maxInstanceEvents {
		return errors.New("gateway state contains too many controller events")
	}
	seen := make(map[string]struct{}, len(events))
	tenantCounts, grantCounts := map[string]int{}, map[string]int{}
	for _, event := range events {
		if event.SchemaVersion != InstanceEventSchemaV1 ||
			!validInstanceEventID(event.EventID) || event.EventID != instanceEventID(event.GrantID, event.IdempotencyKey) ||
			event.Source != "agent" || !bounded(event.TenantID, 128) || !bounded(event.NodeID, 128) ||
			!bounded(event.InstanceID, 256) || event.Generation == 0 || !validGrantID(event.GrantID) ||
			!validExecutorRuntimeRef(event.RuntimeRef) || !validSHA256Digest(event.CapsuleDigest) || !validSHA256Digest(event.PolicyDigest) {
			return errors.New("gateway state contains an invalid controller event binding")
		}
		input := InstanceEventInput{SchemaVersion: event.SchemaVersion, IdempotencyKey: event.IdempotencyKey,
			Kind: event.Kind, Code: event.Code, Severity: event.Severity, Summary: event.Summary,
			Attributes: event.Attributes, TaskID: event.TaskID, RunID: event.RunID, ObservedAt: event.ObservedAt}
		if input.validate() != nil {
			return errors.New("gateway state contains an invalid controller event")
		}
		if accepted, err := time.Parse(time.RFC3339Nano, event.AcceptedAt); err != nil || accepted.Format(time.RFC3339Nano) != event.AcceptedAt {
			return errors.New("gateway state contains an invalid controller event acceptance time")
		}
		if _, duplicate := seen[event.EventID]; duplicate {
			return errors.New("gateway state contains duplicate controller events")
		}
		seen[event.EventID] = struct{}{}
		tenantCounts[event.TenantID]++
		grantCounts[event.GrantID]++
		if tenantCounts[event.TenantID] > maxInstanceEventsTenant || grantCounts[event.GrantID] > maxInstanceEventsGrant {
			return errors.New("gateway state controller event quota is exceeded")
		}
	}
	return nil
}
