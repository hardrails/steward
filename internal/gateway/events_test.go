package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func eventGrant(tenant, instance string, generation uint64) Grant {
	return Grant{
		GrantID: GrantID(tenant, instance, generation), TenantID: tenant, NodeID: "node-a",
		InstanceID: instance, Generation: generation,
		RuntimeRef:    "executor-" + strings.Repeat("a", 64),
		CapsuleDigest: "sha256:" + strings.Repeat("b", 64),
		PolicyDigest:  "sha256:" + strings.Repeat("c", 64), ControllerEvents: true,
	}
}

func registerEventGrant(t *testing.T, server *Server, grant Grant, active bool) {
	t.Helper()
	raw, err := json.Marshal(grant)
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants", bytes.NewReader(raw)))
	if response.Code != http.StatusCreated {
		t.Fatalf("register status=%d body=%s", response.Code, response.Body.String())
	}
	if active {
		response = httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil))
		if response.Code != http.StatusOK {
			t.Fatalf("activate status=%d body=%s", response.Code, response.Body.String())
		}
	}
}

func postInstanceEvent(t *testing.T, socket string, body string) *http.Response {
	t.Helper()
	request, err := http.NewRequest(http.MethodPost, "http://gateway/v1/events", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := unixHTTPClient(socket).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func validEventInput(idempotencyKey string) string {
	raw, _ := json.Marshal(InstanceEventInput{
		SchemaVersion: InstanceEventSchemaV1, IdempotencyKey: idempotencyKey,
		Kind: "finding", Code: "source-confirmed", Severity: "info",
		Summary: "The primary source supports the claim.", Attributes: map[string]string{"url": "https://example.test/source"},
	})
	return string(raw)
}

func TestInstanceEventsDeriveIdentityPersistAndAcknowledge(t *testing.T) {
	server, config := testGateway(t, "http://127.0.0.1:1")
	grant := eventGrant("tenant-a", "researcher-a", 3)
	registerEventGrant(t, server, grant, true)
	socket := eventSocketPath(config.GrantRoot, grant.GrantID)

	response := postInstanceEvent(t, socket, validEventInput("finding-1"))
	if response.StatusCode != http.StatusAccepted {
		body := new(bytes.Buffer)
		_, _ = body.ReadFrom(response.Body)
		t.Fatalf("event status=%d body=%s input=%s", response.StatusCode, body.String(), validEventInput("finding-1"))
	}
	_ = response.Body.Close()
	// Idempotent replay acknowledges the same event without growing the outbox.
	response = postInstanceEvent(t, socket, validEventInput("finding-1"))
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("replay status=%d", response.StatusCode)
	}
	_ = response.Body.Close()

	client := &ControlClient{client: &http.Client{Transport: roundTripperFunc(func(request *http.Request) (*http.Response, error) {
		recorder := httptest.NewRecorder()
		server.ControlHandler().ServeHTTP(recorder, request)
		return recorder.Result(), nil
	})}}
	events, err := client.ListInstanceEvents(context.Background())
	if err != nil || len(events) != 1 {
		t.Fatalf("events=%+v err=%v", events, err)
	}
	event := events[0]
	if event.Source != "agent" || event.TenantID != grant.TenantID || event.NodeID != grant.NodeID ||
		event.InstanceID != grant.InstanceID || event.Generation != grant.Generation || event.RuntimeRef != grant.RuntimeRef ||
		event.GrantID != grant.GrantID || event.CapsuleDigest != grant.CapsuleDigest || event.PolicyDigest != grant.PolicyDigest {
		t.Fatalf("event identity was not derived from grant: %+v", event)
	}
	if err := client.AckInstanceEvents(context.Background(), []string{event.EventID}); err != nil {
		t.Fatal(err)
	}
	events, err = client.ListInstanceEvents(context.Background())
	if err != nil || len(events) != 0 {
		t.Fatalf("acknowledged events=%+v err=%v", events, err)
	}
}

func TestInstanceEventsRejectAgentIdentityOversizeAndInactiveGrant(t *testing.T) {
	server, config := testGateway(t, "http://127.0.0.1:1")
	grant := eventGrant("tenant-a", "researcher-a", 1)
	registerEventGrant(t, server, grant, false)
	socket := eventSocketPath(config.GrantRoot, grant.GrantID)

	response := postInstanceEvent(t, socket, validEventInput("inactive"))
	if response.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("inactive status=%d", response.StatusCode)
	}
	_ = response.Body.Close()

	controlResponse := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(controlResponse, httptest.NewRequest(http.MethodPost, "/v1/grants/"+grant.GrantID+"/activate", nil))
	if controlResponse.Code != http.StatusOK {
		t.Fatal(controlResponse.Body.String())
	}
	response = postInstanceEvent(t, socket, strings.TrimSuffix(validEventInput("identity"), "}")+`,"tenant_id":"other"}`)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("agent identity status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
	response = postInstanceEvent(t, socket, `{"schema_version":"steward.instance-event.v1","idempotency_key":"large","kind":"status","code":"large","severity":"info","summary":"`+strings.Repeat("x", maxInstanceEventBytes)+`"}`)
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversize status=%d", response.StatusCode)
	}
	_ = response.Body.Close()
}

func TestInstanceEventOutboxSurvivesRestartAndGrantRemoval(t *testing.T) {
	server, config := testGateway(t, "http://127.0.0.1:1")
	grant := eventGrant("tenant-a", "researcher-a", 1)
	registerEventGrant(t, server, grant, true)
	response := postInstanceEvent(t, eventSocketPath(config.GrantRoot, grant.GrantID), validEventInput("restart"))
	_ = response.Body.Close()
	server.closeGrantListeners()

	reopened, err := Open(config, map[string]loadedRoute{"local": server.routes["local"]}, nil, "service-secret")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.closeGrantListeners)
	list := httptest.NewRecorder()
	reopened.ControlHandler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/v1/events", nil))
	var batch eventBatch
	if list.Code != http.StatusOK || json.Unmarshal(list.Body.Bytes(), &batch) != nil || len(batch.Events) != 1 {
		t.Fatalf("restored status=%d body=%s", list.Code, list.Body.String())
	}
	remove := httptest.NewRecorder()
	reopened.ControlHandler().ServeHTTP(remove, httptest.NewRequest(http.MethodDelete, "/v1/grants/"+grant.GrantID, nil))
	if remove.Code != http.StatusNoContent {
		t.Fatalf("remove status=%d body=%s", remove.Code, remove.Body.String())
	}
	list = httptest.NewRecorder()
	reopened.ControlHandler().ServeHTTP(list, httptest.NewRequest(http.MethodGet, "/v1/events", nil))
	if json.Unmarshal(list.Body.Bytes(), &batch) != nil || len(batch.Events) != 1 {
		t.Fatalf("event was lost with grant: %s", list.Body.String())
	}
}

func TestInstanceEventGrantQuotaBackpressuresAgent(t *testing.T) {
	server, config := testGateway(t, "http://127.0.0.1:1")
	grant := eventGrant("tenant-a", "researcher-a", 1)
	registerEventGrant(t, server, grant, true)
	for index := 0; index < maxInstanceEventsGrant; index++ {
		response := postInstanceEvent(t, eventSocketPath(config.GrantRoot, grant.GrantID), validEventInput("item-"+string(rune('a'+index))))
		if response.StatusCode != http.StatusAccepted {
			t.Fatalf("item %d status=%d", index, response.StatusCode)
		}
		_ = response.Body.Close()
	}
	response := postInstanceEvent(t, eventSocketPath(config.GrantRoot, grant.GrantID), validEventInput("overflow"))
	if response.StatusCode != http.StatusTooManyRequests || response.Header.Get("Retry-After") != "5" {
		t.Fatalf("overflow status=%d retry=%q", response.StatusCode, response.Header.Get("Retry-After"))
	}
	_ = response.Body.Close()
}

func TestInstanceEventValidationRejectsMalformedInputAndRetainedState(t *testing.T) {
	validInput := InstanceEventInput{
		SchemaVersion: InstanceEventSchemaV1, IdempotencyKey: "finding-1", Kind: "finding",
		Code: "source-confirmed", Severity: "info", Summary: "Primary source confirmed.",
		ObservedAt: "2026-07-21T01:00:00Z",
	}
	for name, mutate := range map[string]func(*InstanceEventInput){
		"noncanonical time": func(input *InstanceEventInput) { input.ObservedAt = "2026-07-21T01:00:00+00:00" },
		"too many attributes": func(input *InstanceEventInput) {
			input.Attributes = make(map[string]string, maxInstanceEventAttrs+1)
			for index := 0; index <= maxInstanceEventAttrs; index++ {
				input.Attributes["key-"+string(rune('a'+index))] = "value"
			}
		},
		"invalid attribute": func(input *InstanceEventInput) { input.Attributes = map[string]string{"bad key": "value"} },
		"oversized attributes": func(input *InstanceEventInput) {
			input.Attributes = map[string]string{
				"key-a": strings.Repeat("a", 1024), "key-b": strings.Repeat("b", 1024),
				"key-c": strings.Repeat("c", 1024), "key-d": strings.Repeat("d", 1024),
			}
		},
		"control character": func(input *InstanceEventInput) { input.Summary = "unsafe\nsummary" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := validInput
			mutate(&candidate)
			if candidate.validate() == nil {
				t.Fatalf("invalid input accepted: %+v", candidate)
			}
		})
	}

	grant := eventGrant("tenant-a", "researcher-a", 1)
	retained := InstanceEvent{
		SchemaVersion: InstanceEventSchemaV1, IdempotencyKey: "finding-1", Source: "agent",
		TenantID: grant.TenantID, NodeID: grant.NodeID, InstanceID: grant.InstanceID, Generation: grant.Generation,
		RuntimeRef: grant.RuntimeRef, GrantID: grant.GrantID, CapsuleDigest: grant.CapsuleDigest, PolicyDigest: grant.PolicyDigest,
		Kind: validInput.Kind, Code: validInput.Code, Severity: validInput.Severity, Summary: validInput.Summary,
		ObservedAt: validInput.ObservedAt, AcceptedAt: "2026-07-21T01:00:01Z",
	}
	retained.EventID = instanceEventID(retained.GrantID, retained.IdempotencyKey)
	if err := validateRetainedEvents([]InstanceEvent{retained}); err != nil {
		t.Fatal(err)
	}
	tooMany := make([]InstanceEvent, maxInstanceEvents+1)
	if validateRetainedEvents(tooMany) == nil {
		t.Fatal("oversized retained event state accepted")
	}
	for name, mutate := range map[string]func(*InstanceEvent){
		"binding":         func(event *InstanceEvent) { event.Generation = 0 },
		"input":           func(event *InstanceEvent) { event.Summary = " bad" },
		"acceptance time": func(event *InstanceEvent) { event.AcceptedAt = "yesterday" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := retained
			mutate(&candidate)
			if validateRetainedEvents([]InstanceEvent{candidate}) == nil {
				t.Fatalf("invalid retained event accepted: %+v", candidate)
			}
		})
	}
	if validateRetainedEvents([]InstanceEvent{retained, retained}) == nil {
		t.Fatal("duplicate retained events accepted")
	}
	quota := make([]InstanceEvent, 0, maxInstanceEventsGrant+1)
	for index := 0; index <= maxInstanceEventsGrant; index++ {
		event := retained
		event.IdempotencyKey = "finding-" + string(rune('a'+index))
		event.EventID = instanceEventID(event.GrantID, event.IdempotencyKey)
		quota = append(quota, event)
	}
	if validateRetainedEvents(quota) == nil {
		t.Fatal("retained grant quota excess accepted")
	}

	server, _ := testGateway(t, "http://127.0.0.1:1")
	response := httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/events?unexpected=1", nil))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("event list query status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/events/ack", strings.NewReader(`{}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("empty acknowledgement status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/v1/events/ack", strings.NewReader(`{"event_ids":["event-invalid"]}`)))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid acknowledgement status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	server.ControlHandler().ServeHTTP(response, httptest.NewRequest(
		http.MethodPost, "/v1/events/ack", strings.NewReader(strings.Repeat("x", maxInstanceEventBytes+1)),
	))
	if response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized acknowledgement status=%d body=%s", response.Code, response.Body.String())
	}
	grant = eventGrant("tenant-a", "validation-a", 1)
	registerEventGrant(t, server, grant, true)
	socket := eventSocketPath(server.config.GrantRoot, grant.GrantID)
	if err := server.listenEventGrantLocked(grant.GrantID); err != nil {
		t.Fatalf("idempotent event listener: %v", err)
	}
	request, err := http.NewRequest(http.MethodGet, "http://gateway/v1/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	routeResponse, err := unixHTTPClient(socket).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = routeResponse.Body.Close()
	if routeResponse.StatusCode != http.StatusNotFound {
		t.Fatalf("wrong event route status=%d", routeResponse.StatusCode)
	}
	malformed := postInstanceEvent(t, socket, `{"schema_version":"steward.instance-event.v1"}`)
	_ = malformed.Body.Close()
	if malformed.StatusCode != http.StatusBadRequest {
		t.Fatalf("malformed event status=%d", malformed.StatusCode)
	}
}

func TestInstanceEventControlClientFailsClosedOnInvalidPagesAndAcknowledgements(t *testing.T) {
	invalidPage := newTestControlClient(t, http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/v1/events" {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"events":[{"schema_version":"invalid"}]}`))
	}))
	if _, err := invalidPage.ListInstanceEvents(context.Background()); err == nil {
		t.Fatal("invalid Gateway event page accepted")
	}

	unavailable := newTestControlClient(t, http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusServiceUnavailable)
		_, _ = writer.Write([]byte(`{"error":"unavailable","message":"retry"}`))
	}))
	if _, err := unavailable.ListInstanceEvents(context.Background()); err == nil {
		t.Fatal("Gateway event transport failure accepted")
	}

	validID := "event-" + strings.Repeat("a", 64)
	for name, ids := range map[string][]string{
		"empty": nil,
		"too many": func() []string {
			values := make([]string, maxInstanceEvents+1)
			for index := range values {
				values[index] = validID
			}
			return values
		}(),
		"invalid":   {"event-invalid"},
		"duplicate": {validID, validID},
	} {
		t.Run(name, func(t *testing.T) {
			if err := invalidPage.AckInstanceEvents(context.Background(), ids); err == nil {
				t.Fatalf("invalid acknowledgement accepted: %v", ids)
			}
		})
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
