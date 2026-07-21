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

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (function roundTripperFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}
