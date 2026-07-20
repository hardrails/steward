package controlplane

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hardrails/steward/internal/controlstore"
)

func TestOperationsHTTPAuthenticatesProjectsFiltersAndExcludesSecrets(t *testing.T) {
	fixture := newServerFixture(t)
	for _, tenantID := range []string{"tenant-a", "tenant-b"} {
		requireStatus(t, fixture.request(
			t, http.MethodPost, "/v1/tenants", fixture.adminToken,
			`{"tenant_id":"`+tenantID+`"}`,
		), http.StatusCreated)
	}
	operatorA := issueOperatorThroughAPI(t, fixture, "operations-operator-a", "tenant-a")
	operatorB := issueOperatorThroughAPI(t, fixture, "operations-operator-b", "tenant-b")
	node := enrollNodeThroughAPI(
		t, fixture, fixture.adminToken, "operations-enrollment", "node-operations",
		[]string{"tenant-a", "tenant-b"},
	)
	commandBytes := make(map[string][]byte)
	for _, input := range []struct {
		tenantID string
		token    string
		command  string
	}{
		{"tenant-a", operatorA, "command-a-1"},
		{"tenant-a", operatorA, "command-a-2"},
		{"tenant-b", operatorB, "command-b-1"},
	} {
		raw := signedCommand(t, fixture.now, input.command, input.tenantID, "node-operations")
		commandBytes[input.command] = raw
		body := mustJSON(t, map[string]string{"command_dsse_base64": base64.StdEncoding.EncodeToString(raw)})
		requireStatus(t, fixture.request(
			t, http.MethodPost,
			"/v1/tenants/"+input.tenantID+"/nodes/node-operations/commands",
			input.token, body,
		), http.StatusCreated)
	}

	for _, route := range []string{
		"/v1/operations/summary",
		"/v1/operations/attention",
		"/v1/operations/timeline",
		"/v1/operations/agents",
		"/v1/operations/commands",
		"/v1/operations/credentials",
	} {
		requireError(t, fixture.request(t, http.MethodGet, route, "", ""), http.StatusUnauthorized, "unauthorized")
		requireError(t, fixture.request(
			t, http.MethodGet, route+"?unexpected=1", "", "",
		), http.StatusUnauthorized, "unauthorized")
	}

	summaryResponse := fixture.request(t, http.MethodGet, "/v1/operations/summary", operatorA, "")
	requireStatus(t, summaryResponse, http.StatusOK)
	var summary controlstore.OperationsSummary
	decodeResponse(t, summaryResponse, &summary)
	if summary.TenantID != "tenant-a" || summary.Commands.Total != 2 {
		t.Fatalf("tenant operations summary = %+v", summary)
	}
	requireError(t, fixture.request(
		t, http.MethodGet, "/v1/operations/summary?tenant_id=tenant-b", operatorA, "",
	), http.StatusNotFound, "not_found")

	requireStatus(t, fixture.request(
		t, http.MethodPut, "/v1/tenants/tenant-a/freeze", operatorA,
		`{"action":"freeze","expected_revision":0,"reason":"timeline test"}`,
	), http.StatusOK)
	timeline := fixture.request(
		t, http.MethodGet,
		"/v1/operations/timeline?tenant_id=tenant-a&kind=containment&severity=critical&limit=1",
		operatorA, "",
	)
	requireStatus(t, timeline, http.StatusOK)
	var timelinePage controlstore.IncidentTimelinePage
	decodeResponse(t, timeline, &timelinePage)
	if len(timelinePage.Events) != 1 || timelinePage.Events[0].Action != "freeze_set" ||
		timelinePage.Events[0].TenantID != "tenant-a" || timelinePage.Events[0].Reason != "timeline test" {
		t.Fatalf("incident timeline = %+v", timelinePage)
	}
	if strings.Contains(timeline.Body.String(), "command_dsse") ||
		strings.Contains(timeline.Body.String(), node.Credential) {
		t.Fatalf("incident timeline exposed sensitive material: %s", timeline.Body.String())
	}

	first := fixture.request(
		t, http.MethodGet,
		"/v1/operations/commands?tenant_id=tenant-a&node_id=node-operations&state=pending&limit=1",
		operatorA, "",
	)
	requireStatus(t, first, http.StatusOK)
	var firstCommands controlstore.CommandInventoryPage
	decodeResponse(t, first, &firstCommands)
	if len(firstCommands.Commands) != 1 || firstCommands.NextCursor == "" ||
		firstCommands.Commands[0].TenantID != "tenant-a" {
		t.Fatalf("first command inventory page = %+v", firstCommands)
	}
	second := fixture.request(
		t, http.MethodGet,
		"/v1/operations/commands?tenant_id=tenant-a&node_id=node-operations&state=pending&cursor="+firstCommands.NextCursor+"&limit=1",
		operatorA, "",
	)
	requireStatus(t, second, http.StatusOK)
	var secondCommands controlstore.CommandInventoryPage
	decodeResponse(t, second, &secondCommands)
	if len(secondCommands.Commands) != 1 || secondCommands.NextCursor != "" ||
		secondCommands.Commands[0].TenantID != "tenant-a" ||
		secondCommands.Commands[0].ID == firstCommands.Commands[0].ID {
		t.Fatalf("second command inventory page = %+v", secondCommands)
	}
	requireError(t, fixture.request(
		t, http.MethodGet,
		"/v1/operations/commands?tenant_id=tenant-a&node_id=node-operations&state=leased&cursor="+firstCommands.NextCursor,
		operatorA, "",
	), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(
		t, http.MethodGet,
		"/v1/operations/commands?tenant_id=tenant-b&node_id=node-operations&state=pending&cursor="+firstCommands.NextCursor,
		fixture.adminToken, "",
	), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(
		t, http.MethodGet, "/v1/operations/commands?cursor=Zh",
		fixture.adminToken, "",
	), http.StatusBadRequest, "invalid_request")
	for commandID, raw := range commandBytes {
		if strings.Contains(first.Body.String(), base64.StdEncoding.EncodeToString(raw)) ||
			strings.Contains(second.Body.String(), base64.StdEncoding.EncodeToString(raw)) {
			t.Fatalf("command inventory exposed signed bytes for %s", commandID)
		}
	}
	if strings.Contains(first.Body.String(), "command_dsse") ||
		strings.Contains(second.Body.String(), "result") ||
		strings.Contains(first.Body.String(), "reported_status") ||
		strings.Contains(second.Body.String(), "reported_status") ||
		strings.Contains(first.Body.String(), "error_code") ||
		strings.Contains(second.Body.String(), "error_code") {
		t.Fatal("command inventory exposed payload or result fields")
	}

	credentials := fixture.request(
		t, http.MethodGet,
		"/v1/operations/credentials?kind=node&node_id=node-operations&revoked=false",
		operatorA, "",
	)
	requireStatus(t, credentials, http.StatusOK)
	var credentialPage controlstore.CredentialInventoryPage
	decodeResponse(t, credentials, &credentialPage)
	if len(credentialPage.Credentials) != 1 ||
		len(credentialPage.Credentials[0].TenantIDs) != 1 ||
		credentialPage.Credentials[0].TenantIDs[0] != "tenant-a" {
		t.Fatalf("tenant credential projection = %+v", credentialPage)
	}
	for _, secret := range []string{node.Credential, fixture.adminToken, "token_mac"} {
		if strings.Contains(credentials.Body.String(), secret) {
			t.Fatalf("credential inventory exposed %q", secret)
		}
	}
	firstCredentials := fixture.request(
		t, http.MethodGet, "/v1/operations/credentials?limit=1", operatorA, "",
	)
	requireStatus(t, firstCredentials, http.StatusOK)
	var firstCredentialPage controlstore.CredentialInventoryPage
	decodeResponse(t, firstCredentials, &firstCredentialPage)
	if len(firstCredentialPage.Credentials) != 1 || firstCredentialPage.NextCursor == "" {
		t.Fatalf("first credential inventory page = %+v", firstCredentialPage)
	}
	requireError(t, fixture.request(
		t, http.MethodGet,
		"/v1/operations/credentials?revoked=false&cursor="+firstCredentialPage.NextCursor,
		operatorA, "",
	), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(
		t, http.MethodGet,
		"/v1/operations/credentials?tenant_id=tenant-b&cursor="+firstCredentialPage.NextCursor,
		fixture.adminToken, "",
	), http.StatusBadRequest, "invalid_request")

	fixture.now = fixture.now.Add(6 * time.Minute)
	attention := fixture.request(
		t, http.MethodGet,
		"/v1/operations/attention?reason=command_pending_overdue&limit=1",
		operatorA, "",
	)
	requireStatus(t, attention, http.StatusOK)
	var attentionPage controlstore.AttentionPage
	decodeResponse(t, attention, &attentionPage)
	if len(attentionPage.Items) != 1 || attentionPage.Items[0].TenantID != "tenant-a" ||
		attentionPage.Items[0].Reason != controlstore.AttentionCommandPendingOverdue ||
		attentionPage.NextCursor == "" {
		t.Fatalf("filtered attention page = %+v", attentionPage)
	}
	requireError(t, fixture.request(
		t, http.MethodGet,
		"/v1/operations/attention?reason=node_stale&cursor="+attentionPage.NextCursor,
		operatorA, "",
	), http.StatusBadRequest, "invalid_request")
	requireError(t, fixture.request(
		t, http.MethodGet,
		"/v1/operations/attention?tenant_id=tenant-b&reason=command_pending_overdue&cursor="+attentionPage.NextCursor,
		fixture.adminToken, "",
	), http.StatusBadRequest, "invalid_request")
}

func TestOperationsHTTPRejectsAmbiguousQueriesAndBoundsPages(t *testing.T) {
	fixture := newServerFixture(t)
	for _, path := range []string{
		"/v1/operations/summary?unexpected=1",
		"/v1/operations/summary?tenant_id=tenant-a&tenant_id=tenant-a",
		"/v1/operations/attention?reason=",
		"/v1/operations/attention?limit=01",
		"/v1/operations/commands?state=pending;limit=1",
		"/v1/operations/commands?cursor=a&cursor=b",
		"/v1/operations/commands?terminal_status=failed",
		"/v1/operations/commands?state=pending&terminal_status=failed",
		"/v1/operations/timeline?kind=unknown",
		"/v1/operations/timeline?severity=urgent",
		"/v1/operations/timeline?kind=containment&kind=evidence",
		"/v1/operations/credentials?revoked=1",
		"/v1/operations/credentials?kind=node&unknown=x",
		"/v1/operations/credentials?role=tenant_operator&node_id=node-1",
		"/v1/operations/credentials?kind=node&role=tenant_operator",
		"/v1/operations/credentials?kind=operator&node_id=node-1",
	} {
		requireError(t, fixture.request(
			t, http.MethodGet, path, fixture.adminToken, "",
		), http.StatusBadRequest, "invalid_request")
	}
	requireError(t, fixture.request(
		t, http.MethodPost, "/v1/operations/summary", fixture.adminToken, `{}`,
	), http.StatusMethodNotAllowed, "method_not_allowed")

	type largePage struct {
		Items []string `json:"items"`
	}
	item := strings.Repeat("x", 300_000)
	page, err := boundedOperationsPage(8, func(limit int) (largePage, error) {
		items := make([]string, limit)
		for index := range items {
			items[index] = item
		}
		return largePage{Items: items}, nil
	})
	if err != nil || len(page.Items) != 2 {
		t.Fatalf("bounded operations page = (%d, %v), want 2 bounded records", len(page.Items), err)
	}
	_, err = boundedOperationsPage(1, func(int) (largePage, error) {
		return largePage{Items: []string{strings.Repeat("x", maxResponseBytes)}}, nil
	})
	if !errors.Is(err, errOperationsPageTooLarge) {
		t.Fatalf("oversized single operations record error = %v", err)
	}
}

func TestMetricsAreOptInAuthenticatedTenantProjectedAndFixedCardinality(t *testing.T) {
	fixture := newServerFixture(t)
	requireError(t, fixture.request(
		t, http.MethodGet, "/metrics", fixture.adminToken, "",
	), http.StatusNotFound, "not_found")

	requireStatus(t, fixture.request(
		t, http.MethodPost, "/v1/tenants", fixture.adminToken, `{"tenant_id":"tenant-a"}`,
	), http.StatusCreated)
	operator := issueOperatorThroughAPI(t, fixture, "metrics-operator", "tenant-a")
	node := enrollNodeThroughAPI(
		t, fixture, operator, "metrics-enrollment", "metrics-node", []string{"tenant-a"},
	)
	commandRaw := signedCommand(t, fixture.now, "metrics-command", "tenant-a", "metrics-node")
	requireStatus(t, fixture.request(
		t, http.MethodPost, "/v1/tenants/tenant-a/nodes/metrics-node/commands", operator,
		mustJSON(t, map[string]string{"command_dsse_base64": base64.StdEncoding.EncodeToString(commandRaw)}),
	), http.StatusCreated)
	enabled, err := New(Config{
		Store: fixture.store, Auth: fixture.server.auth, WitnessPrivateKey: fixture.witnessPrivate,
		LeaseDuration: 2 * time.Minute, MaxPoll: 32, EnableMetrics: true,
		Now: func() time.Time { return fixture.now },
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func(path, token string) *httptest.ResponseRecorder {
		t.Helper()
		input := httptest.NewRequest(http.MethodGet, path, nil)
		if token != "" {
			input.Header.Set("Authorization", "Bearer "+token)
		}
		output := httptest.NewRecorder()
		enabled.ServeHTTP(output, input)
		return output
	}
	requireError(t, request("/metrics", ""), http.StatusUnauthorized, "unauthorized")
	requireError(t, request("/metrics?unknown=1", ""), http.StatusUnauthorized, "unauthorized")
	requireError(t, request("/metrics?unknown=1", fixture.adminToken), http.StatusBadRequest, "invalid_request")
	requireError(t, request(
		"/metrics?tenant_id=tenant-a&tenant_id=tenant-a", fixture.adminToken,
	), http.StatusBadRequest, "invalid_request")

	site := request("/metrics", fixture.adminToken)
	requireStatus(t, site, http.StatusOK)
	if site.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" ||
		!strings.Contains(site.Body.String(), `steward_control_capacity_used{scope="site",resource="tenants"}`) {
		t.Fatalf("site metrics headers/body = %v\n%s", site.Header(), site.Body.String())
	}
	tenant := request("/metrics", operator)
	requireStatus(t, tenant, http.StatusOK)
	if !strings.Contains(tenant.Body.String(), `scope="tenant"`) {
		t.Fatalf("tenant metrics omitted projected scope:\n%s", tenant.Body.String())
	}
	for _, sensitive := range []string{
		"tenant-a", "metrics-node", "metrics-command", node.Credential,
		fixture.adminToken, base64.StdEncoding.EncodeToString(commandRaw),
		"tenant_id=", "node_id=", "credential_id=", "command_id=",
	} {
		if strings.Contains(site.Body.String(), sensitive) || strings.Contains(tenant.Body.String(), sensitive) {
			t.Fatalf("metrics exposed sensitive or high-cardinality value %q", sensitive)
		}
	}
	for _, line := range strings.Split(tenant.Body.String(), "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.HasPrefix(line, "steward_control_") {
			t.Fatalf("unexpected metric family: %s", line)
		}
		for _, label := range []string{"tenant=", "node=", "credential=", "command="} {
			if strings.Contains(line, label) {
				t.Fatalf("high-cardinality metric label in %s", line)
			}
		}
	}
}

func TestControlServerOperationsThresholdConfigDefaultsOrFailsClosed(t *testing.T) {
	fixture := newServerFixture(t)
	base := Config{
		Store: fixture.store, Auth: fixture.server.auth, WitnessPrivateKey: fixture.witnessPrivate,
		LeaseDuration: time.Minute, MaxPoll: 1,
	}
	server, err := New(base)
	if err != nil || server.operationsThresholds != controlstore.DefaultOperationsThresholds() {
		t.Fatalf("zero operations thresholds = (%+v, %v)", server, err)
	}
	partial := base
	partial.OperationsThresholds.NodeStaleAfter = time.Minute
	if _, err := New(partial); err == nil {
		t.Fatal("partial operations thresholds were accepted")
	}
	valid := base
	valid.OperationsThresholds = controlstore.DefaultOperationsThresholds()
	valid.OperationsThresholds.CapacityWarningPercent = 90
	server, err = New(valid)
	if err != nil || server.operationsThresholds.CapacityWarningPercent != 90 {
		t.Fatalf("valid operations thresholds = (%+v, %v)", server, err)
	}
	invalid := base
	invalid.OperationsThresholds = controlstore.DefaultOperationsThresholds()
	invalid.OperationsThresholds.EvidenceStaleAfter = controlstore.MaxOperationsThreshold + time.Nanosecond
	if _, err := New(invalid); err == nil {
		t.Fatal("unbounded operations thresholds were accepted")
	}
}
