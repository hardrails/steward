package controlplane

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlstore"
)

var errOperationsPageTooLarge = errors.New("one operations record cannot fit the response limit")

func resolveOperationsThresholds(configured controlstore.OperationsThresholds) (controlstore.OperationsThresholds, error) {
	if configured == (controlstore.OperationsThresholds{}) {
		return controlstore.DefaultOperationsThresholds(), nil
	}
	if err := configured.Validate(); err != nil {
		return controlstore.OperationsThresholds{}, err
	}
	return configured, nil
}

func (server *Server) operationsSummary(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	query, ok := parseExactQuery(writer, request, "tenant_id")
	if !ok {
		return
	}
	summary, err := server.store.OperationsSummary(
		identity, query.Get("tenant_id"), server.now(), server.operationsThresholds,
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, summary)
}

func (server *Server) operationsAttention(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	query, ok := parseExactQuery(writer, request, "tenant_id", "reason", "resource_id", "cursor", "limit")
	if !ok {
		return
	}
	limit, ok := parseOperationsLimit(writer, query)
	if !ok {
		return
	}
	input := controlstore.AttentionQuery{
		TenantID: query.Get("tenant_id"), Reason: controlstore.AttentionReason(query.Get("reason")),
		ResourceID: query.Get("resource_id"),
		Now:        server.now(), Thresholds: server.operationsThresholds, Limit: limit, Cursor: query.Get("cursor"),
	}
	page, err := boundedOperationsPage(limit, func(candidateLimit int) (controlstore.AttentionPage, error) {
		input.Limit = candidateLimit
		return server.store.ListAttention(identity, input)
	})
	if err != nil {
		server.operationsPageError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (server *Server) operationsTimeline(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	query, ok := parseExactQuery(
		writer, request, "tenant_id", "node_id", "kind", "severity", "cursor", "limit",
	)
	if !ok {
		return
	}
	limit, ok := parseOperationsLimit(writer, query)
	if !ok {
		return
	}
	input := controlstore.IncidentTimelineQuery{
		TenantID: query.Get("tenant_id"), NodeID: query.Get("node_id"),
		Kind:     controlstore.IncidentKind(query.Get("kind")),
		Severity: controlstore.IncidentSeverity(query.Get("severity")),
		Limit:    limit, Cursor: query.Get("cursor"),
	}
	page, err := boundedOperationsPage(limit, func(candidateLimit int) (controlstore.IncidentTimelinePage, error) {
		input.Limit = candidateLimit
		return server.store.ListIncidentTimeline(identity, input)
	})
	if err != nil {
		server.operationsPageError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (server *Server) operationsCommands(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	query, ok := parseExactQuery(
		writer, request, "tenant_id", "node_id", "state", "terminal_status", "cursor", "limit",
	)
	if !ok {
		return
	}
	limit, ok := parseOperationsLimit(writer, query)
	if !ok {
		return
	}
	input := controlstore.CommandInventoryQuery{
		TenantID: query.Get("tenant_id"), NodeID: query.Get("node_id"),
		State: controlstore.CommandState(query.Get("state")), TerminalStatus: query.Get("terminal_status"),
		Limit: limit, Cursor: query.Get("cursor"),
	}
	page, err := boundedOperationsPage(limit, func(candidateLimit int) (controlstore.CommandInventoryPage, error) {
		input.Limit = candidateLimit
		return server.store.ListCommandInventory(identity, input)
	})
	if err != nil {
		server.operationsPageError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (server *Server) operationsAgents(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	query, ok := parseExactQuery(
		writer, request, "tenant_id", "node_id", "status", "cursor", "limit",
	)
	if !ok {
		return
	}
	limit, ok := parseOperationsLimit(writer, query)
	if !ok {
		return
	}
	input := controlstore.AgentInventoryQuery{
		TenantID: query.Get("tenant_id"), NodeID: query.Get("node_id"),
		Status: query.Get("status"), Limit: limit, Cursor: query.Get("cursor"),
	}
	page, err := boundedOperationsPage(limit, func(candidateLimit int) (controlstore.AgentInventoryPage, error) {
		input.Limit = candidateLimit
		return server.store.ListAgentInventory(identity, input)
	})
	if err != nil {
		server.operationsPageError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (server *Server) operationsCredentials(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	query, ok := parseExactQuery(
		writer, request, "tenant_id", "kind", "role", "node_id", "revoked", "cursor", "limit",
	)
	if !ok {
		return
	}
	limit, ok := parseOperationsLimit(writer, query)
	if !ok {
		return
	}
	revoked, ok := parseOptionalBool(writer, query, "revoked")
	if !ok {
		return
	}
	input := controlstore.CredentialInventoryQuery{
		TenantID: query.Get("tenant_id"), Kind: controlauth.CredentialKind(query.Get("kind")),
		Role: controlauth.Role(query.Get("role")), NodeID: query.Get("node_id"),
		Revoked: revoked, Limit: limit, Cursor: query.Get("cursor"),
	}
	page, err := boundedOperationsPage(limit, func(candidateLimit int) (controlstore.CredentialInventoryPage, error) {
		input.Limit = candidateLimit
		return server.store.ListCredentialInventory(identity, input)
	})
	if err != nil {
		server.operationsPageError(writer, err)
		return
	}
	writeJSON(writer, http.StatusOK, page)
}

func (server *Server) metrics(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	query, ok := parseExactQuery(writer, request, "tenant_id")
	if !ok {
		return
	}
	summary, err := server.store.OperationsSummary(
		identity, query.Get("tenant_id"), server.now(), server.operationsThresholds,
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	scope := "site"
	if summary.TenantID != "" {
		scope = "tenant"
	}
	raw := operationsMetrics(summary, scope)
	if len(raw) > maxResponseBytes {
		writeError(writer, http.StatusInternalServerError, "internal_error", "metrics could not be encoded within its limit")
		return
	}
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	writer.WriteHeader(http.StatusOK)
	_, _ = writer.Write(raw)
}

func parseExactQuery(writer http.ResponseWriter, request *http.Request, allowed ...string) (url.Values, bool) {
	values, err := url.ParseQuery(request.URL.RawQuery)
	if err != nil {
		writeError(writer, http.StatusBadRequest, "invalid_request", "query string is malformed")
		return nil, false
	}
	accepted := make(map[string]struct{}, len(allowed))
	for _, key := range allowed {
		accepted[key] = struct{}{}
	}
	for key, entries := range values {
		if _, ok := accepted[key]; !ok || len(entries) != 1 || entries[0] == "" {
			writeError(writer, http.StatusBadRequest, "invalid_request", "query parameters must be known, non-empty, and appear once")
			return nil, false
		}
	}
	return values, true
}

func parseOperationsLimit(writer http.ResponseWriter, query url.Values) (int, bool) {
	value, present := query["limit"]
	if !present {
		return 0, true
	}
	raw := value[0]
	for _, character := range raw {
		if character < '0' || character > '9' {
			writeError(writer, http.StatusBadRequest, "invalid_request", "limit must be a canonical integer between 1 and 500")
			return 0, false
		}
	}
	limit, err := strconv.Atoi(raw)
	if err != nil || limit < 1 || limit > controlstore.MaxInventoryPageLimit || strconv.Itoa(limit) != raw {
		writeError(writer, http.StatusBadRequest, "invalid_request", "limit must be a canonical integer between 1 and 500")
		return 0, false
	}
	return limit, true
}

func parseOptionalBool(writer http.ResponseWriter, query url.Values, key string) (*bool, bool) {
	value, present := query[key]
	if !present {
		return nil, true
	}
	switch value[0] {
	case "true":
		result := true
		return &result, true
	case "false":
		result := false
		return &result, true
	default:
		writeError(writer, http.StatusBadRequest, "invalid_request", key+" must be true or false")
		return nil, false
	}
}

func boundedOperationsPage[T any](requestedLimit int, load func(int) (T, error)) (T, error) {
	limit := requestedLimit
	if limit == 0 {
		limit = controlstore.DefaultInventoryPageLimit
	}
	for {
		page, err := load(limit)
		if err != nil {
			var zero T
			return zero, err
		}
		raw, err := json.Marshal(page)
		if err != nil {
			var zero T
			return zero, err
		}
		if len(raw)+1 <= maxResponseBytes {
			return page, nil
		}
		if limit == 1 {
			var zero T
			return zero, errOperationsPageTooLarge
		}
		limit = max(1, limit/2)
	}
}

func (server *Server) operationsPageError(writer http.ResponseWriter, err error) {
	if errors.Is(err, errOperationsPageTooLarge) {
		server.logger.Error("one operations record exceeded the response bound")
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode a bounded operations page")
		return
	}
	server.storeError(writer, err, false)
}

func operationsMetrics(summary controlstore.OperationsSummary, scope string) []byte {
	var output strings.Builder
	output.WriteString("# HELP steward_control_capacity_used Retained control-plane objects.\n")
	output.WriteString("# TYPE steward_control_capacity_used gauge\n")
	output.WriteString("# HELP steward_control_capacity_limit Configured control-plane object limit.\n")
	output.WriteString("# TYPE steward_control_capacity_limit gauge\n")
	output.WriteString("# HELP steward_control_capacity_warning Whether usage reached the configured warning threshold.\n")
	output.WriteString("# TYPE steward_control_capacity_warning gauge\n")
	for _, capacity := range summary.Capacity {
		fmt.Fprintf(&output, "steward_control_capacity_used{scope=%q,resource=%q} %d\n", scope, capacity.Resource, capacity.Used)
		fmt.Fprintf(&output, "steward_control_capacity_limit{scope=%q,resource=%q} %d\n", scope, capacity.Resource, capacity.Limit)
		warning := 0
		if capacity.Warning {
			warning = 1
		}
		fmt.Fprintf(&output, "steward_control_capacity_warning{scope=%q,resource=%q} %d\n", scope, capacity.Resource, warning)
	}
	output.WriteString("# HELP steward_control_commands Retained commands by lifecycle state and terminal status.\n")
	output.WriteString("# TYPE steward_control_commands gauge\n")
	commandMetrics := []struct {
		state  string
		status string
		value  int
	}{
		{"all", "all", summary.Commands.Total},
		{"pending", "none", summary.Commands.Pending},
		{"leased", "none", summary.Commands.Leased},
		{"terminal", "all", summary.Commands.Terminal},
		{"terminal", "done", summary.Commands.Done},
		{"terminal", "failed", summary.Commands.Failed},
		{"terminal", "rejected", summary.Commands.Rejected},
		{"terminal", "outcome_unknown", summary.Commands.OutcomeUnknown},
	}
	for _, metric := range commandMetrics {
		fmt.Fprintf(
			&output, "steward_control_commands{scope=%q,state=%q,status=%q} %d\n",
			scope, metric.state, metric.status, metric.value,
		)
	}
	output.WriteString("# HELP steward_control_evidence_nodes Retained nodes by evidence status.\n")
	output.WriteString("# TYPE steward_control_evidence_nodes gauge\n")
	evidenceMetrics := []struct {
		status string
		value  int
	}{
		{"all", summary.Evidence.Nodes},
		{"active", summary.Evidence.ActiveNodes},
		{"witnessed", summary.Evidence.Witnessed},
		{"unwitnessed", summary.Evidence.Unwitnessed},
		{"current", summary.Evidence.Current},
		{"stale", summary.Evidence.Stale},
		{"rollback_detected", summary.Evidence.RollbackDetected},
		{"equivocation_detected", summary.Evidence.EquivocationDetected},
	}
	for _, metric := range evidenceMetrics {
		fmt.Fprintf(
			&output, "steward_control_evidence_nodes{scope=%q,status=%q} %d\n",
			scope, metric.status, metric.value,
		)
	}
	output.WriteString("# HELP steward_control_attention Derived action-required facts.\n")
	output.WriteString("# TYPE steward_control_attention gauge\n")
	for _, count := range summary.Attention.Counts {
		fmt.Fprintf(
			&output, "steward_control_attention{scope=%q,reason=%q,severity=%q} %d\n",
			scope, count.Reason, count.Severity, count.Count,
		)
	}
	return []byte(output.String())
}
