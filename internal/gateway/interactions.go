package gateway

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/interactionpermit"
)

const (
	interactionRequestSchemaV1      = controlprotocol.InteractionRequestSchemaV1
	interactionResponseBodySchemaV1 = interactionpermit.ResponseBodySchemaV1
	maxInteractionRequestBytes      = 8 << 10
	maxInteractionCourierBytes      = 32 << 10
	maxInteractions                 = 64
	maxInteractionsTenant           = 32
	maxInteractionsGrant            = 16
	maxInteractionOptions           = 8
	maxInteractionWait              = 7 * 24 * time.Hour
)

type InteractionInput struct {
	SchemaVersion  string   `json:"schema_version"`
	IdempotencyKey string   `json:"idempotency_key"`
	Kind           string   `json:"kind"`
	Title          string   `json:"title"`
	Prompt         string   `json:"prompt"`
	Options        []string `json:"options,omitempty"`
	AllowText      bool     `json:"allow_text,omitempty"`
	TaskID         string   `json:"task_id,omitempty"`
	RunID          string   `json:"run_id,omitempty"`
	ObservedAt     string   `json:"observed_at,omitempty"`
	ExpiresAt      string   `json:"expires_at"`
}

// Interaction is durable workflow data, not authority. Its identity fields are
// derived by Gateway from the active grant. A response becomes visible only
// after Gateway verifies a tenant signature over this exact request digest and
// the exact response bytes.
type Interaction struct {
	SchemaVersion      string               `json:"schema_version"`
	InteractionID      string               `json:"interaction_id"`
	IdempotencyKey     string               `json:"idempotency_key"`
	Source             string               `json:"source"`
	TenantID           string               `json:"tenant_id"`
	NodeID             string               `json:"node_id"`
	InstanceID         string               `json:"instance_id"`
	Generation         uint64               `json:"generation"`
	RuntimeRef         string               `json:"runtime_ref"`
	GrantID            string               `json:"grant_id"`
	CapsuleDigest      string               `json:"capsule_digest"`
	PolicyDigest       string               `json:"policy_digest"`
	Kind               string               `json:"kind"`
	Title              string               `json:"title"`
	Prompt             string               `json:"prompt"`
	Options            []string             `json:"options"`
	AllowText          bool                 `json:"allow_text"`
	TaskID             string               `json:"task_id,omitempty"`
	RunID              string               `json:"run_id,omitempty"`
	ObservedAt         string               `json:"observed_at"`
	AcceptedAt         string               `json:"accepted_at"`
	ExpiresAt          string               `json:"expires_at"`
	RequestDigest      string               `json:"request_digest"`
	State              string               `json:"state"`
	ControllerAccepted bool                 `json:"controller_accepted"`
	Response           *InteractionResponse `json:"response,omitempty"`
}

type InteractionResponse struct {
	Body           InteractionResponseBody `json:"body"`
	KeyID          string                  `json:"key_id"`
	PermitDigest   string                  `json:"permit_digest"`
	ResponseDigest string                  `json:"response_digest"`
	ResolvedAt     string                  `json:"resolved_at"`
}

type InteractionResponseBody = interactionpermit.ResponseBody

type interactionBatch struct {
	Interactions []Interaction `json:"interactions"`
}

type interactionAck struct {
	InteractionIDs []string `json:"interaction_ids"`
}

type interactionResponseCourier struct {
	InteractionID  string `json:"interaction_id"`
	PermitBase64   string `json:"permit_base64"`
	ResponseBase64 string `json:"response_base64"`
}

func (input InteractionInput) validate(now time.Time) error {
	if input.SchemaVersion != interactionRequestSchemaV1 || !routeID(input.IdempotencyKey) ||
		(input.Kind != "question" && input.Kind != "decision") ||
		!eventText(input.Title, 128) || !eventText(input.Prompt, 4096) ||
		len(input.Options) > maxInteractionOptions ||
		input.TaskID != "" && !eventText(input.TaskID, 256) ||
		input.RunID != "" && !eventText(input.RunID, 256) {
		return errors.New("interaction fields are invalid")
	}
	if input.Kind == "decision" && len(input.Options) < 2 || len(input.Options) == 0 && !input.AllowText {
		return errors.New("interaction has no bounded response path")
	}
	seen := make(map[string]struct{}, len(input.Options))
	for _, option := range input.Options {
		if !eventText(option, 128) {
			return errors.New("interaction option is invalid")
		}
		if _, duplicate := seen[option]; duplicate {
			return errors.New("interaction contains a duplicate option")
		}
		seen[option] = struct{}{}
	}
	if input.ObservedAt != "" {
		observed, err := canonicalInteractionTime(input.ObservedAt)
		if err != nil || observed.After(now.Add(5*time.Minute)) {
			return errors.New("interaction observed_at is invalid")
		}
	}
	expires, err := canonicalInteractionTime(input.ExpiresAt)
	if err != nil || !expires.After(now) || expires.After(now.Add(maxInteractionWait)) {
		return errors.New("interaction expires_at is invalid")
	}
	return nil
}

func canonicalInteractionTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(time.RFC3339) != value {
		return time.Time{}, errors.New("timestamp must be canonical UTC RFC3339 seconds")
	}
	return parsed, nil
}

func interactionID(grantID, idempotencyKey string) string {
	sum := sha256.Sum256([]byte("steward-interaction-v1\x00" + grantID + "\x00" + idempotencyKey))
	return "interaction-" + hex.EncodeToString(sum[:])
}

func validInteractionID(value string) bool {
	if !strings.HasPrefix(value, "interaction-") || len(value) != len("interaction-")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "interaction-"))
	return err == nil
}

func interactionRequestDigest(value Interaction) string {
	return controlprotocol.InteractionRequestDigest(controlprotocol.InteractionRequestV1{
		SchemaVersion: value.SchemaVersion, InteractionID: value.InteractionID,
		TenantID: value.TenantID, NodeID: value.NodeID, InstanceID: value.InstanceID,
		Generation: value.Generation, RuntimeRef: value.RuntimeRef, GrantID: value.GrantID,
		CapsuleDigest: value.CapsuleDigest, PolicyDigest: value.PolicyDigest,
		Kind: value.Kind, Title: value.Title, Prompt: value.Prompt,
		Options: append([]string(nil), value.Options...), AllowText: value.AllowText,
		TaskID: value.TaskID, RunID: value.RunID, ObservedAt: value.ObservedAt,
		AcceptedAt: value.AcceptedAt, ExpiresAt: value.ExpiresAt,
	})
}

func cloneInteraction(value Interaction) Interaction {
	value.Options = append([]string(nil), value.Options...)
	if value.Response != nil {
		response := *value.Response
		value.Response = &response
	}
	return value
}

func (s *Server) interactionGrantHandler(grantID string) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost && request.URL.Path == "/v1/interactions":
			s.createInteraction(writer, request, grantID)
		case request.Method == http.MethodGet && request.URL.Path == "/v1/interactions":
			s.listGrantInteractions(writer, request, grantID)
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/interactions/"):
			s.getGrantInteraction(writer, request, grantID)
		default:
			writeGatewayError(writer, http.StatusNotFound, "interaction_route_not_found", "interaction route not found")
		}
	})
}

func (s *Server) createInteraction(writer http.ResponseWriter, request *http.Request, grantID string) {
	if request.URL.RawQuery != "" {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_interaction", "interaction request does not accept query parameters")
		return
	}
	request.Body = http.MaxBytesReader(writer, request.Body, maxInteractionRequestBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		writeGatewayError(writer, http.StatusRequestEntityTooLarge, "interaction_too_large", "interaction request exceeds limit")
		return
	}
	var input InteractionInput
	now := s.now().UTC()
	if err := dsse.DecodeStrictInto(raw, maxInteractionRequestBytes, &input); err != nil || input.validate(now) != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_interaction", "interaction request is invalid")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	grant, active := s.grants[grantID]
	if !active || !grant.Active || !grant.ControllerEvents || len(grant.TaskAuthorities) == 0 {
		writeGatewayError(writer, http.StatusServiceUnavailable, "interaction_grant_inactive", "interaction grant is not active")
		return
	}
	id := interactionID(grantID, input.IdempotencyKey)
	for _, existing := range s.interactions {
		if existing.InteractionID != id {
			continue
		}
		if interactionInputMatches(existing, input) {
			writeJSON(writer, http.StatusAccepted, cloneInteraction(existing))
			return
		}
		writeGatewayError(writer, http.StatusConflict, "interaction_conflict", "interaction idempotency key identifies different content")
		return
	}
	tenantCount, grantCount := 0, 0
	for _, existing := range s.interactions {
		if existing.TenantID == grant.TenantID {
			tenantCount++
		}
		if existing.GrantID == grantID {
			grantCount++
		}
	}
	if len(s.interactions) >= maxInteractions || tenantCount >= maxInteractionsTenant || grantCount >= maxInteractionsGrant {
		writer.Header().Set("Retry-After", "5")
		writeGatewayError(writer, http.StatusTooManyRequests, "interaction_queue_full", "interaction queue is full")
		return
	}
	acceptedAt := now.Format(time.RFC3339Nano)
	observedAt := input.ObservedAt
	if observedAt == "" {
		observedAt = now.Format(time.RFC3339)
	}
	interaction := Interaction{
		SchemaVersion: interactionRequestSchemaV1, InteractionID: id,
		IdempotencyKey: input.IdempotencyKey, Source: "agent",
		TenantID: grant.TenantID, NodeID: grant.NodeID, InstanceID: grant.InstanceID,
		Generation: grant.Generation, RuntimeRef: grant.RuntimeRef, GrantID: grant.GrantID,
		CapsuleDigest: grant.CapsuleDigest, PolicyDigest: grant.PolicyDigest,
		Kind: input.Kind, Title: input.Title, Prompt: input.Prompt,
		Options: append([]string(nil), input.Options...), AllowText: input.AllowText,
		TaskID: input.TaskID, RunID: input.RunID, ObservedAt: observedAt,
		AcceptedAt: acceptedAt, ExpiresAt: input.ExpiresAt, State: "open",
	}
	interaction.RequestDigest = interactionRequestDigest(interaction)
	s.interactions = append(s.interactions, interaction)
	if err := s.persistLocked(); err != nil {
		s.interactions = s.interactions[:len(s.interactions)-1]
		writeGatewayError(writer, http.StatusServiceUnavailable, "interaction_state_unavailable", "interaction could not be committed")
		return
	}
	writeJSON(writer, http.StatusAccepted, cloneInteraction(interaction))
}

func interactionInputMatches(existing Interaction, input InteractionInput) bool {
	return existing.IdempotencyKey == input.IdempotencyKey && existing.Kind == input.Kind &&
		existing.Title == input.Title && existing.Prompt == input.Prompt &&
		slices.Equal(existing.Options, input.Options) && existing.AllowText == input.AllowText &&
		existing.TaskID == input.TaskID && existing.RunID == input.RunID &&
		(input.ObservedAt == "" || existing.ObservedAt == input.ObservedAt) &&
		existing.ExpiresAt == input.ExpiresAt
}

func (s *Server) listGrantInteractions(writer http.ResponseWriter, request *http.Request, grantID string) {
	if request.URL.RawQuery != "" {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction list does not accept query parameters")
		return
	}
	s.mu.Lock()
	result := make([]Interaction, 0)
	for _, interaction := range s.interactions {
		if interaction.GrantID == grantID {
			result = append(result, effectiveInteraction(cloneInteraction(interaction), s.now().UTC()))
		}
	}
	s.mu.Unlock()
	writeJSON(writer, http.StatusOK, interactionBatch{Interactions: result})
}

func (s *Server) getGrantInteraction(writer http.ResponseWriter, request *http.Request, grantID string) {
	if request.URL.RawQuery != "" {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction lookup does not accept query parameters")
		return
	}
	id := strings.TrimPrefix(request.URL.Path, "/v1/interactions/")
	if !validInteractionID(id) {
		writeGatewayError(writer, http.StatusNotFound, "interaction_not_found", "interaction not found")
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, interaction := range s.interactions {
		if interaction.InteractionID == id && interaction.GrantID == grantID {
			writeJSON(writer, http.StatusOK, effectiveInteraction(cloneInteraction(interaction), s.now().UTC()))
			return
		}
	}
	writeGatewayError(writer, http.StatusNotFound, "interaction_not_found", "interaction not found")
}

func effectiveInteraction(value Interaction, now time.Time) Interaction {
	expires, err := canonicalInteractionTime(value.ExpiresAt)
	if err == nil && value.State == "open" && !now.Before(expires) {
		value.State = "expired"
	}
	return value
}

func (s *Server) listInteractionOutbox(writer http.ResponseWriter, request *http.Request) {
	if request.URL.RawQuery != "" {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction outbox does not accept query parameters")
		return
	}
	s.mu.Lock()
	result := make([]Interaction, 0)
	for _, interaction := range s.interactions {
		if !interaction.ControllerAccepted {
			result = append(result, cloneInteraction(interaction))
		}
	}
	s.mu.Unlock()
	writeJSON(writer, http.StatusOK, interactionBatch{Interactions: result})
}

func (s *Server) ackInteractionOutbox(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxInteractionCourierBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		writeGatewayError(writer, http.StatusRequestEntityTooLarge, "invalid_request", "interaction acknowledgement exceeds limit")
		return
	}
	var input interactionAck
	if err := dsse.DecodeStrictInto(raw, maxInteractionCourierBytes, &input); err != nil ||
		len(input.InteractionIDs) == 0 || len(input.InteractionIDs) > maxInteractions {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction acknowledgement is invalid")
		return
	}
	wanted := make(map[string]struct{}, len(input.InteractionIDs))
	for _, id := range input.InteractionIDs {
		if !validInteractionID(id) {
			writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction acknowledgement is invalid")
			return
		}
		if _, duplicate := wanted[id]; duplicate {
			writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction acknowledgement contains a duplicate")
			return
		}
		wanted[id] = struct{}{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	previous := make([]Interaction, len(s.interactions))
	for index, interaction := range s.interactions {
		previous[index] = cloneInteraction(interaction)
		if _, accepted := wanted[interaction.InteractionID]; accepted {
			s.interactions[index].ControllerAccepted = true
		}
	}
	if err := s.persistLocked(); err != nil {
		s.interactions = previous
		writeGatewayError(writer, http.StatusServiceUnavailable, "interaction_state_unavailable", "interaction acknowledgement could not be committed")
		return
	}
	writer.WriteHeader(http.StatusNoContent)
}

func (s *Server) resolveInteraction(writer http.ResponseWriter, request *http.Request) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxInteractionCourierBytes)
	raw, err := io.ReadAll(request.Body)
	if err != nil {
		writeGatewayError(writer, http.StatusRequestEntityTooLarge, "invalid_request", "interaction response courier exceeds limit")
		return
	}
	var courier interactionResponseCourier
	if err := dsse.DecodeStrictInto(raw, maxInteractionCourierBytes, &courier); err != nil ||
		!validInteractionID(courier.InteractionID) {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction response courier is invalid")
		return
	}
	permitRaw, err := base64.StdEncoding.DecodeString(courier.PermitBase64)
	if err != nil || base64.StdEncoding.EncodeToString(permitRaw) != courier.PermitBase64 {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction response permit encoding is invalid")
		return
	}
	responseRaw, err := base64.StdEncoding.DecodeString(courier.ResponseBase64)
	if err != nil || base64.StdEncoding.EncodeToString(responseRaw) != courier.ResponseBase64 ||
		len(responseRaw) == 0 || len(responseRaw) > interactionpermit.MaxResponseBytes {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_request", "interaction response encoding is invalid")
		return
	}
	var body InteractionResponseBody
	if err := dsse.DecodeStrictInto(responseRaw, interactionpermit.MaxResponseBytes, &body); err != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_interaction_response", "interaction response is invalid")
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	index := -1
	for candidate := range s.interactions {
		if s.interactions[candidate].InteractionID == courier.InteractionID {
			index = candidate
			break
		}
	}
	if index < 0 {
		writeGatewayError(writer, http.StatusNotFound, "interaction_not_found", "interaction not found")
		return
	}
	interaction := s.interactions[index]
	if body.Validate(interaction.Options, interaction.AllowText) != nil {
		writeGatewayError(writer, http.StatusBadRequest, "invalid_interaction_response", "interaction response is not valid for the offered choices")
		return
	}
	if interaction.Response != nil {
		if interaction.Response.PermitDigest == dsse.Digest(permitRaw) &&
			interaction.Response.ResponseDigest == interactionpermit.ResponseDigest(responseRaw) {
			writeJSON(writer, http.StatusOK, cloneInteraction(interaction))
			return
		}
		writeGatewayError(writer, http.StatusConflict, "interaction_already_resolved", "interaction was already resolved by a different response")
		return
	}
	expires, _ := canonicalInteractionTime(interaction.ExpiresAt)
	if !s.now().UTC().Before(expires) {
		writeGatewayError(writer, http.StatusConflict, "interaction_expired", "interaction expired before response delivery")
		return
	}
	grant, active := s.grants[interaction.GrantID]
	if !active || !grant.Active || len(grant.TaskAuthorities) == 0 {
		writeGatewayError(writer, http.StatusServiceUnavailable, "interaction_grant_inactive", "interaction grant is not active")
		return
	}
	trusted, err := taskAuthorityKeys(grant.TaskAuthorities)
	if err != nil {
		writeGatewayError(writer, http.StatusServiceUnavailable, "interaction_authority_unavailable", "interaction response authority could not be loaded")
		return
	}
	verified, err := interactionpermit.Verify(permitRaw, trusted, s.now().UTC(), interactionpermit.MaxValidity)
	if err != nil || !interactionPermitMatches(verified, interaction, responseRaw) {
		writeGatewayError(writer, http.StatusForbidden, "interaction_response_denied", "interaction response does not authorize this exact active request")
		return
	}
	resolved := s.now().UTC().Format(time.RFC3339Nano)
	s.interactions[index].State = "resolved"
	s.interactions[index].Response = &InteractionResponse{
		Body: body, KeyID: verified.KeyID, PermitDigest: verified.EnvelopeDigest,
		ResponseDigest: verified.Statement.ResponseDigest, ResolvedAt: resolved,
	}
	if err := s.persistLocked(); err != nil {
		s.interactions[index] = interaction
		writeGatewayError(writer, http.StatusServiceUnavailable, "interaction_state_unavailable", "interaction response could not be committed")
		return
	}
	writeJSON(writer, http.StatusOK, cloneInteraction(s.interactions[index]))
}

func interactionPermitMatches(verified interactionpermit.Verified, interaction Interaction, response []byte) bool {
	statement := verified.Statement
	return statement.NodeID == interaction.NodeID && statement.TenantID == interaction.TenantID &&
		statement.InstanceID == interaction.InstanceID && statement.RuntimeRef == interaction.RuntimeRef &&
		statement.GrantID == interaction.GrantID && statement.Generation == interaction.Generation &&
		statement.CapsuleDigest == interaction.CapsuleDigest && statement.PolicyDigest == interaction.PolicyDigest &&
		statement.InteractionID == interaction.InteractionID &&
		statement.RequestDigest == interaction.RequestDigest &&
		statement.ResponseDigest == interactionpermit.ResponseDigest(response) &&
		statement.ResponseBytes == int64(len(response))
}

func validateRetainedInteractions(values []Interaction) error {
	if len(values) > maxInteractions {
		return errors.New("gateway state contains too many interactions")
	}
	ids := make(map[string]struct{}, len(values))
	tenantCounts, grantCounts := map[string]int{}, map[string]int{}
	for _, value := range values {
		if value.SchemaVersion != interactionRequestSchemaV1 ||
			!validInteractionID(value.InteractionID) ||
			value.InteractionID != interactionID(value.GrantID, value.IdempotencyKey) ||
			value.Source != "agent" || !bounded(value.TenantID, 128) || !bounded(value.NodeID, 128) ||
			!bounded(value.InstanceID, 256) || value.Generation == 0 ||
			!validExecutorRuntimeRef(value.RuntimeRef) || !validGrantID(value.GrantID) ||
			!validSHA256Digest(value.CapsuleDigest) || !validSHA256Digest(value.PolicyDigest) ||
			value.State != "open" && value.State != "resolved" ||
			value.RequestDigest != interactionRequestDigest(value) {
			return errors.New("gateway state contains an invalid interaction binding")
		}
		input := InteractionInput{
			SchemaVersion: value.SchemaVersion, IdempotencyKey: value.IdempotencyKey,
			Kind: value.Kind, Title: value.Title, Prompt: value.Prompt,
			Options: value.Options, AllowText: value.AllowText, TaskID: value.TaskID,
			RunID: value.RunID, ObservedAt: value.ObservedAt, ExpiresAt: value.ExpiresAt,
		}
		accepted, err := time.Parse(time.RFC3339Nano, value.AcceptedAt)
		if err != nil || accepted.Format(time.RFC3339Nano) != value.AcceptedAt ||
			input.validate(accepted.UTC()) != nil {
			return errors.New("gateway state contains an invalid interaction")
		}
		if value.State == "resolved" {
			if value.Response == nil || value.Response.Body.Validate(value.Options, value.AllowText) != nil ||
				!validSHA256Digest(value.Response.PermitDigest) ||
				!validSHA256Digest(value.Response.ResponseDigest) ||
				!routeID(value.Response.KeyID) {
				return errors.New("gateway state contains an invalid interaction response")
			}
			if _, err := time.Parse(time.RFC3339Nano, value.Response.ResolvedAt); err != nil {
				return errors.New("gateway state contains an invalid interaction response time")
			}
		} else if value.Response != nil {
			return errors.New("gateway state contains a response on an open interaction")
		}
		if _, duplicate := ids[value.InteractionID]; duplicate {
			return errors.New("gateway state contains duplicate interactions")
		}
		ids[value.InteractionID] = struct{}{}
		tenantCounts[value.TenantID]++
		grantCounts[value.GrantID]++
		if tenantCounts[value.TenantID] > maxInteractionsTenant || grantCounts[value.GrantID] > maxInteractionsGrant {
			return errors.New("gateway state interaction quota is exceeded")
		}
	}
	return nil
}

func interactionCourier(interactionID string, permit, response []byte) interactionResponseCourier {
	return interactionResponseCourier{
		InteractionID:  interactionID,
		PermitBase64:   base64.StdEncoding.EncodeToString(permit),
		ResponseBase64: base64.StdEncoding.EncodeToString(response),
	}
}
