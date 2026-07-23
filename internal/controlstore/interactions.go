package controlstore

import (
	"encoding/base64"
	"errors"
	"reflect"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/interactionpermit"
)

const (
	MaxInteractionsRetained      = 4096
	MaxInteractionsPerTenant     = 1024
	MaxInteractionBytesRetained  = 64 << 20
	MaxInteractionBytesPerTenant = 16 << 20

	InteractionOpen           = "open"
	InteractionResponseQueued = "response_queued"
	InteractionResolved       = "resolved"
	InteractionExpired        = "expired"
)

// Interaction is Control's bounded operator view of an agent request. The
// signed response and its body remain private courier fields so list/get APIs,
// logs, metrics, and support bundles cannot disclose answer text or replayable
// material.
type Interaction struct {
	SchemaVersion    string   `json:"schema_version"`
	InteractionID    string   `json:"interaction_id"`
	IdempotencyKey   string   `json:"idempotency_key"`
	Source           string   `json:"source"`
	TenantID         string   `json:"tenant_id"`
	NodeID           string   `json:"node_id"`
	InstanceID       string   `json:"instance_id"`
	Generation       uint64   `json:"generation"`
	RuntimeRef       string   `json:"runtime_ref"`
	GrantID          string   `json:"grant_id"`
	CapsuleDigest    string   `json:"capsule_digest"`
	PolicyDigest     string   `json:"policy_digest"`
	Kind             string   `json:"kind"`
	Title            string   `json:"title"`
	Prompt           string   `json:"prompt"`
	Options          []string `json:"options"`
	AllowText        bool     `json:"allow_text"`
	TaskID           string   `json:"task_id,omitempty"`
	RunID            string   `json:"run_id,omitempty"`
	ObservedAt       string   `json:"observed_at"`
	AcceptedAt       string   `json:"accepted_at"`
	ExpiresAt        string   `json:"expires_at"`
	RequestDigest    string   `json:"request_digest"`
	ProjectID        string   `json:"project_id,omitempty"`
	SessionID        string   `json:"session_id,omitempty"`
	State            string   `json:"state"`
	ResponseKeyID    string   `json:"response_key_id,omitempty"`
	PermitDigest     string   `json:"permit_digest,omitempty"`
	ResponseDigest   string   `json:"response_digest,omitempty"`
	ResponseBytes    int64    `json:"response_bytes,omitempty"`
	ResponseQueuedAt string   `json:"response_queued_at,omitempty"`
	ResolvedAt       string   `json:"resolved_at,omitempty"`
	ReceivedAt       string   `json:"received_at"`
}

type storedInteraction struct {
	Interaction    `json:"interaction"`
	PermitBase64   string `json:"permit_base64,omitempty"`
	ResponseBase64 string `json:"response_base64,omitempty"`
}

func (value Interaction) Validate() error {
	if interactionRequest(value).Validate() != nil || !validTimestamp(value.ReceivedAt) ||
		(value.ProjectID == "") != (value.SessionID == "") ||
		value.ProjectID != "" && !validRecordID(value.ProjectID, 128) ||
		value.SessionID != "" && !validRecordID(value.SessionID, 128) ||
		(value.State != InteractionOpen && value.State != InteractionResponseQueued &&
			value.State != InteractionResolved && value.State != InteractionExpired) {
		return errors.New("interaction projection is invalid")
	}
	hasResponse := value.ResponseKeyID != "" || value.PermitDigest != "" ||
		value.ResponseDigest != "" || value.ResponseBytes != 0 || value.ResponseQueuedAt != ""
	if hasResponse {
		if !validRecordID(value.ResponseKeyID, 128) || !validSHA256Digest(value.PermitDigest) ||
			!validSHA256Digest(value.ResponseDigest) || value.ResponseBytes <= 0 ||
			value.ResponseBytes > interactionpermit.MaxResponseBytes || !validTimestamp(value.ResponseQueuedAt) {
			return errors.New("interaction response projection is invalid")
		}
	}
	if value.State == InteractionOpen && hasResponse ||
		value.State == InteractionResponseQueued && !hasResponse ||
		value.State == InteractionResolved && (!hasResponse || !validTimestamp(value.ResolvedAt)) ||
		value.State != InteractionResolved && value.ResolvedAt != "" {
		return errors.New("interaction state projection is invalid")
	}
	return nil
}

func cloneStoredInteraction(value storedInteraction) storedInteraction {
	value.Options = append([]string(nil), value.Options...)
	return value
}

func cloneInteractionView(value storedInteraction, now time.Time) Interaction {
	view := value.Interaction
	view.Options = append([]string(nil), value.Options...)
	if view.State != InteractionResolved && interactionExpired(view, now) {
		view.State = InteractionExpired
	}
	return view
}

func validStoredInteraction(value storedInteraction) bool {
	if interactionRequest(value.Interaction).Validate() != nil || !validTimestamp(value.ReceivedAt) ||
		(value.ProjectID == "") != (value.SessionID == "") ||
		value.ProjectID != "" && !validRecordID(value.ProjectID, 128) ||
		value.SessionID != "" && !validRecordID(value.SessionID, 128) ||
		!validInteractionState(value.State) {
		return false
	}
	hasResponse := value.State == InteractionResponseQueued || value.State == InteractionResolved
	if hasResponse != (value.PermitBase64 != "") || hasResponse != (value.ResponseBase64 != "") ||
		hasResponse != (value.ResponseKeyID != "") || hasResponse != (value.PermitDigest != "") ||
		hasResponse != (value.ResponseDigest != "") || hasResponse != (value.ResponseBytes > 0) ||
		hasResponse != (value.ResponseQueuedAt != "") ||
		(value.State == InteractionResolved) != (value.ResolvedAt != "") {
		return false
	}
	if !hasResponse {
		return value.ResolvedAt == ""
	}
	permit, permitErr := decodeCanonicalBase64(value.PermitBase64)
	response, responseErr := decodeCanonicalBase64(value.ResponseBase64)
	if permitErr != nil || responseErr != nil ||
		len(permit) > interactionpermit.MaxEnvelopeBytes ||
		int64(len(response)) != value.ResponseBytes ||
		len(response) > interactionpermit.MaxResponseBytes ||
		!validRecordID(value.ResponseKeyID, 128) ||
		!validSHA256Digest(value.PermitDigest) ||
		!validSHA256Digest(value.ResponseDigest) ||
		value.ResponseDigest != interactionpermit.ResponseDigest(response) ||
		!validTimestamp(value.ResponseQueuedAt) ||
		value.ResolvedAt != "" && !validTimestamp(value.ResolvedAt) {
		return false
	}
	inspected, err := interactionpermit.InspectUnverified(permit)
	if err != nil || inspected.KeyID != value.ResponseKeyID ||
		inspected.EnvelopeDigest != value.PermitDigest ||
		!interactionStatementMatches(inspected.Statement, interactionRequest(value.Interaction), response) {
		return false
	}
	permitExpires, permitExpiresErr := time.Parse(time.RFC3339, inspected.Statement.ExpiresAt)
	interactionExpires, interactionExpiresErr := time.Parse(time.RFC3339, value.ExpiresAt)
	queuedAt, queuedErr := parseTimestamp(value.ResponseQueuedAt)
	if permitExpiresErr != nil || interactionExpiresErr != nil || queuedErr != nil ||
		permitExpires.After(interactionExpires) || !queuedAt.Before(interactionExpires) {
		return false
	}
	if value.ResolvedAt != "" {
		resolvedAt, resolvedErr := parseTimestamp(value.ResolvedAt)
		if resolvedErr != nil || resolvedAt.Before(queuedAt) {
			return false
		}
	}
	return true
}

func validInteractionState(value string) bool {
	return value == InteractionOpen || value == InteractionResponseQueued || value == InteractionResolved
}

func interactionKey(tenantID, interactionID string) string {
	return tenantID + "\x00" + interactionID
}

func interactionExpired(value Interaction, now time.Time) bool {
	expires, err := time.Parse(time.RFC3339, value.ExpiresAt)
	return err == nil && !now.Before(expires)
}

// RetainInteractions commits one complete Gateway outbox batch idempotently.
// Capacity is recovered only from terminal records; an unanswered request is
// never silently discarded to admit a newer one.
func (store *Store) RetainInteractions(
	identity controlauth.NodeIdentity,
	batch controlprotocol.InteractionRequestBatchV1,
	now time.Time,
) (int, error) {
	if store == nil {
		return 0, ErrUnavailable
	}
	if now.IsZero() || identity.Audience != "executor" || batch.Validate() != nil ||
		batch.NodeID != identity.NodeID || !validTenantSet(identity.TenantIDs) {
		return 0, invalid("interaction batch or node identity is invalid")
	}
	for _, interaction := range batch.Interactions {
		if !controlauth.NodeAuthorizedTenant(identity, interaction.TenantID) {
			return 0, ErrForbidden
		}
		accepted, err := time.Parse(time.RFC3339Nano, interaction.AcceptedAt)
		if err != nil || accepted.After(now.Add(5*time.Minute)) {
			return 0, invalid("interaction accepted_at is ahead of controller time")
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return 0, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return 0, err
	}
	node, found := store.current.nodes[identity.NodeID]
	if !found || !node.Active || !tenantSubset(identity.TenantIDs, node.TenantIDs) {
		return 0, ErrNotFound
	}

	candidates := make(map[string]storedInteraction, len(store.current.interactions)+len(batch.Interactions))
	for key, interaction := range store.current.interactions {
		candidates[key] = cloneStoredInteraction(interaction)
	}
	mutations := make([]mutation, 0, 2*len(batch.Interactions))
	applied := 0
	receivedAtTime := now.UTC()
	for _, existing := range store.current.interactions {
		existingTime, err := parseTimestamp(existing.ReceivedAt)
		if err == nil && !receivedAtTime.After(existingTime) {
			receivedAtTime = existingTime.Add(time.Nanosecond)
		}
	}
	receivedAt := canonicalTimestamp(receivedAtTime)
	for _, request := range batch.Interactions {
		key := interactionKey(request.TenantID, request.InteractionID)
		if existing, exists := candidates[key]; exists {
			if !reflect.DeepEqual(interactionRequest(existing.Interaction), request) {
				return 0, ErrConflict
			}
			continue
		}
		stored := storedInteraction{Interaction: interactionFromRequest(request)}
		stored.State = InteractionOpen
		stored.ReceivedAt = receivedAt
		stored.ProjectID, stored.SessionID = interactionWorkroomLink(store.current.taskRequests, request)
		candidates[key] = stored
		mutations = append(mutations, interactionMutation(stored))
		applied++
	}
	if applied == 0 {
		return 0, nil
	}
	evictions, err := interactionRetentionEvictions(candidates, now)
	if err != nil {
		return 0, err
	}
	for _, ref := range evictions {
		if _, existed := store.current.interactions[interactionKey(ref.TenantID, ref.InteractionID)]; existed {
			mutations = append([]mutation{interactionDeleteMutation(ref.TenantID, ref.InteractionID)}, mutations...)
		}
	}
	if len(mutations) > maxMutationsPerRecord {
		return 0, ErrCapacityExceeded
	}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return 0, err
	}
	return applied, nil
}

func interactionWorkroomLink(tasks map[string]storedTaskRequest, request controlprotocol.InteractionRequestV1) (string, string) {
	if request.TaskID == "" {
		return "", ""
	}
	task, found := tasks[taskRequestKey(request.TenantID, request.TaskID)]
	if !found || task.NodeID != request.NodeID || task.InstanceID != request.InstanceID ||
		task.InstanceGeneration != request.Generation || task.RuntimeRef != request.RuntimeRef {
		return "", ""
	}
	return task.ProjectID, task.SessionID
}

func (store *Store) ListInteractions(actor controlauth.Identity, tenantID string, now time.Time) ([]Interaction, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	if now.IsZero() {
		return nil, invalid("interaction list time is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return nil, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return nil, ErrNotFound
	}
	result := make([]Interaction, 0)
	for _, interaction := range store.current.interactions {
		if interaction.TenantID == tenantID {
			result = append(result, cloneInteractionView(interaction, now))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].AcceptedAt != result[j].AcceptedAt {
			return timestampBefore(result[j].AcceptedAt, result[i].AcceptedAt)
		}
		return result[i].InteractionID > result[j].InteractionID
	})
	return result, nil
}

func (store *Store) GetInteraction(
	actor controlauth.Identity,
	tenantID, interactionID string,
	now time.Time,
) (Interaction, bool, error) {
	if store == nil {
		return Interaction{}, false, ErrUnavailable
	}
	if now.IsZero() || !validRecordID(tenantID, 128) {
		return Interaction{}, false, invalid("interaction lookup is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Interaction{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return Interaction{}, false, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return Interaction{}, false, ErrNotFound
	}
	value, found := store.current.interactions[interactionKey(tenantID, interactionID)]
	if !found {
		return Interaction{}, false, nil
	}
	return cloneInteractionView(value, now), true, nil
}

type InteractionResponseInput struct {
	TenantID      string
	InteractionID string
	Permit        []byte
	Response      []byte
}

// SubmitInteractionResponse stores an opaque signed response without trusting
// it. Exact binding and size are inspected for safe routing; Gateway performs
// signature verification before the agent can observe the response.
func (store *Store) SubmitInteractionResponse(
	actor controlauth.Identity,
	input InteractionResponseInput,
	now time.Time,
) (Interaction, bool, error) {
	if store == nil {
		return Interaction{}, false, ErrUnavailable
	}
	if now.IsZero() || !controlauth.AuthorizedTenant(actor, input.TenantID) ||
		len(input.Permit) == 0 || len(input.Permit) > interactionpermit.MaxEnvelopeBytes ||
		len(input.Response) == 0 || len(input.Response) > interactionpermit.MaxResponseBytes {
		return Interaction{}, false, invalid("interaction response is invalid or exceeds its bound")
	}
	inspected, err := interactionpermit.InspectUnverified(input.Permit)
	if err != nil || inspected.Statement.TenantID != input.TenantID ||
		inspected.Statement.InteractionID != input.InteractionID ||
		inspected.Statement.ResponseDigest != interactionpermit.ResponseDigest(input.Response) ||
		inspected.Statement.ResponseBytes != int64(len(input.Response)) {
		return Interaction{}, false, invalid("interaction response permit does not bind this request and response")
	}
	notBefore, beforeErr := time.Parse(time.RFC3339, inspected.Statement.NotBefore)
	expires, expiresErr := time.Parse(time.RFC3339, inspected.Statement.ExpiresAt)
	if beforeErr != nil || expiresErr != nil || now.Before(notBefore) || !now.Before(expires) {
		return Interaction{}, false, invalid("interaction response permit is not currently active")
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Interaction{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return Interaction{}, false, err
	}
	key := interactionKey(input.TenantID, input.InteractionID)
	existing, found := store.current.interactions[key]
	if !found {
		return Interaction{}, false, ErrNotFound
	}
	if existing.State == InteractionResponseQueued || existing.State == InteractionResolved {
		if existing.PermitDigest == inspected.EnvelopeDigest &&
			existing.ResponseDigest == inspected.Statement.ResponseDigest {
			return cloneInteractionView(existing, now), false, nil
		}
		return Interaction{}, false, ErrConflict
	}
	if interactionExpired(existing.Interaction, now) {
		return Interaction{}, false, ErrConflict
	}
	interactionExpires, _ := time.Parse(time.RFC3339, existing.ExpiresAt)
	if expires.After(interactionExpires) ||
		!interactionStatementMatches(inspected.Statement, interactionRequest(existing.Interaction), input.Response) {
		return Interaction{}, false, invalid("interaction response permit does not bind the retained active request")
	}
	existing.State = InteractionResponseQueued
	existing.ResponseKeyID = inspected.KeyID
	existing.PermitDigest = inspected.EnvelopeDigest
	existing.ResponseDigest = inspected.Statement.ResponseDigest
	existing.ResponseBytes = inspected.Statement.ResponseBytes
	existing.ResponseQueuedAt = canonicalTimestamp(now)
	existing.PermitBase64 = base64.StdEncoding.EncodeToString(input.Permit)
	existing.ResponseBase64 = base64.StdEncoding.EncodeToString(input.Response)
	evictions, err := interactionCourierEvictions(store.current.interactions, existing, now)
	if err != nil {
		return Interaction{}, false, err
	}
	mutations := make([]mutation, 0, len(evictions)+1)
	for _, ref := range evictions {
		mutations = append(mutations, interactionDeleteMutation(ref.TenantID, ref.InteractionID))
	}
	mutations = append(mutations, interactionMutation(existing))
	if len(mutations) > maxMutationsPerRecord {
		return Interaction{}, false, ErrCapacityExceeded
	}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return Interaction{}, false, err
	}
	return cloneInteractionView(existing, now), true, nil
}

func interactionFromRequest(request controlprotocol.InteractionRequestV1) Interaction {
	return Interaction{
		SchemaVersion: request.SchemaVersion, InteractionID: request.InteractionID,
		IdempotencyKey: request.IdempotencyKey, Source: request.Source,
		TenantID: request.TenantID, NodeID: request.NodeID, InstanceID: request.InstanceID,
		Generation: request.Generation, RuntimeRef: request.RuntimeRef, GrantID: request.GrantID,
		CapsuleDigest: request.CapsuleDigest, PolicyDigest: request.PolicyDigest,
		Kind: request.Kind, Title: request.Title, Prompt: request.Prompt,
		Options: append([]string(nil), request.Options...), AllowText: request.AllowText,
		TaskID: request.TaskID, RunID: request.RunID, ObservedAt: request.ObservedAt,
		AcceptedAt: request.AcceptedAt, ExpiresAt: request.ExpiresAt,
		RequestDigest: request.RequestDigest,
	}
}

func interactionRequest(value Interaction) controlprotocol.InteractionRequestV1 {
	return controlprotocol.InteractionRequestV1{
		SchemaVersion: value.SchemaVersion, InteractionID: value.InteractionID,
		IdempotencyKey: value.IdempotencyKey, Source: value.Source,
		TenantID: value.TenantID, NodeID: value.NodeID, InstanceID: value.InstanceID,
		Generation: value.Generation, RuntimeRef: value.RuntimeRef, GrantID: value.GrantID,
		CapsuleDigest: value.CapsuleDigest, PolicyDigest: value.PolicyDigest,
		Kind: value.Kind, Title: value.Title, Prompt: value.Prompt,
		Options: append([]string(nil), value.Options...), AllowText: value.AllowText,
		TaskID: value.TaskID, RunID: value.RunID, ObservedAt: value.ObservedAt,
		AcceptedAt: value.AcceptedAt, ExpiresAt: value.ExpiresAt,
		RequestDigest: value.RequestDigest,
	}
}

func interactionStatementMatches(
	statement interactionpermit.Statement,
	request controlprotocol.InteractionRequestV1,
	response []byte,
) bool {
	return statement.NodeID == request.NodeID && statement.TenantID == request.TenantID &&
		statement.InstanceID == request.InstanceID && statement.RuntimeRef == request.RuntimeRef &&
		statement.GrantID == request.GrantID && statement.Generation == request.Generation &&
		statement.CapsuleDigest == request.CapsuleDigest && statement.PolicyDigest == request.PolicyDigest &&
		statement.InteractionID == request.InteractionID &&
		statement.RequestDigest == request.RequestDigest &&
		statement.ResponseDigest == interactionpermit.ResponseDigest(response) &&
		statement.ResponseBytes == int64(len(response))
}

func (store *Store) PollInteractionResponses(
	identity controlauth.NodeIdentity,
	now time.Time,
	limit int,
) ([]controlprotocol.InteractionResponseDeliveryV1, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	if now.IsZero() || limit <= 0 || limit > controlprotocol.MaxInteractionBatch ||
		identity.Audience != "executor" || !validTenantSet(identity.TenantIDs) {
		return nil, invalid("interaction response poll is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return nil, err
	}
	candidates := make([]storedInteraction, 0)
	for _, interaction := range store.current.interactions {
		if interaction.NodeID == identity.NodeID && interaction.State == InteractionResponseQueued &&
			controlauth.NodeAuthorizedTenant(identity, interaction.TenantID) &&
			!interactionExpired(interaction.Interaction, now) {
			candidates = append(candidates, cloneStoredInteraction(interaction))
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ResponseQueuedAt != candidates[j].ResponseQueuedAt {
			return timestampBefore(candidates[i].ResponseQueuedAt, candidates[j].ResponseQueuedAt)
		}
		return candidates[i].InteractionID < candidates[j].InteractionID
	})
	if len(candidates) > limit {
		candidates = candidates[:limit]
	}
	result := make([]controlprotocol.InteractionResponseDeliveryV1, 0, len(candidates))
	for _, interaction := range candidates {
		result = append(result, controlprotocol.InteractionResponseDeliveryV1{
			SchemaVersion: controlprotocol.InteractionResponseSchemaV1,
			InteractionID: interaction.InteractionID,
			PermitBase64:  interaction.PermitBase64, ResponseBase64: interaction.ResponseBase64,
			PermitDigest: interaction.PermitDigest,
		})
	}
	return result, nil
}

func (store *Store) AckInteractionResponse(
	identity controlauth.NodeIdentity,
	ack controlprotocol.InteractionResponseAckV1,
	now time.Time,
) (bool, error) {
	if store == nil {
		return false, ErrUnavailable
	}
	if now.IsZero() || ack.SchemaVersion != controlprotocol.InteractionAckSchemaV1 ||
		!validSHA256Digest(ack.PermitDigest) || identity.Audience != "executor" {
		return false, invalid("interaction response acknowledgement is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return false, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return false, err
	}
	var key string
	var existing storedInteraction
	for candidateKey, candidate := range store.current.interactions {
		if candidate.NodeID == identity.NodeID && candidate.InteractionID == ack.InteractionID &&
			controlauth.NodeAuthorizedTenant(identity, candidate.TenantID) {
			key, existing = candidateKey, candidate
			break
		}
	}
	if key == "" {
		return false, ErrNotFound
	}
	if existing.PermitDigest != ack.PermitDigest {
		return false, ErrConflict
	}
	if existing.State == InteractionResolved {
		return false, nil
	}
	if existing.State != InteractionResponseQueued {
		return false, ErrConflict
	}
	existing.State = InteractionResolved
	existing.ResolvedAt = canonicalTimestamp(now)
	if err := store.applyMutationsLocked(interactionMutation(existing)); err != nil {
		return false, err
	}
	return true, nil
}

type interactionReference struct {
	TenantID      string `json:"tenant_id"`
	InteractionID string `json:"interaction_id"`
}

func interactionMutation(value storedInteraction) mutation {
	cloned := cloneStoredInteraction(value)
	return mutation{Kind: mutationInteraction, Interaction: &cloned}
}

func interactionDeleteMutation(tenantID, interactionID string) mutation {
	return mutation{
		Kind:           mutationInteractionDelete,
		InteractionRef: &interactionReference{TenantID: tenantID, InteractionID: interactionID},
	}
}

func interactionRetentionEvictions(
	values map[string]storedInteraction,
	now time.Time,
) ([]interactionReference, error) {
	byTenant := make(map[string][]storedInteraction)
	for _, interaction := range values {
		byTenant[interaction.TenantID] = append(byTenant[interaction.TenantID], interaction)
	}
	evicted := make(map[string]interactionReference)
	for tenantID, tenantInteractions := range byTenant {
		sortOldestInteractions(tenantInteractions)
		for len(tenantInteractions) > MaxInteractionsPerTenant {
			oldest := tenantInteractions[0]
			if !interactionTerminal(oldest, now) {
				return nil, ErrCapacityExceeded
			}
			ref := interactionReference{TenantID: tenantID, InteractionID: oldest.InteractionID}
			evicted[interactionKey(ref.TenantID, ref.InteractionID)] = ref
			tenantInteractions = tenantInteractions[1:]
		}
	}
	remaining := make([]storedInteraction, 0, len(values)-len(evicted))
	for key, interaction := range values {
		if _, removed := evicted[key]; !removed {
			remaining = append(remaining, interaction)
		}
	}
	sortOldestInteractions(remaining)
	for len(remaining) > MaxInteractionsRetained {
		oldest := remaining[0]
		if !interactionTerminal(oldest, now) {
			return nil, ErrCapacityExceeded
		}
		ref := interactionReference{TenantID: oldest.TenantID, InteractionID: oldest.InteractionID}
		evicted[interactionKey(ref.TenantID, ref.InteractionID)] = ref
		remaining = remaining[1:]
	}
	result := make([]interactionReference, 0, len(evicted))
	for _, ref := range evicted {
		result = append(result, ref)
	}
	sort.Slice(result, func(i, j int) bool {
		return interactionKey(result[i].TenantID, result[i].InteractionID) <
			interactionKey(result[j].TenantID, result[j].InteractionID)
	})
	return result, nil
}

func interactionTerminal(value storedInteraction, now time.Time) bool {
	return value.State == InteractionResolved ||
		value.State != InteractionResolved && interactionExpired(value.Interaction, now)
}

func sortOldestInteractions(values []storedInteraction) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].ReceivedAt != values[j].ReceivedAt {
			return timestampBefore(values[i].ReceivedAt, values[j].ReceivedAt)
		}
		return values[i].InteractionID < values[j].InteractionID
	})
}

func interactionCourierBytes(value storedInteraction) int64 {
	return int64(len(value.PermitBase64) + len(value.ResponseBase64))
}

func interactionCourierEvictions(
	current map[string]storedInteraction,
	replacement storedInteraction,
	now time.Time,
) ([]interactionReference, error) {
	values := make(map[string]storedInteraction, len(current))
	for key, value := range current {
		values[key] = cloneStoredInteraction(value)
	}
	replacementKey := interactionKey(replacement.TenantID, replacement.InteractionID)
	values[replacementKey] = cloneStoredInteraction(replacement)
	evicted := make([]interactionReference, 0)
	for {
		byTenant := make(map[string]int64)
		var total int64
		for _, value := range values {
			bytes := interactionCourierBytes(value)
			total += bytes
			byTenant[value.TenantID] += bytes
		}
		tenantOver := byTenant[replacement.TenantID] > MaxInteractionBytesPerTenant
		if !tenantOver && total <= MaxInteractionBytesRetained {
			return evicted, nil
		}
		candidates := make([]storedInteraction, 0)
		for key, value := range values {
			if key == replacementKey || !interactionTerminal(value, now) ||
				tenantOver && value.TenantID != replacement.TenantID {
				continue
			}
			candidates = append(candidates, value)
		}
		if len(candidates) == 0 {
			return nil, ErrCapacityExceeded
		}
		sortOldestInteractions(candidates)
		oldest := candidates[0]
		ref := interactionReference{TenantID: oldest.TenantID, InteractionID: oldest.InteractionID}
		delete(values, interactionKey(ref.TenantID, ref.InteractionID))
		evicted = append(evicted, ref)
		if len(evicted)+1 > maxMutationsPerRecord {
			return nil, ErrCapacityExceeded
		}
	}
}
