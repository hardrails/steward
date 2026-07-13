package controlstore

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	// MaxDeliveryLease is the single supported upper bound shared by storage,
	// HTTP, and command-line validation.
	MaxDeliveryLease     = 10 * time.Minute
	observationInterval  = time.Minute
	maxPollResponseBytes = 1 << 20
)

// BootstrapSiteAdmin creates or reproduces the sole reserved bootstrap
// credential while every other retained collection is empty. The bearer is
// derived from the auth key and is never persisted by Store.
func (store *Store) BootstrapSiteAdmin(auth *controlauth.Manager, now time.Time) (string, controlauth.Credential, bool, error) {
	if store == nil || auth == nil {
		return "", controlauth.Credential{}, false, ErrUnavailable
	}
	if now.IsZero() {
		return "", controlauth.Credential{}, false, invalid("bootstrap time is required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return "", controlauth.Credential{}, false, err
	}
	otherState := len(store.current.tenants) != 0 || len(store.current.nodes) != 0 ||
		len(store.current.enrollments) != 0 || len(store.current.commands) != 0
	if otherState || len(store.current.credentials) > 1 {
		return "", controlauth.Credential{}, false, ErrConflict
	}
	if len(store.current.credentials) == 1 {
		var existing controlauth.Credential
		for _, credential := range store.current.credentials {
			existing = cloneCredential(credential)
		}
		if existing.Kind != controlauth.KindOperator || existing.Role != controlauth.RoleSiteAdmin ||
			existing.TenantID != "" || existing.RequestID != controlauth.BootstrapRequestID || existing.Revoked {
			return "", controlauth.Credential{}, false, ErrConflict
		}
		createdAt, err := parseTimestamp(existing.CreatedAt)
		if err != nil {
			return "", controlauth.Credential{}, false, ErrConflict
		}
		raw, derived, err := auth.MintBootstrapOperator(createdAt)
		if err != nil || !credentialsEqual(existing, derived) {
			return "", controlauth.Credential{}, false, ErrConflict
		}
		return raw, existing, false, nil
	}
	raw, credential, err := auth.MintBootstrapOperator(now)
	if err != nil {
		return "", controlauth.Credential{}, false, err
	}
	if err := store.applyMutationsLocked(credentialMutation(credential)); err != nil {
		return "", controlauth.Credential{}, false, err
	}
	return raw, cloneCredential(credential), true, nil
}

func (store *Store) AuthenticateOperator(auth *controlauth.Manager, raw string) (controlauth.Identity, error) {
	if store == nil || auth == nil {
		return controlauth.Identity{}, controlauth.ErrUnauthorized
	}
	id, err := auth.OperatorCredentialID(raw)
	if err != nil {
		return controlauth.Identity{}, controlauth.ErrUnauthorized
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return controlauth.Identity{}, err
	}
	credential, ok := store.current.credentials[id]
	if !ok {
		return controlauth.Identity{}, controlauth.ErrUnauthorized
	}
	return auth.AuthenticateOperator(raw, cloneCredential(credential))
}

func (store *Store) AuthenticateNode(auth *controlauth.Manager, raw string) (controlauth.NodeIdentity, error) {
	if store == nil || auth == nil {
		return controlauth.NodeIdentity{}, controlauth.ErrUnauthorized
	}
	id, err := auth.NodeCredentialID(raw)
	if err != nil {
		return controlauth.NodeIdentity{}, controlauth.ErrUnauthorized
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return controlauth.NodeIdentity{}, err
	}
	credential, ok := store.current.credentials[id]
	if !ok {
		return controlauth.NodeIdentity{}, controlauth.ErrUnauthorized
	}
	node, ok := store.current.nodes[credential.NodeID]
	if !ok || !node.Active || !tenantSubset(credential.TenantIDs, node.TenantIDs) {
		return controlauth.NodeIdentity{}, controlauth.ErrUnauthorized
	}
	return auth.AuthenticateNode(raw, cloneCredential(credential))
}

func (store *Store) CreateTenant(actor controlauth.Identity, tenantID string, now time.Time) (Tenant, bool, error) {
	if store == nil {
		return Tenant{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return Tenant{}, false, ErrForbidden
	}
	if !validRecordID(tenantID, 128) || now.IsZero() {
		return Tenant{}, false, invalid("tenant identity and creation time are required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Tenant{}, false, err
	}
	if existing, ok := store.current.tenants[tenantID]; ok {
		return existing, false, nil
	}
	tenant := Tenant{ID: tenantID, CreatedAt: canonicalTimestamp(now), Active: true}
	if err := store.applyMutationsLocked(mutation{Kind: mutationTenant, Tenant: &tenant}); err != nil {
		return Tenant{}, false, err
	}
	return tenant, true, nil
}

func (store *Store) GetTenant(actor controlauth.Identity, tenantID string) (Tenant, bool, error) {
	if store == nil {
		return Tenant{}, false, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Tenant{}, false, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return Tenant{}, false, nil
	}
	tenant, ok := store.current.tenants[tenantID]
	return tenant, ok, nil
}

func (store *Store) ListTenants(actor controlauth.Identity) ([]Tenant, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	result := make([]Tenant, 0, len(store.current.tenants))
	if controlauth.IsSiteAdmin(actor) {
		for _, tenant := range store.current.tenants {
			result = append(result, tenant)
		}
	} else if actor.Role == controlauth.RoleTenantOperator && controlauth.AuthorizedTenant(actor, actor.TenantID) {
		if tenant, ok := store.current.tenants[actor.TenantID]; ok {
			result = append(result, tenant)
		}
	} else {
		return nil, ErrForbidden
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (store *Store) IssueOperator(actor controlauth.Identity, auth *controlauth.Manager, requestID string, role controlauth.Role, tenantID string, now time.Time) (string, controlauth.Credential, bool, error) {
	if store == nil {
		return "", controlauth.Credential{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return "", controlauth.Credential{}, false, ErrForbidden
	}
	if auth == nil {
		return "", controlauth.Credential{}, false, ErrUnavailable
	}
	if !validRecordID(requestID, 128) || requestID == controlauth.BootstrapRequestID || now.IsZero() ||
		role != controlauth.RoleSiteAdmin && role != controlauth.RoleTenantOperator ||
		role == controlauth.RoleSiteAdmin && tenantID != "" || role == controlauth.RoleTenantOperator && !validRecordID(tenantID, 128) {
		return "", controlauth.Credential{}, false, invalid("operator request identity, role, tenant scope, or creation time is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return "", controlauth.Credential{}, false, err
	}
	for _, existing := range store.current.credentials {
		if existing.RequestID != requestID {
			continue
		}
		if existing.Kind != controlauth.KindOperator || existing.Role != role || existing.TenantID != tenantID || existing.Revoked {
			return "", controlauth.Credential{}, false, ErrConflict
		}
		createdAt, err := parseTimestamp(existing.CreatedAt)
		if err != nil {
			return "", controlauth.Credential{}, false, ErrConflict
		}
		raw, derived, err := auth.MintOperatorForRequest(requestID, role, tenantID, createdAt)
		if err != nil || !credentialsEqual(existing, derived) {
			return "", controlauth.Credential{}, false, ErrConflict
		}
		return raw, cloneCredential(existing), false, nil
	}
	if role == controlauth.RoleTenantOperator {
		tenant, ok := store.current.tenants[tenantID]
		if !ok || !tenant.Active {
			return "", controlauth.Credential{}, false, ErrNotFound
		}
	}
	raw, credential, err := auth.MintOperatorForRequest(requestID, role, tenantID, now)
	if err != nil {
		return "", controlauth.Credential{}, false, err
	}
	if _, exists := store.current.credentials[credential.ID]; exists {
		return "", controlauth.Credential{}, false, ErrConflict
	}
	if err := store.applyMutationsLocked(credentialMutation(credential)); err != nil {
		return "", controlauth.Credential{}, false, err
	}
	return raw, cloneCredential(credential), true, nil
}

func (store *Store) RevokeCredential(actor controlauth.Identity, credentialID string, now time.Time) (bool, error) {
	return store.revokeCredential(actor, credentialID, now, false)
}

// RevokeOperator revokes only an operator credential. A node credential is
// reported as absent so an operator-management endpoint cannot revoke node
// access accidentally or reveal credential kinds through this operation.
func (store *Store) RevokeOperator(actor controlauth.Identity, credentialID string, now time.Time) (bool, error) {
	return store.revokeCredential(actor, credentialID, now, true)
}

func (store *Store) revokeCredential(actor controlauth.Identity, credentialID string, now time.Time, operatorOnly bool) (bool, error) {
	if store == nil {
		return false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return false, ErrForbidden
	}
	if !validRecordID(credentialID, 128) || now.IsZero() {
		return false, invalid("credential identity and revocation time are required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return false, err
	}
	credential, ok := store.current.credentials[credentialID]
	if !ok || operatorOnly && credential.Kind != controlauth.KindOperator {
		return false, ErrNotFound
	}
	if credential.Revoked {
		return false, nil
	}
	created, _ := parseTimestamp(credential.CreatedAt)
	if now.Before(created) {
		return false, invalid("revocation time precedes credential creation")
	}
	credential.Revoked = true
	credential.RevokedAt = canonicalTimestamp(now)
	if err := store.applyMutationsLocked(credentialMutation(credential)); err != nil {
		return false, err
	}
	return true, nil
}

// RevokeNode atomically disables a node and every retained credential and
// enrollment capability bound to it. Only a site administrator may do this.
func (store *Store) RevokeNode(actor controlauth.Identity, nodeID string, now time.Time) (int, error) {
	if store == nil {
		return 0, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return 0, ErrForbidden
	}
	if !validRecordID(nodeID, 128) || now.IsZero() {
		return 0, invalid("node identity and revocation time are required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return 0, err
	}
	node, ok := store.current.nodes[nodeID]
	if !ok {
		return 0, ErrNotFound
	}
	if !node.Active {
		return 0, nil
	}
	created, _ := parseTimestamp(node.CreatedAt)
	if now.Before(created) {
		return 0, invalid("revocation time precedes node creation")
	}
	revoked := 0
	for _, credential := range store.current.credentials {
		if credential.Kind == controlauth.KindNode && credential.NodeID == nodeID && !credential.Revoked {
			credentialCreated, _ := parseTimestamp(credential.CreatedAt)
			if now.Before(credentialCreated) {
				return 0, invalid("revocation time precedes a node credential")
			}
			revoked++
		}
	}
	for _, enrollment := range store.current.enrollments {
		if enrollment.NodeID == nodeID && !enrollment.Revoked {
			enrollmentCreated, _ := parseTimestamp(enrollment.CreatedAt)
			if now.Before(enrollmentCreated) {
				return 0, invalid("revocation time precedes a node enrollment")
			}
		}
	}
	revocation := nodeRevocation{NodeID: nodeID, RevokedAt: canonicalTimestamp(now)}
	if err := store.applyMutationsLocked(mutation{Kind: mutationNodeRevoke, NodeRevoke: &revocation}); err != nil {
		return 0, err
	}
	return revoked, nil
}

func (store *Store) CreateEnrollment(actor controlauth.Identity, auth *controlauth.Manager, nodeID string, tenantIDs []string, expiresAt, now time.Time) (string, controlauth.Enrollment, Node, error) {
	if store == nil {
		return "", controlauth.Enrollment{}, Node{}, ErrUnavailable
	}
	if auth == nil {
		return "", controlauth.Enrollment{}, Node{}, ErrUnavailable
	}
	canonical, err := controlauth.CanonicalTenantIDs(tenantIDs)
	if err != nil || !validRecordID(nodeID, 128) || now.IsZero() || !expiresAt.After(now) || expiresAt.Sub(now) > 24*time.Hour {
		return "", controlauth.Enrollment{}, Node{}, invalid("enrollment node, tenant set, or lifetime is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return "", controlauth.Enrollment{}, Node{}, err
	}
	for _, tenantID := range canonical {
		if !controlauth.AuthorizedTenant(actor, tenantID) {
			return "", controlauth.Enrollment{}, Node{}, ErrNotFound
		}
		tenant, ok := store.current.tenants[tenantID]
		if !ok || !tenant.Active {
			return "", controlauth.Enrollment{}, Node{}, ErrNotFound
		}
	}
	if err := store.reclaimExpiredEnrollmentsLocked(now, 2); err != nil {
		return "", controlauth.Enrollment{}, Node{}, err
	}
	node, exists := store.current.nodes[nodeID]
	if exists && !node.Active {
		return "", controlauth.Enrollment{}, Node{}, ErrConflict
	}
	if !exists {
		node = Node{
			ID: nodeID, TenantIDs: append([]string(nil), canonical...), Capabilities: []string{},
			CreatedAt: canonicalTimestamp(now), Active: true,
		}
	} else {
		node.TenantIDs = unionTenantIDs(node.TenantIDs, canonical)
	}
	raw, enrollment, err := auth.MintEnrollment(canonical, nodeID, expiresAt, now)
	if err != nil {
		return "", controlauth.Enrollment{}, Node{}, err
	}
	mutations := []mutation{{Kind: mutationNode, Node: &node}, enrollmentMutation(enrollment)}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return "", controlauth.Enrollment{}, Node{}, err
	}
	return raw, cloneEnrollment(enrollment), projectNode(node, actor, canonical[0]), nil
}

func (store *Store) ExchangeEnrollment(auth *controlauth.Manager, raw, requestID string, now time.Time) (controlauth.NodeCredentialFile, error) {
	if store == nil {
		return controlauth.NodeCredentialFile{}, ErrUnavailable
	}
	if auth == nil {
		return controlauth.NodeCredentialFile{}, controlauth.ErrUnauthorized
	}
	if !validRecordID(requestID, 128) || now.IsZero() {
		return controlauth.NodeCredentialFile{}, invalid("enrollment request identity and time are required")
	}
	id, err := auth.EnrollmentID(raw)
	if err != nil {
		return controlauth.NodeCredentialFile{}, controlauth.ErrUnauthorized
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return controlauth.NodeCredentialFile{}, err
	}
	enrollment, ok := store.current.enrollments[id]
	if !ok {
		return controlauth.NodeCredentialFile{}, controlauth.ErrUnauthorized
	}
	node, ok := store.current.nodes[enrollment.NodeID]
	if !ok || !node.Active || !tenantSubset(enrollment.TenantIDs, node.TenantIDs) {
		return controlauth.NodeCredentialFile{}, controlauth.ErrUnauthorized
	}
	file, credential, updated, err := auth.Exchange(raw, requestID, now, cloneEnrollment(enrollment))
	if err != nil {
		return controlauth.NodeCredentialFile{}, err
	}
	if existing, exists := store.current.credentials[credential.ID]; exists {
		if !credentialsEqual(existing, credential) || !enrollmentsEqual(enrollment, updated) {
			return controlauth.NodeCredentialFile{}, ErrConflict
		}
		return file, nil
	}
	mutations := []mutation{credentialMutation(credential), enrollmentMutation(updated)}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return controlauth.NodeCredentialFile{}, err
	}
	return file, nil
}

func (store *Store) ListNodes(actor controlauth.Identity, tenantID string) ([]Node, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return nil, ErrNotFound
	}
	if _, ok := store.current.tenants[tenantID]; !ok {
		return nil, ErrNotFound
	}
	result := make([]Node, 0)
	for _, node := range store.current.nodes {
		if tenantMember(node.TenantIDs, tenantID) {
			result = append(result, projectNode(node, actor, tenantID))
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (store *Store) GetNode(actor controlauth.Identity, tenantID, nodeID string) (Node, bool, error) {
	if store == nil {
		return Node{}, false, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Node{}, false, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return Node{}, false, nil
	}
	node, ok := store.current.nodes[nodeID]
	if !ok || !tenantMember(node.TenantIDs, tenantID) {
		return Node{}, false, nil
	}
	return projectNode(node, actor, tenantID), true, nil
}

// SubmitCommand parses untrusted DSSE only far enough to bind signed identity
// fields to the requested tenant and node. Signature authority remains solely
// on the node; Store never accepts a command verification key.
func (store *Store) SubmitCommand(actor controlauth.Identity, tenantID, nodeID string, commandDSSE []byte, now time.Time) (Command, bool, error) {
	if store == nil {
		return Command{}, false, ErrUnavailable
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return Command{}, false, ErrNotFound
	}
	if now.IsZero() || len(commandDSSE) == 0 || len(commandDSSE) > store.limits.MaxCommandBytes {
		return Command{}, false, invalid("command bytes or submission time are invalid")
	}
	commandID, signedTenant, signedNode, err := parseCommandIdentity(commandDSSE)
	if err != nil {
		return Command{}, false, invalidError("parse command DSSE", err)
	}
	if signedTenant != tenantID || signedNode != nodeID {
		return Command{}, false, invalid("signed command identity does not match its route")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Command{}, false, err
	}
	tenant, ok := store.current.tenants[tenantID]
	if !ok || !tenant.Active {
		return Command{}, false, ErrNotFound
	}
	node, ok := store.current.nodes[nodeID]
	if !ok || !node.Active || !tenantMember(node.TenantIDs, tenantID) {
		return Command{}, false, ErrNotFound
	}
	key := commandKey(tenantID, nodeID, commandID)
	if existing, exists := store.current.commands[key]; exists {
		candidate := Command{TenantID: tenantID, NodeID: nodeID, ID: commandID, Digest: digestBytes(commandDSSE), CommandDSSE: commandDSSE}
		if !commandsEqual(existing, candidate) {
			return Command{}, false, ErrConflict
		}
		return cloneCommand(existing), false, nil
	}
	command := Command{
		TenantID: tenantID, NodeID: nodeID, ID: commandID, DeliveryID: deliveryID(tenantID, nodeID, commandID),
		Digest: digestBytes(commandDSSE), CommandDSSE: append([]byte(nil), commandDSSE...),
		State: CommandPending, CreatedAt: canonicalTimestamp(now),
	}
	if _, err := deliveryFor(command, 1); err != nil {
		return Command{}, false, invalidError("command cannot fit one Executor delivery", err)
	}
	if err := store.applyMutationsLocked(commandMutation(command)); err == nil {
		return cloneCommand(command), true, nil
	} else if !errors.Is(err, ErrCapacityExceeded) {
		return Command{}, false, err
	}
	candidates := store.prunableCommandsLocked(tenantID, nodeID, now)
	mutations := make([]mutation, 0, minInt(len(candidates)+1, maxMutationsPerRecord))
	for index, candidate := range candidates {
		if index >= maxMutationsPerRecord-1 {
			break
		}
		reference := commandReference{TenantID: candidate.TenantID, NodeID: candidate.NodeID, ID: candidate.ID}
		mutations = append(mutations, mutation{Kind: mutationCommandDelete, CommandRef: &reference})
		attempt := append(append([]mutation(nil), mutations...), commandMutation(command))
		if err := store.applyMutationsLocked(attempt...); err == nil {
			return cloneCommand(command), true, nil
		} else if !errors.Is(err, ErrCapacityExceeded) {
			return Command{}, false, err
		}
	}
	return Command{}, false, ErrCapacityExceeded
}

func (store *Store) GetCommand(actor controlauth.Identity, tenantID, nodeID, commandID string) (Command, bool, error) {
	if store == nil {
		return Command{}, false, ErrUnavailable
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Command{}, false, err
	}
	if !controlauth.AuthorizedTenant(actor, tenantID) {
		return Command{}, false, nil
	}
	command, ok := store.current.commands[commandKey(tenantID, nodeID, commandID)]
	if !ok {
		return Command{}, false, nil
	}
	return cloneCommand(command), true, nil
}

// Poll claims pending or expired-leased commands in deterministic order. The
// exact encoded response is capped before any lease is persisted.
func (store *Store) Poll(identity controlauth.NodeIdentity, capabilities []string, now time.Time, lease time.Duration, max int) ([]controlprotocol.ExecutorDeliveryV3, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	canonical, err := canonicalCapabilities(capabilities)
	if err != nil || now.IsZero() || lease <= 0 || lease > MaxDeliveryLease || max <= 0 || max > controlprotocol.MaxExecutorDeliveries ||
		identity.Audience != "executor" || !validRecordID(identity.NodeID, 128) || !validTenantSet(identity.TenantIDs) {
		return nil, invalid("poll identity, capabilities, lease, or batch size is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	node, ok := store.current.nodes[identity.NodeID]
	if !ok || !node.Active || !tenantSubset(identity.TenantIDs, node.TenantIDs) {
		return nil, ErrNotFound
	}
	mutations := make([]mutation, 0, minInt(max+1, maxMutationsPerRecord))
	if observationDue(node.LastSeenAt, now) {
		observed := cloneNode(node)
		observed.LastSeenAt = canonicalTimestamp(now)
		observed.Capabilities = canonical
		mutations = append(mutations, mutation{Kind: mutationNode, Node: &observed})
	}
	candidates := make([]Command, 0)
	for _, command := range store.current.commands {
		if command.NodeID != identity.NodeID || !controlauth.NodeAuthorizedTenant(identity, command.TenantID) {
			continue
		}
		if command.State == CommandPending {
			candidates = append(candidates, cloneCommand(command))
			continue
		}
		if command.State == CommandLeased {
			expires, _ := parseTimestamp(command.LeaseUntil)
			if !expires.After(now) {
				candidates = append(candidates, cloneCommand(command))
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].CreatedAt != candidates[j].CreatedAt {
			return candidates[i].CreatedAt < candidates[j].CreatedAt
		}
		if candidates[i].TenantID != candidates[j].TenantID {
			return candidates[i].TenantID < candidates[j].TenantID
		}
		return candidates[i].ID < candidates[j].ID
	})
	deliveries := make([]controlprotocol.ExecutorDeliveryV3, 0, minInt(max, len(candidates)))
	for _, candidate := range candidates {
		if len(deliveries) >= max || len(mutations) >= maxMutationsPerRecord {
			break
		}
		if candidate.DeliveryGeneration == math.MaxUint64 {
			return nil, ErrCapacityExceeded
		}
		created, _ := parseTimestamp(candidate.CreatedAt)
		if now.Before(created) {
			return nil, invalid("poll time precedes command submission")
		}
		candidate.State = CommandLeased
		candidate.DeliveryGeneration++
		candidate.LeaseUntil = canonicalTimestamp(now.Add(lease))
		delivery, err := deliveryFor(candidate, candidate.DeliveryGeneration)
		if err != nil {
			if len(deliveries) == 0 && len(mutations) == 0 {
				return nil, ErrCapacityExceeded
			}
			break
		}
		tentativeDeliveries := append(append([]controlprotocol.ExecutorDeliveryV3(nil), deliveries...), delivery)
		if !pollResponseFits(tentativeDeliveries) {
			if len(deliveries) == 0 && len(mutations) == 0 {
				return nil, ErrCapacityExceeded
			}
			break
		}
		tentativeMutations := append(append([]mutation(nil), mutations...), commandMutation(candidate))
		if !store.transactionFitsLocked(tentativeMutations) {
			if len(deliveries) == 0 && len(mutations) == 0 {
				return nil, ErrCapacityExceeded
			}
			break
		}
		mutations = tentativeMutations
		deliveries = tentativeDeliveries
	}
	if len(mutations) > 0 {
		if err := store.applyMutationsLocked(mutations...); err != nil {
			return nil, err
		}
	}
	return append([]controlprotocol.ExecutorDeliveryV3(nil), deliveries...), nil
}

func (store *Store) ApplyReport(identity controlauth.NodeIdentity, report controlprotocol.ExecutorReportV3, now time.Time) (bool, error) {
	if store == nil {
		return false, ErrUnavailable
	}
	if now.IsZero() || report.Validate() != nil || identity.Audience != "executor" ||
		!validRecordID(identity.NodeID, 128) || !validTenantSet(identity.TenantIDs) {
		return false, invalid("report or node identity is invalid")
	}
	digest, raw, err := reportDigest(report)
	if err != nil {
		return false, err
	}
	if len(raw) > store.limits.MaxReportBytes {
		return false, invalid("report exceeds the configured size limit")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return false, err
	}
	node, ok := store.current.nodes[identity.NodeID]
	if !ok || !node.Active || !tenantSubset(identity.TenantIDs, node.TenantIDs) {
		return false, ErrNotFound
	}
	key := ""
	var command Command
	for candidateKey, candidate := range store.current.commands {
		if candidate.NodeID == identity.NodeID && candidate.ID == report.CommandID && candidate.DeliveryID == report.DeliveryID &&
			controlauth.NodeAuthorizedTenant(identity, candidate.TenantID) {
			key, command = candidateKey, cloneCommand(candidate)
			break
		}
	}
	if key == "" {
		return false, ErrNotFound
	}
	if report.CommandDigest != command.Digest {
		return false, ErrConflict
	}
	created, _ := parseTimestamp(command.CreatedAt)
	if now.Before(created) {
		return false, invalid("report time precedes command submission")
	}
	if report.DeliveryGeneration < command.DeliveryGeneration {
		return false, nil
	}
	if report.DeliveryGeneration > command.DeliveryGeneration {
		return false, ErrConflict
	}
	if command.State == CommandTerminal {
		if command.Terminal != nil && command.Terminal.Digest == digest {
			return false, nil
		}
		return false, ErrConflict
	}
	if command.State != CommandLeased {
		return false, ErrConflict
	}
	command.State = CommandTerminal
	command.LeaseUntil = ""
	command.Terminal = &TerminalReport{Report: report, Digest: digest, CompletedAt: canonicalTimestamp(now)}
	if err := store.applyMutationsLocked(commandMutation(command)); err != nil {
		return false, err
	}
	return true, nil
}

func (store *Store) reclaimExpiredEnrollmentsLocked(now time.Time, reserve int) error {
	type expiredEnrollment struct {
		id      string
		expires string
	}
	expired := make([]expiredEnrollment, 0)
	for id, enrollment := range store.current.enrollments {
		expires, _ := parseTimestamp(enrollment.ExpiresAt)
		if !expires.After(now) {
			expired = append(expired, expiredEnrollment{id: id, expires: enrollment.ExpiresAt})
		}
	}
	sort.Slice(expired, func(i, j int) bool {
		return expired[i].expires < expired[j].expires || expired[i].expires == expired[j].expires && expired[i].id < expired[j].id
	})
	batchLimit := maxMutationsPerRecord - reserve
	for len(expired) > 0 {
		count := minInt(len(expired), batchLimit)
		mutations := make([]mutation, 0, count)
		for _, enrollment := range expired[:count] {
			mutations = append(mutations, mutation{Kind: mutationEnrollmentDelete, EnrollmentID: enrollment.id})
		}
		if err := store.applyMutationsLocked(mutations...); err != nil {
			return err
		}
		expired = expired[count:]
	}
	return nil
}

func (store *Store) prunableCommandsLocked(tenantID, nodeID string, now time.Time) []Command {
	cutoff := now.Add(-store.limits.TerminalRetention)
	result := make([]Command, 0)
	for _, command := range store.current.commands {
		if command.State != CommandTerminal || command.Terminal == nil ||
			command.Terminal.Report.Status == controlprotocol.ExecutorStatusOutcomeUnknown {
			continue
		}
		completed, _ := parseTimestamp(command.Terminal.CompletedAt)
		if !completed.After(cutoff) {
			result = append(result, cloneCommand(command))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		leftPriority := prunePriority(result[i], tenantID, nodeID)
		rightPriority := prunePriority(result[j], tenantID, nodeID)
		if leftPriority != rightPriority {
			return leftPriority < rightPriority
		}
		if result[i].Terminal.CompletedAt != result[j].Terminal.CompletedAt {
			return result[i].Terminal.CompletedAt < result[j].Terminal.CompletedAt
		}
		return commandKey(result[i].TenantID, result[i].NodeID, result[i].ID) < commandKey(result[j].TenantID, result[j].NodeID, result[j].ID)
	})
	return result
}

func prunePriority(command Command, tenantID, nodeID string) int {
	if command.TenantID == tenantID && command.NodeID == nodeID {
		return 0
	}
	if command.TenantID == tenantID {
		return 1
	}
	return 2
}

func parseCommandIdentity(raw []byte) (string, string, string, error) {
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return "", "", "", err
	}
	if envelope.PayloadType != admission.CommandPayloadType {
		return "", "", "", errors.New("DSSE payload type is not an Executor command")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > dsse.MaxPayloadBytes || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return "", "", "", errors.New("DSSE payload encoding is invalid")
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
		return "", "", "", err
	}
	if statement.SchemaVersion != admission.CommandSchemaV2 || !validRecordID(statement.CommandID, 256) ||
		!validRecordID(statement.TenantID, 128) || !validRecordID(statement.NodeID, 128) {
		return "", "", "", errors.New("signed command identity is invalid")
	}
	return statement.CommandID, statement.TenantID, statement.NodeID, nil
}

func deliveryFor(command Command, generation uint64) (controlprotocol.ExecutorDeliveryV3, error) {
	delivery := controlprotocol.ExecutorDeliveryV3{
		DeliveryID: command.DeliveryID, DeliveryGeneration: generation, CommandID: command.ID,
		CommandDigest: command.Digest, CommandDSSEBase64: base64.StdEncoding.EncodeToString(command.CommandDSSE),
	}
	if err := delivery.Validate(); err != nil {
		return controlprotocol.ExecutorDeliveryV3{}, err
	}
	if !pollResponseFits([]controlprotocol.ExecutorDeliveryV3{delivery}) {
		return controlprotocol.ExecutorDeliveryV3{}, errors.New("single delivery exceeds the poll response cap")
	}
	return delivery, nil
}

func pollResponseFits(deliveries []controlprotocol.ExecutorDeliveryV3) bool {
	rawDeliveries := make([]json.RawMessage, 0, len(deliveries))
	for _, delivery := range deliveries {
		raw, err := json.Marshal(delivery)
		if err != nil {
			return false
		}
		rawDeliveries = append(rawDeliveries, raw)
	}
	raw, err := json.Marshal(controlprotocol.ExecutorPollResponseV3{
		ProtocolVersion: controlprotocol.ExecutorProtocolV3, Deliveries: rawDeliveries,
	})
	// controlplane.writeJSON uses Encoder.Encode, which appends one newline.
	return err == nil && len(raw)+1 <= maxPollResponseBytes
}

func (store *Store) transactionFitsLocked(mutations []mutation) bool {
	if store.sequence == math.MaxUint64 {
		return false
	}
	payload, err := encodeTransaction(mutations...)
	if err != nil {
		return false
	}
	_, _, err = marshalWALRecord(store.sequence+1, store.lastHash, payload, store.limits.MaxRecordBytes)
	return err == nil
}

func observationDue(lastSeen string, now time.Time) bool {
	if lastSeen == "" {
		return true
	}
	last, err := parseTimestamp(lastSeen)
	return err == nil && !now.Before(last.Add(observationInterval))
}

func unionTenantIDs(left, right []string) []string {
	combined := append(append([]string(nil), left...), right...)
	sort.Strings(combined)
	result := combined[:0]
	for _, tenantID := range combined {
		if len(result) == 0 || result[len(result)-1] != tenantID {
			result = append(result, tenantID)
		}
	}
	return append([]string(nil), result...)
}

func projectNode(node Node, actor controlauth.Identity, tenantID string) Node {
	projected := cloneNode(node)
	if !controlauth.IsSiteAdmin(actor) {
		projected.TenantIDs = []string{tenantID}
	}
	return projected
}

func cloneNode(node Node) Node {
	node.TenantIDs = append([]string(nil), node.TenantIDs...)
	node.Capabilities = copyStringSlice(node.Capabilities)
	return node
}

func cloneCredential(credential controlauth.Credential) controlauth.Credential {
	credential.TokenMAC = append([]byte(nil), credential.TokenMAC...)
	credential.TenantIDs = append([]string(nil), credential.TenantIDs...)
	return credential
}

func cloneEnrollment(enrollment controlauth.Enrollment) controlauth.Enrollment {
	enrollment.TokenMAC = append([]byte(nil), enrollment.TokenMAC...)
	enrollment.TenantIDs = append([]string(nil), enrollment.TenantIDs...)
	return enrollment
}

func credentialMutation(credential controlauth.Credential) mutation {
	stored := credentialToStored(credential)
	return mutation{Kind: mutationCredential, Credential: &stored}
}

func enrollmentMutation(enrollment controlauth.Enrollment) mutation {
	stored := enrollmentToStored(enrollment)
	return mutation{Kind: mutationEnrollment, Enrollment: &stored}
}

func commandMutation(command Command) mutation {
	stored := commandToStored(command)
	return mutation{Kind: mutationCommand, Command: &stored}
}

func credentialsEqual(left, right controlauth.Credential) bool {
	return left.Version == right.Version && left.ID == right.ID && left.Kind == right.Kind && left.Role == right.Role &&
		left.TenantID == right.TenantID && equalStrings(left.TenantIDs, right.TenantIDs) && left.NodeID == right.NodeID &&
		left.Audience == right.Audience && bytes.Equal(left.TokenMAC, right.TokenMAC) && left.RequestID == right.RequestID &&
		left.CreatedAt == right.CreatedAt && left.Revoked == right.Revoked && left.RevokedAt == right.RevokedAt
}

func enrollmentsEqual(left, right controlauth.Enrollment) bool {
	return left.Version == right.Version && left.ID == right.ID && equalStrings(left.TenantIDs, right.TenantIDs) &&
		left.NodeID == right.NodeID && left.Audience == right.Audience && bytes.Equal(left.TokenMAC, right.TokenMAC) &&
		left.CreatedAt == right.CreatedAt && left.ExpiresAt == right.ExpiresAt && left.RequestID == right.RequestID &&
		left.CredentialID == right.CredentialID && left.ConsumedAt == right.ConsumedAt && left.Revoked == right.Revoked &&
		left.RevokedAt == right.RevokedAt
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func invalid(message string) error { return fmt.Errorf("%w: %s", ErrInvalid, message) }

func invalidError(message string, err error) error {
	return fmt.Errorf("%w: %s: %v", ErrInvalid, message, err)
}

func minInt(left, right int) int {
	if left < right {
		return left
	}
	return right
}
