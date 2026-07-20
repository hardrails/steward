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

	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
)

const (
	// MaxDeliveryLease is the single supported upper bound shared by storage,
	// HTTP, and command-line validation.
	MaxDeliveryLease     = 10 * time.Minute
	observationInterval  = time.Minute
	maxPollResponseBytes = 1 << 20
	evidenceGenesisHash  = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
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

// revalidateOperatorLocked closes the gap between HTTP bearer authentication
// and the durable operation. A credential can be revoked while a bounded
// request body is still arriving; every operation therefore confirms the
// detached identity against current state while holding the same mutex used by
// revocation and mutation.
func (store *Store) revalidateOperatorLocked(actor controlauth.Identity) error {
	credential, ok := store.current.credentials[actor.CredentialID]
	if !ok || credential.Revoked || credential.Kind != controlauth.KindOperator ||
		credential.Role != actor.Role || credential.TenantID != actor.TenantID {
		return controlauth.ErrUnauthorized
	}
	return nil
}

// revalidateNodeLocked gives poll/report the same atomic revocation boundary.
// The durable node binding is included because node revocation and tenant-set
// changes must fence an already authenticated long request as well.
func (store *Store) revalidateNodeLocked(identity controlauth.NodeIdentity) error {
	credential, ok := store.current.credentials[identity.CredentialID]
	if !ok || credential.Revoked || credential.Kind != controlauth.KindNode ||
		credential.NodeID != identity.NodeID || credential.Audience != identity.Audience ||
		!equalStrings(credential.TenantIDs, identity.TenantIDs) {
		return controlauth.ErrUnauthorized
	}
	node, ok := store.current.nodes[credential.NodeID]
	if !ok || !node.Active || !tenantSubset(credential.TenantIDs, node.TenantIDs) {
		return controlauth.ErrUnauthorized
	}
	return nil
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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

// RevokeNodeCredential disables one node transport bearer without revoking the
// node or its sibling credentials. This is the narrow primitive needed for a
// staged credential rotation; only a site administrator may use it.
func (store *Store) RevokeNodeCredential(actor controlauth.Identity, credentialID string, now time.Time) (string, bool, error) {
	if store == nil {
		return "", false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return "", false, ErrForbidden
	}
	if !validRecordID(credentialID, 128) || now.IsZero() {
		return "", false, invalid("node credential identity and revocation time are required")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return "", false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return "", false, err
	}
	credential, ok := store.current.credentials[credentialID]
	if !ok || credential.Kind != controlauth.KindNode {
		return "", false, ErrNotFound
	}
	if credential.Revoked {
		return credential.NodeID, false, nil
	}
	created, _ := parseTimestamp(credential.CreatedAt)
	if now.Before(created) {
		return "", false, invalid("revocation time precedes credential creation")
	}
	credential.Revoked = true
	credential.RevokedAt = canonicalTimestamp(now)
	if err := store.applyMutationsLocked(credentialMutation(credential)); err != nil {
		return "", false, err
	}
	return credential.NodeID, true, nil
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
	if credential.Kind == controlauth.KindOperator && credential.Role == controlauth.RoleSiteAdmin {
		liveSiteAdmins := 0
		for _, candidate := range store.current.credentials {
			if candidate.Kind == controlauth.KindOperator && candidate.Role == controlauth.RoleSiteAdmin && !candidate.Revoked {
				liveSiteAdmins++
			}
		}
		if liveSiteAdmins <= 1 {
			return false, ErrConflict
		}
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
	raw, enrollment, node, _, err := store.createEnrollment(actor, auth, "", nodeID, tenantIDs, expiresAt, now)
	return raw, enrollment, node, err
}

// CreateEnrollmentForRequest makes secret-bearing enrollment issuance
// recoverable after an ambiguous response loss. An exact retry by the same
// operator credential returns the same bearer and record; a changed scope or
// lifetime conflicts instead of minting another live capability.
func (store *Store) CreateEnrollmentForRequest(actor controlauth.Identity, auth *controlauth.Manager, requestID, nodeID string, tenantIDs []string, expiresAt, now time.Time) (string, controlauth.Enrollment, Node, bool, error) {
	return store.createEnrollment(actor, auth, requestID, nodeID, tenantIDs, expiresAt, now)
}

func (store *Store) createEnrollment(actor controlauth.Identity, auth *controlauth.Manager, issueRequestID, nodeID string, tenantIDs []string, expiresAt, now time.Time) (string, controlauth.Enrollment, Node, bool, error) {
	if store == nil || auth == nil {
		return "", controlauth.Enrollment{}, Node{}, false, ErrUnavailable
	}
	canonical, err := controlauth.CanonicalTenantIDs(tenantIDs)
	if err != nil || !validRecordID(nodeID, 128) || now.IsZero() || !expiresAt.After(now) || expiresAt.Sub(now) > 24*time.Hour {
		return "", controlauth.Enrollment{}, Node{}, false, invalid("enrollment node, tenant set, or lifetime is invalid")
	}
	if issueRequestID != "" && (!validRecordID(issueRequestID, 128) || !validRecordID(actor.CredentialID, 128)) {
		return "", controlauth.Enrollment{}, Node{}, false, invalid("enrollment issuance request identity is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return "", controlauth.Enrollment{}, Node{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return "", controlauth.Enrollment{}, Node{}, false, err
	}
	for _, tenantID := range canonical {
		if !controlauth.AuthorizedTenant(actor, tenantID) {
			return "", controlauth.Enrollment{}, Node{}, false, ErrNotFound
		}
		tenant, ok := store.current.tenants[tenantID]
		if !ok || !tenant.Active {
			return "", controlauth.Enrollment{}, Node{}, false, ErrNotFound
		}
	}
	if issueRequestID != "" {
		for _, existing := range store.current.enrollments {
			if existing.IssueRequestID != issueRequestID || existing.IssuerCredentialID != actor.CredentialID {
				continue
			}
			created, createdErr := parseTimestamp(existing.CreatedAt)
			expires, expiresErr := parseTimestamp(existing.ExpiresAt)
			if createdErr != nil || expiresErr != nil || existing.Revoked || existing.NodeID != nodeID ||
				!equalStrings(existing.TenantIDs, canonical) || expires.Sub(created) != expiresAt.Sub(now) {
				return "", controlauth.Enrollment{}, Node{}, false, ErrConflict
			}
			raw, derived, mintErr := auth.MintEnrollmentForRequest(
				issueRequestID, actor.CredentialID, existing.TenantIDs, existing.NodeID, expires, created,
			)
			if mintErr != nil {
				return "", controlauth.Enrollment{}, Node{}, false, mintErr
			}
			unconsumed := cloneEnrollment(existing)
			unconsumed.RequestID, unconsumed.CredentialID, unconsumed.ConsumedAt = "", "", ""
			if !enrollmentsEqual(unconsumed, derived) {
				return "", controlauth.Enrollment{}, Node{}, false, ErrConflict
			}
			node, ok := store.current.nodes[existing.NodeID]
			if !ok || !node.Active || !tenantSubset(existing.TenantIDs, node.TenantIDs) {
				return "", controlauth.Enrollment{}, Node{}, false, ErrConflict
			}
			return raw, cloneEnrollment(existing), projectNode(node, actor, canonical[0]), false, nil
		}
	}
	if err := store.reclaimExpiredEnrollmentsLocked(now, 2); err != nil {
		return "", controlauth.Enrollment{}, Node{}, false, err
	}
	node, exists := store.current.nodes[nodeID]
	if exists && !node.Active {
		return "", controlauth.Enrollment{}, Node{}, false, ErrConflict
	}
	// Node IDs are global fleet identities. A tenant-scoped operator may claim a
	// new ID for its own tenant, but only a site administrator may issue another
	// enrollment for an existing node or extend that node's tenant bindings.
	// Without this gate, a second tenant could attach itself to an unrelated
	// node ID and use a separately exchanged credential to overwrite the shared
	// node's capabilities and last-seen observation.
	if exists && !controlauth.IsSiteAdmin(actor) {
		return "", controlauth.Enrollment{}, Node{}, false, ErrNotFound
	}
	if !exists {
		node = Node{
			ID: nodeID, TenantIDs: append([]string(nil), canonical...), Capabilities: []string{},
			CreatedAt: canonicalTimestamp(now), Active: true,
		}
	} else {
		node.TenantIDs = unionTenantIDs(node.TenantIDs, canonical)
	}
	var raw string
	var enrollment controlauth.Enrollment
	if issueRequestID == "" {
		raw, enrollment, err = auth.MintEnrollment(canonical, nodeID, expiresAt, now)
	} else {
		raw, enrollment, err = auth.MintEnrollmentForRequest(issueRequestID, actor.CredentialID, canonical, nodeID, expiresAt, now)
	}
	if err != nil {
		return "", controlauth.Enrollment{}, Node{}, false, err
	}
	mutations := []mutation{{Kind: mutationNode, Node: &node}, enrollmentMutation(enrollment)}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return "", controlauth.Enrollment{}, Node{}, false, err
	}
	return raw, cloneEnrollment(enrollment), projectNode(node, actor, canonical[0]), true, nil
}

func (store *Store) ExchangeEnrollment(auth *controlauth.Manager, raw, requestID string, proof controlprotocol.ExecutorEvidenceIdentityProofV1, now time.Time) (controlauth.NodeCredentialFile, error) {
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
	public, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(proof)
	if err != nil {
		return controlauth.NodeCredentialFile{}, controlauth.ErrUnauthorized
	}
	if proof.Claim.ControllerInstanceID != auth.InstanceID() || proof.Claim.EnrollmentID != id ||
		proof.Claim.ReceiptEpoch != 1 {
		return controlauth.NodeCredentialFile{}, ErrConflict
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
	if proof.Claim.ControlNodeID != node.ID || proof.Claim.ReceiptNodeID != node.ID {
		return controlauth.NodeCredentialFile{}, ErrConflict
	}
	if node.Evidence != nil && !evidenceReceiptIdentityMatches(*node.Evidence, proof) {
		return controlauth.NodeCredentialFile{}, ErrConflict
	}
	for otherNodeID, otherNode := range store.current.nodes {
		if otherNodeID != node.ID && otherNode.Evidence != nil &&
			otherNode.Evidence.PublicKeyDigest == proof.Claim.PublicKeySHA256 {
			return controlauth.NodeCredentialFile{}, ErrConflict
		}
	}
	file, credential, updated, err := auth.Exchange(raw, requestID, now, cloneEnrollment(enrollment))
	if err != nil {
		return controlauth.NodeCredentialFile{}, err
	}
	if existing, exists := store.current.credentials[credential.ID]; exists {
		if !credentialsEqual(existing, credential) || !enrollmentsEqual(enrollment, updated) ||
			node.Evidence == nil || !evidenceReceiptIdentityMatches(*node.Evidence, proof) {
			return controlauth.NodeCredentialFile{}, ErrConflict
		}
		return file, nil
	}
	mutations := []mutation{credentialMutation(credential), enrollmentMutation(updated)}
	pinnedEvidence := false
	if node.Evidence == nil {
		node.Evidence = &EvidenceWitness{
			IdentityProof: proof, ReceiptNodeID: node.ID, Epoch: proof.Claim.ReceiptEpoch,
			PublicKeyBase64: proof.Claim.PublicKeyBase64, KeyID: evidence.KeyID(public),
			PublicKeyDigest: proof.Claim.PublicKeySHA256, PinnedAt: credential.CreatedAt,
			ChainHash: evidenceGenesisHash,
		}
		mutations = append(mutations, mutation{Kind: mutationNode, Node: &node})
		pinnedEvidence = true
	}
	if err := store.applyMutationsLocked(mutations...); err != nil {
		return controlauth.NodeCredentialFile{}, err
	}
	if pinnedEvidence {
		store.recordExecutorEvidenceReportLocked(node.ID, now)
	}
	return file, nil
}

func evidenceReceiptIdentityMatches(witness EvidenceWitness, proof controlprotocol.ExecutorEvidenceIdentityProofV1) bool {
	pinned := witness.IdentityProof.Claim
	return pinned.ControllerInstanceID == proof.Claim.ControllerInstanceID &&
		pinned.ControlNodeID == proof.Claim.ControlNodeID &&
		pinned.Stream == proof.Claim.Stream &&
		pinned.ReceiptNodeID == proof.Claim.ReceiptNodeID &&
		pinned.ReceiptEpoch == proof.Claim.ReceiptEpoch &&
		pinned.PublicKeyBase64 == proof.Claim.PublicKeyBase64 &&
		pinned.PublicKeySHA256 == proof.Claim.PublicKeySHA256 &&
		witness.ReceiptNodeID == proof.Claim.ReceiptNodeID &&
		witness.Epoch == proof.Claim.ReceiptEpoch && witness.PublicKeyBase64 == proof.Claim.PublicKeyBase64 &&
		witness.PublicKeyDigest == proof.Claim.PublicKeySHA256
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
	binding, err := parseCommandBindingForSubmission(commandDSSE)
	if err != nil {
		return Command{}, false, invalidError("parse command DSSE", err)
	}
	if binding.TenantID != tenantID || binding.NodeID != nodeID {
		return Command{}, false, invalid("signed command identity does not match its route")
	}
	commandID := binding.CommandID
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Command{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
		CommandKind: binding.Kind, SignedRuntimeRef: binding.RuntimeRef,
		SignedClaimGeneration:    binding.ClaimGeneration,
		SignedInstanceGeneration: binding.InstanceGeneration,
		State:                    CommandPending, CreatedAt: canonicalTimestamp(now),
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
	if err := store.revalidateOperatorLocked(actor); err != nil {
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
	return store.poll(identity, capabilities, now, lease, max, controlprotocol.ExecutorProtocolV3)
}

// PollV4 claims the same signed command records as Poll while durably fencing
// the lease to protocol 4 and returning the distinct immutable v4 delivery
// type. A later report from another protocol cannot close this generation.
func (store *Store) PollV4(identity controlauth.NodeIdentity, capabilities []string, now time.Time, lease time.Duration, max int) ([]controlprotocol.ExecutorDeliveryV4, error) {
	deliveries, err := store.poll(identity, capabilities, now, lease, max, controlprotocol.ExecutorProtocolV4)
	if err != nil {
		return nil, err
	}
	result := make([]controlprotocol.ExecutorDeliveryV4, 0, len(deliveries))
	for _, delivery := range deliveries {
		result = append(result, controlprotocol.ExecutorDeliveryV4(delivery))
	}
	return result, nil
}

func (store *Store) poll(identity controlauth.NodeIdentity, capabilities []string, now time.Time, lease time.Duration, max, protocolVersion int) ([]controlprotocol.ExecutorDeliveryV3, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	canonical, err := canonicalCapabilities(capabilities)
	if err != nil || now.IsZero() || lease <= 0 || lease > MaxDeliveryLease || max <= 0 || max > controlprotocol.MaxExecutorDeliveries ||
		!validExecutorDeliveryProtocol(protocolVersion) ||
		identity.Audience != "executor" || !validRecordID(identity.NodeID, 128) || !validTenantSet(identity.TenantIDs) {
		return nil, invalid("poll identity, capabilities, lease, or batch size is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
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
			return retainedTimestampLess(
				candidates[i].CreatedAt,
				candidates[j].CreatedAt,
			)
		}
		if candidates[i].TenantID != candidates[j].TenantID {
			return candidates[i].TenantID < candidates[j].TenantID
		}
		return candidates[i].ID < candidates[j].ID
	})
	nextActivationTenant := activationCanaryTenantForPoll(
		store.current.commands,
		identity.NodeID,
		candidates,
	)
	deliveries := make([]controlprotocol.ExecutorDeliveryV3, 0, minInt(max, len(candidates)))
	leasedActivationCanary := false
	for _, candidate := range candidates {
		if len(deliveries) >= max || len(mutations) >= maxMutationsPerRecord {
			break
		}
		if candidate.CommandKind == "activation-canary" &&
			(protocolVersion != controlprotocol.ExecutorProtocolV4 ||
				!hasCapability(canonical, controlprotocol.ExecutorCapabilityActivationCanaryV1) ||
				leasedActivationCanary ||
				candidate.TenantID != nextActivationTenant) {
			continue
		}
		if candidate.DeliveryGeneration == math.MaxUint64 {
			return nil, ErrCapacityExceeded
		}
		created, _ := parseTimestamp(candidate.CreatedAt)
		if now.Before(created) {
			return nil, invalid("poll time precedes command submission")
		}
		candidate.State = CommandLeased
		candidate.DeliveryProtocol = protocolVersion
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
		if !pollResponseFits(tentativeDeliveries, protocolVersion) {
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
		if candidate.CommandKind == "activation-canary" {
			leasedActivationCanary = true
		}
	}
	if len(mutations) > 0 {
		if err := store.applyMutationsLocked(mutations...); err != nil {
			return nil, err
		}
	}
	// deliveries is initialized as a non-nil empty slice because both wire
	// versions require `deliveries:[]` on an idle poll. Returning an append to a
	// nil slice would collapse that distinction and encode JSON null.
	return deliveries, nil
}

// activationCanaryTenantForPoll rotates the node's single canary worker across
// tenants. The cursor is derived from durable lease/terminal history, so it
// survives restart without adding mutable scheduler state. A tenant backlog
// receives at most one turn before the next pending tenant in canonical order.
func activationCanaryTenantForPoll(
	commands map[string]Command,
	nodeID string,
	candidates []Command,
) string {
	pendingSet := make(map[string]struct{})
	for _, candidate := range candidates {
		if candidate.CommandKind == "activation-canary" {
			pendingSet[candidate.TenantID] = struct{}{}
		}
	}
	if len(pendingSet) == 0 {
		return ""
	}
	pending := make([]string, 0, len(pendingSet))
	for tenantID := range pendingSet {
		pending = append(pending, tenantID)
	}
	sort.Strings(pending)

	lastTenant, lastKey := "", ""
	var lastAt time.Time
	for key, command := range commands {
		if command.NodeID != nodeID ||
			command.CommandKind != "activation-canary" ||
			command.DeliveryGeneration == 0 {
			continue
		}
		activityAt, _ := parseTimestamp(command.LeaseUntil)
		if command.Terminal != nil {
			activityAt, _ = parseTimestamp(command.Terminal.CompletedAt)
		} else if activityAt.IsZero() {
			activityAt, _ = parseTimestamp(command.CreatedAt)
		}
		if activityAt.After(lastAt) || activityAt.Equal(lastAt) && key > lastKey {
			lastTenant, lastAt, lastKey = command.TenantID, activityAt, key
		}
	}
	if lastTenant != "" {
		index := sort.SearchStrings(pending, lastTenant)
		for index < len(pending) && pending[index] <= lastTenant {
			index++
		}
		if index < len(pending) {
			return pending[index]
		}
	}
	return pending[0]
}

func hasCapability(capabilities []string, required string) bool {
	index := sort.SearchStrings(capabilities, required)
	return index < len(capabilities) && capabilities[index] == required
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
	if err := store.revalidateNodeLocked(identity); err != nil {
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
	if command.DeliveryProtocol != controlprotocol.ExecutorProtocolV3 {
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

// ApplyReportV4 closes only a protocol-4 lease generation. The controller
// retains the complete bounded admission projection, but treats it as a node
// observation: it must correlate to the exact stored signed admit command and
// never creates authority that was absent from the report.
func (store *Store) ApplyReportV4(identity controlauth.NodeIdentity, report controlprotocol.ExecutorReportV4, now time.Time) (bool, error) {
	if store == nil {
		return false, ErrUnavailable
	}
	if now.IsZero() || report.Validate() != nil || identity.Audience != "executor" ||
		!validRecordID(identity.NodeID, 128) || !validTenantSet(identity.TenantIDs) {
		return false, invalid("report or node identity is invalid")
	}
	digest, raw, err := reportDigestV4(report)
	if err != nil {
		return false, err
	}
	if len(raw) > controlprotocol.MaxExecutorReportBytes || len(raw) > store.limits.MaxReportBytes {
		return false, invalid("report exceeds the configured size limit")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return false, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return false, err
	}
	node, ok := store.current.nodes[identity.NodeID]
	if !ok || !node.Active || !tenantSubset(identity.TenantIDs, node.TenantIDs) {
		return false, ErrNotFound
	}
	key := ""
	var command Command
	for candidateKey, candidate := range store.current.commands {
		if candidate.NodeID == identity.NodeID && candidate.ID == report.CommandID &&
			candidate.DeliveryID == report.DeliveryID &&
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
	if command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 {
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
	if err := validateExecutorReportV4Binding(command, report); err != nil {
		return false, ErrConflict
	}
	command.State = CommandTerminal
	command.LeaseUntil = ""
	command.Terminal = terminalReportFromV4(report, digest, now)
	if err := store.applyMutationsLocked(commandMutation(command)); err != nil {
		return false, err
	}
	return true, nil
}

func terminalReportFromV4(report controlprotocol.ExecutorReportV4, digest string, completedAt time.Time) *TerminalReport {
	return &TerminalReport{
		Report: controlprotocol.ExecutorReportV3{
			ProtocolVersion:    controlprotocol.ExecutorProtocolV4,
			DeliveryID:         report.DeliveryID,
			DeliveryGeneration: report.DeliveryGeneration,
			CommandID:          report.CommandID,
			CommandDigest:      report.CommandDigest,
			Status:             report.Status,
			ReportedStatus:     report.ReportedStatus,
			ClaimGeneration:    report.ClaimGeneration,
			ErrorCode:          report.ErrorCode,
			Result: controlprotocol.ExecutorReportResultV3{
				RuntimeRef: report.Result.RuntimeRef,
				Error:      report.Result.Error,
				Replayed:   report.Result.Replayed,
				Absent:     report.Result.Absent,
			},
		},
		Admission:        cloneAdmissionProjection(report.Result.Admission),
		ActivationCanary: cloneActivationCanaryResult(report.Result.ActivationCanary),
		Digest:           digest,
		CompletedAt:      canonicalTimestamp(completedAt),
	}
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
		return expired[i].expires != expired[j].expires &&
			retainedTimestampLess(expired[i].expires, expired[j].expires) ||
			expired[i].expires == expired[j].expires &&
				expired[i].id < expired[j].id
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
	workloadLeaseCutoff := now.Add(-admission.MaxWorkloadLeaseDuration - admission.CommandClockSkew)
	protectedCanaryCursors := activationCanaryPruningCursors(store.current.commands)
	protectedDeploymentCursors := deploymentCommandPruningCursors(store.current.deployments)
	protectedCaptureCanaries := evidenceCapturePruningCanaries(
		store.current.captures,
		store.current.commands,
		now,
	)
	result := make([]Command, 0)
	for key, command := range store.current.commands {
		if !terminalCommandSafeToPrune(command) {
			continue
		}
		if _, protected := protectedCanaryCursors[key]; protected {
			continue
		}
		if _, protected := protectedDeploymentCursors[key]; protected {
			continue
		}
		if _, protected := protectedCaptureCanaries[key]; protected {
			continue
		}
		completed, _ := parseTimestamp(command.Terminal.CompletedAt)
		if !completed.After(cutoff) || (command.CommandKind == "renew" && !completed.After(workloadLeaseCutoff)) {
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
			return retainedTimestampLess(
				result[i].Terminal.CompletedAt,
				result[j].Terminal.CompletedAt,
			)
		}
		return commandKey(result[i].TenantID, result[i].NodeID, result[i].ID) < commandKey(result[j].TenantID, result[j].NodeID, result[j].ID)
	})
	return result
}

// deploymentCommandPruningCursors retains every command whose terminal
// result has not yet been incorporated into its deployment cursor. Without
// this protection, capacity-driven pruning could erase the only durable
// evidence needed to decide whether a workload effect succeeded.
func deploymentCommandPruningCursors(deployments map[string]Deployment) map[string]struct{} {
	protected := make(map[string]struct{})
	for _, deployment := range deployments {
		for _, instance := range deployment.Instances {
			if instance.CommandID == "" || instance.NodeID == "" || instance.CommandOperation == "" ||
				!deploymentCommandInFlight(instance) {
				continue
			}
			protected[commandKey(deployment.TenantID, instance.NodeID, instance.CommandID)] = struct{}{}
		}
	}
	return protected
}

// evidenceCapturePruningCanaries retains one deterministic, fully successful
// protocol-4 canary for every armed or observed capture. Seal needs the
// command's signed admission and terminal result, so pruning every matching
// command could make an otherwise complete capture impossible to seal.
//
// Protection is deliberately bounded to one command per capture. Selecting
// the earliest completion (then command key) is stable when later commands
// arrive and after store recovery. This retention rule preserves sealability;
// it does not establish when the node generated a marker or when the command
// ran. The capture proves only the controller-observed order after its retained
// baseline; arm-before-submit remains an operator procedure.
func evidenceCapturePruningCanaries(
	captures map[string]storedEvidenceCapture,
	commands map[string]Command,
	now time.Time,
) map[string]struct{} {
	type captureTarget struct {
		tenantID              string
		nodeID                string
		runtimeRef            string
		generation            uint64
		activationID          string
		activationBeginDigest string
	}
	type selection struct {
		key         string
		completedAt string
	}

	active := make(map[captureTarget][]storedEvidenceCapture)
	for _, capture := range captures {
		if capture.State != EvidenceCaptureArmed && capture.State != EvidenceCaptureObserved {
			continue
		}
		if capture.State == EvidenceCaptureArmed {
			expiresAt, err := parseTimestamp(capture.ExpiresAt)
			if err != nil || !now.Before(expiresAt) {
				continue
			}
		}
		target := captureTarget{
			tenantID: capture.TenantID, nodeID: capture.NodeID,
			runtimeRef: capture.RuntimeRef, generation: capture.Generation,
			activationID:          capture.ActivationID,
			activationBeginDigest: capture.ActivationBeginDigest,
		}
		active[target] = append(active[target], capture)
	}
	if len(active) == 0 {
		return nil
	}

	selected := make(map[string]selection, len(captures))
	for key, command := range commands {
		canary, result, ok := retainedSuccessfulActivationCanary(command)
		if !ok {
			continue
		}
		target := captureTarget{
			tenantID: command.TenantID, nodeID: command.NodeID,
			runtimeRef:            canary.Admission.RuntimeRef,
			generation:            command.SignedInstanceGeneration,
			activationID:          canary.ActivationID,
			activationBeginDigest: canary.Admission.ActivationBeginDigest,
		}
		for _, capture := range active[target] {
			if !activationCanaryMatchesCapture(canary, result, capture) {
				continue
			}
			current, exists := selected[capture.CaptureID]
			completedAt := command.Terminal.CompletedAt
			if !exists || retainedTimestampLess(completedAt, current.completedAt) ||
				completedAt == current.completedAt && key < current.key {
				selected[capture.CaptureID] = selection{key: key, completedAt: completedAt}
			}
		}
	}

	protected := make(map[string]struct{}, len(selected))
	for _, command := range selected {
		protected[command.key] = struct{}{}
	}
	return protected
}

func retainedSuccessfulActivationCanary(
	command Command,
) (activationcanary.CommandV1, *controlprotocol.ExecutorActivationCanaryResultV1, bool) {
	if command.CommandKind != "activation-canary" ||
		command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
		command.State != CommandTerminal || command.Terminal == nil ||
		command.Terminal.Report.Status != controlprotocol.ExecutorStatusDone ||
		command.Terminal.ActivationCanary == nil {
		return activationcanary.CommandV1{}, nil, false
	}
	result := command.Terminal.ActivationCanary
	if err := result.Validate(); err != nil ||
		validateRetainedExecutorReportV4Binding(
			command,
			executorReportV4FromTerminal(*command.Terminal),
		) != nil {
		return activationcanary.CommandV1{}, nil, false
	}
	statement, err := parseCommandStatement(command.CommandDSSE)
	if err != nil || statement.CommandID != command.ID ||
		statement.TenantID != command.TenantID || statement.NodeID != command.NodeID ||
		statement.RuntimeRef != command.SignedRuntimeRef ||
		statement.InstanceGeneration != command.SignedInstanceGeneration {
		return activationcanary.CommandV1{}, nil, false
	}
	canary, err := activationcanary.ParseCommandV1(statement.Payload)
	if err != nil || result.ActivationID != canary.ActivationID ||
		result.AdmissionDigest != canary.AdmissionDigest {
		return activationcanary.CommandV1{}, nil, false
	}
	return canary, result, true
}

func activationCanaryMatchesCapture(
	canary activationcanary.CommandV1,
	result *controlprotocol.ExecutorActivationCanaryResultV1,
	capture storedEvidenceCapture,
) bool {
	if result == nil || canary.ActivationID != capture.ActivationID ||
		canary.Admission.RuntimeRef != capture.RuntimeRef ||
		canary.Admission.Generation != capture.Generation ||
		canary.Admission.ActivationBeginDigest != capture.ActivationBeginDigest {
		return false
	}
	if capture.ActivationBeginSequence != 0 &&
		(canary.Admission.CapsuleDigest != capture.CapsuleDigest ||
			canary.Admission.PolicyDigest != capture.PolicyDigest) {
		return false
	}
	return capture.State != EvidenceCaptureObserved ||
		result.ActivationCheckpointDigest == capture.ActivationCheckpointDigest
}

func retainedTimestampLess(left, right string) bool {
	leftTime, leftErr := parseTimestamp(left)
	rightTime, rightErr := parseTimestamp(right)
	if leftErr != nil || rightErr != nil {
		// Persisted state is validated before these ordering paths run. Keep a
		// deterministic fallback for tests or an internal caller that violates
		// that invariant rather than making sort's comparator inconsistent.
		return left < right
	}
	return leftTime.Before(rightTime)
}

// activationCanaryPruningCursors retains at most one otherwise-prunable
// command per node while that node still has non-terminal canary work. The
// scheduler derives its tenant cursor from command history, so deleting the
// most recent terminal immediately before a capacity-driven submission would
// reset rotation to the first tenant. Once a newer canary is leased, the older
// cursor is no longer newest and becomes prunable; once the queue drains, no
// cursor is protected.
func activationCanaryPruningCursors(commands map[string]Command) map[string]struct{} {
	type activity struct {
		at  time.Time
		key string
	}
	nonTerminal := make(map[string]bool)
	latest := make(map[string]activity)
	for key, command := range commands {
		if command.CommandKind != "activation-canary" {
			continue
		}
		if command.State != CommandTerminal {
			nonTerminal[command.NodeID] = true
		}
		if command.DeliveryGeneration == 0 {
			continue
		}
		activityAt, _ := parseTimestamp(command.LeaseUntil)
		if command.Terminal != nil {
			activityAt, _ = parseTimestamp(command.Terminal.CompletedAt)
		} else if activityAt.IsZero() {
			activityAt, _ = parseTimestamp(command.CreatedAt)
		}
		current := latest[command.NodeID]
		if activityAt.After(current.at) ||
			activityAt.Equal(current.at) && key > current.key {
			latest[command.NodeID] = activity{at: activityAt, key: key}
		}
	}
	protected := make(map[string]struct{})
	for nodeID, current := range latest {
		if nonTerminal[nodeID] && current.key != "" {
			protected[current.key] = struct{}{}
		}
	}
	return protected
}

// terminalCommandSafeToPrune mirrors the Executor's durable-delivery rule.
// Generic failures remain evidence of a possibly incomplete effect. The two
// closed activation-canary failures are different: the authenticated command
// kind and reserved error code identify a completed Gateway run whose outcome
// is final, even though it did not qualify the release.
func terminalCommandSafeToPrune(command Command) bool {
	if command.State != CommandTerminal || command.Terminal == nil {
		return false
	}
	status := command.Terminal.Report.Status
	if status == controlprotocol.ExecutorStatusDone ||
		status == controlprotocol.ExecutorStatusRejected {
		return true
	}
	return command.DeliveryProtocol == controlprotocol.ExecutorProtocolV4 &&
		command.CommandKind == "activation-canary" &&
		validActivationCanaryTerminalFailure(
			status,
			command.Terminal.Report.ReportedStatus,
			command.Terminal.Report.ErrorCode,
			command.Terminal.Report.Result.Error,
		)
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

type commandBinding struct {
	CommandID          string
	TenantID           string
	NodeID             string
	RuntimeRef         string
	Kind               string
	ClaimGeneration    uint64
	InstanceGeneration uint64
}

func parseCommandBinding(raw []byte) (commandBinding, error) {
	statement, err := parseCommandStatement(raw)
	if err != nil {
		return commandBinding{}, err
	}
	return commandBinding{
		CommandID: statement.CommandID, TenantID: statement.TenantID, NodeID: statement.NodeID,
		RuntimeRef: statement.RuntimeRef, Kind: statement.Kind,
		ClaimGeneration: statement.ClaimGeneration, InstanceGeneration: statement.InstanceGeneration,
	}, nil
}

func parseCommandStatement(raw []byte) (admission.CommandStatement, error) {
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return admission.CommandStatement{}, err
	}
	if envelope.PayloadType != admission.CommandPayloadType {
		return admission.CommandStatement{}, errors.New("DSSE payload type is not an Executor command")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || len(payload) == 0 || len(payload) > dsse.MaxPayloadBytes || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return admission.CommandStatement{}, errors.New("DSSE payload encoding is invalid")
	}
	var statement admission.CommandStatement
	if err := dsse.DecodeStrictInto(payload, dsse.MaxPayloadBytes, &statement); err != nil {
		return admission.CommandStatement{}, err
	}
	if statement.SchemaVersion != admission.CommandSchemaV2 || !validRecordID(statement.CommandID, 256) ||
		!validRecordID(statement.TenantID, 128) || !validRecordID(statement.NodeID, 128) {
		return admission.CommandStatement{}, errors.New("signed command identity is invalid")
	}
	return statement, nil
}

func parseCommandBindingForSubmission(raw []byte) (commandBinding, error) {
	binding, err := parseCommandBinding(raw)
	if err != nil {
		return commandBinding{}, err
	}
	if !boundedRetainedText(binding.RuntimeRef, 1024) ||
		!boundedRetainedText(binding.Kind, 64) {
		return commandBinding{}, errors.New("signed command metadata is invalid")
	}
	return binding, nil
}

// retainedCommandBinding projects only bounded metadata into controller state.
// Releases before format 3 accepted signed commands without bounding these two
// fields. Recovery must keep those commands available for protocol-3 delivery,
// but unsafe legacy metadata is deliberately not promoted into the controller's
// protocol-4 correlation surface.
func retainedCommandBinding(binding commandBinding) commandBinding {
	if !boundedRetainedText(binding.RuntimeRef, 1024) {
		binding.RuntimeRef = ""
	}
	if !boundedRetainedText(binding.Kind, 64) {
		binding.Kind = ""
	}
	return binding
}

func parseCommandIdentity(raw []byte) (string, string, string, error) {
	binding, err := parseCommandBinding(raw)
	if err != nil {
		return "", "", "", err
	}
	return binding.CommandID, binding.TenantID, binding.NodeID, nil
}

func deliveryFor(command Command, generation uint64) (controlprotocol.ExecutorDeliveryV3, error) {
	delivery := controlprotocol.ExecutorDeliveryV3{
		DeliveryID: command.DeliveryID, DeliveryGeneration: generation, CommandID: command.ID,
		CommandDigest: command.Digest, CommandDSSEBase64: base64.StdEncoding.EncodeToString(command.CommandDSSE),
	}
	if err := delivery.Validate(); err != nil {
		return controlprotocol.ExecutorDeliveryV3{}, err
	}
	if !pollResponseFits([]controlprotocol.ExecutorDeliveryV3{delivery}, controlprotocol.ExecutorProtocolV3) {
		return controlprotocol.ExecutorDeliveryV3{}, errors.New("single delivery exceeds the poll response cap")
	}
	return delivery, nil
}

func pollResponseFits(deliveries []controlprotocol.ExecutorDeliveryV3, protocolVersion int) bool {
	rawDeliveries := make([]json.RawMessage, 0, len(deliveries))
	for _, delivery := range deliveries {
		raw, err := json.Marshal(delivery)
		if err != nil {
			return false
		}
		rawDeliveries = append(rawDeliveries, raw)
	}
	var raw []byte
	var err error
	switch protocolVersion {
	case controlprotocol.ExecutorProtocolV3:
		raw, err = json.Marshal(controlprotocol.ExecutorPollResponseV3{
			ProtocolVersion: controlprotocol.ExecutorProtocolV3, Deliveries: rawDeliveries,
		})
	case controlprotocol.ExecutorProtocolV4:
		raw, err = json.Marshal(controlprotocol.ExecutorPollResponseV4{
			ProtocolVersion: controlprotocol.ExecutorProtocolV4, Deliveries: rawDeliveries,
		})
	default:
		return false
	}
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
	node.Evidence = cloneEvidenceWitness(node.Evidence)
	node.Scheduling = cloneNodeScheduling(node.Scheduling)
	return node
}

func cloneNodeScheduling(value *NodeScheduling) *NodeScheduling {
	if value == nil {
		return nil
	}
	cloned := *value
	cloned.Observation = cloneSchedulingObservation(value.Observation)
	return &cloned
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
		left.IssueRequestID == right.IssueRequestID && left.IssuerCredentialID == right.IssuerCredentialID &&
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
