package controlstore

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"math"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/poolmembership"
)

const (
	NodePoolLabelKey           = "steward.io/node-pool"
	MaxNodePoolTenantScopes    = 64
	MaxNodePoolDesiredCapacity = 4096

	NodePoolConditionCapacityShortfall    = "capacity_shortfall"
	NodePoolConditionNodesNotReady        = "nodes_not_ready"
	NodePoolConditionScaleInAvailable     = "scale_in_available"
	NodePoolConditionMembershipUnverified = "membership_unverified"
)

type NodePoolNode struct {
	NodeID             string         `json:"node_id"`
	Ready              bool           `json:"ready"`
	Reason             string         `json:"reason,omitempty"`
	DrainState         NodeDrainState `json:"drain_state,omitempty"`
	Eligible           bool           `json:"eligible"`
	MembershipDigest   string         `json:"membership_digest,omitempty"`
	MembershipNotAfter string         `json:"membership_not_after,omitempty"`
}

// NodePoolStatus is a provider-neutral capacity observation. ScaleOutNeeded is
// safe to consume as a creation request. ScaleInCandidates names only exact,
// drained, empty nodes; it still does not destroy infrastructure by itself.
type NodePoolStatus struct {
	Pool              NodePool       `json:"pool"`
	Nodes             []NodePoolNode `json:"nodes"`
	RegisteredNodes   int            `json:"registered_nodes"`
	ReadyNodes        int            `json:"ready_nodes"`
	EligibleNodes     int            `json:"eligible_nodes"`
	ScaleOutNeeded    int            `json:"scale_out_needed"`
	ScaleInCandidates []string       `json:"scale_in_candidates"`
	Conditions        []string       `json:"conditions"`
	ObservedAt        string         `json:"observed_at"`
}

func (pool NodePool) Validate() error {
	if !validNodePool(pool) {
		return errors.New("node pool is invalid")
	}
	return nil
}

func (status NodePoolStatus) Validate() error {
	if status.Pool.Validate() != nil || status.Nodes == nil || status.ScaleInCandidates == nil ||
		status.Conditions == nil || status.RegisteredNodes != len(status.Nodes) || status.ReadyNodes < 0 ||
		status.ReadyNodes > status.EligibleNodes || status.EligibleNodes > status.RegisteredNodes ||
		status.ScaleOutNeeded != max(0, status.Pool.DesiredNodes-status.EligibleNodes) ||
		len(status.ScaleInCandidates) > max(0, status.EligibleNodes-status.Pool.DesiredNodes) ||
		!validTimestamp(status.ObservedAt) {
		return errors.New("node pool status is invalid")
	}
	ready := 0
	eligible := 0
	byID := make(map[string]NodePoolNode, len(status.Nodes))
	for index, node := range status.Nodes {
		if !validRecordID(node.NodeID, 128) || index > 0 && status.Nodes[index-1].NodeID >= node.NodeID ||
			!validNodePoolNodeState(node) {
			return errors.New("node pool status contains an invalid node")
		}
		if node.Ready {
			ready++
		}
		if node.Eligible {
			eligible++
		}
		byID[node.NodeID] = node
	}
	if ready != status.ReadyNodes || eligible != status.EligibleNodes {
		return errors.New("node pool ready count is inconsistent")
	}
	for index, nodeID := range status.ScaleInCandidates {
		node, ok := byID[nodeID]
		if !ok || node.DrainState != NodeDrainCompleted || node.Ready ||
			index > 0 && status.ScaleInCandidates[index-1] >= nodeID {
			return errors.New("node pool scale-in candidate is invalid")
		}
	}
	wantConditions := []string{}
	if status.ScaleOutNeeded > 0 {
		wantConditions = append(wantConditions, NodePoolConditionCapacityShortfall)
	}
	if status.ReadyNodes < status.EligibleNodes {
		wantConditions = append(wantConditions, NodePoolConditionNodesNotReady)
	}
	if status.EligibleNodes < status.RegisteredNodes {
		wantConditions = append(wantConditions, NodePoolConditionMembershipUnverified)
	}
	if len(status.ScaleInCandidates) > 0 && status.EligibleNodes > status.Pool.DesiredNodes {
		wantConditions = append(wantConditions, NodePoolConditionScaleInAvailable)
	}
	if len(wantConditions) != len(status.Conditions) {
		return errors.New("node pool conditions are inconsistent")
	}
	for index := range wantConditions {
		if wantConditions[index] != status.Conditions[index] {
			return errors.New("node pool conditions are not canonical")
		}
	}
	return nil
}

func validNodePoolNodeState(node NodePoolNode) bool {
	if node.Ready != (node.Reason == "") {
		return false
	}
	if node.Ready && !node.Eligible {
		return false
	}
	if (node.MembershipDigest == "") != (node.MembershipNotAfter == "") ||
		node.MembershipDigest != "" && (!validSHA256Digest(node.MembershipDigest) || !validTimestamp(node.MembershipNotAfter)) {
		return false
	}
	switch node.Reason {
	case "", "scheduling_unavailable", "scheduling_stale", "placement_blocked":
		if !node.Eligible {
			return false
		}
	case "membership_missing":
		if node.Eligible || node.MembershipDigest != "" {
			return false
		}
	case "membership_expired", "membership_mismatch":
		if node.Eligible || node.MembershipDigest == "" {
			return false
		}
	case "draining":
		if !node.Eligible || node.DrainState != NodeDrainActive {
			return false
		}
	case "drained":
		if !node.Eligible || node.DrainState != NodeDrainCompleted {
			return false
		}
	case "drain_failed":
		if !node.Eligible || node.DrainState != NodeDrainFailed {
			return false
		}
	default:
		return false
	}
	switch node.DrainState {
	case "", NodeDrainCancelled:
		return true
	case NodeDrainActive, NodeDrainCompleted, NodeDrainFailed:
		if node.Ready {
			return false
		}
		return true
	default:
		return false
	}
}

func (store *Store) ListNodePools(actor controlauth.Identity) ([]NodePool, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return nil, ErrForbidden
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return nil, err
	}
	result := make([]NodePool, 0, len(store.current.nodePools))
	for _, pool := range store.current.nodePools {
		result = append(result, cloneNodePool(pool))
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func (store *Store) GetNodePoolStatus(
	actor controlauth.Identity,
	poolID string,
	now time.Time,
	staleAfter time.Duration,
) (NodePoolStatus, error) {
	if store == nil {
		return NodePoolStatus{}, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return NodePoolStatus{}, ErrForbidden
	}
	if !validRecordID(poolID, 128) || now.IsZero() || staleAfter <= 0 || staleAfter > MaxOperationsThreshold {
		return NodePoolStatus{}, invalid("node pool status request is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return NodePoolStatus{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return NodePoolStatus{}, err
	}
	pool, ok := store.current.nodePools[poolID]
	if !ok {
		return NodePoolStatus{}, ErrNotFound
	}
	return nodePoolStatusLocked(store.current, pool, now, staleAfter), nil
}

func (store *Store) ListNodePoolStatuses(
	actor controlauth.Identity,
	now time.Time,
	staleAfter time.Duration,
) ([]NodePoolStatus, error) {
	if store == nil {
		return nil, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return nil, ErrForbidden
	}
	if now.IsZero() || staleAfter <= 0 || staleAfter > MaxOperationsThreshold {
		return nil, invalid("node pool status request is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return nil, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return nil, err
	}
	poolIDs := make([]string, 0, len(store.current.nodePools))
	for poolID := range store.current.nodePools {
		poolIDs = append(poolIDs, poolID)
	}
	sort.Strings(poolIDs)
	result := make([]NodePoolStatus, 0, len(poolIDs))
	for _, poolID := range poolIDs {
		result = append(result, nodePoolStatusLocked(store.current, store.current.nodePools[poolID], now, staleAfter))
	}
	return result, nil
}

func (store *Store) ApplyNodePool(
	actor controlauth.Identity,
	pool NodePool,
	expectedRevision uint64,
	now time.Time,
) (NodePool, bool, error) {
	if store == nil {
		return NodePool{}, false, ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return NodePool{}, false, ErrForbidden
	}
	pool.Revision = 1
	pool.MembershipGeneration = 1
	pool.CreatedAt = canonicalTimestamp(now)
	pool.UpdatedAt = pool.CreatedAt
	if now.IsZero() || !validNodePool(pool) {
		return NodePool{}, false, invalid("node pool input is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return NodePool{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return NodePool{}, false, err
	}
	for _, tenantID := range pool.TenantIDs {
		if tenant, ok := store.current.tenants[tenantID]; !ok || !tenant.Active {
			return NodePool{}, false, ErrNotFound
		}
	}
	current, exists := store.current.nodePools[pool.ID]
	if !exists {
		if expectedRevision != 0 {
			return NodePool{}, false, ErrConflict
		}
		if len(store.current.nodePools) >= store.limits.MaxNodePools {
			return NodePool{}, false, ErrCapacityExceeded
		}
	} else {
		if current.Revision != expectedRevision {
			return NodePool{}, false, ErrConflict
		}
		updatedAt, _ := parseTimestamp(current.UpdatedAt)
		if now.Before(updatedAt) {
			return NodePool{}, false, invalid("node pool update predates retained state")
		}
		if sameNodePoolSpec(current, pool) {
			return cloneNodePool(current), false, nil
		}
		if current.Revision == math.MaxUint64 {
			return NodePool{}, false, ErrCapacityExceeded
		}
		pool.MembershipGeneration = current.MembershipGeneration
		if !sameNodePoolMembershipSpec(current, pool) {
			if current.MembershipGeneration == math.MaxUint64 {
				return NodePool{}, false, ErrCapacityExceeded
			}
			pool.MembershipGeneration++
		}
		pool.Revision = current.Revision + 1
		pool.CreatedAt = current.CreatedAt
		pool.UpdatedAt = canonicalTimestamp(now)
	}
	if err := store.applyMutationsLocked(mutation{Kind: mutationNodePool, NodePool: &pool}); err != nil {
		return NodePool{}, false, err
	}
	return cloneNodePool(pool), true, nil
}

func (store *Store) DeleteNodePool(
	actor controlauth.Identity,
	poolID string,
	expectedRevision uint64,
) error {
	if store == nil {
		return ErrUnavailable
	}
	if !controlauth.IsSiteAdmin(actor) {
		return ErrForbidden
	}
	if !validRecordID(poolID, 128) || expectedRevision == 0 {
		return invalid("node pool deletion is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return err
	}
	pool, exists := store.current.nodePools[poolID]
	if !exists {
		return ErrNotFound
	}
	if pool.Revision != expectedRevision {
		return ErrConflict
	}
	return store.applyMutationsLocked(mutation{Kind: mutationNodePoolDelete, NodePoolID: poolID})
}

func nodePoolStatusLocked(current state, pool NodePool, now time.Time, staleAfter time.Duration) NodePoolStatus {
	status := NodePoolStatus{
		Pool: cloneNodePool(pool), Nodes: []NodePoolNode{}, ScaleInCandidates: []string{},
		Conditions: []string{}, ObservedAt: canonicalTimestamp(now),
	}
	for _, node := range current.nodes {
		if !nodeAdvertisesPool(node, pool) {
			continue
		}
		projection := NodePoolNode{NodeID: node.ID}
		if node.Drain != nil {
			projection.DrainState = node.Drain.State
		}
		projection.Eligible, projection.Reason = nodePoolMembershipEligible(node, pool, now)
		if node.PoolMembership != nil {
			projection.MembershipDigest = node.PoolMembership.Digest
			projection.MembershipNotAfter = node.PoolMembership.NotAfter
		}
		if projection.Eligible {
			status.EligibleNodes++
			projection.Ready, projection.Reason = nodePoolNodeReady(node, now, staleAfter)
		}
		if projection.Ready {
			status.ReadyNodes++
		}
		status.Nodes = append(status.Nodes, projection)
		if projection.Eligible && node.Drain != nil && node.Drain.State == NodeDrainCompleted && !nodeHasAssignedWorkload(current.deployments, node.ID) {
			status.ScaleInCandidates = append(status.ScaleInCandidates, node.ID)
		}
	}
	sort.Slice(status.Nodes, func(i, j int) bool { return status.Nodes[i].NodeID < status.Nodes[j].NodeID })
	sort.Strings(status.ScaleInCandidates)
	status.RegisteredNodes = len(status.Nodes)
	surplus := max(0, status.EligibleNodes-pool.DesiredNodes)
	if len(status.ScaleInCandidates) > surplus {
		status.ScaleInCandidates = status.ScaleInCandidates[:surplus]
	}
	if status.EligibleNodes < pool.DesiredNodes {
		status.ScaleOutNeeded = pool.DesiredNodes - status.EligibleNodes
		status.Conditions = append(status.Conditions, NodePoolConditionCapacityShortfall)
	}
	if status.ReadyNodes < status.EligibleNodes {
		status.Conditions = append(status.Conditions, NodePoolConditionNodesNotReady)
	}
	if status.EligibleNodes < status.RegisteredNodes {
		status.Conditions = append(status.Conditions, NodePoolConditionMembershipUnverified)
	}
	if len(status.ScaleInCandidates) > 0 && status.EligibleNodes > pool.DesiredNodes {
		status.Conditions = append(status.Conditions, NodePoolConditionScaleInAvailable)
	}
	return status
}

func nodeAdvertisesPool(node Node, pool NodePool) bool {
	if !node.Active || node.Scheduling == nil || pool.Architecture != "" && node.Scheduling.Observation.Architecture != pool.Architecture {
		return false
	}
	for _, tenantID := range pool.TenantIDs {
		if !tenantMember(node.TenantIDs, tenantID) {
			return false
		}
	}
	labels := node.Scheduling.Observation.Labels
	index := sort.Search(len(labels), func(index int) bool { return labels[index].Key >= NodePoolLabelKey })
	return index < len(labels) && labels[index].Key == NodePoolLabelKey && labels[index].Value == pool.ID
}

func nodePoolMembershipEligible(node Node, pool NodePool, now time.Time) (bool, string) {
	if pool.MembershipKeyID == "" {
		return true, ""
	}
	membership := node.PoolMembership
	if membership == nil {
		return false, "membership_missing"
	}
	if membership.PoolID != pool.ID || membership.PoolMembershipGeneration != pool.MembershipGeneration || membership.KeyID != pool.MembershipKeyID ||
		pool.Architecture != "" && membership.Architecture != pool.Architecture {
		return false, "membership_mismatch"
	}
	notAfter, err := time.Parse(time.RFC3339Nano, membership.NotAfter)
	if err != nil || !now.Before(notAfter) {
		return false, "membership_expired"
	}
	if !nodeMeasurementsMatchMembership(node, membership) {
		return false, "membership_mismatch"
	}
	return true, ""
}

func nodeMeasurementsMatchMembership(node Node, membership *NodePoolMembership) bool {
	if node.Scheduling == nil || membership == nil {
		return false
	}
	observation := node.Scheduling.Observation
	return observation.BootIdentitySHA256 != "" && observation.SchedulingPolicySHA256 != "" &&
		observation.BootIdentitySHA256 == membership.BootIdentitySHA256 &&
		observation.SchedulingPolicySHA256 == membership.SchedulingPolicySHA256 &&
		(membership.RuntimeAssuranceSHA256 == "" ||
			observation.RuntimeAssuranceSHA256 == membership.RuntimeAssuranceSHA256)
}

func nodePoolNodeReady(node Node, now time.Time, staleAfter time.Duration) (bool, string) {
	if node.Scheduling == nil {
		return false, "scheduling_unavailable"
	}
	observed, err := parseTimestamp(node.Scheduling.ObservedAt)
	if err != nil || !now.Before(observed.Add(staleAfter)) {
		return false, "scheduling_stale"
	}
	if EffectiveNodePlacement(node).Mode != NodeSchedulable {
		return false, "placement_blocked"
	}
	if node.Drain != nil {
		switch node.Drain.State {
		case NodeDrainActive:
			return false, "draining"
		case NodeDrainCompleted:
			return false, "drained"
		case NodeDrainFailed:
			return false, "drain_failed"
		}
	}
	return true, ""
}

func nodeHasAssignedWorkload(deployments map[string]Deployment, nodeID string) bool {
	for _, deployment := range deployments {
		for _, instance := range deployment.Instances {
			if instance.NodeID == nodeID && instance.Phase != DeploymentInstanceRemoved {
				return true
			}
		}
	}
	return false
}

func validNodePool(pool NodePool) bool {
	if !validRecordID(pool.ID, 128) || pool.Revision == 0 || pool.MembershipGeneration == 0 || !validTenantSet(pool.TenantIDs) ||
		len(pool.TenantIDs) > MaxNodePoolTenantScopes ||
		pool.Architecture != "" && !controlprotocol.ValidSchedulingAttribute(pool.Architecture) ||
		pool.MinNodes < 0 || pool.DesiredNodes < pool.MinNodes || pool.MaxNodes < pool.DesiredNodes ||
		pool.MaxNodes <= 0 || pool.MaxNodes > MaxNodePoolDesiredCapacity ||
		!validNodePoolMembershipAuthority(pool) ||
		!validTimestamp(pool.CreatedAt) || !validTimestamp(pool.UpdatedAt) {
		return false
	}
	created, _ := parseTimestamp(pool.CreatedAt)
	updated, _ := parseTimestamp(pool.UpdatedAt)
	return !updated.Before(created)
}

func sameNodePoolSpec(left, right NodePool) bool {
	if left.ID != right.ID || left.Architecture != right.Architecture || left.MinNodes != right.MinNodes ||
		left.DesiredNodes != right.DesiredNodes || left.MaxNodes != right.MaxNodes || len(left.TenantIDs) != len(right.TenantIDs) {
		return false
	}
	if left.MembershipKeyID != right.MembershipKeyID || left.MembershipPublicKeyBase64 != right.MembershipPublicKeyBase64 {
		return false
	}
	for index := range left.TenantIDs {
		if left.TenantIDs[index] != right.TenantIDs[index] {
			return false
		}
	}
	return true
}

func sameNodePoolMembershipSpec(left, right NodePool) bool {
	if left.Architecture != right.Architecture || left.MembershipKeyID != right.MembershipKeyID ||
		left.MembershipPublicKeyBase64 != right.MembershipPublicKeyBase64 || len(left.TenantIDs) != len(right.TenantIDs) {
		return false
	}
	for index := range left.TenantIDs {
		if left.TenantIDs[index] != right.TenantIDs[index] {
			return false
		}
	}
	return true
}

func validNodePoolMembershipAuthority(pool NodePool) bool {
	if pool.MembershipKeyID == "" || pool.MembershipPublicKeyBase64 == "" {
		return pool.MembershipKeyID == "" && pool.MembershipPublicKeyBase64 == ""
	}
	if !validRecordID(pool.MembershipKeyID, 128) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(pool.MembershipPublicKeyBase64)
	return err == nil && len(decoded) == ed25519.PublicKeySize && base64.StdEncoding.EncodeToString(decoded) == pool.MembershipPublicKeyBase64
}

func validStoredNodePoolMembership(value *NodePoolMembership, nodeID string, tenantIDs []string) bool {
	if value == nil || !validRecordID(value.PoolID, 128) || value.PoolMembershipGeneration == 0 ||
		!validTimestamp(value.PoolCreatedAt) || !validSHA256Digest(value.Digest) || !validRecordID(value.KeyID, 128) ||
		!validSHA256Digest(value.BootIdentitySHA256) || !validSHA256Digest(value.SchedulingPolicySHA256) ||
		value.RuntimeAssuranceSHA256 != "" && !validSHA256Digest(value.RuntimeAssuranceSHA256) ||
		!validTimestamp(value.IssuedAt) || !validTimestamp(value.NotAfter) {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(value.EnvelopeBase64)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value.EnvelopeBase64 || dsse.Digest(raw) != value.Digest {
		return false
	}
	claim, err := poolmembership.Inspect(raw)
	if err != nil || claim.NodeID != nodeID || !tenantSubset(claim.TenantIDs, tenantIDs) ||
		claim.PoolID != value.PoolID || claim.PoolMembershipGeneration != value.PoolMembershipGeneration ||
		claim.PoolCreatedAt != value.PoolCreatedAt || claim.Architecture != value.Architecture ||
		claim.BootIdentitySHA256 != value.BootIdentitySHA256 || claim.SchedulingPolicySHA256 != value.SchedulingPolicySHA256 ||
		claim.RuntimeAssuranceSHA256 != value.RuntimeAssuranceSHA256 ||
		claim.IssuedAt != value.IssuedAt || claim.NotAfter != value.NotAfter {
		return false
	}
	envelope, err := dsse.Parse(raw)
	if err != nil {
		return false
	}
	for _, signature := range envelope.Signatures {
		if signature.KeyID == value.KeyID {
			return true
		}
	}
	return false
}

func (store *Store) BindNodePoolMembership(identity controlauth.NodeIdentity, auth *controlauth.Manager, raw []byte, now time.Time) (Node, error) {
	if store == nil || auth == nil {
		return Node{}, ErrUnavailable
	}
	statement, err := poolmembership.Inspect(raw)
	if err != nil || statement.NodeID != identity.NodeID || statement.ControllerInstanceID != auth.InstanceID() || now.IsZero() {
		return Node{}, invalid("node-pool membership identity is invalid")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return Node{}, err
	}
	if err := store.revalidateNodeLocked(identity); err != nil {
		return Node{}, err
	}
	pool, ok := store.current.nodePools[statement.PoolID]
	if !ok || pool.MembershipKeyID == "" {
		return Node{}, ErrNotFound
	}
	public, err := base64.StdEncoding.DecodeString(pool.MembershipPublicKeyBase64)
	if err != nil {
		return Node{}, ErrConflict
	}
	verified, err := poolmembership.Verify(raw, pool.MembershipKeyID, ed25519.PublicKey(public), now)
	if err != nil {
		return Node{}, invalid("node-pool membership signature or validity is invalid")
	}
	claim := verified.Statement
	if claim.PoolMembershipGeneration != pool.MembershipGeneration || claim.PoolCreatedAt != pool.CreatedAt || claim.Architecture != pool.Architecture ||
		!equalStrings(claim.TenantIDs, pool.TenantIDs) || !tenantSubset(claim.TenantIDs, identity.TenantIDs) {
		return Node{}, ErrConflict
	}
	node, ok := store.current.nodes[identity.NodeID]
	if !ok || !node.Active {
		return Node{}, ErrNotFound
	}
	membership := &NodePoolMembership{
		PoolID: claim.PoolID, PoolMembershipGeneration: claim.PoolMembershipGeneration, PoolCreatedAt: claim.PoolCreatedAt, Digest: verified.Digest, KeyID: verified.KeyID,
		EnvelopeBase64: base64.StdEncoding.EncodeToString(raw), Architecture: claim.Architecture,
		BootIdentitySHA256: claim.BootIdentitySHA256, SchedulingPolicySHA256: claim.SchedulingPolicySHA256,
		RuntimeAssuranceSHA256: claim.RuntimeAssuranceSHA256,
		IssuedAt:               claim.IssuedAt, NotAfter: claim.NotAfter,
	}
	if !nodeMeasurementsMatchMembership(node, membership) {
		return Node{}, ErrConflict
	}
	if node.PoolMembership != nil {
		if node.PoolMembership.Digest == membership.Digest {
			return cloneNode(node), nil
		}
		if sameNodePoolMembershipLineage(node.PoolMembership, membership) {
			previous, _ := time.Parse(time.RFC3339Nano, node.PoolMembership.IssuedAt)
			issued, _ := time.Parse(time.RFC3339Nano, membership.IssuedAt)
			if !issued.After(previous) {
				return Node{}, ErrConflict
			}
		}
	}
	node.PoolMembership = membership
	if err := store.applyMutationsLocked(mutation{Kind: mutationNode, Node: &node}); err != nil {
		return Node{}, err
	}
	return cloneNode(node), nil
}

func sameNodePoolMembershipLineage(left, right *NodePoolMembership) bool {
	return left != nil && right != nil && left.PoolID == right.PoolID &&
		left.PoolMembershipGeneration == right.PoolMembershipGeneration &&
		left.PoolCreatedAt == right.PoolCreatedAt && left.KeyID == right.KeyID
}

func cloneNodePool(pool NodePool) NodePool {
	pool.TenantIDs = append([]string{}, pool.TenantIDs...)
	return pool
}
