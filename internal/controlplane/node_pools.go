package controlplane

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"

	"github.com/hardrails/steward/internal/controlstore"
)

type nodePoolApplyRequest struct {
	ExpectedRevision          uint64   `json:"expected_revision"`
	TenantIDs                 []string `json:"tenant_ids"`
	Architecture              string   `json:"architecture,omitempty"`
	MinNodes                  int      `json:"min_nodes"`
	DesiredNodes              int      `json:"desired_nodes"`
	MaxNodes                  int      `json:"max_nodes"`
	MembershipKeyID           string   `json:"membership_key_id,omitempty"`
	MembershipPublicKeyBase64 string   `json:"membership_public_key_base64,omitempty"`
}

type nodePoolDeleteRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
}

type nodePoolListResponse struct {
	NodePools []controlstore.NodePoolStatus `json:"node_pools"`
	NextAfter string                        `json:"next_after,omitempty"`
}

func (server *Server) nodePools(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodGet) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	page, ok := parsePage(writer, request)
	if !ok {
		return
	}
	statuses, err := server.store.ListNodePoolStatuses(
		identity, server.now(), server.operationsThresholds.NodeStaleAfter,
	)
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	selected, next, err := pageNodePoolStatuses(statuses, page)
	if err != nil {
		server.logger.Error("control node pool page exceeded response bound", "error", err)
		writeError(writer, http.StatusInternalServerError, "internal_error", "the control plane could not encode a bounded node pool page")
		return
	}
	writeJSON(writer, http.StatusOK, nodePoolListResponse{NodePools: selected, NextAfter: next})
}

func (server *Server) nodePool(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet && request.Method != http.MethodPut && request.Method != http.MethodDelete {
		methodNotAllowed(writer, http.MethodGet, http.MethodPut, http.MethodDelete)
		return
	}
	if !noQuery(writer, request) {
		return
	}
	identity, ok := server.operatorIdentity(writer, request)
	if !ok {
		return
	}
	poolID := request.PathValue("pool_id")
	switch request.Method {
	case http.MethodGet:
		status, err := server.store.GetNodePoolStatus(
			identity, poolID, server.now(), server.operationsThresholds.NodeStaleAfter,
		)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		writeJSON(writer, http.StatusOK, status)
	case http.MethodPut:
		var input nodePoolApplyRequest
		if !server.decode(writer, request, &input) {
			return
		}
		pool, changed, err := server.store.ApplyNodePool(identity, controlstore.NodePool{
			ID: poolID, TenantIDs: input.TenantIDs, Architecture: input.Architecture,
			MinNodes: input.MinNodes, DesiredNodes: input.DesiredNodes, MaxNodes: input.MaxNodes,
			MembershipKeyID: input.MembershipKeyID, MembershipPublicKeyBase64: input.MembershipPublicKeyBase64,
		}, input.ExpectedRevision, server.now())
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		status, err := server.store.GetNodePoolStatus(
			identity, pool.ID, server.now(), server.operationsThresholds.NodeStaleAfter,
		)
		if err != nil {
			server.storeError(writer, err, false)
			return
		}
		code := http.StatusOK
		if changed && pool.Revision == 1 {
			code = http.StatusCreated
		}
		writeJSON(writer, code, status)
	case http.MethodDelete:
		var input nodePoolDeleteRequest
		if !server.decode(writer, request, &input) {
			return
		}
		if err := server.store.DeleteNodePool(identity, poolID, input.ExpectedRevision); err != nil {
			server.storeError(writer, err, false)
			return
		}
		writeNoContent(writer)
	}
}

func (server *Server) executorPoolMembership(writer http.ResponseWriter, request *http.Request) {
	if !method(writer, request, http.MethodPut) || !noQuery(writer, request) {
		return
	}
	identity, ok := server.nodeIdentity(writer, request)
	if !ok {
		return
	}
	var input struct {
		Membership json.RawMessage `json:"membership"`
	}
	if !server.decode(writer, request, &input) {
		return
	}
	node, err := server.store.BindNodePoolMembership(identity, server.auth, input.Membership, server.now())
	if err != nil {
		server.storeError(writer, err, false)
		return
	}
	writeJSON(writer, http.StatusOK, struct {
		NodeID     string                           `json:"node_id"`
		Membership *controlstore.NodePoolMembership `json:"membership"`
	}{NodeID: node.ID, Membership: node.PoolMembership})
}

func pageNodePoolStatuses(
	values []controlstore.NodePoolStatus,
	page pageRequest,
) ([]controlstore.NodePoolStatus, string, error) {
	start := sort.Search(len(values), func(index int) bool { return values[index].Pool.ID > page.after })
	selected := make([]controlstore.NodePoolStatus, 0, min(page.limit, len(values)-start))
	for index := start; index < len(values) && len(selected) < page.limit; index++ {
		candidate := append(append([]controlstore.NodePoolStatus(nil), selected...), values[index])
		next := ""
		if index+1 < len(values) {
			next = values[index].Pool.ID
		}
		raw, err := json.Marshal(nodePoolListResponse{NodePools: candidate, NextAfter: next})
		if err != nil {
			return nil, "", err
		}
		if len(raw)+1 > maxResponseBytes {
			if len(selected) == 0 {
				return nil, "", errors.New("one valid node pool cannot fit the response limit")
			}
			break
		}
		selected = candidate
	}
	next := ""
	if start+len(selected) < len(values) {
		next = selected[len(selected)-1].Pool.ID
	}
	return selected, next, nil
}
