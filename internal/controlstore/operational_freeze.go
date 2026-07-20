package controlstore

import (
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
)

type OperationalFreezeAction string

const (
	OperationalFreezeActionFreeze   OperationalFreezeAction = "freeze"
	OperationalFreezeActionUnfreeze OperationalFreezeAction = "unfreeze"
)

type OperationalFreezeStatus struct {
	Site      *OperationalFreeze `json:"site,omitempty"`
	Tenant    *OperationalFreeze `json:"tenant,omitempty"`
	Effective *OperationalFreeze `json:"effective,omitempty"`
}

// InspectOperationalFreeze returns the durable site gate and, when tenantID is
// non-empty, the exact tenant gate. Effective prefers an active site freeze so
// a tenant operator cannot mistake a locally unfrozen tenant for an available
// site.
func (store *Store) InspectOperationalFreeze(
	actor controlauth.Identity,
	tenantID string,
) (OperationalFreezeStatus, error) {
	if store == nil {
		return OperationalFreezeStatus{}, ErrUnavailable
	}
	if tenantID == "" {
		if !controlauth.IsSiteAdmin(actor) {
			return OperationalFreezeStatus{}, ErrForbidden
		}
	} else if !controlauth.AuthorizedTenant(actor, tenantID) {
		return OperationalFreezeStatus{}, ErrNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return OperationalFreezeStatus{}, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return OperationalFreezeStatus{}, err
	}
	if tenantID != "" {
		if tenant, ok := store.current.tenants[tenantID]; !ok || !tenant.Active {
			return OperationalFreezeStatus{}, ErrNotFound
		}
	}
	return operationalFreezeStatus(store.current.freezes, tenantID), nil
}

// ChangeOperationalFreeze applies an optimistic, durable delivery gate. An
// initial transition expects revision zero. Every later transition must name
// the retained revision, including unfreeze, so a stale incident response
// cannot overwrite a newer decision.
func (store *Store) ChangeOperationalFreeze(
	actor controlauth.Identity,
	tenantID string,
	action OperationalFreezeAction,
	expectedRevision uint64,
	reason string,
	now time.Time,
) (OperationalFreezeStatus, bool, error) {
	if store == nil {
		return OperationalFreezeStatus{}, false, ErrUnavailable
	}
	if tenantID == "" {
		if !controlauth.IsSiteAdmin(actor) {
			return OperationalFreezeStatus{}, false, ErrForbidden
		}
	} else if !controlauth.AuthorizedTenant(actor, tenantID) {
		return OperationalFreezeStatus{}, false, ErrNotFound
	}
	if !validOperationalFreezeChange(action, reason) || now.IsZero() {
		return OperationalFreezeStatus{}, false, invalid("operational freeze transition is invalid")
	}
	scope := OperationalFreezeSite
	if tenantID != "" {
		scope = OperationalFreezeTenant
	}
	key := operationalFreezeKey(scope, tenantID)
	store.mu.Lock()
	defer store.mu.Unlock()
	if err := store.availableLocked(); err != nil {
		return OperationalFreezeStatus{}, false, err
	}
	if err := store.revalidateOperatorLocked(actor); err != nil {
		return OperationalFreezeStatus{}, false, err
	}
	if tenantID != "" {
		if tenant, ok := store.current.tenants[tenantID]; !ok || !tenant.Active {
			return OperationalFreezeStatus{}, false, ErrNotFound
		}
	}
	current, exists := store.current.freezes[key]
	if !exists {
		if expectedRevision != 0 {
			return OperationalFreezeStatus{}, false, ErrConflict
		}
		if action == OperationalFreezeActionUnfreeze {
			return operationalFreezeStatus(store.current.freezes, tenantID), false, nil
		}
	} else {
		if current.Revision != expectedRevision {
			return OperationalFreezeStatus{}, false, ErrConflict
		}
		changedAt, _ := parseTimestamp(current.ChangedAt)
		if now.Before(changedAt) {
			return OperationalFreezeStatus{}, false, invalid("operational freeze transition predates retained state")
		}
		wantFrozen := action == OperationalFreezeActionFreeze
		if current.Frozen == wantFrozen && current.Reason == reason {
			return operationalFreezeStatus(store.current.freezes, tenantID), false, nil
		}
		if current.Revision == ^uint64(0) {
			return OperationalFreezeStatus{}, false, ErrCapacityExceeded
		}
	}
	revision := uint64(1)
	if exists {
		revision = current.Revision + 1
	}
	updated := OperationalFreeze{
		Scope: scope, TenantID: tenantID,
		Frozen:   action == OperationalFreezeActionFreeze,
		Revision: revision, Reason: reason, ChangedAt: canonicalTimestamp(now),
	}
	if err := store.applyMutationsLocked(mutation{Kind: mutationOperationalFreeze, Freeze: &updated}); err != nil {
		return OperationalFreezeStatus{}, false, err
	}
	return operationalFreezeStatus(store.current.freezes, tenantID), true, nil
}

func operationalFreezeStatus(freezes map[string]OperationalFreeze, tenantID string) OperationalFreezeStatus {
	result := OperationalFreezeStatus{}
	if site, ok := freezes[operationalFreezeKey(OperationalFreezeSite, "")]; ok {
		result.Site = cloneOperationalFreeze(site)
	}
	if tenantID != "" {
		if tenant, ok := freezes[operationalFreezeKey(OperationalFreezeTenant, tenantID)]; ok {
			result.Tenant = cloneOperationalFreeze(tenant)
		}
	}
	if result.Site != nil && result.Site.Frozen {
		result.Effective = cloneOperationalFreeze(*result.Site)
	} else if result.Tenant != nil && result.Tenant.Frozen {
		result.Effective = cloneOperationalFreeze(*result.Tenant)
	}
	return result
}

func effectiveOperationalFreezeMap(freezes map[string]OperationalFreeze, tenantID string) (OperationalFreeze, bool) {
	status := operationalFreezeStatus(freezes, tenantID)
	if status.Effective == nil {
		return OperationalFreeze{}, false
	}
	return *status.Effective, true
}

// EffectiveOperationalFreeze selects the strongest active freeze from a
// bounded fleet snapshot. Site scope always takes precedence over tenant scope.
func EffectiveOperationalFreeze(freezes []OperationalFreeze, tenantID string) (OperationalFreeze, bool) {
	indexed := make(map[string]OperationalFreeze, len(freezes))
	for _, freeze := range freezes {
		if key := operationalFreezeKey(freeze.Scope, freeze.TenantID); key != "" {
			indexed[key] = freeze
		}
	}
	return effectiveOperationalFreezeMap(indexed, tenantID)
}

func cloneOperationalFreeze(value OperationalFreeze) *OperationalFreeze {
	cloned := value
	return &cloned
}

func operationalFreezeKey(scope OperationalFreezeScope, tenantID string) string {
	switch scope {
	case OperationalFreezeSite:
		if tenantID == "" {
			return "site"
		}
	case OperationalFreezeTenant:
		if validRecordID(tenantID, 128) {
			return "tenant\x00" + tenantID
		}
	}
	return ""
}

func validOperationalFreezeChange(action OperationalFreezeAction, reason string) bool {
	switch action {
	case OperationalFreezeActionFreeze:
		return reason != "" && len(reason) <= 256 && strings.TrimSpace(reason) == reason &&
			boundedRetainedText(reason, 256)
	case OperationalFreezeActionUnfreeze:
		return reason == ""
	default:
		return false
	}
}

func validOperationalFreeze(value OperationalFreeze) bool {
	if operationalFreezeKey(value.Scope, value.TenantID) == "" || value.Revision == 0 ||
		!validTimestamp(value.ChangedAt) {
		return false
	}
	if value.Frozen {
		return validOperationalFreezeChange(OperationalFreezeActionFreeze, value.Reason)
	}
	return validOperationalFreezeChange(OperationalFreezeActionUnfreeze, value.Reason)
}
