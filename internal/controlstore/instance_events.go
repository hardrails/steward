package controlstore

import (
	"maps"
	"reflect"
	"slices"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
)

const (
	MaxInstanceEventsRetained  = 4096
	MaxInstanceEventsPerTenant = 1024
)

// InstanceEvent wraps an agent-authored observation with the time at which the
// controller durably accepted it. The nested event remains clearly untrusted
// telemetry and never becomes command authority or signed evidence.
type InstanceEvent struct {
	Event      controlprotocol.InstanceEventV1 `json:"event"`
	ReceivedAt string                          `json:"received_at"`
}

func cloneInstanceEvent(value InstanceEvent) InstanceEvent {
	value.Event.Attributes = maps.Clone(value.Event.Attributes)
	return value
}

func validInstanceEvent(value InstanceEvent) bool {
	return value.Event.Validate() == nil && validTimestamp(value.ReceivedAt)
}

// RetainInstanceEvents commits one complete node batch idempotently. The store
// maintains bounded newest-first retention by deleting the oldest records in
// the same synced transaction that adds replacements.
func (store *Store) RetainInstanceEvents(
	identity controlauth.NodeIdentity,
	batch controlprotocol.InstanceEventBatchRequestV1,
	now time.Time,
) (int, error) {
	if store == nil {
		return 0, ErrUnavailable
	}
	if now.IsZero() || identity.Audience != "executor" || batch.Validate() != nil ||
		batch.NodeID != identity.NodeID || !validTenantSet(identity.TenantIDs) {
		return 0, invalid("instance event batch or node identity is invalid")
	}
	for _, event := range batch.Events {
		if !slices.Contains(identity.TenantIDs, event.TenantID) {
			return 0, ErrForbidden
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

	mutations := make([]mutation, 0, 2*len(batch.Events))
	candidates := make(map[string]InstanceEvent, len(store.current.events)+len(batch.Events))
	for id, event := range store.current.events {
		candidates[id] = cloneInstanceEvent(event)
	}
	// A wall clock can move backwards after an NTP correction or VM resume. Keep
	// retention order monotonic so a newly accepted event cannot immediately
	// evict itself merely because the controller clock regressed.
	receivedAtTime := now.UTC()
	for _, existing := range store.current.events {
		existingTime, err := parseTimestamp(existing.ReceivedAt)
		if err == nil && !receivedAtTime.After(existingTime) {
			receivedAtTime = existingTime.Add(time.Nanosecond)
		}
	}
	receivedAt := canonicalTimestamp(receivedAtTime)
	applied := 0
	for _, event := range batch.Events {
		candidate := InstanceEvent{Event: event, ReceivedAt: receivedAt}
		if existing, exists := candidates[event.EventID]; exists {
			if !instanceEventsEqual(existing.Event, event) {
				return 0, ErrConflict
			}
			continue
		}
		candidates[event.EventID] = cloneInstanceEvent(candidate)
		copy := cloneInstanceEvent(candidate)
		mutations = append(mutations, mutation{Kind: mutationInstanceEvent, Event: &copy})
		applied++
	}
	if applied == 0 {
		return 0, nil
	}
	evicted := retentionEvictions(candidates)
	for _, id := range evicted {
		if _, existed := store.current.events[id]; existed {
			mutations = append([]mutation{{Kind: mutationInstanceEventDelete, EventID: id}}, mutations...)
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

func (store *Store) ListInstanceEvents(actor controlauth.Identity, tenantID string) ([]InstanceEvent, error) {
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
	result := make([]InstanceEvent, 0)
	for _, event := range store.current.events {
		if event.Event.TenantID == tenantID {
			result = append(result, cloneInstanceEvent(event))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Event.AcceptedAt != result[j].Event.AcceptedAt {
			return result[i].Event.AcceptedAt > result[j].Event.AcceptedAt
		}
		return result[i].Event.EventID > result[j].Event.EventID
	})
	return result, nil
}

func instanceEventsEqual(left, right controlprotocol.InstanceEventV1) bool {
	return reflect.DeepEqual(left, right)
}

func retentionEvictions(events map[string]InstanceEvent) []string {
	byTenant := make(map[string][]InstanceEvent)
	for _, event := range events {
		byTenant[event.Event.TenantID] = append(byTenant[event.Event.TenantID], event)
	}
	evicted := make(map[string]struct{})
	for _, tenantEvents := range byTenant {
		sortOldestEvents(tenantEvents)
		for len(tenantEvents) > MaxInstanceEventsPerTenant {
			evicted[tenantEvents[0].Event.EventID] = struct{}{}
			tenantEvents = tenantEvents[1:]
		}
	}
	remaining := make([]InstanceEvent, 0, len(events)-len(evicted))
	for id, event := range events {
		if _, removed := evicted[id]; !removed {
			remaining = append(remaining, event)
		}
	}
	sortOldestEvents(remaining)
	for len(remaining) > MaxInstanceEventsRetained {
		evicted[remaining[0].Event.EventID] = struct{}{}
		remaining = remaining[1:]
	}
	result := make([]string, 0, len(evicted))
	for id := range evicted {
		result = append(result, id)
	}
	sort.Strings(result)
	return result
}

func sortOldestEvents(events []InstanceEvent) {
	sort.Slice(events, func(i, j int) bool {
		if events[i].ReceivedAt != events[j].ReceivedAt {
			return events[i].ReceivedAt < events[j].ReceivedAt
		}
		return events[i].Event.EventID < events[j].Event.EventID
	})
}
