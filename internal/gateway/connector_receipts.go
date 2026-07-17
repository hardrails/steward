package gateway

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/hardrails/steward/internal/connectorledger"
)

type connectorSpendOwner struct {
	GrantID     string
	ConnectorID string
}

type connectorReceiptIndex struct {
	spends  map[string]connectorSpendOwner
	counts  map[string]map[string]int
	denials map[string]struct{}
	pending map[string]connectorledger.Event
	tasks   map[string]serviceTaskReceipt
	permits map[string]string
}

type serviceTaskReceipt struct {
	Authorization          connectorledger.Event
	Dispatch               connectorledger.Event
	Terminal               connectorledger.Event
	authorizationAmbiguous bool
	dispatchAmbiguous      bool
	terminalUnavailable    bool
	observing              bool
	nextObservationAt      time.Time
}

// ConnectorReceiptFormatSummary identifies the connector receipt compatibility
// boundary without exposing receipt contents.
type ConnectorReceiptFormatSummary struct {
	Present       bool `json:"present"`
	FormatVersion int  `json:"format_version"`
}

// InspectConnectorReceiptFormat verifies an existing connector receipt ledger
// without creating or changing it. A configured but not-yet-created ledger is
// a valid prospective path and is reported as absent.
func InspectConnectorReceiptFormat(config Config) (ConnectorReceiptFormatSummary, error) {
	requiredFormat := 0
	if len(config.ActionAuthorities) > 0 {
		requiredFormat = 2
	}
	if len(config.ServiceOperations) > 0 {
		requiredFormat = 3
	}
	if config.hasTaskLifecycle() {
		requiredFormat = 4
	}
	key, err := config.connectorReceiptPrivateKey()
	if err != nil {
		return ConnectorReceiptFormatSummary{}, err
	}
	if key == nil {
		return ConnectorReceiptFormatSummary{FormatVersion: requiredFormat}, nil
	}
	if _, err := os.Lstat(config.ConnectorReceiptFile); errors.Is(err, os.ErrNotExist) {
		return ConnectorReceiptFormatSummary{FormatVersion: requiredFormat}, nil
	} else if err != nil {
		return ConnectorReceiptFormatSummary{}, fmt.Errorf("stat connector receipt ledger: %w", err)
	}
	public := key.Public().(ed25519.PublicKey)
	formatVersion := 1
	if requiredFormat > formatVersion {
		formatVersion = requiredFormat
	}
	if _, err := connectorledger.VerifyRecords(
		config.ConnectorReceiptFile, public, config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			switch record.Receipt.SchemaVersion {
			case connectorledger.SchemaV5:
				formatVersion = 5
			case connectorledger.SchemaV4:
				if formatVersion < 4 {
					formatVersion = 4
				}
			case connectorledger.SchemaV3:
				if formatVersion < 3 {
					formatVersion = 3
				}
			case connectorledger.SchemaV2:
				if formatVersion < 2 {
					formatVersion = 2
				}
			}
			return nil
		},
	); err != nil {
		return ConnectorReceiptFormatSummary{}, fmt.Errorf("inspect connector receipt ledger: %w", err)
	}
	return ConnectorReceiptFormatSummary{Present: true, FormatVersion: formatVersion}, nil
}

func newConnectorReceiptIndex() *connectorReceiptIndex {
	return &connectorReceiptIndex{
		spends: make(map[string]connectorSpendOwner), counts: make(map[string]map[string]int),
		denials: make(map[string]struct{}), pending: make(map[string]connectorledger.Event),
		tasks: make(map[string]serviceTaskReceipt), permits: make(map[string]string),
	}
}

func (index *connectorReceiptIndex) visit(record connectorledger.VerifiedReceipt) error {
	event := record.Receipt.Event
	if event.Kind == connectorledger.ConnectorCall && event.EffectMode == connectorledger.EffectModeAuthorized &&
		event.Phase == connectorledger.Deny {
		index.denials[connectorDenialKey(event.GrantID, event.ErrorCode)] = struct{}{}
		return nil
	}
	if event.Kind == connectorledger.ServiceTask {
		state := index.tasks[event.TaskDigest]
		switch event.Phase {
		case connectorledger.Authorize:
			if taskDigest, exists := index.permits[event.PermitDigest]; exists && taskDigest != event.TaskDigest {
				return errors.New("connector receipts bind one task permit to multiple task identities")
			}
			state.Authorization = event
			index.pending[event.TaskDigest] = event
			index.permits[event.PermitDigest] = event.TaskDigest
		case connectorledger.Dispatch:
			state.Dispatch = event
			index.pending[event.TaskDigest] = event
		case connectorledger.Terminal:
			state.Terminal = event
			delete(index.pending, event.TaskDigest)
		}
		index.tasks[event.TaskDigest] = state
		return nil
	}
	switch event.Phase {
	case connectorledger.Authorize:
		index.spends[event.TaskDigest] = connectorSpendOwner{GrantID: event.GrantID, ConnectorID: event.ConnectorID}
		if index.counts[event.GrantID] == nil {
			index.counts[event.GrantID] = make(map[string]int)
		}
		index.counts[event.GrantID][event.ConnectorID]++
		index.pending[event.TaskDigest] = event
	case connectorledger.Terminal:
		delete(index.pending, event.TaskDigest)
	}
	return nil
}

func openConnectorReceiptLedger(config Config, key ed25519.PrivateKey) (*connectorledger.Log, *connectorReceiptIndex, error) {
	index := newConnectorReceiptIndex()
	if key == nil {
		return nil, index, nil
	}
	limits, err := config.connectorReceiptLimits()
	if err != nil {
		return nil, nil, err
	}
	log, err := connectorledger.OpenWithLimits(
		config.ConnectorReceiptFile, key, config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch, limits, index.visit,
	)
	if err != nil {
		return nil, nil, err
	}
	// An authorization without a known run means Gateway stopped while an
	// effect may have been in flight. Close it conservatively; "outcome_unknown"
	// does not claim that the upstream service did or did not commit the request.
	// A durable lifecycle dispatch is different: it identifies one accepted run
	// and remains pending so Gateway can resume observation without redispatch.
	pending := log.Pending()
	sort.Slice(pending, func(i, j int) bool { return pending[i].TaskDigest < pending[j].TaskDigest })
	for _, latest := range pending {
		if latest.TaskProtocol == connectorledger.TaskProtocolLifecycleV1 && latest.Phase == connectorledger.Dispatch {
			continue
		}
		terminal := latest
		terminal.Phase = connectorledger.Terminal
		terminal.Outcome = connectorledger.Failed
		terminal.ErrorCode = "outcome_unknown"
		if _, err := log.Finish(terminal); err != nil {
			_ = log.Close()
			return nil, nil, fmt.Errorf("close incomplete connector receipt: %w", err)
		}
		delete(index.pending, latest.TaskDigest)
		if latest.Kind == connectorledger.ServiceTask {
			state := index.tasks[latest.TaskDigest]
			state.Terminal = terminal
			index.tasks[latest.TaskDigest] = state
		}
	}
	return log, index, nil
}

func (s *Server) mergeRetainedConnectorSpends() error {
	for grantID, byConnector := range s.connectorCalls {
		for connectorID, digests := range byConnector {
			for _, digest := range digests {
				owner := connectorSpendOwner{GrantID: grantID, ConnectorID: connectorID}
				if current, exists := s.connectorSpends[digest]; exists {
					if current != owner {
						return errors.New("gateway state and connector receipts disagree on spent-call ownership")
					}
					continue
				}
				s.connectorSpends[digest] = owner
				if s.connectorCallCounts[grantID] == nil {
					s.connectorCallCounts[grantID] = make(map[string]int)
				}
				s.connectorCallCounts[grantID][connectorID]++
			}
		}
	}
	return nil
}

func connectorReceiptEvent(
	grant Grant,
	routePolicyDigest, connectorID, operationID, callDigest, authorityKeyID, permitDigest, requestDigest string,
	requestBytes int64,
	operationPolicyDigests ...string,
) connectorledger.Event {
	event := connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		TenantID: grant.TenantID, RuntimeRef: grant.RuntimeRef, CapsuleDigest: grant.CapsuleDigest,
		PolicyDigest: grant.PolicyDigest, RoutePolicyDigest: routePolicyDigest, Generation: grant.Generation,
		GrantID: grant.GrantID, ConnectorID: connectorID, OperationID: operationID,
		TaskDigest: callDigest, AuthorityKeyID: authorityKeyID, PermitDigest: permitDigest,
		RequestDigest: requestDigest, RequestBytes: requestBytes,
	}
	if grant.EffectMode == EffectModeAuthorized {
		event.Kind = connectorledger.ConnectorCall
		event.EffectMode = connectorledger.EffectModeAuthorized
		if len(operationPolicyDigests) == 1 {
			event.OperationPolicyDigest = operationPolicyDigests[0]
		}
	}
	return event
}

func connectorDenialEvent(
	grant Grant,
	routePolicyDigest, connectorID, operationID, operationPolicyDigest, callDigest, requestDigest string,
	requestBytes int64,
) connectorledger.Event {
	return connectorledger.Event{
		Phase: connectorledger.Deny, Outcome: connectorledger.Denied, Kind: connectorledger.ConnectorCall,
		EffectMode: connectorledger.EffectModeAuthorized,
		TenantID:   grant.TenantID, RuntimeRef: grant.RuntimeRef, CapsuleDigest: grant.CapsuleDigest,
		PolicyDigest: grant.PolicyDigest, RoutePolicyDigest: routePolicyDigest, Generation: grant.Generation,
		GrantID: grant.GrantID, ConnectorID: connectorID, OperationID: operationID,
		OperationPolicyDigest: operationPolicyDigest, TaskDigest: callDigest,
		RequestDigest: requestDigest, RequestBytes: requestBytes, ErrorCode: "action_permit_denied",
	}
}

func connectorDenialKey(grantID, errorCode string) string {
	return grantID + "\x00" + errorCode
}

type connectorDenialAppender interface {
	Append(connectorledger.Event) (connectorledger.Head, error)
}

// recordActionPermitDenial writes at most one signed record for each stable
// denial code in a retained grant. The cap prevents an untrusted workload from
// converting invalid permits into unbounded evidence writes.
func (s *Server) recordActionPermitDenial(event connectorledger.Event) error {
	key := connectorDenialKey(event.GrantID, event.ErrorCode)
	for {
		s.mu.Lock()
		if s.connectorDenials == nil {
			s.connectorDenials = make(map[string]struct{})
		}
		if _, recorded := s.connectorDenials[key]; recorded {
			s.mu.Unlock()
			return nil
		}
		if s.connectorDenialPending == nil {
			s.connectorDenialPending = make(map[string]chan struct{})
		}
		if pending := s.connectorDenialPending[key]; pending != nil {
			s.mu.Unlock()
			<-pending
			continue
		}
		appender, ok := s.connectorLedger.(connectorDenialAppender)
		if !ok {
			s.mu.Unlock()
			return errors.New("connector denial receipt ledger is unavailable")
		}
		pending := make(chan struct{})
		s.connectorDenialPending[key] = pending
		s.mu.Unlock()

		_, err := appender.Append(event)
		s.mu.Lock()
		if err == nil {
			s.connectorDenials[key] = struct{}{}
		}
		delete(s.connectorDenialPending, key)
		close(pending)
		s.mu.Unlock()
		if err != nil {
			return err
		}
		return nil
	}
}

func (s *Server) finishConnectorReceipt(event connectorledger.Event, status int, responseBytes int64, errorCode string) error {
	event.Phase = connectorledger.Terminal
	event.HTTPStatus = status
	event.ResponseBytes = responseBytes
	event.ErrorCode = errorCode
	if errorCode == "" {
		event.Outcome = connectorledger.Responded
	} else {
		event.Outcome = connectorledger.Failed
	}
	if s.connectorLedger == nil {
		return errors.New("connector receipt ledger is unavailable")
	}
	_, err := s.connectorLedger.Finish(event)
	return err
}

func connectorReceiptKeyID(config Config) string {
	if len(config.connectorReceiptKey) != ed25519.PrivateKeySize {
		return ""
	}
	return connectorledger.KeyID(config.connectorReceiptKey.Public().(ed25519.PublicKey))
}
