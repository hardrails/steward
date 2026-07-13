package gateway

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/hardrails/steward/internal/connectorledger"
)

type connectorSpendOwner struct {
	GrantID     string
	ConnectorID string
}

type connectorReceiptIndex struct {
	spends  map[string]connectorSpendOwner
	counts  map[string]map[string]int
	pending map[string]connectorledger.Event
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
	key, err := config.connectorReceiptPrivateKey()
	if err != nil {
		return ConnectorReceiptFormatSummary{}, err
	}
	if key == nil {
		return ConnectorReceiptFormatSummary{}, nil
	}
	if _, err := os.Lstat(config.ConnectorReceiptFile); errors.Is(err, os.ErrNotExist) {
		return ConnectorReceiptFormatSummary{}, nil
	} else if err != nil {
		return ConnectorReceiptFormatSummary{}, fmt.Errorf("stat connector receipt ledger: %w", err)
	}
	public := key.Public().(ed25519.PublicKey)
	if _, err := connectorledger.VerifyRecords(
		config.ConnectorReceiptFile, public, config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch, nil,
	); err != nil {
		return ConnectorReceiptFormatSummary{}, fmt.Errorf("inspect connector receipt ledger: %w", err)
	}
	return ConnectorReceiptFormatSummary{Present: true, FormatVersion: 1}, nil
}

func newConnectorReceiptIndex() *connectorReceiptIndex {
	return &connectorReceiptIndex{
		spends: make(map[string]connectorSpendOwner), counts: make(map[string]map[string]int),
		pending: make(map[string]connectorledger.Event),
	}
}

func (index *connectorReceiptIndex) visit(record connectorledger.VerifiedReceipt) error {
	event := record.Receipt.Event
	switch event.Phase {
	case connectorledger.Authorize:
		if _, duplicate := index.spends[event.TaskDigest]; duplicate {
			return errors.New("connector receipt ledger contains a duplicate spent call")
		}
		index.spends[event.TaskDigest] = connectorSpendOwner{GrantID: event.GrantID, ConnectorID: event.ConnectorID}
		if index.counts[event.GrantID] == nil {
			index.counts[event.GrantID] = make(map[string]int)
		}
		index.counts[event.GrantID][event.ConnectorID]++
		index.pending[event.TaskDigest] = event
	case connectorledger.Terminal:
		authorized, ok := index.pending[event.TaskDigest]
		if !ok || !sameConnectorReceiptCall(authorized, event) {
			return errors.New("connector receipt ledger has an unmatched terminal record")
		}
		delete(index.pending, event.TaskDigest)
	}
	return nil
}

func sameConnectorReceiptCall(left, right connectorledger.Event) bool {
	return left.TenantID == right.TenantID && left.RuntimeRef == right.RuntimeRef &&
		left.CapsuleDigest == right.CapsuleDigest && left.PolicyDigest == right.PolicyDigest &&
		left.RoutePolicyDigest == right.RoutePolicyDigest && left.Generation == right.Generation &&
		left.GrantID == right.GrantID && left.ConnectorID == right.ConnectorID &&
		left.OperationID == right.OperationID && left.TaskDigest == right.TaskDigest &&
		left.RequestBytes == right.RequestBytes
}

func openConnectorReceiptLedger(config Config, key ed25519.PrivateKey) (*connectorledger.Log, *connectorReceiptIndex, error) {
	index := newConnectorReceiptIndex()
	if key == nil {
		return nil, index, nil
	}
	log, err := connectorledger.OpenWithVisit(
		config.ConnectorReceiptFile, key, config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch, index.visit,
	)
	if err != nil {
		return nil, nil, err
	}
	// An authorization without a terminal record means Gateway stopped while
	// an effect was in flight. Close it conservatively; "outcome_unknown" does
	// not claim that the upstream service did or did not commit the request.
	pending := log.Pending()
	sort.Slice(pending, func(i, j int) bool { return pending[i].TaskDigest < pending[j].TaskDigest })
	for _, authorized := range pending {
		terminal := authorized
		terminal.Phase = connectorledger.Terminal
		terminal.Outcome = connectorledger.Failed
		terminal.ErrorCode = "outcome_unknown"
		if _, err := log.Finish(terminal); err != nil {
			_ = log.Close()
			return nil, nil, fmt.Errorf("close incomplete connector receipt: %w", err)
		}
		delete(index.pending, authorized.TaskDigest)
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

func connectorReceiptEvent(grant Grant, routePolicyDigest, connectorID, operationID, callDigest string, requestBytes int64) connectorledger.Event {
	return connectorledger.Event{
		Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		TenantID: grant.TenantID, RuntimeRef: grant.RuntimeRef, CapsuleDigest: grant.CapsuleDigest,
		PolicyDigest: grant.PolicyDigest, RoutePolicyDigest: routePolicyDigest, Generation: grant.Generation,
		GrantID: grant.GrantID, ConnectorID: connectorID, OperationID: operationID,
		TaskDigest: callDigest, RequestBytes: requestBytes,
	}
}

func (s *Server) finishConnectorReceipt(event connectorledger.Event, status int, responseBytes int64, errorCode string) error {
	event.Phase = connectorledger.Terminal
	event.HTTPStatus = status
	event.ResponseBytes = responseBytes
	event.ErrorCode = errorCode
	if errorCode == "" {
		event.Outcome = connectorledger.Committed
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
