package gateway

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"github.com/hardrails/steward/internal/connectorledger"
)

var errInferenceAccountingUnavailable = errors.New("inference attempt accounting is unavailable")
var errInferenceAttemptUnknown = errors.New("inference attempt outcome is unknown")

type inferenceAttemptUnknownError struct {
	status  int
	attempt string
}

func (failure *inferenceAttemptUnknownError) Error() string {
	return errInferenceAttemptUnknown.Error()
}
func (failure *inferenceAttemptUnknownError) Unwrap() error { return errInferenceAttemptUnknown }

// A missing terminal receipt must not erase an observed provider response.
// Only the bounded status and locally minted attempt identity cross this error.
type inferenceTerminalAccountingError struct {
	status  int
	attempt string
}

func (failure *inferenceTerminalAccountingError) Error() string {
	return "inference terminal accounting failed"
}

// inferenceAttemptTransport journals before the provider transport can write.
// Authorization is a conservative upper bound on potentially paid attempts:
// a crash after fsync but before the network write must not be called zero usage.
// Terminal means response headers or transport failure, never generation success
// or a billing claim. Body streaming remains owned by the existing bounded proxy.
type inferenceAttemptTransport struct {
	base        http.RoundTripper
	ledger      connectorReceiptLog
	grant       Grant
	routePolicy string
	operation   string
}

func (transport inferenceAttemptTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if transport.ledger == nil || transport.ledger.Failed() {
		return nil, errInferenceAccountingUnavailable
	}
	// The production proxy supplies a nonempty, bounded, non-rewindable POST.
	// Refuse a future caller that would permit hidden net/http body replay.
	if request.Method != http.MethodPost || request.Body == nil || request.GetBody != nil ||
		request.ContentLength < 1 || request.ContentLength > maxProxyBody {
		return nil, errInferenceAccountingUnavailable
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errInferenceAccountingUnavailable
	}
	grant := transport.grant
	event := connectorledger.Event{
		Kind: connectorledger.InferenceAttempt, Phase: connectorledger.Authorize, Outcome: connectorledger.Allowed,
		TenantID: grant.TenantID, RuntimeRef: grant.RuntimeRef, CapsuleDigest: grant.CapsuleDigest,
		PolicyDigest: grant.PolicyDigest, RoutePolicyDigest: transport.routePolicy, Generation: grant.Generation,
		GrantID: grant.GrantID, OperationID: transport.operation,
		TaskDigest: "sha256:" + hex.EncodeToString(nonce[:]), RequestBytes: request.ContentLength,
	}
	if _, err := transport.ledger.Begin(event); err != nil {
		return nil, errInferenceAccountingUnavailable
	}
	base := transport.base
	if base == nil {
		base = http.DefaultTransport
	}
	response, err := base.RoundTrip(request)
	observedStatus := 0
	if response != nil {
		observedStatus = response.StatusCode
	}
	invalidStatus := err == nil && (observedStatus < 100 || observedStatus > 599)
	event.Phase = connectorledger.Terminal
	if err != nil {
		event.Outcome, event.ErrorCode = connectorledger.Failed, "outcome_unknown"
	} else if invalidStatus {
		// net/http accepts three-digit extension codes through 999. Preserve
		// the observed boundary in a bounded error code instead of passing a
		// nonrecordable HTTPStatus to the ledger and leaving a healthy writer
		// with an orphaned authorization.
		event.Outcome = connectorledger.Failed
		event.ErrorCode = fmt.Sprintf("upstream_http_status_%d", observedStatus)
	} else {
		event.Outcome, event.HTTPStatus = connectorledger.Responded, response.StatusCode
	}
	if _, receiptErr := transport.ledger.Finish(event); receiptErr != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, &inferenceTerminalAccountingError{status: observedStatus, attempt: event.TaskDigest}
	}
	if invalidStatus {
		if response.Body != nil {
			_ = response.Body.Close()
		}
		return nil, &inferenceAttemptUnknownError{status: observedStatus, attempt: event.TaskDigest}
	}
	if err != nil {
		return nil, &inferenceAttemptUnknownError{status: observedStatus, attempt: event.TaskDigest}
	}
	return response, err
}
