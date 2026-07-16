package connectorledger

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/hardrails/steward/internal/dsse"
)

const MaxPortableTaskEvidenceBytes = 3 * (MaxLineBytes + 1)

// ErrPortableTaskEvidenceIncomplete means the signed task-local chain has not
// yet reached a terminal receipt. Callers may retry collection without
// treating the partial lifecycle as an immutable contradiction.
var ErrPortableTaskEvidenceIncomplete = errors.New("portable task evidence is incomplete")

// PortableTaskEvidence is the complete signed task-local lifecycle extracted
// from a larger Gateway ledger. Each receipt retains its original global
// coordinate, while PreviousTaskHash proves the closed authorize, dispatch,
// terminal sequence without disclosing unrelated tenants' receipts.
type PortableTaskEvidence struct {
	Records  []VerifiedReceipt
	Terminal Head
}

// VerifyPortableTaskEvidence authenticates two or three exact v4 receipt lines:
// authorize, optional dispatch, and terminal. It verifies the task-local chain,
// every event transition, and the expected task and permit identities. It does
// not claim that the terminal receipt is the current head of the complete
// Gateway ledger.
func VerifyPortableTaskEvidence(
	raw []byte,
	public ed25519.PublicKey,
	nodeID string,
	epoch uint64,
	taskDigest string,
	permitDigest string,
) (PortableTaskEvidence, error) {
	if len(raw) == 0 || len(raw) > MaxPortableTaskEvidenceBytes ||
		raw[len(raw)-1] != '\n' || len(public) != ed25519.PublicKeySize ||
		!validText(nodeID, 256) || epoch == 0 ||
		!digest(taskDigest) || !digest(permitDigest) {
		return PortableTaskEvidence{}, errors.New("portable task evidence arguments are invalid")
	}

	keyID := KeyID(public)
	trusted := map[string]ed25519.PublicKey{keyID: public}
	scanner := bufio.NewScanner(bytes.NewReader(raw))
	scanner.Buffer(make([]byte, 4096), MaxLineBytes+1)
	records := make([]VerifiedReceipt, 0, 3)
	previousTaskHash := zeroHash()
	var previousEvent Event
	var previousGlobalSequence uint64
	for scanner.Scan() {
		line := append([]byte(nil), scanner.Bytes()...)
		if len(line) == 0 || len(line) > MaxLineBytes || len(records) == 3 {
			return PortableTaskEvidence{}, errors.New("portable task evidence must contain two or three bounded receipt lines")
		}
		envelope, err := dsse.Parse(line)
		if err != nil || envelope.PayloadType != PayloadTypeV4 {
			return PortableTaskEvidence{}, fmt.Errorf("portable task receipt %d is not one v4 envelope", len(records)+1)
		}
		payload, verifiedKeyID, err := dsse.Verify(line, PayloadTypeV4, trusted)
		if err != nil || verifiedKeyID != keyID {
			return PortableTaskEvidence{}, fmt.Errorf("verify portable task receipt %d: %w", len(records)+1, err)
		}
		var receipt Receipt
		if err := dsse.DecodeStrictInto(payload, MaxLineBytes, &receipt); err != nil {
			return PortableTaskEvidence{}, fmt.Errorf("decode portable task receipt %d: %w", len(records)+1, err)
		}
		if err := validatePortableTaskReceipt(
			receipt, nodeID, epoch, uint64(len(records)+1), previousTaskHash,
			previousGlobalSequence, taskDigest, permitDigest,
		); err != nil {
			return PortableTaskEvidence{}, fmt.Errorf("validate portable task receipt %d: %w", len(records)+1, err)
		}
		if len(records) > 0 {
			if err := validateTransition(previousEvent, receipt.Event); err != nil {
				return PortableTaskEvidence{}, fmt.Errorf("portable task receipt %d: %w", len(records)+1, err)
			}
		}
		hash := hashLine(line)
		records = append(records, VerifiedReceipt{Receipt: receipt, Raw: line, Hash: hash})
		previousTaskHash = hash
		previousEvent = receipt.Event
		previousGlobalSequence = receipt.Sequence
	}
	if err := scanner.Err(); err != nil {
		return PortableTaskEvidence{}, fmt.Errorf("read portable task evidence: %w", err)
	}
	if len(records) < 2 ||
		records[len(records)-1].Receipt.Event.Phase != Terminal {
		return PortableTaskEvidence{}, fmt.Errorf(
			"%w: signed lifecycle has no terminal receipt",
			ErrPortableTaskEvidenceIncomplete,
		)
	}
	if records[0].Receipt.Event.Phase != Authorize ||
		len(records) == 3 && records[1].Receipt.Event.Phase != Dispatch {
		return PortableTaskEvidence{}, errors.New("portable task evidence is not a closed lifecycle")
	}
	terminal := records[len(records)-1]
	return PortableTaskEvidence{
		Records: records,
		Terminal: Head{
			NodeID: nodeID, Epoch: epoch, Sequence: terminal.Receipt.Sequence,
			ChainHash: terminal.Hash, KeyID: keyID,
		},
	}, nil
}

func validatePortableTaskReceipt(
	receipt Receipt,
	nodeID string,
	epoch uint64,
	taskSequence uint64,
	previousTaskHash string,
	previousGlobalSequence uint64,
	taskDigest string,
	permitDigest string,
) error {
	if receipt.SchemaVersion != SchemaV4 || receipt.NodeID != nodeID ||
		receipt.Epoch != epoch || receipt.Sequence == 0 ||
		previousGlobalSequence > 0 && receipt.Sequence <= previousGlobalSequence ||
		!digest(receipt.PreviousHash) ||
		receipt.TaskSequence != taskSequence ||
		receipt.PreviousTaskHash != previousTaskHash {
		return errors.New("receipt coordinates do not match the portable task chain")
	}
	observed, err := time.Parse(time.RFC3339Nano, receipt.ObservedAt)
	if err != nil || observed.IsZero() ||
		receipt.ObservedAt != observed.UTC().Format(time.RFC3339Nano) {
		return errors.New("receipt has an invalid observation time")
	}
	if receipt.Event.Kind != ServiceTask ||
		receipt.Event.TaskProtocol != TaskProtocolLifecycleV1 ||
		receipt.Event.TaskDigest != taskDigest ||
		receipt.Event.PermitDigest != permitDigest {
		return errors.New("receipt does not match the expected lifecycle task")
	}
	if err := validateEvent(receipt.Event); err != nil {
		return err
	}
	switch taskSequence {
	case 1:
		if receipt.Event.Phase != Authorize {
			return errors.New("first portable task receipt is not authorization")
		}
	case 2:
		if receipt.Event.Phase != Dispatch && receipt.Event.Phase != Terminal {
			return errors.New("second portable task receipt is neither dispatch nor terminal")
		}
	case 3:
		if receipt.Event.Phase != Terminal {
			return errors.New("third portable task receipt is not terminal")
		}
	default:
		return errors.New("portable task evidence contains too many receipts")
	}
	return nil
}

// MarshalPortableTaskEvidence emits the original signed lines for the records
// selected from a fully verified Gateway ledger.
func MarshalPortableTaskEvidence(records []VerifiedReceipt) ([]byte, error) {
	if len(records) < 2 {
		return nil, fmt.Errorf(
			"%w: fewer than two signed receipts",
			ErrPortableTaskEvidenceIncomplete,
		)
	}
	if len(records) > 3 {
		return nil, errors.New("portable task evidence requires two or three receipts")
	}
	var output []byte
	for index, record := range records {
		if len(record.Raw) == 0 || len(record.Raw) > MaxLineBytes ||
			bytes.ContainsAny(record.Raw, "\r\n") {
			return nil, fmt.Errorf("portable task receipt %d is not one exact DSSE line", index+1)
		}
		if len(output) > MaxPortableTaskEvidenceBytes-len(record.Raw)-1 {
			return nil, errors.New("portable task evidence exceeds its byte limit")
		}
		output = append(output, record.Raw...)
		output = append(output, '\n')
	}
	return output, nil
}
