package connectorledger

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/dsse"
)

func TestConnectorLedgerReadsMixedV1ThroughV5ReceiptFormats(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mixed-v1-v5.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}

	legacyDenial := validEvent(Deny, Denied)
	legacyDenial.ErrorCode = "policy_denied"
	if _, err := log.Append(legacyDenial); err != nil {
		t.Fatal(err)
	}

	permitCall := validEvent(Authorize, Allowed)
	permitCall.TaskDigest = "sha256:" + strings.Repeat("1", 64)
	permitCall.AuthorityKeyID = "approver-a"
	permitCall.PermitDigest = "sha256:" + strings.Repeat("8", 64)
	permitCall.RequestDigest = "sha256:" + strings.Repeat("7", 64)
	if _, err := log.Begin(permitCall); err != nil {
		t.Fatal(err)
	}
	permitTerminal := permitCall
	permitTerminal.Phase, permitTerminal.Outcome, permitTerminal.HTTPStatus = Terminal, Responded, 200
	if _, err := log.Finish(permitTerminal); err != nil {
		t.Fatal(err)
	}

	legacyKindCall := permitCall
	legacyKindCall.Kind = ConnectorCall
	legacyKindCall.TaskDigest = "sha256:" + strings.Repeat("2", 64)
	if _, err := log.Begin(legacyKindCall); err != nil {
		t.Fatal(err)
	}
	legacyKindTerminal := legacyKindCall
	legacyKindTerminal.Phase, legacyKindTerminal.Outcome, legacyKindTerminal.HTTPStatus = Terminal, Responded, 200
	if _, err := log.Finish(legacyKindTerminal); err != nil {
		t.Fatal(err)
	}

	lifecycle := validLifecycleEvent(Authorize, Allowed)
	lifecycle.TaskDigest = "sha256:" + strings.Repeat("4", 64)
	if _, err := log.Begin(lifecycle); err != nil {
		t.Fatal(err)
	}
	dispatched := validLifecycleDispatch(lifecycle, "run-mixed-v4")
	if _, err := log.Dispatch(dispatched); err != nil {
		t.Fatal(err)
	}
	lifecycleTerminal := validLifecycleTerminal(dispatched, TaskStatusAgentReportedCompleted)
	if _, err := log.Finish(lifecycleTerminal); err != nil {
		t.Fatal(err)
	}

	authorized := validAuthorizedEffectEvent(Authorize, Allowed)
	if _, err := log.Begin(authorized); err != nil {
		t.Fatal(err)
	}
	authorizedTerminal := authorized
	authorizedTerminal.Phase, authorizedTerminal.Outcome, authorizedTerminal.HTTPStatus = Terminal, Responded, 204
	if _, err := log.Finish(authorizedTerminal); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	wantSchemas := []string{
		SchemaV1,
		SchemaV2, SchemaV2,
		SchemaV3, SchemaV3,
		SchemaV4, SchemaV4, SchemaV4,
		SchemaV5, SchemaV5,
	}
	var gotSchemas []string
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		gotSchemas = append(gotSchemas, record.Receipt.SchemaVersion)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(gotSchemas) != len(wantSchemas) {
		t.Fatalf("mixed schemas=%v want=%v", gotSchemas, wantSchemas)
	}
	for index := range wantSchemas {
		if gotSchemas[index] != wantSchemas[index] {
			t.Fatalf("mixed schemas=%v want=%v", gotSchemas, wantSchemas)
		}
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	wantPayloadTypes := []string{
		PayloadTypeV1,
		PayloadTypeV2, PayloadTypeV2,
		PayloadTypeV3, PayloadTypeV3,
		PayloadTypeV4, PayloadTypeV4, PayloadTypeV4,
		PayloadTypeV5, PayloadTypeV5,
	}
	for index, line := range lines {
		envelope, err := dsse.Parse([]byte(line))
		if err != nil {
			t.Fatal(err)
		}
		if envelope.PayloadType != wantPayloadTypes[index] {
			t.Fatalf("line %d payload type=%q want=%q", index+1, envelope.PayloadType, wantPayloadTypes[index])
		}
	}

	reopened, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if pending := reopened.Pending(); len(pending) != 0 {
		t.Fatalf("completed mixed chain reconstructed pending calls: %#v", pending)
	}
	if _, err := reopened.Begin(authorized); err == nil || !strings.Contains(err.Error(), "already spent") {
		t.Fatalf("authorized effect replay after restart err=%v", err)
	}
}

func TestAuthorizedEffectV5DenialBindsRequestWithoutPermitClaim(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "authorized-denial.ndjson")
	log, err := Open(path, private, "node-a/gateway", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()

	denial := validAuthorizedEffectEvent(Deny, Denied)
	denial.RequestBytes = 0
	denial.ErrorCode = "action_permit_denied"
	for name, mutate := range map[string]func(*Event){
		"missing request digest": func(event *Event) { event.RequestDigest = "" },
		"invalid request digest": func(event *Event) { event.RequestDigest = "sha256:invalid" },
		"authority claim":        func(event *Event) { event.AuthorityKeyID = "unverified-approver" },
		"permit claim":           func(event *Event) { event.PermitDigest = "sha256:" + strings.Repeat("9", 64) },
		"authority and permit claim": func(event *Event) {
			event.AuthorityKeyID = "unverified-approver"
			event.PermitDigest = "sha256:" + strings.Repeat("9", 64)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := denial
			mutate(&candidate)
			if _, err := log.Append(candidate); err == nil || !strings.Contains(err.Error(), "without claiming a permit authority") {
				t.Fatalf("invalid authorized denial err=%v", err)
			}
		})
	}
	if head := log.Head(); head.Sequence != 0 {
		t.Fatalf("rejected denials advanced ledger: %#v", head)
	}
	if _, err := log.Append(denial); err != nil {
		t.Fatalf("valid authorized denial rejected: %v", err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}

	var records []VerifiedReceipt
	if _, err := VerifyRecords(path, public, "node-a/gateway", 1, func(record VerifiedReceipt) error {
		records = append(records, record)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Receipt.SchemaVersion != SchemaV5 ||
		records[0].Receipt.Event.AuthorityKeyID != "" || records[0].Receipt.Event.PermitDigest != "" ||
		records[0].Receipt.Event.RequestDigest != denial.RequestDigest || records[0].Receipt.Event.OperationPolicyDigest != denial.OperationPolicyDigest {
		t.Fatalf("authorized denial record=%#v", records)
	}
}

func TestAuthorizedEffectFinishRejectsModeAndOperationMismatches(t *testing.T) {
	for name, mutate := range map[string]func(*Event){
		"operation policy digest": func(event *Event) {
			event.OperationPolicyDigest = "sha256:" + strings.Repeat("a", 64)
		},
		"effect mode downgrade": func(event *Event) {
			event.EffectMode = ""
			event.OperationPolicyDigest = ""
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			log, err := Open(filepath.Join(t.TempDir(), "mismatch.ndjson"), private, "node-a/gateway", 1)
			if err != nil {
				t.Fatal(err)
			}
			defer log.Close()

			authorized := validAuthorizedEffectEvent(Authorize, Allowed)
			if _, err := log.Begin(authorized); err != nil {
				t.Fatal(err)
			}
			terminal := authorized
			terminal.Phase, terminal.Outcome, terminal.HTTPStatus = Terminal, Responded, 200
			mismatched := terminal
			mutate(&mismatched)
			if err := validateEvent(mismatched); err != nil {
				t.Fatalf("test mismatch is not independently valid: %v", err)
			}
			if _, err := log.Finish(mismatched); err == nil || !strings.Contains(err.Error(), "no matching authorization") {
				t.Fatalf("mismatched terminal err=%v", err)
			}
			if head, pending := log.Head(), log.Pending(); head.Sequence != 1 || len(pending) != 1 {
				t.Fatalf("mismatch changed state: head=%#v pending=%#v", head, pending)
			}
			if _, err := log.Finish(terminal); err != nil {
				t.Fatalf("matching terminal rejected after mismatch: %v", err)
			}
		})
	}
}

func TestVerifyRecordsRejectsSignedAuthorizedEffectFieldAndVersionTampering(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		payloadType string
		mutate      func(*Receipt)
	}{
		"missing effect mode": {
			payloadType: PayloadTypeV5,
			mutate:      func(receipt *Receipt) { receipt.Event.EffectMode = "" },
		},
		"unsupported effect mode": {
			payloadType: PayloadTypeV5,
			mutate:      func(receipt *Receipt) { receipt.Event.EffectMode = "standard" },
		},
		"missing operation policy digest": {
			payloadType: PayloadTypeV5,
			mutate:      func(receipt *Receipt) { receipt.Event.OperationPolicyDigest = "" },
		},
		"legacy envelope downgrade": {
			payloadType: PayloadTypeV3,
			mutate:      func(receipt *Receipt) { receipt.SchemaVersion = SchemaV3 },
		},
		"unverified authority claim": {
			payloadType: PayloadTypeV5,
			mutate: func(receipt *Receipt) {
				receipt.Event.AuthorityKeyID = "unverified-approver"
				receipt.Event.PermitDigest = "sha256:" + strings.Repeat("9", 64)
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "tampered.ndjson")
			event := validAuthorizedEffectEvent(Deny, Denied)
			event.ErrorCode = "action_permit_denied"
			receipt := Receipt{
				SchemaVersion: SchemaV5,
				NodeID:        "node-a/gateway",
				Epoch:         1,
				Sequence:      1,
				PreviousHash:  zeroHash(),
				ObservedAt:    "2026-07-16T12:00:00Z",
				Event:         event,
			}
			test.mutate(&receipt)
			payload, err := json.Marshal(receipt)
			if err != nil {
				t.Fatal(err)
			}
			envelope, err := dsse.Sign(test.payloadType, payload, KeyID(public), private)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := dsse.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, append(raw, '\n'), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := VerifyRecords(path, public, "node-a/gateway", 1, nil); err == nil {
				t.Fatal("signed malformed authorized-effect record verified")
			}
		})
	}
}

func validAuthorizedEffectEvent(phase Phase, outcome Outcome) Event {
	event := validEvent(phase, outcome)
	event.Kind = ConnectorCall
	event.EffectMode = EffectModeAuthorized
	event.OperationPolicyDigest = "sha256:" + strings.Repeat("6", 64)
	event.TaskDigest = "sha256:" + strings.Repeat("5", 64)
	event.AuthorityKeyID = "action-approver-a"
	event.PermitDigest = "sha256:" + strings.Repeat("8", 64)
	event.RequestDigest = "sha256:" + strings.Repeat("7", 64)
	if phase == Deny {
		event.AuthorityKeyID = ""
		event.PermitDigest = ""
	}
	return event
}
