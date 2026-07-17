package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/actionpermit"
	"github.com/hardrails/steward/internal/connectorledger"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
)

type effectBundleAuditStep struct {
	Step          actionpermit.BundleStep `json:"step"`
	Status        string                  `json:"status"`
	Authorization *permitAuditRecord      `json:"authorization,omitempty"`
	Terminal      *permitAuditRecord      `json:"terminal,omitempty"`
}

func auditExactEffectBundle(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("permit bundle audit", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "signed exact effect bundle DSSE envelope")
	publicKeyPath := flags.String("public-key", "", "base64 Ed25519 action-authority public key")
	keyID := flags.String("key-id", "", "trusted action-authority key ID")
	var authorityFlags repeatedFlag
	flags.Var(&authorityFlags, "authority", "trusted KEY_ID=PUBLIC_KEY_FILE; repeat for multi-party bundles")
	planPath := flags.String("plan", "", "optional exact effect plan and request files to compare")
	trustPath := flags.String("trust", "", "Gateway action-trust inventory required with -plan")
	receiptsPath := flags.String("receipts", "", "signed connector receipt ledger")
	receiptPublicKeyPath := flags.String("receipt-public-key", "", "base64 Ed25519 connector receipt public key")
	receiptNodeID := flags.String("receipt-node-id", "", "expected connector receipt node ID")
	receiptEpoch := flags.Uint64("receipt-epoch", 1, "expected connector receipt key epoch")
	maxValidity := flags.Duration("max-validity", actionpermit.MaxValidity, "local maximum bundle validity")
	expectedSequence := flags.String("expected-sequence", "", "externally retained final receipt sequence")
	expectedChainHash := flags.String("expected-chain-hash", "", "externally retained sha256 receipt chain hash")
	requireAllTerminal := flags.Bool("require-all-terminal", false, "fail after valid output unless every step has terminal evidence")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if *input == "" || *receiptsPath == "" || *receiptPublicKeyPath == "" || *receiptNodeID == "" || flags.NArg() != 0 {
		return errors.New("permit bundle audit requires -in, approval authorities, -receipts, -receipt-public-key, and -receipt-node-id")
	}
	if (*planPath == "") != (*trustPath == "") {
		return errors.New("permit bundle audit requires -plan and -trust together")
	}
	raw, err := readBounded(*input)
	if err != nil {
		return err
	}
	trusted, err := readPermitAuthorities(*publicKeyPath, *keyID, authorityFlags)
	if err != nil {
		return err
	}
	verified, err := verifyEffectBundleForAudit(raw, trusted, *maxValidity)
	if err != nil {
		return err
	}
	bundle := *verified.Bundle
	if *planPath != "" {
		plan, err := loadEffectBundlePlan(*planPath)
		if err != nil {
			return err
		}
		if err := compareEffectBundlePlan(plan, bundle, *trustPath, trusted, verified.KeyIDs); err != nil {
			return err
		}
	}
	receiptPublic, err := readPublicKey(*receiptPublicKeyPath)
	if err != nil {
		return err
	}

	steps := make([]effectBundleAuditStep, len(bundle.Steps))
	byTaskDigest := make(map[string]int, len(bundle.Steps))
	for index, step := range bundle.Steps {
		steps[index] = effectBundleAuditStep{Step: step, Status: "unspent"}
		digest := gateway.ConnectorCallDigest(bundle.TenantID, bundle.InstanceID, step.TaskID, step.ConnectorID, step.OperationID)
		byTaskDigest[digest] = index
	}
	head, err := connectorledger.VerifyRecords(*receiptsPath, receiptPublic, *receiptNodeID, *receiptEpoch,
		func(record connectorledger.VerifiedReceipt) error {
			event := record.Receipt.Event
			if event.PermitDigest != verified.EnvelopeDigest {
				return nil
			}
			index, matched := byTaskDigest[event.TaskDigest]
			if !matched {
				return fmt.Errorf("connector receipt sequence %d binds the bundle to an unlisted task", record.Receipt.Sequence)
			}
			if err := checkEffectBundleReceiptBindings(bundle, verified.KeyIDs, steps[index].Step, event); err != nil {
				return fmt.Errorf("connector receipt sequence %d: %w", record.Receipt.Sequence, err)
			}
			matchedRecord := &permitAuditRecord{
				Sequence: record.Receipt.Sequence, ChainHash: record.Hash,
				ObservedAt: record.Receipt.ObservedAt, Event: event,
			}
			switch event.Phase {
			case connectorledger.Authorize:
				if steps[index].Authorization != nil {
					return fmt.Errorf("bundle step %q has multiple authorization receipts", steps[index].Step.StepID)
				}
				observedAt, err := time.Parse(time.RFC3339Nano, matchedRecord.ObservedAt)
				if err != nil {
					return fmt.Errorf("bundle step %q authorization has an invalid observation time", steps[index].Step.StepID)
				}
				if _, err := actionpermit.Verify(raw, trusted, observedAt, *maxValidity); err != nil {
					return fmt.Errorf("bundle step %q was not authorized inside the signed window: %w", steps[index].Step.StepID, err)
				}
				steps[index].Authorization = matchedRecord
				steps[index].Status = "authorized"
			case connectorledger.Terminal:
				if steps[index].Terminal != nil {
					return fmt.Errorf("bundle step %q has multiple terminal receipts", steps[index].Step.StepID)
				}
				steps[index].Terminal = matchedRecord
				steps[index].Status = "terminal"
			default:
				return fmt.Errorf("bundle step %q has an unsupported receipt phase", steps[index].Step.StepID)
			}
			return nil
		})
	if err != nil {
		return err
	}
	for index := range steps {
		if steps[index].Terminal != nil && steps[index].Authorization == nil {
			return fmt.Errorf("bundle step %q has a terminal receipt without authorization", steps[index].Step.StepID)
		}
	}
	if err := checkExpectedConnectorHead(head, *expectedSequence, *expectedChainHash); err != nil {
		return err
	}
	unspent, authorized, terminal := 0, 0, 0
	for _, step := range steps {
		switch step.Status {
		case "unspent":
			unspent++
		case "authorized":
			authorized++
		case "terminal":
			terminal++
		}
	}
	executionStatus := "incomplete"
	if unspent == len(steps) {
		executionStatus = "unspent"
	} else if terminal == len(steps) {
		executionStatus = "terminal"
	}
	allTerminal := terminal == len(steps)
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(struct {
		Valid           bool                         `json:"valid"`
		ExecutionStatus string                       `json:"execution_status"`
		AllTerminal     bool                         `json:"all_terminal"`
		UnspentSteps    int                          `json:"unspent_steps"`
		AuthorizedSteps int                          `json:"authorized_steps"`
		TerminalSteps   int                          `json:"terminal_steps"`
		PermitDigest    string                       `json:"permit_digest"`
		AuthorityKeyIDs []string                     `json:"authority_key_ids"`
		Bundle          actionpermit.BundleStatement `json:"bundle"`
		Steps           []effectBundleAuditStep      `json:"steps"`
		Head            connectorledger.Head         `json:"head"`
	}{Valid: true, ExecutionStatus: executionStatus, AllTerminal: allTerminal,
		UnspentSteps: unspent, AuthorizedSteps: authorized, TerminalSteps: terminal,
		PermitDigest: verified.EnvelopeDigest, AuthorityKeyIDs: verified.KeyIDs,
		Bundle: bundle, Steps: steps, Head: head}); err != nil {
		return err
	}
	if *requireAllTerminal && !allTerminal {
		return errors.New("exact effect bundle does not have terminal evidence for every step")
	}
	return nil
}

func verifyEffectBundleForAudit(
	raw []byte,
	trusted map[string]ed25519.PublicKey,
	maxValidity time.Duration,
) (actionpermit.Verified, error) {
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != actionpermit.PayloadTypeV4 {
		return actionpermit.Verified{}, errors.New("artifact is not an exact effect bundle")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload {
		return actionpermit.Verified{}, errors.New("effect bundle payload is not canonical base64")
	}
	var bundle actionpermit.BundleStatement
	if err := dsse.DecodeStrictInto(payload, actionpermit.MaxEnvelopeBytes, &bundle); err != nil {
		return actionpermit.Verified{}, fmt.Errorf("decode signed effect bundle: %w", err)
	}
	notBefore, err := parsePermitTime(bundle.NotBefore)
	if err != nil {
		return actionpermit.Verified{}, fmt.Errorf("effect bundle not_before: %w", err)
	}
	verified, err := actionpermit.Verify(raw, trusted, notBefore, maxValidity)
	if err != nil {
		return actionpermit.Verified{}, err
	}
	if verified.Bundle == nil {
		return actionpermit.Verified{}, errors.New("verified artifact does not contain an exact effect bundle")
	}
	return verified, nil
}

func checkEffectBundleReceiptBindings(
	bundle actionpermit.BundleStatement,
	authorityKeyIDs []string,
	step actionpermit.BundleStep,
	event connectorledger.Event,
) error {
	taskDigest := gateway.ConnectorCallDigest(bundle.TenantID, bundle.InstanceID, step.TaskID, step.ConnectorID, step.OperationID)
	authorityKeyID, authorityKeySet, approvalThreshold := "", "", 0
	if bundle.ApprovalThreshold > 1 {
		authorityKeySet = strings.Join(authorityKeyIDs, ",")
		approvalThreshold = bundle.ApprovalThreshold
	} else if len(authorityKeyIDs) == 1 {
		authorityKeyID = authorityKeyIDs[0]
	}
	if event.Kind != connectorledger.ConnectorCall || event.EffectMode != actionpermit.EffectModeAuthorized ||
		event.TenantID != bundle.TenantID || event.CapsuleDigest != bundle.CapsuleDigest ||
		event.PolicyDigest != bundle.PolicyDigest || event.RoutePolicyDigest != bundle.RoutePolicyDigest ||
		event.Generation != bundle.Generation || event.GrantID != gateway.GrantID(bundle.TenantID, bundle.InstanceID, bundle.Generation) ||
		event.ConnectorID != step.ConnectorID || event.OperationID != step.OperationID ||
		event.OperationPolicyDigest != step.OperationDigest || event.TaskDigest != taskDigest ||
		event.AuthorityKeyID != authorityKeyID || event.AuthorityKeySet != authorityKeySet ||
		event.ApprovalThreshold != approvalThreshold || event.RequestDigest != step.RequestDigest ||
		event.RequestBytes != step.RequestBytes {
		return errors.New("connector receipt does not match every exact effect bundle binding")
	}
	return nil
}
