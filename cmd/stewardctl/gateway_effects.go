package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/gateway"
	"github.com/hardrails/steward/internal/securefile"
)

const maxGatewayEffectsCheckOutputBytes = 16 << 10

type gatewayEffectsCheckSummary struct {
	Status             string   `json:"status"`
	EffectMode         string   `json:"effect_mode"`
	TenantID           string   `json:"tenant_id"`
	NodeID             string   `json:"node_id"`
	ConnectorIDs       []string `json:"connector_ids"`
	KeyIDs             []string `json:"key_ids"`
	MinApprovals       int      `json:"min_approvals"`
	ReceiptBudgetBytes int64    `json:"receipt_budget_bytes"`
}

func gatewayEffectsCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("gateway effects requires check")
	}
	if arguments[0] != "check" {
		return fmt.Errorf("unsupported gateway effects action %q", arguments[0])
	}
	flags := flag.NewFlagSet("gateway effects check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "Gateway configuration")
	intentPath := flags.String("intent", "", "strict authorized-effects instance intent")
	policyPath := flags.String("policy", "", "signed site policy DSSE envelope")
	siteRootPublicKeyPath := flags.String("site-root-public-key", "", "trusted site-root Ed25519 public key")
	siteRootKeyID := flags.String("site-root-key-id", "", "trusted site-root key ID")
	if err := rejectDuplicateGatewayEffectsFlags(arguments[1:]); err != nil {
		return err
	}
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if *configPath == "" || *intentPath == "" || *policyPath == "" ||
		*siteRootPublicKeyPath == "" || *siteRootKeyID == "" || flags.NArg() != 0 {
		return errors.New("gateway effects check requires -config, -intent, -policy, -site-root-public-key, and -site-root-key-id with no positional arguments")
	}

	config, routes, egressRoutes, token, err := gateway.LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("load Gateway configuration: %w", err)
	}
	if _, err := gateway.Validate(config, routes, egressRoutes, token); err != nil {
		return fmt.Errorf("validate Gateway configuration: %w", err)
	}

	intentRaw, err := securefile.Read(*intentPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read instance intent: %w", err)
	}
	var intent admission.InstanceIntent
	if err := dsse.DecodeStrictInto(intentRaw, maxArtifactBytes, &intent); err != nil {
		return fmt.Errorf("decode instance intent: %w", err)
	}
	if err := intent.Validate(admission.AuthenticatedIdentity{TenantID: intent.TenantID, NodeID: intent.NodeID}); err != nil {
		return fmt.Errorf("validate instance intent: %w", err)
	}
	if intent.EffectMode != admission.EffectModeAuthorized {
		return errors.New("instance intent must explicitly select authorized effect mode")
	}
	if intent.Capabilities.Egress || len(intent.EgressRouteIDs) != 0 {
		return errors.New("authorized effect mode forbids generic egress capability and routes")
	}
	if !intent.Capabilities.Connector || len(intent.ConnectorIDs) == 0 {
		return errors.New("authorized effect mode requires connector capability and at least one selected connector")
	}

	policyRaw, err := securefile.Read(*policyPath, maxArtifactBytes, securefile.TrustFile)
	if err != nil {
		return fmt.Errorf("read signed site policy: %w", err)
	}
	siteRootPublicKey, err := readPublicKey(*siteRootPublicKeyPath)
	if err != nil {
		return fmt.Errorf("read site-root public key: %w", err)
	}
	verifiedPolicy, err := admission.VerifySitePolicy(
		policyRaw,
		map[string]ed25519.PublicKey{*siteRootKeyID: siteRootPublicKey},
	)
	if err != nil {
		return err
	}
	if verifiedPolicy.SiteRootKeyID != *siteRootKeyID {
		return errors.New("verified site policy does not match the requested site-root key ID")
	}
	actionKeys, err := verifiedPolicy.Policy.AuthorizedActionKeys(intent.TenantID, intent.ConnectorIDs)
	if err != nil {
		return err
	}
	minApprovals, err := verifiedPolicy.Policy.AuthorizedActionApprovalThreshold(intent.TenantID, intent.ConnectorIDs)
	if err != nil {
		return err
	}
	keyIDs, receiptBudget, err := checkGatewayEffectsBindings(config, intent, actionKeys)
	if err != nil {
		return err
	}
	connectorIDs := append([]string(nil), intent.ConnectorIDs...)
	slices.Sort(connectorIDs)
	return writeGatewayEffectsCheckSummary(stdout, gatewayEffectsCheckSummary{
		Status: "ready", EffectMode: admission.EffectModeAuthorized,
		TenantID: intent.TenantID, NodeID: intent.NodeID,
		ConnectorIDs: connectorIDs, KeyIDs: keyIDs, MinApprovals: minApprovals, ReceiptBudgetBytes: receiptBudget,
	})
}

func rejectDuplicateGatewayEffectsFlags(arguments []string) error {
	allowed := map[string]struct{}{
		"config": {}, "intent": {}, "policy": {}, "site-root-public-key": {}, "site-root-key-id": {},
	}
	seen := make(map[string]struct{}, len(allowed))
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if argument == "--" {
			break
		}
		nameValue := argument
		if len(nameValue) > 2 && nameValue[:2] == "--" {
			nameValue = nameValue[2:]
		} else if len(nameValue) > 1 && nameValue[0] == '-' {
			nameValue = nameValue[1:]
		} else {
			continue
		}
		name, _, hasInlineValue := strings.Cut(nameValue, "=")
		if _, known := allowed[name]; !known {
			continue
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("gateway effects check flag -%s must be supplied exactly once", name)
		}
		seen[name] = struct{}{}
		if !hasInlineValue && index+1 < len(arguments) {
			index++
		}
	}
	return nil
}

func checkGatewayEffectsBindings(
	config gateway.Config,
	intent admission.InstanceIntent,
	actionKeys []admission.ActionKey,
) ([]string, int64, error) {
	if config.ActionPermitNodeID != intent.NodeID {
		return nil, 0, errors.New("Gateway action-permit node does not match the instance intent")
	}

	configuredAuthorities := make(map[string]gateway.ActionAuthority, len(config.ActionAuthorities))
	for _, authority := range config.ActionAuthorities {
		configuredAuthorities[authority.KeyID] = authority
	}
	expectedByConnector := make(map[string][]string, len(intent.ConnectorIDs))
	for _, connectorID := range intent.ConnectorIDs {
		expectedByConnector[connectorID] = nil
	}
	keyIDs := make([]string, 0, len(actionKeys))
	for _, actionKey := range actionKeys {
		configured, ok := configuredAuthorities[actionKey.KeyID]
		if !ok || configured.TenantID != intent.TenantID || configured.PublicKey != actionKey.PublicKey {
			return nil, 0, fmt.Errorf("Gateway action authority %q does not exactly match signed tenant policy", actionKey.KeyID)
		}
		keyIDs = append(keyIDs, actionKey.KeyID)
		for _, connectorID := range actionKey.ConnectorIDs {
			expected, selected := expectedByConnector[connectorID]
			if !selected {
				return nil, 0, fmt.Errorf("signed action authority %q exceeds the selected connector scope", actionKey.KeyID)
			}
			expectedByConnector[connectorID] = append(expected, actionKey.KeyID)
		}
	}
	slices.Sort(keyIDs)

	configuredConnectors := make(map[string]gateway.Connector, len(config.Connectors))
	for _, connector := range config.Connectors {
		configuredConnectors[connector.ID] = connector
	}
	for _, connectorID := range intent.ConnectorIDs {
		connector, ok := configuredConnectors[connectorID]
		if !ok {
			return nil, 0, fmt.Errorf("Gateway does not configure selected connector %q", connectorID)
		}
		expected := expectedByConnector[connectorID]
		slices.Sort(expected)
		if len(expected) == 0 || !slices.Equal(connector.ActionAuthorityIDs, expected) {
			return nil, 0, fmt.Errorf("Gateway connector %q action-authority scope does not exactly match signed tenant policy", connectorID)
		}
	}

	for _, budget := range config.ConnectorReceiptTenantBudgets {
		if budget.TenantID == intent.TenantID {
			return keyIDs, budget.Bytes, nil
		}
	}
	return nil, 0, errors.New("Gateway has no durable connector receipt budget for the instance tenant")
}

func writeGatewayEffectsCheckSummary(stdout io.Writer, summary gatewayEffectsCheckSummary) error {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(summary); err != nil {
		return err
	}
	if buffer.Len() == 0 || buffer.Len() > maxGatewayEffectsCheckOutputBytes {
		return errors.New("Gateway effects readiness summary exceeds its output limit")
	}
	_, err := io.Copy(stdout, &buffer)
	return err
}
