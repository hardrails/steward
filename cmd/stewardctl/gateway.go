package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/hardrails/steward/internal/gateway"
)

type repeatedFlag []string

const (
	actionTrustSchemaV1  = "steward.action-trust.v1"
	maxActionTrustBytes  = 4 << 20
	serviceTrustSchemaV1 = "steward.service-trust.v1"
	maxServiceTrustBytes = 4 << 20
)

type actionTrustInventory struct {
	SchemaVersion string                 `json:"schema_version"`
	NodeID        string                 `json:"node_id"`
	TenantID      string                 `json:"tenant_id"`
	Authorities   []actionTrustAuthority `json:"authorities"`
	Connectors    []actionTrustConnector `json:"connectors"`
}

type actionTrustAuthority struct {
	KeyID           string   `json:"key_id"`
	TenantID        string   `json:"tenant_id"`
	PublicKeyDigest string   `json:"public_key_digest"`
	ConnectorIDs    []string `json:"connector_ids"`
}

type actionTrustConnector struct {
	ConnectorID      string                 `json:"connector_id"`
	BaseURL          string                 `json:"base_url"`
	CredentialMode   gateway.CredentialMode `json:"credential_mode"`
	CredentialEpoch  uint64                 `json:"credential_epoch"`
	MaxPermitSeconds int                    `json:"max_permit_seconds"`
	AuthorityKeyIDs  []string               `json:"authority_key_ids"`
	Operations       []actionTrustOperation `json:"operations"`
}

type actionTrustOperation struct {
	ID           string `json:"id"`
	Method       string `json:"method"`
	Path         string `json:"path"`
	PolicyDigest string `json:"policy_digest"`
}

type serviceTrustInventory struct {
	SchemaVersion string                `json:"schema_version"`
	NodeID        string                `json:"node_id"`
	TenantID      string                `json:"tenant_id"`
	Services      []serviceTrustService `json:"services"`
}

type serviceTrustService struct {
	ServiceID  string                  `json:"service_id"`
	Operations []serviceTrustOperation `json:"operations"`
}

type serviceTrustOperation struct {
	ServiceID        string `json:"service_id"`
	ID               string `json:"id"`
	Method           string `json:"method"`
	Path             string `json:"path"`
	ContentType      string `json:"content_type"`
	MaxRequestBytes  int64  `json:"max_request_bytes"`
	MaxResponseBytes int64  `json:"max_response_bytes"`
	MaxSeconds       int    `json:"max_seconds"`
	MaxPermitSeconds int    `json:"max_permit_seconds"`
	PolicyDigest     string `json:"policy_digest"`
}

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	if strings.TrimSpace(value) == "" {
		return errors.New("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func gatewayCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("gateway command requires validate, route, connector, or service")
	}
	switch arguments[0] {
	case "validate":
		flags := flag.NewFlagSet("gateway validate", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		path := flags.String("config", "/etc/steward/gateway.json", "gateway configuration")
		if err := flags.Parse(arguments[1:]); err != nil {
			return err
		}
		if flags.NArg() != 0 {
			return errors.New("gateway validate accepts no positional arguments")
		}
		config, routes, egressRoutes, token, err := gateway.LoadConfig(*path)
		if err != nil {
			return err
		}
		if _, err := gateway.Validate(config, routes, egressRoutes, token); err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, "gateway configuration valid")
		return err
	case "route":
		return gatewayRouteCommand(arguments[1:], stdout)
	case "connector":
		return gatewayConnectorCommand(arguments[1:], stdout)
	case "service":
		return gatewayServiceCommand(arguments[1:], stdout)
	default:
		return fmt.Errorf("unsupported gateway command %q", arguments[0])
	}
}

func gatewayServiceCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("gateway service requires list, trust, or set")
	}
	action := arguments[0]
	flags := flag.NewFlagSet("gateway service "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "/etc/steward/gateway.json", "gateway configuration")
	serviceID := flags.String("service-id", "", "exact admitted service ID")
	trustNodeID := flags.String("node-id", "", "exact node identity for an exported service-trust inventory")
	trustTenantID := flags.String("tenant-id", "", "exact tenant identity for an exported service-trust inventory")
	maxRequest := flags.Int64("max-request-bytes", 64<<10, "exact request body byte ceiling")
	maxResponse := flags.Int64("max-response-bytes", 1<<20, "exact response body byte ceiling")
	maxSeconds := flags.Int("max-seconds", 120, "upstream call lifetime ceiling")
	maxPermitSeconds := flags.Int("max-permit-seconds", 300, "maximum tenant task-permit lifetime")
	receiptFile := flags.String("receipt-file", "", "signed receipt ledger path for an older config")
	receiptKeyFile := flags.String("receipt-key-file", "", "receipt private key path for an older config")
	receiptNodeID := flags.String("receipt-node-id", "", "stable receipt node identity for an older config")
	receiptEpoch := flags.Uint64("receipt-epoch", 1, "receipt key epoch for an older config")
	var operations, tenantBudgets repeatedFlag
	flags.Var(&operations, "operation", "exact ID=POST:/path operation; repeat for more")
	flags.Var(&tenantBudgets, "tenant-budget", "exact TENANT=BYTES receipt budget; repeat for more")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("gateway service accepts no positional arguments")
	}
	config, _, _, _, err := gateway.LoadConfig(*path)
	if err != nil {
		return err
	}
	switch action {
	case "list":
		if !onlyConfigFlagVisited(flags) {
			return errors.New("gateway service list accepts only -config")
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(config.ServiceOperations)
	case "trust":
		if *trustNodeID == "" || *trustTenantID == "" ||
			!onlyNamedFlagsVisited(flags, "config", "node-id", "tenant-id") {
			return errors.New("gateway service trust requires -node-id and -tenant-id and accepts only those flags plus -config")
		}
		return writeServiceTrustInventory(stdout, config, *trustNodeID, *trustTenantID)
	case "set":
		// Continue below after the read-only operations have returned.
	default:
		return fmt.Errorf("unsupported gateway service action %q", action)
	}
	if flagWasVisited(flags, "node-id") || flagWasVisited(flags, "tenant-id") {
		return errors.New("-node-id and -tenant-id are accepted only by gateway service trust")
	}
	if *serviceID == "" || len(operations) == 0 {
		return errors.New("gateway service set requires -service-id and at least one -operation")
	}
	parsed := make([]gateway.ServiceOperation, 0, len(operations))
	seenIDs := make(map[string]struct{}, len(operations))
	for _, value := range operations {
		operation, err := parseConnectorOperation(value)
		if err != nil {
			return err
		}
		if operation.Method != http.MethodPost {
			return fmt.Errorf("service operation %q must use POST", operation.ID)
		}
		if _, duplicate := seenIDs[operation.ID]; duplicate {
			return fmt.Errorf("duplicate service operation %q", operation.ID)
		}
		seenIDs[operation.ID] = struct{}{}
		parsed = append(parsed, gateway.ServiceOperation{
			ServiceID: *serviceID, ID: operation.ID, Method: operation.Method, Path: operation.Path,
			ContentType: "application/json", MaxRequestBytes: *maxRequest, MaxResponseBytes: *maxResponse,
			MaxSeconds: *maxSeconds, MaxPermitSeconds: *maxPermitSeconds,
		})
	}

	budgetsChanged := false
	if len(tenantBudgets) > 0 {
		parsedBudgets, err := parseConnectorTenantBudgets(tenantBudgets)
		if err != nil {
			return err
		}
		for _, budget := range parsedBudgets {
			found := false
			for index := range config.ConnectorReceiptTenantBudgets {
				if config.ConnectorReceiptTenantBudgets[index].TenantID != budget.TenantID {
					continue
				}
				found = true
				if config.ConnectorReceiptTenantBudgets[index].Bytes != budget.Bytes {
					config.ConnectorReceiptTenantBudgets[index] = budget
					budgetsChanged = true
				}
				break
			}
			if !found {
				config.ConnectorReceiptTenantBudgets = append(config.ConnectorReceiptTenantBudgets, budget)
				budgetsChanged = true
			}
		}
	}
	if len(config.ConnectorReceiptTenantBudgets) == 0 {
		return errors.New("adding an authorized service task requires at least one -tenant-budget TENANT=BYTES")
	}
	receiptIdentityChanged := false
	if config.ConnectorReceiptFile == "" {
		if *receiptFile == "" || *receiptKeyFile == "" || *receiptNodeID == "" || *receiptEpoch == 0 {
			return errors.New("older gateway config requires -receipt-file, -receipt-key-file, -receipt-node-id, and a positive -receipt-epoch when adding its first authorized service task")
		}
		config.ConnectorReceiptFile, config.ConnectorReceiptKeyFile = *receiptFile, *receiptKeyFile
		config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch = *receiptNodeID, *receiptEpoch
		receiptIdentityChanged = true
	} else if connectorReceiptFlagVisited(flags) {
		return errors.New("receipt flags are accepted only when upgrading a config without a receipt identity")
	}

	kept := config.ServiceOperations[:0]
	for _, operation := range config.ServiceOperations {
		if operation.ServiceID != *serviceID {
			kept = append(kept, operation)
		}
	}
	replaced := len(kept) != len(config.ServiceOperations)
	config.ServiceOperations = append(kept, parsed...)
	sort.Slice(config.ServiceOperations, func(i, j int) bool {
		if config.ServiceOperations[i].ServiceID != config.ServiceOperations[j].ServiceID {
			return config.ServiceOperations[i].ServiceID < config.ServiceOperations[j].ServiceID
		}
		return config.ServiceOperations[i].ID < config.ServiceOperations[j].ID
	})
	if err := writeGatewayConfig(*path, config); err != nil {
		return err
	}
	activation := "systemctl reload steward-gateway.service"
	if budgetsChanged || receiptIdentityChanged {
		activation = "systemctl restart steward-gateway.service"
	}
	result := map[string]any{"service_id": *serviceID, "operations": parsed, "replaced": replaced, "activation": activation}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func writeServiceTrustInventory(stdout io.Writer, config gateway.Config, nodeID, tenantID string) error {
	if !boundedTrustIdentity(nodeID) || !boundedTrustIdentity(tenantID) {
		return errors.New("service trust node and tenant identities must be non-empty, at most 128 bytes, and contain no NUL")
	}
	budgeted := false
	for _, budget := range config.ConnectorReceiptTenantBudgets {
		if budget.TenantID == tenantID {
			budgeted = true
			break
		}
	}
	if !budgeted {
		return fmt.Errorf("tenant %q has no configured receipt budget", tenantID)
	}
	byService := make(map[string][]serviceTrustOperation)
	for _, operation := range config.ServiceOperations {
		byService[operation.ServiceID] = append(byService[operation.ServiceID], serviceTrustOperation{
			ServiceID: operation.ServiceID, ID: operation.ID, Method: operation.Method, Path: operation.Path,
			ContentType: operation.ContentType, MaxRequestBytes: operation.MaxRequestBytes,
			MaxResponseBytes: operation.MaxResponseBytes, MaxSeconds: operation.MaxSeconds,
			MaxPermitSeconds: operation.MaxPermitSeconds, PolicyDigest: gateway.ServiceOperationDigest(operation),
		})
	}
	if len(byService) == 0 {
		return errors.New("gateway has no configured authorized service operations")
	}
	output := serviceTrustInventory{SchemaVersion: serviceTrustSchemaV1, NodeID: nodeID, TenantID: tenantID}
	for serviceID, operations := range byService {
		sort.Slice(operations, func(i, j int) bool { return operations[i].ID < operations[j].ID })
		output.Services = append(output.Services, serviceTrustService{ServiceID: serviceID, Operations: operations})
	}
	sort.Slice(output.Services, func(i, j int) bool { return output.Services[i].ServiceID < output.Services[j].ServiceID })
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return err
	}
	if buffer.Len() > maxServiceTrustBytes {
		return fmt.Errorf("service trust inventory exceeds %d bytes", maxServiceTrustBytes)
	}
	_, err := stdout.Write(buffer.Bytes())
	return err
}

func boundedTrustIdentity(value string) bool {
	return strings.TrimSpace(value) != "" && len(value) <= 128 && !strings.ContainsRune(value, '\x00')
}

func gatewayConnectorCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("gateway connector requires list, trust, or set")
	}
	action := arguments[0]
	flags := flag.NewFlagSet("gateway connector "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "/etc/steward/gateway.json", "gateway configuration")
	id := flags.String("id", "", "stable connector ID")
	baseURL := flags.String("base-url", "", "exact upstream HTTPS origin")
	credentialFile := flags.String("credential-file", "", "owner-only upstream credential file")
	credentialMode := flags.String("credential-mode", string(gateway.CredentialModeBearer), "bearer or x-api-key")
	credentialEpoch := flags.Uint64("credential-epoch", 0, "operator-managed credential authority epoch")
	trustTenantID := flags.String("tenant-id", "", "exact tenant scope for an exported action-trust inventory")
	allowInsecureHTTP := flags.Bool("allow-insecure-http", false, "explicitly permit a plaintext HTTP origin")
	maxConcurrent := flags.Int("max-concurrent", 4, "maximum concurrent calls for this connector")
	maxRequest := flags.Int64("max-request-bytes", 1<<20, "request body byte ceiling")
	maxResponse := flags.Int64("max-response-bytes", 4<<20, "response body byte ceiling")
	maxSeconds := flags.Int("max-seconds", 60, "call lifetime ceiling")
	maxCalls := flags.Int("max-calls-per-grant", 16, "durable call budget for one grant")
	actionNodeID := flags.String("action-node-id", "", "node identity bound into signed action permits")
	maxActionPermitSeconds := flags.Int("max-action-permit-seconds", 0, "maximum signed action permit lifetime")
	clearActionPermit := flags.Bool("clear-action-permit", false, "remove the connector's action-permit requirement")
	receiptFile := flags.String("receipt-file", "", "signed connector receipt ledger path for an older config")
	receiptKeyFile := flags.String("receipt-key-file", "", "connector receipt private key path for an older config")
	receiptNodeID := flags.String("receipt-node-id", "", "stable connector receipt node identity for an older config")
	receiptEpoch := flags.Uint64("receipt-epoch", 1, "connector receipt key epoch for an older config")
	var cidrs, operations, tenantBudgets, actionAuthorities, actionAuthorityTenants repeatedFlag
	flags.Var(&cidrs, "allow-cidr", "explicit resolved-address CIDR; repeat for more")
	flags.Var(&operations, "operation", "exact ID=METHOD:/path operation; repeat for more")
	flags.Var(&tenantBudgets, "tenant-budget", "exact TENANT=BYTES receipt budget; repeat for more")
	flags.Var(&actionAuthorities, "action-authority", "trusted KEY_ID=PUBLIC_KEY_FILE; repeat for more")
	flags.Var(&actionAuthorityTenants, "action-authority-tenant", "exact KEY_ID=TENANT_ID scope; repeat for new keys")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("gateway connector accepts no positional arguments")
	}
	config, _, _, _, err := gateway.LoadConfig(*path)
	if err != nil {
		return err
	}
	if action == "list" {
		if !onlyConfigFlagVisited(flags) {
			return errors.New("gateway connector list accepts only -config")
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(config.Connectors)
	}
	if action == "trust" {
		if *trustTenantID == "" || !onlyNamedFlagsVisited(flags, "config", "tenant-id") {
			return errors.New("gateway connector trust requires -tenant-id and accepts only -config and -tenant-id")
		}
		return writeActionTrustInventory(stdout, config, *trustTenantID)
	}
	if action != "set" {
		return fmt.Errorf("unsupported gateway connector action %q", action)
	}
	if flagWasVisited(flags, "tenant-id") {
		return errors.New("-tenant-id is accepted only by gateway connector trust")
	}
	if *id == "" || *baseURL == "" || *credentialFile == "" || len(operations) == 0 {
		return errors.New("gateway connector set requires -id, -base-url, -credential-file, and at least one -operation")
	}
	parsedOperations := make([]gateway.ConnectorOperation, 0, len(operations))
	for _, value := range operations {
		operation, err := parseConnectorOperation(value)
		if err != nil {
			return err
		}
		parsedOperations = append(parsedOperations, operation)
	}
	if *clearActionPermit && (len(actionAuthorities) != 0 || len(actionAuthorityTenants) != 0 || *actionNodeID != "" ||
		*maxActionPermitSeconds != 0 || flagWasVisited(flags, "credential-epoch")) {
		return errors.New("-clear-action-permit cannot be combined with action authority flags")
	}
	if len(actionAuthorityTenants) > 0 && len(actionAuthorities) == 0 {
		return errors.New("-action-authority-tenant requires matching -action-authority flags")
	}
	if flagWasVisited(flags, "credential-epoch") && *credentialEpoch == 0 {
		return errors.New("-credential-epoch must be positive")
	}
	var existingConnector *gateway.Connector
	for index := range config.Connectors {
		if config.Connectors[index].ID == *id {
			existingConnector = &config.Connectors[index]
			break
		}
	}
	actionAuthorityIDs := []string(nil)
	permitSeconds := 0
	selectedCredentialEpoch := *credentialEpoch
	if !*clearActionPermit && len(actionAuthorities) == 0 && existingConnector != nil {
		actionAuthorityIDs = append(actionAuthorityIDs, existingConnector.ActionAuthorityIDs...)
		permitSeconds = existingConnector.MaxActionPermitSeconds
		if *maxActionPermitSeconds > 0 {
			permitSeconds = *maxActionPermitSeconds
		}
	}
	if selectedCredentialEpoch == 0 {
		if existingConnector != nil {
			selectedCredentialEpoch = existingConnector.CredentialEpoch
		}
	}
	if len(actionAuthorities) > 0 {
		if *maxActionPermitSeconds <= 0 {
			return errors.New("action authorities require a positive -max-action-permit-seconds")
		}
		permitSeconds = *maxActionPermitSeconds
		tenantByKeyID := make(map[string]string, len(actionAuthorityTenants))
		for _, value := range actionAuthorityTenants {
			keyID, tenantID, ok := strings.Cut(value, "=")
			if !ok || keyID == "" || tenantID == "" {
				return fmt.Errorf("invalid action authority tenant %q; use KEY_ID=TENANT_ID", value)
			}
			if _, duplicate := tenantByKeyID[keyID]; duplicate {
				return fmt.Errorf("duplicate action authority tenant scope for %q", keyID)
			}
			tenantByKeyID[keyID] = tenantID
		}
		for _, value := range actionAuthorities {
			keyID, keyPath, ok := strings.Cut(value, "=")
			if !ok || keyID == "" || keyPath == "" {
				return fmt.Errorf("invalid action authority %q; use KEY_ID=PUBLIC_KEY_FILE", value)
			}
			key, err := readPublicKey(keyPath)
			if err != nil {
				return fmt.Errorf("read action authority %q: %w", keyID, err)
			}
			encoded := base64.StdEncoding.EncodeToString(key)
			found := false
			tenantID, tenantSupplied := tenantByKeyID[keyID]
			for _, authority := range config.ActionAuthorities {
				if authority.KeyID != keyID {
					continue
				}
				found = true
				if authority.PublicKey != encoded {
					return fmt.Errorf("action authority %q already has a different public key; add a new key ID", keyID)
				}
				if tenantSupplied && authority.TenantID != tenantID {
					return fmt.Errorf("action authority %q already belongs to tenant %q; add a new key ID", keyID, authority.TenantID)
				}
				tenantID = authority.TenantID
			}
			if !found {
				if !tenantSupplied {
					return fmt.Errorf("new action authority %q requires -action-authority-tenant %s=TENANT_ID", keyID, keyID)
				}
				config.ActionAuthorities = append(config.ActionAuthorities, gateway.ActionAuthority{KeyID: keyID, TenantID: tenantID, PublicKey: encoded})
			}
			delete(tenantByKeyID, keyID)
			actionAuthorityIDs = append(actionAuthorityIDs, keyID)
		}
		if len(tenantByKeyID) != 0 {
			return errors.New("every -action-authority-tenant must name a supplied action authority")
		}
		sort.Strings(actionAuthorityIDs)
		for index := 1; index < len(actionAuthorityIDs); index++ {
			if actionAuthorityIDs[index-1] == actionAuthorityIDs[index] {
				return fmt.Errorf("duplicate action authority %q", actionAuthorityIDs[index])
			}
		}
	}
	if len(actionAuthorityIDs) > 0 {
		if selectedCredentialEpoch == 0 {
			selectedCredentialEpoch = 1
		}
		if config.ActionPermitNodeID == "" {
			if *actionNodeID == "" {
				return errors.New("the first action-permit connector requires -action-node-id")
			}
			config.ActionPermitNodeID = *actionNodeID
		} else if *actionNodeID != "" && *actionNodeID != config.ActionPermitNodeID {
			return errors.New("-action-node-id does not match the configured action permit node identity")
		}
	} else if *actionNodeID != "" || *maxActionPermitSeconds != 0 || flagWasVisited(flags, "credential-epoch") {
		return errors.New("action permit settings require at least one -action-authority")
	} else {
		selectedCredentialEpoch = 0
	}
	budgetsChanged := false
	if len(tenantBudgets) > 0 {
		parsedBudgets, err := parseConnectorTenantBudgets(tenantBudgets)
		if err != nil {
			return err
		}
		for _, budget := range parsedBudgets {
			found := false
			for index := range config.ConnectorReceiptTenantBudgets {
				if config.ConnectorReceiptTenantBudgets[index].TenantID != budget.TenantID {
					continue
				}
				found = true
				if config.ConnectorReceiptTenantBudgets[index].Bytes != budget.Bytes {
					config.ConnectorReceiptTenantBudgets[index] = budget
					budgetsChanged = true
				}
				break
			}
			if !found {
				config.ConnectorReceiptTenantBudgets = append(config.ConnectorReceiptTenantBudgets, budget)
				budgetsChanged = true
			}
		}
	}
	if len(config.Connectors) == 0 && len(config.ConnectorReceiptTenantBudgets) == 0 {
		return errors.New("adding the first connector requires at least one -tenant-budget TENANT=BYTES")
	}
	connector := gateway.Connector{
		ID: *id, BaseURL: *baseURL, CredentialFile: *credentialFile,
		CredentialMode: gateway.CredentialMode(*credentialMode), CredentialEpoch: selectedCredentialEpoch,
		AllowInsecureHTTP: *allowInsecureHTTP,
		AllowedCIDRs:      append([]string(nil), cidrs...), MaxConcurrent: *maxConcurrent,
		MaxRequestBytes: *maxRequest, MaxResponseBytes: *maxResponse, MaxSeconds: *maxSeconds,
		MaxCallsPerGrant: *maxCalls, ActionAuthorityIDs: actionAuthorityIDs,
		MaxActionPermitSeconds: permitSeconds, Operations: parsedOperations,
	}
	receiptIdentityChanged := false
	if config.ConnectorReceiptFile == "" {
		if *receiptFile == "" || *receiptKeyFile == "" || *receiptNodeID == "" || *receiptEpoch == 0 {
			return errors.New("older gateway config requires -receipt-file, -receipt-key-file, -receipt-node-id, and a positive -receipt-epoch when adding its first connector")
		}
		config.ConnectorReceiptFile, config.ConnectorReceiptKeyFile = *receiptFile, *receiptKeyFile
		config.ConnectorReceiptNodeID, config.ConnectorReceiptEpoch = *receiptNodeID, *receiptEpoch
		receiptIdentityChanged = true
	} else if connectorReceiptFlagVisited(flags) {
		return errors.New("receipt flags are accepted only when upgrading a config without a connector receipt identity")
	}
	replaced := false
	for index := range config.Connectors {
		if config.Connectors[index].ID == *id {
			config.Connectors[index], replaced = connector, true
			break
		}
	}
	if !replaced {
		config.Connectors = append(config.Connectors, connector)
	}
	pruneActionAuthorities(&config)
	if err := writeGatewayConfig(*path, config); err != nil {
		return err
	}
	activation := "systemctl reload steward-gateway.service"
	if budgetsChanged || receiptIdentityChanged {
		activation = "systemctl restart steward-gateway.service"
	}
	result := map[string]any{"connector": connector, "replaced": replaced, "activation": activation}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func pruneActionAuthorities(config *gateway.Config) {
	referenced := make(map[string]struct{})
	for _, connector := range config.Connectors {
		for _, keyID := range connector.ActionAuthorityIDs {
			referenced[keyID] = struct{}{}
		}
	}
	kept := config.ActionAuthorities[:0]
	for _, authority := range config.ActionAuthorities {
		if _, ok := referenced[authority.KeyID]; ok {
			kept = append(kept, authority)
		}
	}
	config.ActionAuthorities = kept
	if len(kept) == 0 {
		config.ActionPermitNodeID = ""
	}
}

func writeActionTrustInventory(stdout io.Writer, config gateway.Config, tenantID string) error {
	output := actionTrustInventory{
		SchemaVersion: actionTrustSchemaV1, NodeID: config.ActionPermitNodeID, TenantID: tenantID,
		Authorities: make([]actionTrustAuthority, 0, len(config.ActionAuthorities)),
		Connectors:  make([]actionTrustConnector, 0, len(config.Connectors)),
	}
	connectorsByKey := make(map[string][]string, len(config.ActionAuthorities))
	tenantKeys := make(map[string]struct{})
	for _, authority := range config.ActionAuthorities {
		if authority.TenantID == tenantID {
			tenantKeys[authority.KeyID] = struct{}{}
		}
	}
	if len(tenantKeys) == 0 {
		return fmt.Errorf("tenant %q has no configured action authority", tenantID)
	}
	for _, connector := range config.Connectors {
		authorityKeyIDs := make([]string, 0, len(connector.ActionAuthorityIDs))
		for _, keyID := range connector.ActionAuthorityIDs {
			if _, belongs := tenantKeys[keyID]; !belongs {
				continue
			}
			connectorsByKey[keyID] = append(connectorsByKey[keyID], connector.ID)
			authorityKeyIDs = append(authorityKeyIDs, keyID)
		}
		if len(authorityKeyIDs) > 0 {
			operations := make([]actionTrustOperation, 0, len(connector.Operations))
			for _, operation := range connector.Operations {
				digest, err := gateway.ConnectorOperationPolicyDigest(
					connector.BaseURL, connector.CredentialMode, connector.CredentialEpoch, connector.ID, operation,
				)
				if err != nil {
					return err
				}
				operations = append(operations, actionTrustOperation{
					ID: operation.ID, Method: operation.Method, Path: operation.Path, PolicyDigest: digest,
				})
			}
			sort.Slice(operations, func(i, j int) bool { return operations[i].ID < operations[j].ID })
			output.Connectors = append(output.Connectors, actionTrustConnector{
				ConnectorID: connector.ID, BaseURL: connector.BaseURL, CredentialMode: connector.CredentialMode,
				CredentialEpoch:  connector.CredentialEpoch,
				MaxPermitSeconds: connector.MaxActionPermitSeconds,
				AuthorityKeyIDs:  authorityKeyIDs, Operations: operations,
			})
		}
	}
	for _, authority := range config.ActionAuthorities {
		if authority.TenantID != tenantID {
			continue
		}
		public, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(public)
		connectorIDs := append([]string(nil), connectorsByKey[authority.KeyID]...)
		sort.Strings(connectorIDs)
		output.Authorities = append(output.Authorities, actionTrustAuthority{
			KeyID: authority.KeyID, TenantID: authority.TenantID,
			PublicKeyDigest: fmt.Sprintf("sha256:%x", digest[:]), ConnectorIDs: connectorIDs,
		})
	}
	sort.Slice(output.Authorities, func(i, j int) bool { return output.Authorities[i].KeyID < output.Authorities[j].KeyID })
	sort.Slice(output.Connectors, func(i, j int) bool { return output.Connectors[i].ConnectorID < output.Connectors[j].ConnectorID })
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(output); err != nil {
		return err
	}
	if buffer.Len() > maxActionTrustBytes {
		return fmt.Errorf("action trust inventory exceeds %d bytes", maxActionTrustBytes)
	}
	_, err := stdout.Write(buffer.Bytes())
	return err
}

func parseConnectorTenantBudgets(values []string) ([]gateway.ConnectorReceiptTenantBudget, error) {
	budgets := make([]gateway.ConnectorReceiptTenantBudget, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		separator := strings.LastIndexByte(value, '=')
		ok := separator > 0 && separator < len(value)-1
		tenantID, bytesText := "", ""
		if ok {
			tenantID, bytesText = value[:separator], value[separator+1:]
		}
		bytes, err := strconv.ParseInt(bytesText, 10, 64)
		if !ok || tenantID == "" || err != nil || bytes <= 0 {
			return nil, fmt.Errorf("invalid tenant budget %q; use TENANT=positive-decimal-BYTES", value)
		}
		if _, duplicate := seen[tenantID]; duplicate {
			return nil, fmt.Errorf("duplicate tenant budget for %q", tenantID)
		}
		seen[tenantID] = struct{}{}
		budgets = append(budgets, gateway.ConnectorReceiptTenantBudget{TenantID: tenantID, Bytes: bytes})
	}
	return budgets, nil
}

func parseConnectorOperation(value string) (gateway.ConnectorOperation, error) {
	identifier, rule, ok := strings.Cut(value, "=")
	method, path, methodOK := strings.Cut(rule, ":")
	if !ok || !methodOK || identifier == "" || method == "" || path == "" {
		return gateway.ConnectorOperation{}, fmt.Errorf("invalid operation %q; use ID=METHOD:/exact/path", value)
	}
	return gateway.ConnectorOperation{ID: identifier, Method: method, Path: path}, nil
}

func gatewayRouteCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("gateway route requires list or set")
	}
	action := arguments[0]
	flags := flag.NewFlagSet("gateway route "+action, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("config", "/etc/steward/gateway.json", "gateway configuration")
	id := flags.String("id", "", "stable route ID")
	maxConcurrent := flags.Int("max-concurrent", 8, "maximum concurrent requests")
	maxRequest := flags.Int64("max-request-bytes", 16<<20, "request or tunnel upload byte ceiling")
	maxResponse := flags.Int64("max-response-bytes", 256<<20, "response or tunnel download byte ceiling")
	maxSeconds := flags.Int("max-seconds", 900, "request/tunnel lifetime ceiling")
	var destinations, cidrs repeatedFlag
	flags.Var(&destinations, "destination", "allowed HOST:PORT; repeat for more")
	flags.Var(&cidrs, "allow-cidr", "explicit resolved-address CIDR pin; repeat for more")
	if err := flags.Parse(arguments[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("gateway route accepts no positional arguments")
	}
	config, _, _, _, err := gateway.LoadConfig(*path)
	if err != nil {
		return err
	}
	if action == "list" {
		if !onlyConfigFlagVisited(flags) {
			return errors.New("gateway route list accepts only -config")
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(config.EgressRoutes)
	}
	if action != "set" {
		return fmt.Errorf("unsupported gateway route action %q", action)
	}
	if *id == "" || len(destinations) == 0 {
		return errors.New("gateway route set requires -id and at least one -destination")
	}
	destinationRules := make([]gateway.EgressDestination, 0, len(destinations))
	for _, value := range destinations {
		host, portText, splitErr := net.SplitHostPort(value)
		port, portErr := strconv.Atoi(portText)
		if splitErr != nil || portErr != nil || host == "" || port < 1 || port > 65535 {
			return fmt.Errorf("invalid destination %q; use HOST:PORT (IPv6 in brackets)", value)
		}
		destinationRules = append(destinationRules, gateway.EgressDestination{Host: host, Ports: []int{port}, AllowedCIDRs: append([]string(nil), cidrs...)})
	}
	route := gateway.EgressRoute{ID: *id, Destinations: destinationRules, MaxConcurrent: *maxConcurrent,
		MaxRequestBytes: *maxRequest, MaxResponseBytes: *maxResponse, MaxTunnelSeconds: *maxSeconds}
	replaced := false
	for index := range config.EgressRoutes {
		if config.EgressRoutes[index].ID == *id {
			config.EgressRoutes[index], replaced = route, true
			break
		}
	}
	if !replaced {
		config.EgressRoutes = append(config.EgressRoutes, route)
	}
	if config.EgressAuditFile == "" {
		config.EgressAuditFile = "/var/lib/steward-gateway/egress-audit.jsonl"
	}
	if err := writeGatewayConfig(*path, config); err != nil {
		return err
	}
	result := map[string]any{"route": route, "replaced": replaced, "activation": "systemctl reload steward-gateway.service"}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}

func onlyConfigFlagVisited(flags *flag.FlagSet) bool {
	return onlyNamedFlagsVisited(flags, "config")
}

func onlyNamedFlagsVisited(flags *flag.FlagSet, names ...string) bool {
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[name] = struct{}{}
	}
	valid := true
	flags.Visit(func(visited *flag.Flag) {
		if _, ok := allowed[visited.Name]; !ok {
			valid = false
		}
	})
	return valid
}

func connectorReceiptFlagVisited(flags *flag.FlagSet) bool {
	found := false
	flags.Visit(func(visited *flag.Flag) {
		switch visited.Name {
		case "receipt-file", "receipt-key-file", "receipt-node-id", "receipt-epoch":
			found = true
		}
	})
	return found
}

func flagWasVisited(flags *flag.FlagSet, name string) bool {
	found := false
	flags.Visit(func(visited *flag.Flag) {
		if visited.Name == name {
			found = true
		}
	})
	return found
}

func writeGatewayConfig(path string, config gateway.Config) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 || info.Size() <= 0 || info.Size() > maxArtifactBytes {
		return errors.New("gateway config must be a bounded regular file with no group/world write permission")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("gateway config ownership is unavailable")
	}
	raw, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".gateway.json.*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(info.Mode().Perm()); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Chown(int(stat.Uid), int(stat.Gid)); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	loaded, routes, egressRoutes, token, err := gateway.LoadConfig(name)
	if err != nil {
		return fmt.Errorf("rendered gateway config is invalid: %w", err)
	}
	if _, err := gateway.Validate(loaded, routes, egressRoutes, token); err != nil {
		return fmt.Errorf("rendered gateway config is incompatible with retained state: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}
