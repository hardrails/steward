package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/hardrails/steward/internal/controlclient"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/controlstore"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
)

const (
	controlSupportBundleSchemaVersion = 1
	maxControlSupportBundleBytes      = 32 << 20
	maxControlSupportBundleItems      = 32768
)

var controlSupportBundleNow = time.Now

type controlSupportBundleScope struct {
	TenantID string `json:"tenant_id,omitempty"`
}

type controlSupportBundleTenant struct {
	Tenant controlclient.Tenant                   `json:"tenant"`
	Freeze controlstore.OperationalFreezeStatus   `json:"freeze"`
	Quota  controlstore.TenantResourceQuotaStatus `json:"quota"`
}

type controlSupportBundleEvidence struct {
	NodeID     string                                       `json:"node_id"`
	Inspection controlprotocol.ExecutorEvidenceInspectionV1 `json:"inspection"`
}

// controlSupportBundleV1 deliberately uses only metadata projections already
// exposed by Control. It cannot represent command envelopes, token MACs,
// credential values, prompts, request or response bodies, result text, or logs.
type controlSupportBundleV1 struct {
	SchemaVersion int                                  `json:"schema_version"`
	GeneratedAt   string                               `json:"generated_at"`
	Scope         controlSupportBundleScope            `json:"scope"`
	Operations    controlstore.OperationsSummary       `json:"operations"`
	SiteFreeze    controlstore.OperationalFreezeStatus `json:"site_freeze"`
	Tenants       []controlSupportBundleTenant         `json:"tenants"`
	Nodes         []controlclient.Node                 `json:"nodes"`
	Deployments   []controlclient.Deployment           `json:"deployments"`
	Attention     []controlstore.AttentionItem         `json:"attention"`
	Timeline      []controlstore.IncidentEvent         `json:"timeline"`
	Agents        []controlstore.AgentMetadata         `json:"agents"`
	Commands      []controlstore.CommandMetadata       `json:"commands"`
	Credentials   []controlstore.CredentialMetadata    `json:"credentials"`
	Evidence      []controlSupportBundleEvidence       `json:"evidence"`
	Excluded      []string                             `json:"excluded"`
}

type controlSupportBundleCreateOutput struct {
	Output       string `json:"output"`
	SHA256       string `json:"sha256"`
	SizeBytes    int    `json:"size_bytes"`
	GeneratedAt  string `json:"generated_at"`
	TenantID     string `json:"tenant_id,omitempty"`
	NodeCount    int    `json:"node_count"`
	FindingCount int    `json:"finding_count"`
}

type controlSupportBundleVerifyOutput struct {
	Verified     bool   `json:"verified"`
	SHA256       string `json:"sha256"`
	SizeBytes    int    `json:"size_bytes"`
	GeneratedAt  string `json:"generated_at"`
	TenantID     string `json:"tenant_id,omitempty"`
	NodeCount    int    `json:"node_count"`
	FindingCount int    `json:"finding_count"`
}

type supportBundleControlClient interface {
	ListTenants(context.Context, string, int) (controlclient.TenantList, error)
	ListNodes(context.Context, string, string, int) (controlclient.NodeList, error)
	ListDeployments(context.Context, string, string, int) (controlclient.DeploymentList, error)
	GetTenantResourceQuota(context.Context, string) (controlstore.TenantResourceQuotaStatus, error)
	GetOperationalFreeze(context.Context, string) (controlstore.OperationalFreezeStatus, error)
	GetOperationsSummary(context.Context, string) (controlstore.OperationsSummary, error)
	ListAttention(context.Context, string, string, string, int) (controlstore.AttentionPage, error)
	ListIncidentTimeline(context.Context, string, string, string, string, string, int) (controlstore.IncidentTimelinePage, error)
	ListAgentInventory(context.Context, string, string, string, string, int) (controlstore.AgentInventoryPage, error)
	ListCommandInventory(context.Context, string, string, string, string, string, int) (controlstore.CommandInventoryPage, error)
	ListCredentialInventory(context.Context, string, string, string, string, *bool, string, int) (controlstore.CredentialInventoryPage, error)
	InspectExecutorEvidence(context.Context, string) (controlprotocol.ExecutorEvidenceInspectionV1, error)
}

func controlSupportBundleCommand(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("control support-bundle requires create or verify")
	}
	switch arguments[0] {
	case "create":
		return controlSupportBundleCreate(arguments[1:], stdout)
	case "verify":
		return controlSupportBundleVerify(arguments[1:], stdout)
	default:
		return errors.New("control support-bundle requires create or verify")
	}
}

func controlSupportBundleCreate(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control support-bundle create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	common := addControlFlags(flags, true)
	tenantID := flags.String("tenant-id", "", "optional tenant scope; the default is the whole site")
	output := flags.String("out", "", "new owner-only JSON support bundle")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || !validNewControlEvidenceCaptureOutput(*output) ||
		!validOptionalControlIdentifier(*tenantID, 128) {
		return errors.New("control support-bundle create requires a safe new -out path and an optional bounded -tenant-id")
	}
	client, err := common.client(true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	bundle, err := collectControlSupportBundle(ctx, client, *tenantID, controlSupportBundleNow().UTC())
	if err != nil {
		return err
	}
	raw, err := encodeControlSupportBundle(bundle)
	if err != nil {
		return err
	}
	if err := writeNewFile(*output, raw, 0o600); err != nil {
		return fmt.Errorf("write control support bundle: %w", err)
	}
	digest := sha256.Sum256(raw)
	return writeControlJSON(stdout, controlSupportBundleCreateOutput{
		Output: *output, SHA256: "sha256:" + hex.EncodeToString(digest[:]), SizeBytes: len(raw),
		GeneratedAt: bundle.GeneratedAt, TenantID: bundle.Scope.TenantID,
		NodeCount: len(bundle.Nodes), FindingCount: len(bundle.Attention),
	})
}

func controlSupportBundleVerify(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("control support-bundle verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	input := flags.String("in", "", "owner-only JSON support bundle")
	expectedSHA256 := flags.String("expected-sha256", "", "trusted sha256 digest received separately")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 || *input == "" || !validSupportBundleSHA256(*expectedSHA256) {
		return errors.New("control support-bundle verify requires -in and a trusted -expected-sha256")
	}
	raw, err := securefile.Read(*input, maxControlSupportBundleBytes, securefile.OwnerOnly)
	if err != nil {
		return fmt.Errorf("read control support bundle: %w", err)
	}
	bundle, err := decodeControlSupportBundle(raw)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(raw)
	actualSHA256 := "sha256:" + hex.EncodeToString(digest[:])
	if actualSHA256 != *expectedSHA256 {
		return fmt.Errorf("control support bundle digest mismatch: got %s", actualSHA256)
	}
	return writeControlJSON(stdout, controlSupportBundleVerifyOutput{
		Verified: true, SHA256: actualSHA256, SizeBytes: len(raw),
		GeneratedAt: bundle.GeneratedAt, TenantID: bundle.Scope.TenantID,
		NodeCount: len(bundle.Nodes), FindingCount: len(bundle.Attention),
	})
}

func collectControlSupportBundle(
	ctx context.Context,
	client supportBundleControlClient,
	tenantID string,
	now time.Time,
) (controlSupportBundleV1, error) {
	if client == nil || now.IsZero() || !validOptionalControlIdentifier(tenantID, 128) {
		return controlSupportBundleV1{}, errors.New("control support bundle input is invalid")
	}
	tenants, err := collectSupportBundleTenants(ctx, client, tenantID)
	if err != nil {
		return controlSupportBundleV1{}, err
	}
	bundle := controlSupportBundleV1{
		SchemaVersion: controlSupportBundleSchemaVersion,
		GeneratedAt:   now.UTC().Format(time.RFC3339Nano),
		Scope:         controlSupportBundleScope{TenantID: tenantID},
		Excluded: []string{
			"agent_result_text", "command_envelopes", "credential_values", "logs",
			"private_keys", "prompts", "request_bodies", "response_bodies",
		},
	}
	bundle.Operations, err = client.GetOperationsSummary(ctx, tenantID)
	if err != nil {
		return controlSupportBundleV1{}, fmt.Errorf("collect operations summary: %w", err)
	}
	bundle.SiteFreeze, err = client.GetOperationalFreeze(ctx, "")
	if err != nil {
		return controlSupportBundleV1{}, fmt.Errorf("collect site freeze: %w", err)
	}

	nodesByID := make(map[string]controlclient.Node)
	for _, tenant := range tenants {
		freeze, loadErr := client.GetOperationalFreeze(ctx, tenant.TenantID)
		if loadErr != nil {
			return controlSupportBundleV1{}, fmt.Errorf("collect tenant %q freeze: %w", tenant.TenantID, loadErr)
		}
		quota, loadErr := client.GetTenantResourceQuota(ctx, tenant.TenantID)
		if loadErr != nil {
			return controlSupportBundleV1{}, fmt.Errorf("collect tenant %q quota: %w", tenant.TenantID, loadErr)
		}
		deployments, loadErr := collectSupportBundleDeployments(ctx, client, tenant.TenantID)
		if loadErr != nil {
			return controlSupportBundleV1{}, loadErr
		}
		nodes, loadErr := collectSupportBundleNodes(ctx, client, tenant.TenantID)
		if loadErr != nil {
			return controlSupportBundleV1{}, loadErr
		}
		for _, node := range nodes {
			existing, exists := nodesByID[node.NodeID]
			if exists && !supportBundleNodesEqual(existing, node) {
				return controlSupportBundleV1{}, fmt.Errorf("node %q changed while support bundle was collected", node.NodeID)
			}
			nodesByID[node.NodeID] = node
		}
		bundle.Tenants = append(bundle.Tenants, controlSupportBundleTenant{
			Tenant: tenant, Freeze: freeze, Quota: quota,
		})
		bundle.Deployments = append(bundle.Deployments, deployments...)
	}
	for _, node := range nodesByID {
		bundle.Nodes = append(bundle.Nodes, node)
	}
	sort.Slice(bundle.Nodes, func(i, j int) bool { return bundle.Nodes[i].NodeID < bundle.Nodes[j].NodeID })
	sort.Slice(bundle.Deployments, func(i, j int) bool {
		if bundle.Deployments[i].TenantID != bundle.Deployments[j].TenantID {
			return bundle.Deployments[i].TenantID < bundle.Deployments[j].TenantID
		}
		return bundle.Deployments[i].DeploymentID < bundle.Deployments[j].DeploymentID
	})

	bundle.Attention, err = collectSupportBundleAttention(ctx, client, tenantID)
	if err != nil {
		return controlSupportBundleV1{}, err
	}
	bundle.Timeline, err = collectSupportBundleTimeline(ctx, client, tenantID)
	if err != nil {
		return controlSupportBundleV1{}, err
	}
	bundle.Agents, err = collectSupportBundleAgents(ctx, client, tenantID)
	if err != nil {
		return controlSupportBundleV1{}, err
	}
	bundle.Commands, err = collectSupportBundleCommands(ctx, client, tenantID)
	if err != nil {
		return controlSupportBundleV1{}, err
	}
	bundle.Credentials, err = collectSupportBundleCredentials(ctx, client, tenantID)
	if err != nil {
		return controlSupportBundleV1{}, err
	}
	// Executor evidence inspection is deliberately site-admin-only. A tenant
	// bundle remains useful and tenant scoped without widening that endpoint or
	// failing after all other scoped inventories have been collected.
	if tenantID == "" {
		for _, node := range bundle.Nodes {
			inspection, inspectErr := client.InspectExecutorEvidence(ctx, node.NodeID)
			if inspectErr != nil {
				return controlSupportBundleV1{}, fmt.Errorf("collect node %q evidence: %w", node.NodeID, inspectErr)
			}
			bundle.Evidence = append(bundle.Evidence, controlSupportBundleEvidence{
				NodeID: node.NodeID, Inspection: inspection,
			})
		}
	}
	if err := validateControlSupportBundle(bundle); err != nil {
		return controlSupportBundleV1{}, fmt.Errorf("validate collected support bundle: %w", err)
	}
	return bundle, nil
}

func collectSupportBundleTenants(ctx context.Context, client supportBundleControlClient, selected string) ([]controlclient.Tenant, error) {
	var result []controlclient.Tenant
	after := ""
	seen := 0
	for {
		page, err := client.ListTenants(ctx, after, controlstore.MaxInventoryPageLimit)
		if err != nil {
			return nil, fmt.Errorf("collect tenants: %w", err)
		}
		for _, tenant := range page.Tenants {
			if selected == "" || tenant.TenantID == selected {
				result = append(result, tenant)
			}
		}
		seen += len(page.Tenants)
		if page.NextAfter == "" {
			break
		}
		if len(page.Tenants) == 0 || page.NextAfter <= after || seen > maxControlSupportBundleItems {
			return nil, errors.New("control tenant inventory pagination did not make bounded progress")
		}
		after = page.NextAfter
	}
	if selected != "" && (len(result) != 1 || result[0].TenantID != selected) {
		return nil, fmt.Errorf("tenant %q is not visible to this operator", selected)
	}
	return result, nil
}

func collectSupportBundleNodes(ctx context.Context, client supportBundleControlClient, tenantID string) ([]controlclient.Node, error) {
	var result []controlclient.Node
	after := ""
	for {
		page, err := client.ListNodes(ctx, tenantID, after, controlstore.MaxInventoryPageLimit)
		if err != nil {
			return nil, fmt.Errorf("collect tenant %q nodes: %w", tenantID, err)
		}
		result = append(result, page.Nodes...)
		if len(result) > maxControlSupportBundleItems {
			return nil, errors.New("control node inventory exceeds support bundle limit")
		}
		if page.NextAfter == "" {
			return result, nil
		}
		if len(page.Nodes) == 0 || page.NextAfter <= after {
			return nil, errors.New("control node inventory pagination did not make progress")
		}
		after = page.NextAfter
	}
}

func collectSupportBundleDeployments(ctx context.Context, client supportBundleControlClient, tenantID string) ([]controlclient.Deployment, error) {
	var result []controlclient.Deployment
	after := ""
	for {
		page, err := client.ListDeployments(ctx, tenantID, after, controlstore.MaxInventoryPageLimit)
		if err != nil {
			return nil, fmt.Errorf("collect tenant %q deployments: %w", tenantID, err)
		}
		result = append(result, page.Deployments...)
		if len(result) > maxControlSupportBundleItems {
			return nil, errors.New("control deployment inventory exceeds support bundle limit")
		}
		if page.NextAfter == "" {
			return result, nil
		}
		if len(page.Deployments) == 0 || page.NextAfter <= after {
			return nil, errors.New("control deployment inventory pagination did not make progress")
		}
		after = page.NextAfter
	}
}

func collectSupportBundleAttention(ctx context.Context, client supportBundleControlClient, tenantID string) ([]controlstore.AttentionItem, error) {
	var result []controlstore.AttentionItem
	cursor := ""
	for {
		page, err := client.ListAttention(ctx, tenantID, "", cursor, controlstore.MaxInventoryPageLimit)
		if err != nil {
			return nil, fmt.Errorf("collect attention findings: %w", err)
		}
		result = append(result, page.Items...)
		if err := supportBundleCursorProgress("attention", &cursor, page.NextCursor, len(page.Items), len(result)); err != nil {
			return nil, err
		}
		if page.NextCursor == "" {
			return result, nil
		}
	}
}

func collectSupportBundleTimeline(ctx context.Context, client supportBundleControlClient, tenantID string) ([]controlstore.IncidentEvent, error) {
	var result []controlstore.IncidentEvent
	cursor := ""
	for {
		page, err := client.ListIncidentTimeline(
			ctx, tenantID, "", "", "", cursor, controlstore.MaxInventoryPageLimit,
		)
		if err != nil {
			return nil, fmt.Errorf("collect incident timeline: %w", err)
		}
		result = append(result, page.Events...)
		if err := supportBundleCursorProgress("incident timeline", &cursor, page.NextCursor, len(page.Events), len(result)); err != nil {
			return nil, err
		}
		if page.NextCursor == "" {
			return result, nil
		}
	}
}

func collectSupportBundleAgents(ctx context.Context, client supportBundleControlClient, tenantID string) ([]controlstore.AgentMetadata, error) {
	var result []controlstore.AgentMetadata
	cursor := ""
	for {
		page, err := client.ListAgentInventory(ctx, tenantID, "", "", cursor, controlstore.MaxInventoryPageLimit)
		if err != nil {
			return nil, fmt.Errorf("collect agent inventory: %w", err)
		}
		result = append(result, page.Agents...)
		if err := supportBundleCursorProgress("agent", &cursor, page.NextCursor, len(page.Agents), len(result)); err != nil {
			return nil, err
		}
		if page.NextCursor == "" {
			return result, nil
		}
	}
}

func collectSupportBundleCommands(ctx context.Context, client supportBundleControlClient, tenantID string) ([]controlstore.CommandMetadata, error) {
	var result []controlstore.CommandMetadata
	cursor := ""
	for {
		page, err := client.ListCommandInventory(ctx, tenantID, "", "", "", cursor, controlstore.MaxInventoryPageLimit)
		if err != nil {
			return nil, fmt.Errorf("collect command inventory: %w", err)
		}
		result = append(result, page.Commands...)
		if err := supportBundleCursorProgress("command", &cursor, page.NextCursor, len(page.Commands), len(result)); err != nil {
			return nil, err
		}
		if page.NextCursor == "" {
			return result, nil
		}
	}
}

func collectSupportBundleCredentials(ctx context.Context, client supportBundleControlClient, tenantID string) ([]controlstore.CredentialMetadata, error) {
	var result []controlstore.CredentialMetadata
	cursor := ""
	for {
		page, err := client.ListCredentialInventory(ctx, tenantID, "", "", "", nil, cursor, controlstore.MaxInventoryPageLimit)
		if err != nil {
			return nil, fmt.Errorf("collect credential inventory: %w", err)
		}
		result = append(result, page.Credentials...)
		if err := supportBundleCursorProgress("credential", &cursor, page.NextCursor, len(page.Credentials), len(result)); err != nil {
			return nil, err
		}
		if page.NextCursor == "" {
			return result, nil
		}
	}
}

func supportBundleCursorProgress(kind string, cursor *string, next string, pageCount, count int) error {
	if count > maxControlSupportBundleItems {
		return fmt.Errorf("control %s inventory exceeds support bundle limit", kind)
	}
	if next != "" {
		if pageCount == 0 || next == *cursor {
			return fmt.Errorf("control %s inventory pagination did not make progress", kind)
		}
		*cursor = next
	}
	return nil
}

func supportBundleNodesEqual(left, right controlclient.Node) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func encodeControlSupportBundle(bundle controlSupportBundleV1) ([]byte, error) {
	if err := validateControlSupportBundle(bundle); err != nil {
		return nil, err
	}
	raw, err := json.Marshal(bundle)
	if err != nil {
		return nil, fmt.Errorf("encode control support bundle: %w", err)
	}
	if len(raw)+1 > maxControlSupportBundleBytes {
		return nil, errors.New("control support bundle exceeds 32 MiB")
	}
	return append(raw, '\n'), nil
}

func decodeControlSupportBundle(raw []byte) (controlSupportBundleV1, error) {
	if len(raw) == 0 || len(raw) > maxControlSupportBundleBytes {
		return controlSupportBundleV1{}, errors.New("control support bundle is empty or exceeds 32 MiB")
	}
	var bundle controlSupportBundleV1
	if err := dsse.DecodeStrictInto(raw, maxControlSupportBundleBytes, &bundle); err != nil {
		return controlSupportBundleV1{}, fmt.Errorf("decode control support bundle: %w", err)
	}
	if err := validateControlSupportBundle(bundle); err != nil {
		return controlSupportBundleV1{}, fmt.Errorf("validate control support bundle: %w", err)
	}
	canonical, err := json.Marshal(bundle)
	if err != nil {
		return controlSupportBundleV1{}, err
	}
	if !bytes.Equal(raw, append(canonical, '\n')) {
		return controlSupportBundleV1{}, errors.New("control support bundle is not canonical JSON with one trailing newline")
	}
	return bundle, nil
}

func validateControlSupportBundle(bundle controlSupportBundleV1) error {
	if bundle.SchemaVersion != controlSupportBundleSchemaVersion ||
		!validOptionalControlIdentifier(bundle.Scope.TenantID, 128) {
		return errors.New("unsupported support bundle schema or scope")
	}
	generated, err := time.Parse(time.RFC3339Nano, bundle.GeneratedAt)
	if err != nil || generated.IsZero() || bundle.GeneratedAt != generated.UTC().Format(time.RFC3339Nano) {
		return errors.New("support bundle generation time is not canonical UTC")
	}
	wantExcluded := []string{
		"agent_result_text", "command_envelopes", "credential_values", "logs",
		"private_keys", "prompts", "request_bodies", "response_bodies",
	}
	if !slices.Equal(bundle.Excluded, wantExcluded) {
		return errors.New("support bundle excluded-content contract is incomplete")
	}
	for _, count := range []int{
		len(bundle.Tenants), len(bundle.Nodes), len(bundle.Deployments), len(bundle.Attention),
		len(bundle.Timeline), len(bundle.Agents), len(bundle.Commands), len(bundle.Credentials), len(bundle.Evidence),
	} {
		if count > maxControlSupportBundleItems {
			return errors.New("support bundle collection exceeds its item limit")
		}
	}
	if bundle.Scope.TenantID == "" && len(bundle.Nodes) != len(bundle.Evidence) ||
		bundle.Scope.TenantID != "" && len(bundle.Evidence) != 0 ||
		!supportBundleCanonicalOrder(bundle) {
		return errors.New("support bundle inventories are incomplete or not canonical")
	}
	knownTenants := make(map[string]struct{}, len(bundle.Tenants))
	for _, tenant := range bundle.Tenants {
		knownTenants[tenant.Tenant.TenantID] = struct{}{}
	}
	for _, deployment := range bundle.Deployments {
		if _, ok := knownTenants[deployment.TenantID]; !ok {
			return errors.New("support bundle deployment references an unknown tenant")
		}
	}
	if err := validateSupportBundleTimeline(bundle.Timeline, bundle.Scope.TenantID, knownTenants); err != nil {
		return err
	}
	for _, evidence := range bundle.Evidence {
		if err := evidence.Inspection.Validate(); err != nil {
			return fmt.Errorf("support bundle node %q evidence is invalid: %w", evidence.NodeID, err)
		}
	}
	if bundle.Scope.TenantID != "" {
		if len(bundle.Tenants) != 1 || bundle.Tenants[0].Tenant.TenantID != bundle.Scope.TenantID {
			return errors.New("tenant-scoped support bundle contains an inconsistent tenant inventory")
		}
		for _, deployment := range bundle.Deployments {
			if deployment.TenantID != bundle.Scope.TenantID {
				return errors.New("tenant-scoped support bundle contains another tenant deployment")
			}
		}
	}
	return nil
}

func validSupportBundleSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") ||
		value != strings.ToLower(value) {
		return false
	}
	_, err := hex.DecodeString(value[len("sha256:"):])
	return err == nil
}

func validateSupportBundleTimeline(
	events []controlstore.IncidentEvent,
	tenantID string,
	knownTenants map[string]struct{},
) error {
	seen := make(map[string]struct{}, len(events))
	previousTime := time.Time{}
	previousID := ""
	for _, event := range events {
		when, err := time.Parse(time.RFC3339Nano, event.OccurredAt)
		if err != nil || when.IsZero() || event.OccurredAt != when.UTC().Format(time.RFC3339Nano) {
			return errors.New("support bundle incident timeline has a non-canonical timestamp")
		}
		if !previousTime.IsZero() && (when.After(previousTime) || when.Equal(previousTime) && event.ID <= previousID) {
			return errors.New("support bundle incident timeline is not strict newest-first")
		}
		previousTime, previousID = when, event.ID
		if !strings.HasPrefix(event.ID, "incident-") || len(event.ID) != len("incident-")+64 {
			return errors.New("support bundle incident timeline has an invalid event ID")
		}
		if _, err := hex.DecodeString(event.ID[len("incident-"):]); err != nil || event.ID != strings.ToLower(event.ID) {
			return errors.New("support bundle incident timeline has an invalid event digest")
		}
		if _, exists := seen[event.ID]; exists {
			return errors.New("support bundle incident timeline repeats an event")
		}
		seen[event.ID] = struct{}{}
		if !validSupportBundleIncidentAction(event.Action) ||
			event.Kind != controlstore.IncidentContainment && event.Kind != controlstore.IncidentEvidence &&
				event.Kind != controlstore.IncidentAccess && event.Kind != controlstore.IncidentWorkload ||
			event.Severity != controlstore.IncidentInfo && event.Severity != controlstore.IncidentWarning &&
				event.Severity != controlstore.IncidentCritical ||
			event.Scope != "site" && event.Scope != "tenant" {
			return errors.New("support bundle incident timeline has an invalid classification")
		}
		if event.Scope == "site" {
			if event.TenantID != "" {
				return errors.New("support bundle site incident names a tenant")
			}
		} else {
			if _, known := knownTenants[event.TenantID]; !known || tenantID != "" && event.TenantID != tenantID {
				return errors.New("support bundle incident timeline references an unknown tenant")
			}
		}
		if !validOptionalControlIdentifier(event.NodeID, 128) || len(event.ResourceID) > 512 ||
			len(event.Reason) > 1024 || len(event.Status) > 512 ||
			strings.ContainsAny(event.ResourceID+event.Reason+event.Status, "\r\n\x00") ||
			strings.TrimSpace(event.ResourceID) != event.ResourceID ||
			strings.TrimSpace(event.Reason) != event.Reason || strings.TrimSpace(event.Status) != event.Status {
			return errors.New("support bundle incident timeline contains invalid metadata")
		}
	}
	return nil
}

func validSupportBundleIncidentAction(value string) bool {
	if value == "" || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range []byte(value[1:]) {
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' || character == '_' {
			continue
		}
		return false
	}
	return true
}

func supportBundleCanonicalOrder(bundle controlSupportBundleV1) bool {
	for index := range bundle.Tenants {
		if index > 0 && bundle.Tenants[index-1].Tenant.TenantID >= bundle.Tenants[index].Tenant.TenantID {
			return false
		}
	}
	for index := range bundle.Nodes {
		if !validRequiredControlIdentifier(bundle.Nodes[index].NodeID, 128) ||
			bundle.Scope.TenantID == "" && bundle.Evidence[index].NodeID != bundle.Nodes[index].NodeID ||
			index > 0 && bundle.Nodes[index-1].NodeID >= bundle.Nodes[index].NodeID {
			return false
		}
	}
	for index := 1; index < len(bundle.Deployments); index++ {
		left, right := bundle.Deployments[index-1], bundle.Deployments[index]
		if left.TenantID > right.TenantID || left.TenantID == right.TenantID && left.DeploymentID >= right.DeploymentID {
			return false
		}
	}
	return true
}
