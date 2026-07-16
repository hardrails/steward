package controlstore

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
)

const (
	stateFormatVersion       = 1
	transactionFormatVersion = 1
	maxMutationsPerRecord    = 128
)

var (
	ErrAlreadyInitialized = errors.New("control store is already initialized")
	ErrNotInitialized     = errors.New("control store is not initialized")
	ErrCapacityExceeded   = errors.New("control store capacity exceeded")
	ErrConflict           = errors.New("control store object conflicts with retained state")
	ErrNotFound           = errors.New("control store object not found")
	ErrUnavailable        = errors.New("control store requires recovery after a durable write failure")
	ErrInvalid            = errors.New("control request is invalid")
	ErrForbidden          = controlauth.ErrForbidden
)

type Limits struct {
	MaxTenants              int
	MaxNodes                int
	MaxNodesPerTenant       int
	MaxCredentials          int
	MaxCredentialsPerTenant int
	MaxEnrollments          int
	MaxEnrollmentsPerTenant int
	MaxCommands             int
	MaxCommandsPerTenant    int
	MaxCommandsPerNode      int
	MaxCommandBytes         int
	MaxReportBytes          int
	MaxStateBytes           int
	MaxRecordBytes          int
	MaxWALBytes             int64
	TerminalRetention       time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxTenants: 256, MaxNodes: 4096, MaxNodesPerTenant: 512,
		MaxCredentials: 16384, MaxCredentialsPerTenant: 2048,
		MaxEnrollments: 4096, MaxEnrollmentsPerTenant: 512,
		MaxCommands: 16384, MaxCommandsPerTenant: 1024, MaxCommandsPerNode: 256,
		MaxCommandBytes: 1 << 20, MaxReportBytes: 64 << 10,
		MaxStateBytes: 64 << 20, MaxRecordBytes: 2 << 20, MaxWALBytes: 64 << 20,
		TerminalRetention: 24 * time.Hour,
	}
}

func (limits Limits) Validate() error {
	if limits.MaxTenants <= 0 || limits.MaxNodes <= 0 || limits.MaxNodesPerTenant <= 0 ||
		limits.MaxCredentials <= 0 || limits.MaxCredentialsPerTenant <= 0 ||
		limits.MaxEnrollments <= 0 || limits.MaxEnrollmentsPerTenant <= 0 ||
		limits.MaxCommands <= 0 || limits.MaxCommandsPerTenant <= 0 || limits.MaxCommandsPerNode <= 0 ||
		limits.MaxCommandBytes <= 0 || limits.MaxReportBytes <= 0 || limits.MaxStateBytes <= 0 ||
		limits.MaxRecordBytes <= 0 || limits.MaxWALBytes <= 0 || limits.TerminalRetention <= 0 {
		return errors.New("every control store limit must be positive")
	}
	if limits.MaxNodesPerTenant > limits.MaxNodes || limits.MaxCredentialsPerTenant > limits.MaxCredentials ||
		limits.MaxEnrollmentsPerTenant > limits.MaxEnrollments ||
		limits.MaxCommandsPerTenant > limits.MaxCommands || limits.MaxCommandsPerNode > limits.MaxCommands ||
		limits.MaxCommandBytes > limits.MaxRecordBytes || limits.MaxReportBytes > limits.MaxRecordBytes ||
		limits.MaxRecordBytes > limits.MaxStateBytes || int64(limits.MaxRecordBytes)+walHeaderBytes+4 > limits.MaxWALBytes {
		return errors.New("control store limits are internally inconsistent")
	}
	return nil
}

type Tenant struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	Active    bool   `json:"active"`
}

type Node struct {
	ID           string   `json:"id"`
	TenantIDs    []string `json:"tenant_ids"`
	Capabilities []string `json:"capabilities"`
	CreatedAt    string   `json:"created_at"`
	LastSeenAt   string   `json:"last_seen_at,omitempty"`
	RevokedAt    string   `json:"revoked_at,omitempty"`
	Active       bool     `json:"active"`
}

type CommandState string

const (
	CommandPending  CommandState = "pending"
	CommandLeased   CommandState = "leased"
	CommandTerminal CommandState = "terminal"
)

type TerminalReport struct {
	Report      controlprotocol.ExecutorReportV3 `json:"report"`
	Digest      string                           `json:"digest"`
	CompletedAt string                           `json:"completed_at"`
}

type Command struct {
	TenantID           string          `json:"tenant_id"`
	NodeID             string          `json:"node_id"`
	ID                 string          `json:"id"`
	DeliveryID         string          `json:"delivery_id"`
	Digest             string          `json:"digest"`
	CommandDSSE        []byte          `json:"command_dsse"`
	State              CommandState    `json:"state"`
	DeliveryGeneration uint64          `json:"delivery_generation"`
	LeaseUntil         string          `json:"lease_until,omitempty"`
	CreatedAt          string          `json:"created_at"`
	Terminal           *TerminalReport `json:"terminal,omitempty"`
}

type snapshotState struct {
	Version     int                `json:"version"`
	Tenants     []Tenant           `json:"tenants"`
	Nodes       []Node             `json:"nodes"`
	Credentials []storedCredential `json:"credentials"`
	Enrollments []storedEnrollment `json:"enrollments"`
	Commands    []storedCommand    `json:"commands"`
}

type storedCredential struct {
	Version        int                        `json:"version"`
	ID             string                     `json:"id"`
	Kind           controlauth.CredentialKind `json:"kind"`
	Role           controlauth.Role           `json:"role,omitempty"`
	TenantID       string                     `json:"tenant_id,omitempty"`
	TenantIDs      []string                   `json:"tenant_ids,omitempty"`
	NodeID         string                     `json:"node_id,omitempty"`
	Audience       string                     `json:"audience,omitempty"`
	TokenMACBase64 string                     `json:"token_mac_base64"`
	RequestID      string                     `json:"request_id,omitempty"`
	CreatedAt      string                     `json:"created_at"`
	Revoked        bool                       `json:"revoked"`
	RevokedAt      string                     `json:"revoked_at,omitempty"`
}

type storedEnrollment struct {
	Version            int      `json:"version"`
	ID                 string   `json:"id"`
	TenantIDs          []string `json:"tenant_ids"`
	NodeID             string   `json:"node_id"`
	Audience           string   `json:"audience"`
	TokenMACBase64     string   `json:"token_mac_base64"`
	CreatedAt          string   `json:"created_at"`
	ExpiresAt          string   `json:"expires_at"`
	IssueRequestID     string   `json:"issue_request_id,omitempty"`
	IssuerCredentialID string   `json:"issuer_credential_id,omitempty"`
	RequestID          string   `json:"request_id,omitempty"`
	CredentialID       string   `json:"credential_id,omitempty"`
	ConsumedAt         string   `json:"consumed_at,omitempty"`
	Revoked            bool     `json:"revoked"`
	RevokedAt          string   `json:"revoked_at,omitempty"`
}

type storedCommand struct {
	TenantID           string          `json:"tenant_id"`
	NodeID             string          `json:"node_id"`
	ID                 string          `json:"id"`
	DeliveryID         string          `json:"delivery_id"`
	Digest             string          `json:"digest"`
	CommandDSSEBase64  string          `json:"command_dsse_base64"`
	State              CommandState    `json:"state"`
	DeliveryGeneration uint64          `json:"delivery_generation"`
	LeaseUntil         string          `json:"lease_until,omitempty"`
	CreatedAt          string          `json:"created_at"`
	Terminal           *TerminalReport `json:"terminal,omitempty"`
}

type state struct {
	tenants     map[string]Tenant
	nodes       map[string]Node
	credentials map[string]controlauth.Credential
	enrollments map[string]controlauth.Enrollment
	commands    map[string]Command
}

type transaction struct {
	Version   int        `json:"version"`
	Mutations []mutation `json:"mutations"`
}

type mutation struct {
	Kind         string            `json:"kind"`
	Tenant       *Tenant           `json:"tenant,omitempty"`
	Node         *Node             `json:"node,omitempty"`
	Credential   *storedCredential `json:"credential,omitempty"`
	Enrollment   *storedEnrollment `json:"enrollment,omitempty"`
	Command      *storedCommand    `json:"command,omitempty"`
	EnrollmentID string            `json:"enrollment_id,omitempty"`
	CommandRef   *commandReference `json:"command_ref,omitempty"`
	NodeRevoke   *nodeRevocation   `json:"node_revoke,omitempty"`
}

type commandReference struct {
	TenantID string `json:"tenant_id"`
	NodeID   string `json:"node_id"`
	ID       string `json:"id"`
}

type nodeRevocation struct {
	NodeID    string `json:"node_id"`
	RevokedAt string `json:"revoked_at"`
}

const (
	mutationTenant           = "tenant_upsert"
	mutationNode             = "node_upsert"
	mutationCredential       = "credential_upsert"
	mutationEnrollment       = "enrollment_upsert"
	mutationCommand          = "command_upsert"
	mutationEnrollmentDelete = "enrollment_delete"
	mutationCommandDelete    = "command_delete"
	mutationNodeRevoke       = "node_revoke"
)

func emptyState() state {
	return state{
		tenants: make(map[string]Tenant), nodes: make(map[string]Node),
		credentials: make(map[string]controlauth.Credential), enrollments: make(map[string]controlauth.Enrollment),
		commands: make(map[string]Command),
	}
}

func (current state) clone() state {
	next := emptyState()
	for key, tenant := range current.tenants {
		next.tenants[key] = tenant
	}
	for key, node := range current.nodes {
		node.TenantIDs = append([]string(nil), node.TenantIDs...)
		node.Capabilities = copyStringSlice(node.Capabilities)
		next.nodes[key] = node
	}
	for key, credential := range current.credentials {
		credential.TokenMAC = append([]byte(nil), credential.TokenMAC...)
		credential.TenantIDs = append([]string(nil), credential.TenantIDs...)
		next.credentials[key] = credential
	}
	for key, enrollment := range current.enrollments {
		enrollment.TokenMAC = append([]byte(nil), enrollment.TokenMAC...)
		enrollment.TenantIDs = append([]string(nil), enrollment.TenantIDs...)
		next.enrollments[key] = enrollment
	}
	for key, command := range current.commands {
		next.commands[key] = cloneCommand(command)
	}
	return next
}

func cloneCommand(command Command) Command {
	command.CommandDSSE = append([]byte(nil), command.CommandDSSE...)
	if command.Terminal != nil {
		terminal := *command.Terminal
		command.Terminal = &terminal
	}
	return command
}

func credentialToStored(credential controlauth.Credential) storedCredential {
	return storedCredential{
		Version: credential.Version, ID: credential.ID, Kind: credential.Kind, Role: credential.Role,
		TenantID: credential.TenantID, TenantIDs: append([]string(nil), credential.TenantIDs...),
		NodeID: credential.NodeID, Audience: credential.Audience,
		TokenMACBase64: base64.StdEncoding.EncodeToString(credential.TokenMAC), RequestID: credential.RequestID,
		CreatedAt: credential.CreatedAt,
		Revoked:   credential.Revoked, RevokedAt: credential.RevokedAt,
	}
}

func credentialFromStored(stored storedCredential) (controlauth.Credential, error) {
	mac, err := decodeCanonicalBase64(stored.TokenMACBase64)
	if err != nil {
		return controlauth.Credential{}, err
	}
	return controlauth.Credential{
		Version: stored.Version, ID: stored.ID, Kind: stored.Kind, Role: stored.Role,
		TenantID: stored.TenantID, TenantIDs: append([]string(nil), stored.TenantIDs...),
		NodeID: stored.NodeID, Audience: stored.Audience, TokenMAC: mac, RequestID: stored.RequestID,
		CreatedAt: stored.CreatedAt,
		Revoked:   stored.Revoked, RevokedAt: stored.RevokedAt,
	}, nil
}

func enrollmentToStored(enrollment controlauth.Enrollment) storedEnrollment {
	return storedEnrollment{
		Version: enrollment.Version, ID: enrollment.ID, TenantIDs: append([]string(nil), enrollment.TenantIDs...),
		NodeID: enrollment.NodeID, Audience: enrollment.Audience,
		TokenMACBase64: base64.StdEncoding.EncodeToString(enrollment.TokenMAC), CreatedAt: enrollment.CreatedAt,
		ExpiresAt: enrollment.ExpiresAt, IssueRequestID: enrollment.IssueRequestID, IssuerCredentialID: enrollment.IssuerCredentialID,
		RequestID: enrollment.RequestID, CredentialID: enrollment.CredentialID,
		ConsumedAt: enrollment.ConsumedAt, Revoked: enrollment.Revoked, RevokedAt: enrollment.RevokedAt,
	}
}

func enrollmentFromStored(stored storedEnrollment) (controlauth.Enrollment, error) {
	mac, err := decodeCanonicalBase64(stored.TokenMACBase64)
	if err != nil {
		return controlauth.Enrollment{}, err
	}
	return controlauth.Enrollment{
		Version: stored.Version, ID: stored.ID, TenantIDs: append([]string(nil), stored.TenantIDs...),
		NodeID: stored.NodeID, Audience: stored.Audience, TokenMAC: mac, CreatedAt: stored.CreatedAt,
		ExpiresAt: stored.ExpiresAt, IssueRequestID: stored.IssueRequestID, IssuerCredentialID: stored.IssuerCredentialID,
		RequestID: stored.RequestID, CredentialID: stored.CredentialID,
		ConsumedAt: stored.ConsumedAt, Revoked: stored.Revoked, RevokedAt: stored.RevokedAt,
	}, nil
}

func commandToStored(command Command) storedCommand {
	stored := storedCommand{
		TenantID: command.TenantID, NodeID: command.NodeID, ID: command.ID, DeliveryID: command.DeliveryID,
		Digest: command.Digest, CommandDSSEBase64: base64.StdEncoding.EncodeToString(command.CommandDSSE),
		State: command.State, DeliveryGeneration: command.DeliveryGeneration, LeaseUntil: command.LeaseUntil,
		CreatedAt: command.CreatedAt,
	}
	if command.Terminal != nil {
		terminal := *command.Terminal
		stored.Terminal = &terminal
	}
	return stored
}

func commandFromStored(stored storedCommand) (Command, error) {
	raw, err := decodeCanonicalBase64(stored.CommandDSSEBase64)
	if err != nil {
		return Command{}, err
	}
	command := Command{
		TenantID: stored.TenantID, NodeID: stored.NodeID, ID: stored.ID, DeliveryID: stored.DeliveryID,
		Digest: stored.Digest, CommandDSSE: raw, State: stored.State,
		DeliveryGeneration: stored.DeliveryGeneration, LeaseUntil: stored.LeaseUntil, CreatedAt: stored.CreatedAt,
	}
	if stored.Terminal != nil {
		terminal := *stored.Terminal
		command.Terminal = &terminal
	}
	return command, nil
}

func decodeCanonicalBase64(value string) ([]byte, error) {
	if value == "" {
		return nil, errors.New("base64 field is empty")
	}
	raw, err := base64.StdEncoding.DecodeString(value)
	if err != nil || base64.StdEncoding.EncodeToString(raw) != value {
		return nil, errors.New("base64 field is not canonical")
	}
	return raw, nil
}

func encodeState(current state, limit int) ([]byte, error) {
	snapshot := snapshotState{
		Version: stateFormatVersion, Tenants: []Tenant{}, Nodes: []Node{}, Credentials: []storedCredential{},
		Enrollments: []storedEnrollment{}, Commands: []storedCommand{},
	}
	for _, tenant := range current.tenants {
		snapshot.Tenants = append(snapshot.Tenants, tenant)
	}
	for _, node := range current.nodes {
		node.TenantIDs = append([]string(nil), node.TenantIDs...)
		node.Capabilities = copyStringSlice(node.Capabilities)
		snapshot.Nodes = append(snapshot.Nodes, node)
	}
	for _, credential := range current.credentials {
		snapshot.Credentials = append(snapshot.Credentials, credentialToStored(credential))
	}
	for _, enrollment := range current.enrollments {
		snapshot.Enrollments = append(snapshot.Enrollments, enrollmentToStored(enrollment))
	}
	for _, command := range current.commands {
		snapshot.Commands = append(snapshot.Commands, commandToStored(command))
	}
	sort.Slice(snapshot.Tenants, func(i, j int) bool { return snapshot.Tenants[i].ID < snapshot.Tenants[j].ID })
	sort.Slice(snapshot.Nodes, func(i, j int) bool { return snapshot.Nodes[i].ID < snapshot.Nodes[j].ID })
	sort.Slice(snapshot.Credentials, func(i, j int) bool { return snapshot.Credentials[i].ID < snapshot.Credentials[j].ID })
	sort.Slice(snapshot.Enrollments, func(i, j int) bool { return snapshot.Enrollments[i].ID < snapshot.Enrollments[j].ID })
	sort.Slice(snapshot.Commands, func(i, j int) bool {
		left, right := snapshot.Commands[i], snapshot.Commands[j]
		if left.TenantID != right.TenantID {
			return left.TenantID < right.TenantID
		}
		if left.NodeID != right.NodeID {
			return left.NodeID < right.NodeID
		}
		return left.ID < right.ID
	})
	raw, err := json.Marshal(snapshot)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || len(raw) > limit {
		return nil, ErrCapacityExceeded
	}
	return raw, nil
}

func decodeState(raw []byte, limit int) (state, error) {
	var snapshot snapshotState
	if err := dsse.DecodeStrictInto(raw, limit, &snapshot); err != nil {
		return state{}, err
	}
	if snapshot.Version != stateFormatVersion || snapshot.Tenants == nil || snapshot.Nodes == nil ||
		snapshot.Credentials == nil || snapshot.Enrollments == nil || snapshot.Commands == nil {
		return state{}, errors.New("control snapshot has an invalid version or missing collection")
	}
	current := emptyState()
	for _, tenant := range snapshot.Tenants {
		if _, exists := current.tenants[tenant.ID]; exists {
			return state{}, errors.New("control snapshot contains a duplicate tenant")
		}
		current.tenants[tenant.ID] = tenant
	}
	for _, node := range snapshot.Nodes {
		if _, exists := current.nodes[node.ID]; exists {
			return state{}, errors.New("control snapshot contains a duplicate node")
		}
		node.TenantIDs = append([]string(nil), node.TenantIDs...)
		node.Capabilities = copyStringSlice(node.Capabilities)
		current.nodes[node.ID] = node
	}
	for _, stored := range snapshot.Credentials {
		credential, err := credentialFromStored(stored)
		if err != nil {
			return state{}, fmt.Errorf("control snapshot credential encoding: %w", err)
		}
		if _, exists := current.credentials[credential.ID]; exists {
			return state{}, errors.New("control snapshot contains a duplicate credential")
		}
		current.credentials[credential.ID] = credential
	}
	for _, stored := range snapshot.Enrollments {
		enrollment, err := enrollmentFromStored(stored)
		if err != nil {
			return state{}, fmt.Errorf("control snapshot enrollment encoding: %w", err)
		}
		if _, exists := current.enrollments[enrollment.ID]; exists {
			return state{}, errors.New("control snapshot contains a duplicate enrollment")
		}
		current.enrollments[enrollment.ID] = enrollment
	}
	for _, stored := range snapshot.Commands {
		command, err := commandFromStored(stored)
		if err != nil {
			return state{}, fmt.Errorf("control snapshot command encoding: %w", err)
		}
		key := commandKey(command.TenantID, command.NodeID, command.ID)
		if _, exists := current.commands[key]; exists {
			return state{}, errors.New("control snapshot contains a duplicate command")
		}
		current.commands[key] = cloneCommand(command)
	}
	return current, nil
}

func encodeTransaction(mutations ...mutation) ([]byte, error) {
	if len(mutations) == 0 || len(mutations) > maxMutationsPerRecord {
		return nil, errors.New("control transaction mutation count is invalid")
	}
	return json.Marshal(transaction{Version: transactionFormatVersion, Mutations: mutations})
}

func decodeTransaction(raw []byte, limit int) (transaction, error) {
	var value transaction
	if err := dsse.DecodeStrictInto(raw, limit, &value); err != nil {
		return transaction{}, err
	}
	if value.Version != transactionFormatVersion || len(value.Mutations) == 0 || len(value.Mutations) > maxMutationsPerRecord {
		return transaction{}, errors.New("control transaction has invalid version or mutation count")
	}
	return value, nil
}

func applyTransaction(current state, value transaction) (state, error) {
	next := current.clone()
	for _, change := range value.Mutations {
		present := 0
		if change.Tenant != nil {
			present++
		}
		if change.Node != nil {
			present++
		}
		if change.Credential != nil {
			present++
		}
		if change.Enrollment != nil {
			present++
		}
		if change.Command != nil {
			present++
		}
		if change.EnrollmentID != "" {
			present++
		}
		if change.CommandRef != nil {
			present++
		}
		if change.NodeRevoke != nil {
			present++
		}
		if present != 1 {
			return state{}, errors.New("control mutation must carry exactly one record")
		}
		switch change.Kind {
		case mutationTenant:
			if change.Tenant == nil {
				return state{}, errors.New("tenant mutation is missing tenant")
			}
			next.tenants[change.Tenant.ID] = *change.Tenant
		case mutationNode:
			if change.Node == nil {
				return state{}, errors.New("node mutation is missing node")
			}
			node := *change.Node
			node.TenantIDs = append([]string(nil), change.Node.TenantIDs...)
			node.Capabilities = copyStringSlice(change.Node.Capabilities)
			next.nodes[node.ID] = node
		case mutationCredential:
			if change.Credential == nil {
				return state{}, errors.New("credential mutation is missing credential")
			}
			credential, err := credentialFromStored(*change.Credential)
			if err != nil {
				return state{}, fmt.Errorf("credential mutation encoding: %w", err)
			}
			next.credentials[credential.ID] = credential
		case mutationEnrollment:
			if change.Enrollment == nil {
				return state{}, errors.New("enrollment mutation is missing enrollment")
			}
			enrollment, err := enrollmentFromStored(*change.Enrollment)
			if err != nil {
				return state{}, fmt.Errorf("enrollment mutation encoding: %w", err)
			}
			next.enrollments[enrollment.ID] = enrollment
		case mutationCommand:
			if change.Command == nil {
				return state{}, errors.New("command mutation is missing command")
			}
			command, err := commandFromStored(*change.Command)
			if err != nil {
				return state{}, fmt.Errorf("command mutation encoding: %w", err)
			}
			next.commands[commandKey(command.TenantID, command.NodeID, command.ID)] = command
		case mutationEnrollmentDelete:
			if change.EnrollmentID == "" || !validRecordID(change.EnrollmentID, 128) {
				return state{}, errors.New("enrollment deletion is missing its identity")
			}
			if _, exists := next.enrollments[change.EnrollmentID]; !exists {
				return state{}, errors.New("enrollment deletion references missing state")
			}
			delete(next.enrollments, change.EnrollmentID)
		case mutationCommandDelete:
			if change.CommandRef == nil || !validRecordID(change.CommandRef.TenantID, 128) ||
				!validRecordID(change.CommandRef.NodeID, 128) || !validRecordID(change.CommandRef.ID, 256) {
				return state{}, errors.New("command deletion is missing its identity")
			}
			key := commandKey(change.CommandRef.TenantID, change.CommandRef.NodeID, change.CommandRef.ID)
			if _, exists := next.commands[key]; !exists {
				return state{}, errors.New("command deletion references missing state")
			}
			delete(next.commands, key)
		case mutationNodeRevoke:
			if change.NodeRevoke == nil || !validRecordID(change.NodeRevoke.NodeID, 128) ||
				!validTimestamp(change.NodeRevoke.RevokedAt) {
				return state{}, errors.New("node revocation is invalid")
			}
			node, exists := next.nodes[change.NodeRevoke.NodeID]
			if !exists {
				return state{}, errors.New("node revocation references missing state")
			}
			node.Active = false
			node.RevokedAt = change.NodeRevoke.RevokedAt
			next.nodes[node.ID] = node
			for id, credential := range next.credentials {
				if credential.Kind == controlauth.KindNode && credential.NodeID == node.ID && !credential.Revoked {
					credential.Revoked = true
					credential.RevokedAt = change.NodeRevoke.RevokedAt
					next.credentials[id] = credential
				}
			}
			for id, enrollment := range next.enrollments {
				if enrollment.NodeID == node.ID && !enrollment.Revoked {
					enrollment.Revoked = true
					enrollment.RevokedAt = change.NodeRevoke.RevokedAt
					next.enrollments[id] = enrollment
				}
			}
		default:
			return state{}, errors.New("control mutation kind is unsupported")
		}
	}
	return next, nil
}

func validateState(current state, limits Limits) error {
	if len(current.tenants) > limits.MaxTenants || len(current.nodes) > limits.MaxNodes ||
		len(current.credentials) > limits.MaxCredentials || len(current.enrollments) > limits.MaxEnrollments ||
		len(current.commands) > limits.MaxCommands {
		return ErrCapacityExceeded
	}
	for key, tenant := range current.tenants {
		if key != tenant.ID || !validRecordID(tenant.ID, 128) || !validTimestamp(tenant.CreatedAt) {
			return errors.New("control state contains an invalid tenant")
		}
	}
	nodesByTenant := make(map[string]int)
	for key, node := range current.nodes {
		if key != node.ID || !validRecordID(node.ID, 128) || !validTenantSet(node.TenantIDs) ||
			!validCapabilities(node.Capabilities) || !validTimestamp(node.CreatedAt) ||
			node.LastSeenAt != "" && !validTimestamp(node.LastSeenAt) || node.RevokedAt != "" && !validTimestamp(node.RevokedAt) ||
			node.Active == (node.RevokedAt != "") {
			return errors.New("control state contains an invalid node")
		}
		created, _ := parseTimestamp(node.CreatedAt)
		if node.LastSeenAt != "" {
			lastSeen, _ := parseTimestamp(node.LastSeenAt)
			if lastSeen.Before(created) {
				return errors.New("control node observation predates creation")
			}
		}
		if node.RevokedAt != "" {
			revoked, _ := parseTimestamp(node.RevokedAt)
			if revoked.Before(created) {
				return errors.New("control node revocation predates creation")
			}
		}
		for _, tenantID := range node.TenantIDs {
			if _, ok := current.tenants[tenantID]; !ok {
				return errors.New("control node references an unknown tenant")
			}
			nodesByTenant[tenantID]++
			if nodesByTenant[tenantID] > limits.MaxNodesPerTenant {
				return ErrCapacityExceeded
			}
		}
	}
	credentialsByTenant := make(map[string]int)
	operatorRequests := make(map[string]string)
	for key, credential := range current.credentials {
		if key != credential.ID || controlauth.ValidateCredential(credential) != nil {
			return errors.New("control state contains an invalid credential")
		}
		if credential.Kind == controlauth.KindOperator && credential.RequestID != "" {
			if existingID, exists := operatorRequests[credential.RequestID]; exists && existingID != credential.ID {
				return errors.New("control state contains a duplicate operator request identity")
			}
			operatorRequests[credential.RequestID] = credential.ID
		}
		if credential.Kind == controlauth.KindOperator && credential.TenantID != "" {
			if _, ok := current.tenants[credential.TenantID]; !ok {
				return errors.New("control credential references an unknown tenant")
			}
			credentialsByTenant[credential.TenantID]++
			if credentialsByTenant[credential.TenantID] > limits.MaxCredentialsPerTenant {
				return ErrCapacityExceeded
			}
		}
		if credential.Kind == controlauth.KindNode {
			node, ok := current.nodes[credential.NodeID]
			if !ok || !tenantSubset(credential.TenantIDs, node.TenantIDs) {
				return errors.New("node credential references an unknown node")
			}
			for _, tenantID := range credential.TenantIDs {
				credentialsByTenant[tenantID]++
				if credentialsByTenant[tenantID] > limits.MaxCredentialsPerTenant {
					return ErrCapacityExceeded
				}
			}
		}
	}
	enrollmentsByTenant := make(map[string]int)
	enrollmentRequests := make(map[string]string)
	for key, enrollment := range current.enrollments {
		if key != enrollment.ID || controlauth.ValidateEnrollment(enrollment) != nil {
			return errors.New("control state contains an invalid enrollment")
		}
		node, ok := current.nodes[enrollment.NodeID]
		if !ok || !tenantSubset(enrollment.TenantIDs, node.TenantIDs) {
			return errors.New("control enrollment references an unknown node or tenant binding")
		}
		if enrollment.CredentialID != "" {
			if _, ok := current.credentials[enrollment.CredentialID]; !ok {
				return errors.New("consumed enrollment references an unknown credential")
			}
		}
		if enrollment.IssueRequestID != "" {
			issuer, ok := current.credentials[enrollment.IssuerCredentialID]
			if !ok || issuer.Kind != controlauth.KindOperator {
				return errors.New("enrollment issuance references an unknown operator credential")
			}
			requestKey := enrollment.IssuerCredentialID + "\x00" + enrollment.IssueRequestID
			if existingID, exists := enrollmentRequests[requestKey]; exists && existingID != enrollment.ID {
				return errors.New("control state contains a duplicate enrollment request identity")
			}
			enrollmentRequests[requestKey] = enrollment.ID
		}
		for _, tenantID := range enrollment.TenantIDs {
			enrollmentsByTenant[tenantID]++
			if enrollmentsByTenant[tenantID] > limits.MaxEnrollmentsPerTenant {
				return ErrCapacityExceeded
			}
		}
	}
	tenantCommands := make(map[string]int)
	nodeCommands := make(map[string]int)
	for key, command := range current.commands {
		if key != commandKey(command.TenantID, command.NodeID, command.ID) || validateCommand(command, limits) != nil {
			return errors.New("control state contains an invalid command")
		}
		node, ok := current.nodes[command.NodeID]
		if !ok || !tenantMember(node.TenantIDs, command.TenantID) {
			return errors.New("control command references an unknown node")
		}
		tenantCommands[command.TenantID]++
		nodeCommands[nodeTenantKey(command.TenantID, command.NodeID)]++
		if tenantCommands[command.TenantID] > limits.MaxCommandsPerTenant ||
			nodeCommands[nodeTenantKey(command.TenantID, command.NodeID)] > limits.MaxCommandsPerNode {
			return ErrCapacityExceeded
		}
	}
	if raw, err := encodeState(current, limits.MaxStateBytes); err != nil {
		return err
	} else if len(raw) > limits.MaxStateBytes {
		return ErrCapacityExceeded
	}
	return nil
}

func validateCommand(command Command, limits Limits) error {
	expectedDeliveryID, deliveryIDError := controlprotocol.ExecutorDeliveryID(command.TenantID, command.NodeID, command.ID)
	if !validRecordID(command.TenantID, 128) || !validRecordID(command.NodeID, 128) ||
		!validRecordID(command.ID, 256) || !validRecordID(command.DeliveryID, 256) ||
		deliveryIDError != nil || command.DeliveryID != expectedDeliveryID ||
		len(command.CommandDSSE) == 0 || len(command.CommandDSSE) > limits.MaxCommandBytes ||
		command.Digest != digestBytes(command.CommandDSSE) || !validTimestamp(command.CreatedAt) {
		return errors.New("invalid command identity or bytes")
	}
	created, _ := parseTimestamp(command.CreatedAt)
	switch command.State {
	case CommandPending:
		if command.DeliveryGeneration != 0 || command.LeaseUntil != "" || command.Terminal != nil {
			return errors.New("pending command contains delivery state")
		}
	case CommandLeased:
		if command.DeliveryGeneration == 0 || !validTimestamp(command.LeaseUntil) || command.Terminal != nil {
			return errors.New("leased command has invalid delivery state")
		}
		leaseUntil, _ := parseTimestamp(command.LeaseUntil)
		if !leaseUntil.After(created) {
			return errors.New("command lease does not follow submission")
		}
	case CommandTerminal:
		if command.DeliveryGeneration == 0 || command.LeaseUntil != "" || command.Terminal == nil {
			return errors.New("terminal command has invalid delivery state")
		}
		if err := command.Terminal.Report.Validate(); err != nil ||
			command.Terminal.Report.DeliveryID != command.DeliveryID ||
			command.Terminal.Report.DeliveryGeneration != command.DeliveryGeneration ||
			command.Terminal.Report.CommandID != command.ID ||
			command.Terminal.Report.CommandDigest != command.Digest || !validTimestamp(command.Terminal.CompletedAt) {
			return errors.New("terminal report does not bind the command")
		}
		raw, err := json.Marshal(command.Terminal.Report)
		if err != nil || len(raw) > limits.MaxReportBytes || command.Terminal.Digest != digestBytes(raw) {
			return errors.New("terminal report digest or size is invalid")
		}
		completed, _ := parseTimestamp(command.Terminal.CompletedAt)
		if completed.Before(created) {
			return errors.New("terminal report predates command submission")
		}
	default:
		return errors.New("command state is invalid")
	}
	return nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func deliveryID(tenantID, nodeID, commandID string) string {
	value, _ := controlprotocol.ExecutorDeliveryID(tenantID, nodeID, commandID)
	return value
}

func commandKey(tenantID, nodeID, commandID string) string {
	return tenantID + "\x00" + nodeID + "\x00" + commandID
}

func nodeTenantKey(tenantID, nodeID string) string { return tenantID + "\x00" + nodeID }

func validTenantSet(tenantIDs []string) bool {
	canonical, err := controlauth.CanonicalTenantIDs(tenantIDs)
	if err != nil || len(canonical) != len(tenantIDs) {
		return false
	}
	for index := range tenantIDs {
		if canonical[index] != tenantIDs[index] {
			return false
		}
	}
	return true
}

func tenantMember(tenantIDs []string, tenantID string) bool {
	index := sort.SearchStrings(tenantIDs, tenantID)
	return index < len(tenantIDs) && tenantIDs[index] == tenantID
}

func tenantSubset(subset, superset []string) bool {
	if !validTenantSet(subset) || !validTenantSet(superset) {
		return false
	}
	for _, tenantID := range subset {
		if !tenantMember(superset, tenantID) {
			return false
		}
	}
	return true
}

func canonicalCapabilities(capabilities []string) ([]string, error) {
	if capabilities == nil || len(capabilities) > 64 {
		return nil, errors.New("node capabilities must be a present collection with at most 64 entries")
	}
	canonical := copyStringSlice(capabilities)
	for _, capability := range canonical {
		if !validRecordID(capability, 128) {
			return nil, errors.New("node capability is invalid")
		}
	}
	sort.Strings(canonical)
	for index := 1; index < len(canonical); index++ {
		if canonical[index] == canonical[index-1] {
			return nil, errors.New("node capability is duplicated")
		}
	}
	return canonical, nil
}

func copyStringSlice(values []string) []string {
	if values == nil {
		return nil
	}
	result := make([]string, len(values))
	copy(result, values)
	return result
}

func validCapabilities(capabilities []string) bool {
	canonical, err := canonicalCapabilities(capabilities)
	if err != nil || len(canonical) != len(capabilities) {
		return false
	}
	for index := range capabilities {
		if capabilities[index] != canonical[index] {
			return false
		}
	}
	return true
}

func validRecordID(value string, limit int) bool {
	if value == "" || len(value) > limit || !utf8.ValidString(value) || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\r\n\x00") {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' || character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

func canonicalTimestamp(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func validTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero() && value == parsed.UTC().Format(time.RFC3339Nano)
}

func parseTimestamp(value string) (time.Time, error) {
	if !validTimestamp(value) {
		return time.Time{}, errors.New("invalid canonical timestamp")
	}
	return time.Parse(time.RFC3339Nano, value)
}

func reportDigest(report controlprotocol.ExecutorReportV3) (string, []byte, error) {
	raw, err := json.Marshal(report)
	if err != nil {
		return "", nil, err
	}
	return digestBytes(raw), raw, nil
}

func commandsEqual(left, right Command) bool {
	return left.TenantID == right.TenantID && left.NodeID == right.NodeID && left.ID == right.ID &&
		left.Digest == right.Digest && bytes.Equal(left.CommandDSSE, right.CommandDSSE)
}

func formatStateError(err error) error {
	if errors.Is(err, ErrCapacityExceeded) {
		return ErrCapacityExceeded
	}
	return fmt.Errorf("validate control state: %w", err)
}
