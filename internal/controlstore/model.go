package controlstore

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/activationcanary"
	"github.com/hardrails/steward/internal/admission"
	"github.com/hardrails/steward/internal/controlauth"
	"github.com/hardrails/steward/internal/controlprotocol"
	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/evidence"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	stateFormatMinReadVersion         = 1
	stateFormatWriteVersion           = 9
	stateFormatMaxReadVersion         = stateFormatWriteVersion
	stateFormatEvidenceVersion        = 2
	stateFormatExecutorV4Version      = 3
	stateFormatCaptureVersion         = 4
	stateFormatDeploymentVersion      = 5
	stateFormatWorkloadLeaseVersion   = 6
	stateFormatSchedulingVersion      = 7
	stateFormatNodePlacementVersion   = 8
	stateFormatFleetOperationsVersion = 9
	transactionFormatMinReadVersion   = 1
	transactionFormatWriteVersion     = 9
	transactionFormatMaxReadVersion   = transactionFormatWriteVersion
	transactionEvidenceVersion        = 2
	transactionExecutorV4Version      = 3
	transactionCaptureVersion         = 4
	transactionDeploymentVersion      = 5
	transactionWorkloadLeaseVersion   = 6
	transactionSchedulingVersion      = 7
	transactionNodePlacementVersion   = 8
	transactionFleetOperationsVersion = 9
	maxMutationsPerRecord             = 128

	MaxEvidenceCapturesActive        = 16
	MaxEvidenceCapturesRetained      = 256
	MaxEvidenceCaptureFrames         = controlprotocol.MaxControllerEvidenceCaptureFrames
	MaxEvidenceCaptureDecodedBytes   = controlprotocol.MaxControllerEvidenceCaptureDecodedBytes
	MaxEvidenceCaptureAggregateBytes = 16 << 20
	MinEvidenceCaptureTTL            = time.Second
	MaxEvidenceCaptureTTL            = time.Hour
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
	MaxDeployments          int
	MaxDeploymentsPerTenant int
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
		MaxDeployments: 1024, MaxDeploymentsPerTenant: 128,
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
		limits.MaxDeployments <= 0 || limits.MaxDeploymentsPerTenant <= 0 ||
		limits.MaxCommandBytes <= 0 || limits.MaxReportBytes <= 0 || limits.MaxStateBytes <= 0 ||
		limits.MaxRecordBytes <= 0 || limits.MaxWALBytes <= 0 || limits.TerminalRetention <= 0 {
		return errors.New("every control store limit must be positive")
	}
	if limits.MaxNodesPerTenant > limits.MaxNodes || limits.MaxCredentialsPerTenant > limits.MaxCredentials ||
		limits.MaxEnrollmentsPerTenant > limits.MaxEnrollments ||
		limits.MaxCommandsPerTenant > limits.MaxCommands || limits.MaxCommandsPerNode > limits.MaxCommands ||
		limits.MaxDeploymentsPerTenant > limits.MaxDeployments ||
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
	ID           string           `json:"id"`
	TenantIDs    []string         `json:"tenant_ids"`
	Capabilities []string         `json:"capabilities"`
	Evidence     *EvidenceWitness `json:"evidence,omitempty"`
	Scheduling   *NodeScheduling  `json:"scheduling,omitempty"`
	Placement    *NodePlacement   `json:"placement,omitempty"`
	Drain        *NodeDrain       `json:"drain,omitempty"`
	CreatedAt    string           `json:"created_at"`
	LastSeenAt   string           `json:"last_seen_at,omitempty"`
	RevokedAt    string           `json:"revoked_at,omitempty"`
	Active       bool             `json:"active"`
}

type NodeDrainState string

const (
	NodeDrainActive    NodeDrainState = "active"
	NodeDrainCompleted NodeDrainState = "completed"
	NodeDrainCancelled NodeDrainState = "cancelled"
)

// NodeDrain is the controller-owned intent for a planned, disruption-budgeted
// evacuation. Starting a drain also cordons the node. Completed and cancelled
// records remain visible until a later request replaces them.
type NodeDrain struct {
	RequestID   string         `json:"request_id"`
	State       NodeDrainState `json:"state"`
	Reason      string         `json:"reason"`
	RequestedAt string         `json:"requested_at"`
	UpdatedAt   string         `json:"updated_at"`
	CompletedAt string         `json:"completed_at,omitempty"`
}

type NodePlacementMode string

const (
	NodeSchedulable NodePlacementMode = "schedulable"
	NodeCordoned    NodePlacementMode = "cordoned"
	NodeQuarantined NodePlacementMode = "quarantined"
)

// NodePlacement is the controller-owned scheduling and command-delivery gate.
// A nil value is the legacy representation of schedulable.
type NodePlacement struct {
	Mode      NodePlacementMode `json:"mode"`
	Reason    string            `json:"reason,omitempty"`
	ChangedAt string            `json:"changed_at"`
}

// NodeScheduling is the most recent controller-timestamped capacity and
// placement observation accepted from the authenticated Executor node.
type NodeScheduling struct {
	Observation controlprotocol.ExecutorSchedulingObservationV1 `json:"observation"`
	ObservedAt  string                                          `json:"observed_at"`
}

type EvidenceFindingReason string

const (
	EvidenceRollback EvidenceFindingReason = "rollback"
	EvidenceFork     EvidenceFindingReason = "fork"
)

// EvidenceFinding retains the first and most recent authenticated divergence
// together with the exact controller checkpoints used for comparison, without
// allowing hostile nodes to grow controller state. Count saturates at
// MaxUint64; a later valid extension never erases the finding.
type EvidenceFinding struct {
	FirstReason            EvidenceFindingReason `json:"first_reason"`
	FirstComparedSequence  uint64                `json:"first_compared_sequence"`
	FirstComparedChainHash string                `json:"first_compared_chain_hash"`
	FirstSequence          uint64                `json:"first_sequence"`
	FirstChainHash         string                `json:"first_chain_hash"`
	FirstObservedAt        string                `json:"first_observed_at"`
	LastReason             EvidenceFindingReason `json:"last_reason"`
	LastComparedSequence   uint64                `json:"last_compared_sequence"`
	LastComparedChainHash  string                `json:"last_compared_chain_hash"`
	LastSequence           uint64                `json:"last_sequence"`
	LastChainHash          string                `json:"last_chain_hash"`
	LastObservedAt         string                `json:"last_observed_at"`
	Count                  uint64                `json:"count"`
	CountSaturated         bool                  `json:"count_saturated,omitempty"`
}

// EvidenceWitness is the bounded controller-side state for one Executor
// receipt chain. Full signed records remain on the node.
type EvidenceWitness struct {
	IdentityProof   controlprotocol.ExecutorEvidenceIdentityProofV1 `json:"identity_proof"`
	ReceiptNodeID   string                                          `json:"receipt_node_id"`
	Epoch           uint64                                          `json:"epoch"`
	PublicKeyBase64 string                                          `json:"public_key_base64"`
	KeyID           string                                          `json:"key_id"`
	PublicKeyDigest string                                          `json:"public_key_digest"`
	PinnedAt        string                                          `json:"pinned_at"`
	Sequence        uint64                                          `json:"sequence"`
	ChainHash       string                                          `json:"chain_hash"`
	AdvancedAt      string                                          `json:"advanced_at,omitempty"`
	RecordsAccepted uint64                                          `json:"records_accepted"`
	LastBatchStart  uint64                                          `json:"last_batch_start,omitempty"`
	LastBatchEnd    uint64                                          `json:"last_batch_end,omitempty"`
	LastBatchDigest string                                          `json:"last_batch_digest,omitempty"`
	Finding         *EvidenceFinding                                `json:"finding,omitempty"`
}

type CommandState string

const (
	CommandPending  CommandState = "pending"
	CommandLeased   CommandState = "leased"
	CommandTerminal CommandState = "terminal"
)

type TerminalReport struct {
	Report           controlprotocol.ExecutorReportV3                  `json:"report"`
	Admission        *controlprotocol.ExecutorAdmissionProjectionV1    `json:"admission,omitempty"`
	ActivationCanary *controlprotocol.ExecutorActivationCanaryResultV1 `json:"activation_canary,omitempty"`
	Digest           string                                            `json:"digest"`
	CompletedAt      string                                            `json:"completed_at"`
}

type Command struct {
	TenantID                 string          `json:"tenant_id"`
	NodeID                   string          `json:"node_id"`
	ID                       string          `json:"id"`
	DeliveryID               string          `json:"delivery_id"`
	Digest                   string          `json:"digest"`
	CommandDSSE              []byte          `json:"command_dsse"`
	CommandKind              string          `json:"-"`
	SignedRuntimeRef         string          `json:"-"`
	SignedClaimGeneration    uint64          `json:"-"`
	SignedInstanceGeneration uint64          `json:"-"`
	State                    CommandState    `json:"state"`
	DeliveryProtocol         int             `json:"delivery_protocol,omitempty"`
	DeliveryGeneration       uint64          `json:"delivery_generation"`
	LeaseUntil               string          `json:"lease_until,omitempty"`
	CreatedAt                string          `json:"created_at"`
	Terminal                 *TerminalReport `json:"terminal,omitempty"`
}

type DeploymentDesiredState string

const (
	DeploymentRunning DeploymentDesiredState = "running"
	DeploymentAbsent  DeploymentDesiredState = "absent"
)

type DeploymentPhase string

const (
	DeploymentPending     DeploymentPhase = "pending"
	DeploymentReconciling DeploymentPhase = "reconciling"
	DeploymentReady       DeploymentPhase = "ready"
	DeploymentStopping    DeploymentPhase = "stopping"
	DeploymentRemoved     DeploymentPhase = "removed"
	DeploymentDegraded    DeploymentPhase = "degraded"
)

type DeploymentInstancePhase string

const (
	DeploymentInstancePending    DeploymentInstancePhase = "pending"
	DeploymentInstanceAdmitting  DeploymentInstancePhase = "admitting"
	DeploymentInstanceStarting   DeploymentInstancePhase = "starting"
	DeploymentInstanceRunning    DeploymentInstancePhase = "running"
	DeploymentInstanceStopping   DeploymentInstancePhase = "stopping"
	DeploymentInstanceDestroying DeploymentInstancePhase = "destroying"
	DeploymentInstanceRemoved    DeploymentInstancePhase = "removed"
	DeploymentInstanceFailed     DeploymentInstancePhase = "failed"
)

// DeploymentInstance is the controller's durable progress record for one
// exact instance named by the tenant-signed delegation.
type DeploymentInstance struct {
	InstanceID string                                         `json:"instance_id"`
	LineageID  string                                         `json:"lineage_id"`
	Generation uint64                                         `json:"generation"`
	NodeID     string                                         `json:"node_id,omitempty"`
	Placement  *DeploymentPlacementDecision                   `json:"placement,omitempty"`
	Drain      *DeploymentInstanceDrain                       `json:"drain,omitempty"`
	Intent     *admission.InstanceIntent                      `json:"intent,omitempty"`
	Admission  *controlprotocol.ExecutorAdmissionProjectionV1 `json:"admission,omitempty"`
	// LeaseExpiresAt is the latest signed lease expiry that Executor could have
	// accepted. It is persisted before delivery and is therefore a conservative
	// replacement safety bound even when the terminal report is lost.
	LeaseExpiresAt   string                  `json:"lease_expires_at,omitempty"`
	Phase            DeploymentInstancePhase `json:"phase"`
	CommandID        string                  `json:"command_id,omitempty"`
	CommandOperation string                  `json:"command_operation,omitempty"`
	CommandSequence  uint64                  `json:"command_sequence,omitempty"`
	Attempts         uint32                  `json:"attempts,omitempty"`
	LastError        string                  `json:"last_error,omitempty"`
	TransitionedAt   string                  `json:"transitioned_at"`
}

// DeploymentInstanceDrain records one move before the first stop command is
// issued. Source authority remains explicit while NodeID is cleared between a
// proven destroy and replacement admission.
type DeploymentInstanceDrain struct {
	RequestID    string `json:"request_id"`
	SourceNodeID string `json:"source_node_id"`
	StartedAt    string `json:"started_at"`
}

type DeploymentDisruptionBudget struct {
	MaxUnavailable int `json:"max_unavailable"`
}

// DeploymentPlacementDecision is the bounded explanation retained with the
// admission cursor. Hard eligibility and capacity are rechecked separately in
// the enqueue transaction; this record explains the deterministic soft ranking
// that selected the node.
type DeploymentPlacementDecision struct {
	NodeID                       string   `json:"node_id"`
	PreferredLabelMatches        []string `json:"preferred_label_matches"`
	PreferredLabelCount          int      `json:"preferred_label_count"`
	SpreadBy                     string   `json:"spread_by,omitempty"`
	SpreadValue                  string   `json:"spread_value,omitempty"`
	SpreadLabelPresent           bool     `json:"spread_label_present,omitempty"`
	SameDeploymentInSpreadDomain int      `json:"same_deployment_in_spread_domain"`
	AssignedWorkloads            int      `json:"assigned_workloads"`
	DecidedAt                    string   `json:"decided_at"`
}

// Deployment is bounded desired state. It contains public signed artifacts,
// never a tenant or controller private key.
type Deployment struct {
	TenantID         string                     `json:"tenant_id"`
	ID               string                     `json:"id"`
	Generation       uint64                     `json:"generation"`
	Revision         uint64                     `json:"revision"`
	AgentName        string                     `json:"agent_name"`
	BundleDigest     string                     `json:"bundle_digest"`
	CapsuleDSSE      []byte                     `json:"-"`
	DelegationDSSE   []byte                     `json:"-"`
	DesiredState     DeploymentDesiredState     `json:"desired_state"`
	DisruptionBudget DeploymentDisruptionBudget `json:"disruption_budget"`
	Phase            DeploymentPhase            `json:"phase"`
	Instances        []DeploymentInstance       `json:"instances"`
	CreatedAt        string                     `json:"created_at"`
	UpdatedAt        string                     `json:"updated_at"`
}

type EvidenceCaptureState string

const (
	EvidenceCaptureArmed    EvidenceCaptureState = "armed"
	EvidenceCaptureObserved EvidenceCaptureState = "observed"
	EvidenceCaptureSealed   EvidenceCaptureState = "sealed"
	EvidenceCaptureExpired  EvidenceCaptureState = "expired"
	EvidenceCaptureFailed   EvidenceCaptureState = "failed"
)

type EvidenceCaptureFailure string

const (
	EvidenceCaptureFailureOverflow      EvidenceCaptureFailure = "capture_overflow"
	EvidenceCaptureFailureCoordinate    EvidenceCaptureFailure = "coordinate_changed"
	EvidenceCaptureFailureFinding       EvidenceCaptureFailure = "evidence_finding"
	EvidenceCaptureFailureContradiction EvidenceCaptureFailure = "target_contradiction"
	EvidenceCaptureFailureCapacity      EvidenceCaptureFailure = "storage_capacity"
)

// EvidenceCapture is the bounded, frame-free operator view of a controller
// evidence capture. Exact signed frames are returned only by the sealed export
// snapshot path.
type EvidenceCapture struct {
	CaptureID                  string                                 `json:"capture_id"`
	RequestID                  string                                 `json:"request_id"`
	NodeID                     string                                 `json:"node_id"`
	TenantID                   string                                 `json:"tenant_id"`
	RuntimeRef                 string                                 `json:"runtime_ref"`
	Generation                 uint64                                 `json:"generation"`
	ActivationID               string                                 `json:"activation_id"`
	ActivationBeginDigest      string                                 `json:"activation_begin_digest"`
	ActivationBeginSequence    uint64                                 `json:"activation_begin_sequence,omitempty"`
	State                      EvidenceCaptureState                   `json:"state"`
	BaselineHead               controlprotocol.ExecutorEvidenceHeadV1 `json:"baseline_head"`
	FinalHead                  controlprotocol.ExecutorEvidenceHeadV1 `json:"final_head"`
	FrameCount                 int                                    `json:"frame_count"`
	CapturedBytes              int                                    `json:"captured_bytes"`
	CapsuleDigest              string                                 `json:"capsule_digest,omitempty"`
	PolicyDigest               string                                 `json:"policy_digest,omitempty"`
	ActivationCheckpointDigest string                                 `json:"activation_checkpoint_digest,omitempty"`
	CanaryCommandID            string                                 `json:"canary_command_id,omitempty"`
	ArmedAt                    string                                 `json:"armed_at"`
	ExpiresAt                  string                                 `json:"expires_at"`
	ObservedAt                 string                                 `json:"observed_at,omitempty"`
	SealedAt                   string                                 `json:"sealed_at,omitempty"`
	ExpiredAt                  string                                 `json:"expired_at,omitempty"`
	FailedAt                   string                                 `json:"failed_at,omitempty"`
	Failure                    EvidenceCaptureFailure                 `json:"failure,omitempty"`
}

type storedEvidenceCapture struct {
	CaptureID                     string                                          `json:"capture_id"`
	RequestID                     string                                          `json:"request_id"`
	NodeID                        string                                          `json:"node_id"`
	TenantID                      string                                          `json:"tenant_id"`
	RuntimeRef                    string                                          `json:"runtime_ref"`
	Generation                    uint64                                          `json:"generation"`
	ActivationID                  string                                          `json:"activation_id"`
	ActivationBeginDigest         string                                          `json:"activation_begin_digest"`
	ActivationBeginSequence       uint64                                          `json:"activation_begin_sequence,omitempty"`
	ActivationLatestStartSequence uint64                                          `json:"activation_latest_start_sequence,omitempty"`
	State                         EvidenceCaptureState                            `json:"state"`
	BaselineHead                  controlprotocol.ExecutorEvidenceHeadV1          `json:"baseline_head"`
	FinalHead                     controlprotocol.ExecutorEvidenceHeadV1          `json:"final_head"`
	FrameCount                    int                                             `json:"frame_count"`
	CapturedBytes                 int                                             `json:"captured_bytes"`
	CapsuleDigest                 string                                          `json:"capsule_digest,omitempty"`
	PolicyDigest                  string                                          `json:"policy_digest,omitempty"`
	ActivationCheckpointDigest    string                                          `json:"activation_checkpoint_digest,omitempty"`
	CanaryCommandID               string                                          `json:"canary_command_id,omitempty"`
	ArmedAt                       string                                          `json:"armed_at"`
	ExpiresAt                     string                                          `json:"expires_at"`
	ObservedAt                    string                                          `json:"observed_at,omitempty"`
	SealedAt                      string                                          `json:"sealed_at,omitempty"`
	ExpiredAt                     string                                          `json:"expired_at,omitempty"`
	FailedAt                      string                                          `json:"failed_at,omitempty"`
	Failure                       EvidenceCaptureFailure                          `json:"failure,omitempty"`
	IdentityProof                 controlprotocol.ExecutorEvidenceIdentityProofV1 `json:"identity_proof"`
	FramesBase64                  []string                                        `json:"frames"`
	Frames                        [][]byte                                        `json:"-"`
}

type snapshotState struct {
	Version     int                     `json:"version"`
	Tenants     []Tenant                `json:"tenants"`
	Nodes       []Node                  `json:"nodes"`
	Credentials []storedCredential      `json:"credentials"`
	Enrollments []storedEnrollment      `json:"enrollments"`
	Commands    []storedCommand         `json:"commands"`
	Captures    []storedEvidenceCapture `json:"captures"`
	Deployments []storedDeployment      `json:"deployments"`
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
	DeliveryProtocol   int             `json:"delivery_protocol,omitempty"`
	DeliveryGeneration uint64          `json:"delivery_generation"`
	LeaseUntil         string          `json:"lease_until,omitempty"`
	CreatedAt          string          `json:"created_at"`
	Terminal           *TerminalReport `json:"terminal,omitempty"`
}

type storedDeployment struct {
	TenantID             string                     `json:"tenant_id"`
	ID                   string                     `json:"id"`
	Generation           uint64                     `json:"generation"`
	Revision             uint64                     `json:"revision"`
	AgentName            string                     `json:"agent_name"`
	BundleDigest         string                     `json:"bundle_digest"`
	CapsuleDSSEBase64    string                     `json:"capsule_dsse_base64"`
	DelegationDSSEBase64 string                     `json:"delegation_dsse_base64"`
	DesiredState         DeploymentDesiredState     `json:"desired_state"`
	DisruptionBudget     DeploymentDisruptionBudget `json:"disruption_budget"`
	Phase                DeploymentPhase            `json:"phase"`
	Instances            []DeploymentInstance       `json:"instances"`
	CreatedAt            string                     `json:"created_at"`
	UpdatedAt            string                     `json:"updated_at"`
}

type state struct {
	tenants     map[string]Tenant
	nodes       map[string]Node
	credentials map[string]controlauth.Credential
	enrollments map[string]controlauth.Enrollment
	commands    map[string]Command
	captures    map[string]storedEvidenceCapture
	deployments map[string]Deployment
}

type transaction struct {
	Version   int        `json:"version"`
	Mutations []mutation `json:"mutations"`
}

type mutation struct {
	Kind         string                 `json:"kind"`
	Tenant       *Tenant                `json:"tenant,omitempty"`
	Node         *Node                  `json:"node,omitempty"`
	Credential   *storedCredential      `json:"credential,omitempty"`
	Enrollment   *storedEnrollment      `json:"enrollment,omitempty"`
	Command      *storedCommand         `json:"command,omitempty"`
	EnrollmentID string                 `json:"enrollment_id,omitempty"`
	CommandRef   *commandReference      `json:"command_ref,omitempty"`
	NodeRevoke   *nodeRevocation        `json:"node_revoke,omitempty"`
	Capture      *storedEvidenceCapture `json:"capture,omitempty"`
	CaptureID    string                 `json:"capture_id,omitempty"`
	Deployment   *storedDeployment      `json:"deployment,omitempty"`
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
	mutationCapture          = "evidence_capture_upsert"
	mutationCaptureDelete    = "evidence_capture_delete"
	mutationDeployment       = "deployment_upsert"
)

func emptyState() state {
	return state{
		tenants: make(map[string]Tenant), nodes: make(map[string]Node),
		credentials: make(map[string]controlauth.Credential), enrollments: make(map[string]controlauth.Enrollment),
		commands: make(map[string]Command), captures: make(map[string]storedEvidenceCapture),
		deployments: make(map[string]Deployment),
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
		node.Evidence = cloneEvidenceWitness(node.Evidence)
		node.Scheduling = cloneNodeScheduling(node.Scheduling)
		node.Placement = cloneNodePlacement(node.Placement)
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
	for key, capture := range current.captures {
		next.captures[key] = cloneStoredEvidenceCapture(capture)
	}
	for key, deployment := range current.deployments {
		next.deployments[key] = cloneDeployment(deployment)
	}
	return next
}

func cloneStoredEvidenceCapture(capture storedEvidenceCapture) storedEvidenceCapture {
	if capture.FramesBase64 != nil {
		encoded := make([]string, len(capture.FramesBase64))
		copy(encoded, capture.FramesBase64)
		capture.FramesBase64 = encoded
	}
	capture.Frames = cloneEvidenceCaptureFrames(capture.Frames)
	return capture
}

func evidenceCaptureView(capture storedEvidenceCapture) EvidenceCapture {
	return EvidenceCapture{
		CaptureID: capture.CaptureID, RequestID: capture.RequestID,
		NodeID: capture.NodeID, TenantID: capture.TenantID,
		RuntimeRef: capture.RuntimeRef, Generation: capture.Generation,
		ActivationID: capture.ActivationID, ActivationBeginDigest: capture.ActivationBeginDigest,
		ActivationBeginSequence: capture.ActivationBeginSequence, State: capture.State,
		BaselineHead: capture.BaselineHead, FinalHead: capture.FinalHead,
		FrameCount: capture.FrameCount, CapturedBytes: capture.CapturedBytes,
		CapsuleDigest: capture.CapsuleDigest, PolicyDigest: capture.PolicyDigest,
		ActivationCheckpointDigest: capture.ActivationCheckpointDigest,
		CanaryCommandID:            capture.CanaryCommandID,
		ArmedAt:                    capture.ArmedAt, ExpiresAt: capture.ExpiresAt,
		ObservedAt: capture.ObservedAt, SealedAt: capture.SealedAt,
		ExpiredAt: capture.ExpiredAt, FailedAt: capture.FailedAt,
		Failure: capture.Failure,
	}
}

func cloneEvidenceCaptureFrames(frames [][]byte) [][]byte {
	cloned := make([][]byte, len(frames))
	for index := range frames {
		cloned[index] = append([]byte(nil), frames[index]...)
	}
	return cloned
}

func cloneEvidenceWitness(witness *EvidenceWitness) *EvidenceWitness {
	if witness == nil {
		return nil
	}
	cloned := *witness
	if witness.Finding != nil {
		finding := *witness.Finding
		cloned.Finding = &finding
	}
	return &cloned
}

func cloneCommand(command Command) Command {
	command.CommandDSSE = append([]byte(nil), command.CommandDSSE...)
	if command.Terminal != nil {
		terminal := *command.Terminal
		terminal.Admission = cloneAdmissionProjection(terminal.Admission)
		terminal.ActivationCanary = cloneActivationCanaryResult(terminal.ActivationCanary)
		command.Terminal = &terminal
	}
	return command
}

func cloneDeployment(deployment Deployment) Deployment {
	deployment.CapsuleDSSE = append([]byte(nil), deployment.CapsuleDSSE...)
	deployment.DelegationDSSE = append([]byte(nil), deployment.DelegationDSSE...)
	deployment.Instances = append([]DeploymentInstance(nil), deployment.Instances...)
	for index := range deployment.Instances {
		deployment.Instances[index].Placement = cloneDeploymentPlacement(deployment.Instances[index].Placement)
		deployment.Instances[index].Drain = cloneDeploymentInstanceDrain(deployment.Instances[index].Drain)
		deployment.Instances[index].Intent = cloneInstanceIntent(deployment.Instances[index].Intent)
		deployment.Instances[index].Admission = cloneAdmissionProjection(deployment.Instances[index].Admission)
	}
	return deployment
}

func cloneDeploymentInstanceDrain(value *DeploymentInstanceDrain) *DeploymentInstanceDrain {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func cloneDeploymentPlacement(value *DeploymentPlacementDecision) *DeploymentPlacementDecision {
	if value == nil {
		return nil
	}
	cloned := *value
	if value.PreferredLabelMatches != nil {
		cloned.PreferredLabelMatches = append([]string{}, value.PreferredLabelMatches...)
	}
	return &cloned
}

func deploymentToStored(deployment Deployment) storedDeployment {
	return storedDeployment{
		TenantID: deployment.TenantID, ID: deployment.ID,
		Generation: deployment.Generation, Revision: deployment.Revision,
		AgentName: deployment.AgentName, BundleDigest: deployment.BundleDigest,
		CapsuleDSSEBase64:    base64.StdEncoding.EncodeToString(deployment.CapsuleDSSE),
		DelegationDSSEBase64: base64.StdEncoding.EncodeToString(deployment.DelegationDSSE),
		DesiredState:         deployment.DesiredState, Phase: deployment.Phase,
		DisruptionBudget: deployment.DisruptionBudget,
		Instances:        cloneDeployment(deployment).Instances,
		CreatedAt:        deployment.CreatedAt, UpdatedAt: deployment.UpdatedAt,
	}
}

func deploymentFromStored(stored storedDeployment) (Deployment, error) {
	capsule, err := decodeCanonicalBase64(stored.CapsuleDSSEBase64)
	if err != nil {
		return Deployment{}, fmt.Errorf("capsule encoding: %w", err)
	}
	delegation, err := decodeCanonicalBase64(stored.DelegationDSSEBase64)
	if err != nil {
		return Deployment{}, fmt.Errorf("delegation encoding: %w", err)
	}
	return Deployment{
		TenantID: stored.TenantID, ID: stored.ID,
		Generation: stored.Generation, Revision: stored.Revision,
		AgentName: stored.AgentName, BundleDigest: stored.BundleDigest,
		CapsuleDSSE: capsule, DelegationDSSE: delegation,
		DesiredState: stored.DesiredState, DisruptionBudget: stored.DisruptionBudget, Phase: stored.Phase,
		Instances: cloneDeployment(Deployment{Instances: stored.Instances}).Instances,
		CreatedAt: stored.CreatedAt, UpdatedAt: stored.UpdatedAt,
	}, nil
}

func cloneInstanceIntent(intent *admission.InstanceIntent) *admission.InstanceIntent {
	if intent == nil {
		return nil
	}
	cloned := *intent
	cloned.EgressRouteIDs = copyStringSlice(intent.EgressRouteIDs)
	cloned.ConnectorIDs = copyStringSlice(intent.ConnectorIDs)
	return &cloned
}

func cloneAdmissionProjection(projection *controlprotocol.ExecutorAdmissionProjectionV1) *controlprotocol.ExecutorAdmissionProjectionV1 {
	if projection == nil {
		return nil
	}
	cloned := *projection
	cloned.TaskAuthorities = append([]controlprotocol.ExecutorTaskAuthorityV1(nil), projection.TaskAuthorities...)
	cloned.EgressRouteIDs = copyStringSlice(projection.EgressRouteIDs)
	cloned.ConnectorIDs = copyStringSlice(projection.ConnectorIDs)
	return &cloned
}

func cloneActivationCanaryResult(
	result *controlprotocol.ExecutorActivationCanaryResultV1,
) *controlprotocol.ExecutorActivationCanaryResultV1 {
	if result == nil {
		return nil
	}
	cloned := *result
	return &cloned
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
		State: command.State, DeliveryProtocol: command.DeliveryProtocol,
		DeliveryGeneration: command.DeliveryGeneration, LeaseUntil: command.LeaseUntil,
		CreatedAt: command.CreatedAt,
	}
	if command.Terminal != nil {
		terminal := *command.Terminal
		terminal.Admission = cloneAdmissionProjection(terminal.Admission)
		terminal.ActivationCanary = cloneActivationCanaryResult(terminal.ActivationCanary)
		stored.Terminal = &terminal
	}
	return stored
}

func commandFromStored(stored storedCommand, supportsExecutorV4 bool) (Command, error) {
	raw, err := decodeCanonicalBase64(stored.CommandDSSEBase64)
	if err != nil {
		return Command{}, err
	}
	binding, err := parseCommandBinding(raw)
	if err != nil {
		return Command{}, fmt.Errorf("parse signed command binding: %w", err)
	}
	binding = retainedCommandBinding(binding)
	deliveryProtocol := stored.DeliveryProtocol
	if !supportsExecutorV4 {
		if stored.DeliveryProtocol != 0 ||
			stored.Terminal != nil && (stored.Terminal.Report.ProtocolVersion != controlprotocol.ExecutorProtocolV3 ||
				stored.Terminal.Admission != nil) {
			return Command{}, errors.New("legacy command contains protocol-4 delivery state")
		}
		if stored.State == CommandLeased || stored.State == CommandTerminal {
			deliveryProtocol = controlprotocol.ExecutorProtocolV3
		}
	}
	command := Command{
		TenantID: stored.TenantID, NodeID: stored.NodeID, ID: stored.ID, DeliveryID: stored.DeliveryID,
		Digest: stored.Digest, CommandDSSE: raw,
		CommandKind: binding.Kind, SignedRuntimeRef: binding.RuntimeRef,
		SignedClaimGeneration:    binding.ClaimGeneration,
		SignedInstanceGeneration: binding.InstanceGeneration,
		State:                    stored.State, DeliveryProtocol: deliveryProtocol,
		DeliveryGeneration: stored.DeliveryGeneration, LeaseUntil: stored.LeaseUntil, CreatedAt: stored.CreatedAt,
	}
	if stored.Terminal != nil {
		terminal := *stored.Terminal
		terminal.Admission = cloneAdmissionProjection(stored.Terminal.Admission)
		terminal.ActivationCanary = cloneActivationCanaryResult(stored.Terminal.ActivationCanary)
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
		Version: stateFormatWriteVersion, Tenants: []Tenant{}, Nodes: []Node{}, Credentials: []storedCredential{},
		Enrollments: []storedEnrollment{}, Commands: []storedCommand{}, Captures: []storedEvidenceCapture{},
		Deployments: []storedDeployment{},
	}
	for _, tenant := range current.tenants {
		snapshot.Tenants = append(snapshot.Tenants, tenant)
	}
	for _, node := range current.nodes {
		node.TenantIDs = append([]string(nil), node.TenantIDs...)
		node.Capabilities = copyStringSlice(node.Capabilities)
		node.Evidence = cloneEvidenceWitness(node.Evidence)
		node.Scheduling = cloneNodeScheduling(node.Scheduling)
		node.Placement = cloneNodePlacement(node.Placement)
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
	for _, capture := range current.captures {
		snapshot.Captures = append(snapshot.Captures, cloneStoredEvidenceCapture(capture))
	}
	for _, deployment := range current.deployments {
		snapshot.Deployments = append(snapshot.Deployments, deploymentToStored(deployment))
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
	sort.Slice(snapshot.Captures, func(i, j int) bool {
		return snapshot.Captures[i].CaptureID < snapshot.Captures[j].CaptureID
	})
	sort.Slice(snapshot.Deployments, func(i, j int) bool {
		left, right := snapshot.Deployments[i], snapshot.Deployments[j]
		if left.TenantID != right.TenantID {
			return left.TenantID < right.TenantID
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
	if snapshot.Version < stateFormatMinReadVersion || snapshot.Version > stateFormatMaxReadVersion ||
		snapshot.Tenants == nil || snapshot.Nodes == nil ||
		snapshot.Credentials == nil || snapshot.Enrollments == nil || snapshot.Commands == nil ||
		snapshot.Version >= stateFormatCaptureVersion && snapshot.Captures == nil ||
		snapshot.Version < stateFormatCaptureVersion && snapshot.Captures != nil ||
		snapshot.Version >= stateFormatDeploymentVersion && snapshot.Deployments == nil ||
		snapshot.Version < stateFormatDeploymentVersion && snapshot.Deployments != nil {
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
		if snapshot.Version < stateFormatEvidenceVersion && node.Evidence != nil {
			return state{}, errors.New("legacy control snapshot contains evidence witness state")
		}
		if snapshot.Version < stateFormatSchedulingVersion && node.Scheduling != nil {
			return state{}, errors.New("legacy control snapshot contains scheduling observation state")
		}
		if snapshot.Version < stateFormatNodePlacementVersion && node.Placement != nil {
			return state{}, errors.New("legacy control snapshot contains node placement state")
		}
		if snapshot.Version < stateFormatFleetOperationsVersion && node.Drain != nil {
			return state{}, errors.New("legacy control snapshot contains node drain state")
		}
		if node.Placement != nil && !validNodePlacement(*node.Placement) {
			return state{}, errors.New("control snapshot contains invalid node placement state")
		}
		if node.Drain != nil && !validNodeDrain(*node.Drain) {
			return state{}, errors.New("control snapshot contains invalid node drain state")
		}
		node.Evidence = cloneEvidenceWitness(node.Evidence)
		node.Scheduling = cloneNodeScheduling(node.Scheduling)
		node.Placement = cloneNodePlacement(node.Placement)
		node.Drain = cloneNodeDrain(node.Drain)
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
		command, err := commandFromStored(stored, snapshot.Version >= stateFormatExecutorV4Version)
		if err != nil {
			return state{}, fmt.Errorf("control snapshot command encoding: %w", err)
		}
		key := commandKey(command.TenantID, command.NodeID, command.ID)
		if _, exists := current.commands[key]; exists {
			return state{}, errors.New("control snapshot contains a duplicate command")
		}
		current.commands[key] = cloneCommand(command)
	}
	for _, capture := range snapshot.Captures {
		if err := hydrateStoredEvidenceCapture(&capture); err != nil {
			return state{}, fmt.Errorf("control snapshot evidence capture encoding: %w", err)
		}
		if _, exists := current.captures[capture.CaptureID]; exists {
			return state{}, errors.New("control snapshot contains a duplicate evidence capture")
		}
		current.captures[capture.CaptureID] = cloneStoredEvidenceCapture(capture)
	}
	for _, stored := range snapshot.Deployments {
		deployment, err := deploymentFromStored(stored)
		if err != nil {
			return state{}, fmt.Errorf("control snapshot deployment encoding: %w", err)
		}
		if snapshot.Version < stateFormatWorkloadLeaseVersion && deploymentUsesWorkloadLeaseFormat(deployment) {
			return state{}, errors.New("legacy control snapshot contains workload lease state")
		}
		if snapshot.Version < stateFormatFleetOperationsVersion {
			if deploymentUsesFleetOperationsFormat(deployment) {
				return state{}, errors.New("legacy control snapshot contains fleet operations state")
			}
			deployment.DisruptionBudget = DeploymentDisruptionBudget{MaxUnavailable: 1}
		}
		key := deploymentKey(deployment.TenantID, deployment.ID)
		if _, exists := current.deployments[key]; exists {
			return state{}, errors.New("control snapshot contains a duplicate deployment")
		}
		current.deployments[key] = cloneDeployment(deployment)
	}
	return current, nil
}

func encodeTransaction(mutations ...mutation) ([]byte, error) {
	if len(mutations) == 0 || len(mutations) > maxMutationsPerRecord {
		return nil, errors.New("control transaction mutation count is invalid")
	}
	return json.Marshal(transaction{Version: transactionFormatWriteVersion, Mutations: mutations})
}

func decodeTransaction(raw []byte, limit int) (transaction, error) {
	var value transaction
	if err := dsse.DecodeStrictInto(raw, limit, &value); err != nil {
		return transaction{}, err
	}
	if value.Version < transactionFormatMinReadVersion || value.Version > transactionFormatMaxReadVersion ||
		len(value.Mutations) == 0 || len(value.Mutations) > maxMutationsPerRecord {
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
		if change.Capture != nil {
			present++
		}
		if change.CaptureID != "" {
			present++
		}
		if change.Deployment != nil {
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
			if value.Version < transactionEvidenceVersion && node.Evidence != nil {
				return state{}, errors.New("legacy control transaction contains evidence witness state")
			}
			if value.Version < transactionSchedulingVersion && node.Scheduling != nil {
				return state{}, errors.New("legacy control transaction contains scheduling observation state")
			}
			if value.Version < transactionNodePlacementVersion && node.Placement != nil {
				return state{}, errors.New("legacy control transaction contains node placement state")
			}
			if value.Version < transactionFleetOperationsVersion && node.Drain != nil {
				return state{}, errors.New("legacy control transaction contains node drain state")
			}
			if node.Placement != nil && !validNodePlacement(*node.Placement) {
				return state{}, errors.New("control transaction contains invalid node placement state")
			}
			if node.Drain != nil && !validNodeDrain(*node.Drain) {
				return state{}, errors.New("control transaction contains invalid node drain state")
			}
			node.TenantIDs = append([]string(nil), change.Node.TenantIDs...)
			node.Capabilities = copyStringSlice(change.Node.Capabilities)
			node.Evidence = cloneEvidenceWitness(change.Node.Evidence)
			node.Scheduling = cloneNodeScheduling(change.Node.Scheduling)
			node.Placement = cloneNodePlacement(change.Node.Placement)
			node.Drain = cloneNodeDrain(change.Node.Drain)
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
			command, err := commandFromStored(*change.Command, value.Version >= transactionExecutorV4Version)
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
		case mutationCapture:
			if value.Version < transactionCaptureVersion || change.Capture == nil {
				return state{}, errors.New("evidence capture mutation is invalid for this transaction version")
			}
			capture := *change.Capture
			if err := hydrateStoredEvidenceCapture(&capture); err != nil {
				return state{}, fmt.Errorf("evidence capture mutation encoding: %w", err)
			}
			capture = cloneStoredEvidenceCapture(capture)
			next.captures[capture.CaptureID] = capture
		case mutationCaptureDelete:
			if value.Version < transactionCaptureVersion || change.CaptureID == "" ||
				!validRecordID(change.CaptureID, 128) {
				return state{}, errors.New("evidence capture deletion is invalid for this transaction version")
			}
			if _, exists := next.captures[change.CaptureID]; !exists {
				return state{}, errors.New("evidence capture deletion references missing state")
			}
			delete(next.captures, change.CaptureID)
		case mutationDeployment:
			if value.Version < transactionDeploymentVersion || change.Deployment == nil {
				return state{}, errors.New("deployment mutation is invalid for this transaction version")
			}
			deployment, err := deploymentFromStored(*change.Deployment)
			if err != nil {
				return state{}, fmt.Errorf("deployment mutation encoding: %w", err)
			}
			if value.Version < transactionWorkloadLeaseVersion && deploymentUsesWorkloadLeaseFormat(deployment) {
				return state{}, errors.New("legacy deployment mutation contains workload lease state")
			}
			if value.Version < transactionFleetOperationsVersion {
				if deploymentUsesFleetOperationsFormat(deployment) {
					return state{}, errors.New("legacy deployment mutation contains fleet operations state")
				}
				deployment.DisruptionBudget = DeploymentDisruptionBudget{MaxUnavailable: 1}
			}
			next.deployments[deploymentKey(deployment.TenantID, deployment.ID)] = cloneDeployment(deployment)
		default:
			return state{}, errors.New("control mutation kind is unsupported")
		}
	}
	return next, nil
}

func deploymentUsesWorkloadLeaseFormat(deployment Deployment) bool {
	for _, instance := range deployment.Instances {
		if instance.LeaseExpiresAt != "" ||
			instance.CommandID == "" && instance.CommandOperation == "" && instance.CommandSequence > 0 {
			return true
		}
	}
	return false
}

func deploymentUsesFleetOperationsFormat(deployment Deployment) bool {
	if deployment.DisruptionBudget.MaxUnavailable != 0 {
		return true
	}
	for _, instance := range deployment.Instances {
		if instance.Placement != nil || instance.Drain != nil {
			return true
		}
	}
	return false
}

func validateState(current state, limits Limits) error {
	if len(current.tenants) > limits.MaxTenants || len(current.nodes) > limits.MaxNodes ||
		len(current.credentials) > limits.MaxCredentials || len(current.enrollments) > limits.MaxEnrollments ||
		len(current.commands) > limits.MaxCommands || len(current.captures) > MaxEvidenceCapturesRetained ||
		len(current.deployments) > limits.MaxDeployments {
		return ErrCapacityExceeded
	}
	for key, tenant := range current.tenants {
		if key != tenant.ID || !validRecordID(tenant.ID, 128) || !validTimestamp(tenant.CreatedAt) {
			return errors.New("control state contains an invalid tenant")
		}
	}
	nodesByTenant := make(map[string]int)
	evidenceKeys := make(map[string]string)
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
		if node.Evidence != nil {
			if err := validateEvidenceWitness(node.ID, node.CreatedAt, *node.Evidence); err != nil {
				return errors.New("control state contains an invalid evidence witness")
			}
			if existingNode, exists := evidenceKeys[node.Evidence.PublicKeyDigest]; exists && existingNode != node.ID {
				return errors.New("control evidence key is reused across nodes")
			}
			evidenceKeys[node.Evidence.PublicKeyDigest] = node.ID
		}
		if node.Scheduling != nil {
			if node.Scheduling.Observation.Validate() != nil ||
				node.Scheduling.Observation.NodeID != node.ID ||
				!validTimestamp(node.Scheduling.ObservedAt) {
				return errors.New("control state contains an invalid node scheduling observation")
			}
			observed, _ := parseTimestamp(node.Scheduling.ObservedAt)
			if observed.Before(created) {
				return errors.New("control node scheduling observation predates creation")
			}
		}
		if node.Placement != nil && !validNodePlacement(*node.Placement) ||
			node.Drain != nil && !validNodeDrain(*node.Drain) {
			return errors.New("control state contains invalid node operations state")
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
	activeCaptureNodes := make(map[string]string)
	captureRequests := make(map[string]string)
	for key, capture := range current.captures {
		if key != capture.CaptureID || validateEvidenceCapture(capture) != nil {
			return errors.New("control state contains an invalid evidence capture")
		}
		node, ok := current.nodes[capture.NodeID]
		if !ok || !tenantMember(node.TenantIDs, capture.TenantID) || node.Evidence == nil ||
			capture.IdentityProof != node.Evidence.IdentityProof {
			return errors.New("control evidence capture references an unknown node or tenant binding")
		}
		if existingID, exists := captureRequests[capture.RequestID]; exists && existingID != capture.CaptureID {
			return errors.New("control state contains a duplicate evidence capture request identity")
		}
		captureRequests[capture.RequestID] = capture.CaptureID
		if capture.State == EvidenceCaptureArmed {
			if existingID, exists := activeCaptureNodes[capture.NodeID]; exists && existingID != capture.CaptureID {
				return errors.New("control state contains more than one armed evidence capture for a node")
			}
			activeCaptureNodes[capture.NodeID] = capture.CaptureID
		}
	}
	activeCaptures, reservedCaptureBytes := evidenceCaptureUsage(current.captures)
	if activeCaptures > MaxEvidenceCapturesActive {
		return ErrCapacityExceeded
	}
	if reservedCaptureBytes > MaxEvidenceCaptureAggregateBytes {
		return ErrCapacityExceeded
	}
	deploymentsByTenant := make(map[string]int)
	for key, deployment := range current.deployments {
		if key != deploymentKey(deployment.TenantID, deployment.ID) || validateDeployment(deployment, limits) != nil {
			return errors.New("control state contains an invalid deployment")
		}
		if tenant, ok := current.tenants[deployment.TenantID]; !ok || !tenant.Active {
			return errors.New("control deployment references an unknown tenant")
		}
		deploymentsByTenant[deployment.TenantID]++
		if deploymentsByTenant[deployment.TenantID] > limits.MaxDeploymentsPerTenant {
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

func validateDeployment(deployment Deployment, limits Limits) error {
	if !validRecordID(deployment.TenantID, 128) || !validRecordID(deployment.ID, 128) ||
		!validRecordID(deployment.AgentName, 128) || !validSHA256Digest(deployment.BundleDigest) ||
		deployment.Generation == 0 || deployment.Revision == 0 ||
		len(deployment.CapsuleDSSE) == 0 || len(deployment.CapsuleDSSE) > limits.MaxCommandBytes ||
		len(deployment.DelegationDSSE) == 0 || len(deployment.DelegationDSSE) > limits.MaxCommandBytes ||
		!validTimestamp(deployment.CreatedAt) || !validTimestamp(deployment.UpdatedAt) {
		return errors.New("deployment identity or signed artifacts are invalid")
	}
	created, _ := parseTimestamp(deployment.CreatedAt)
	updated, _ := parseTimestamp(deployment.UpdatedAt)
	if updated.Before(created) {
		return errors.New("deployment update predates creation")
	}
	if deployment.DesiredState != DeploymentRunning && deployment.DesiredState != DeploymentAbsent {
		return errors.New("deployment desired state is invalid")
	}
	if deployment.DisruptionBudget.MaxUnavailable < 0 ||
		deployment.DisruptionBudget.MaxUnavailable > len(deployment.Instances) {
		return errors.New("deployment disruption budget is invalid")
	}
	switch deployment.Phase {
	case DeploymentPending, DeploymentReconciling, DeploymentReady, DeploymentStopping, DeploymentRemoved, DeploymentDegraded:
	default:
		return errors.New("deployment phase is invalid")
	}
	delegation, err := admission.InspectCommandDelegation(deployment.DelegationDSSE, time.Time{})
	if err != nil || delegation.TenantID != deployment.TenantID || delegation.Admission == nil ||
		delegation.Admission.CapsuleDigest != dsse.Digest(deployment.CapsuleDSSE) ||
		len(deployment.Instances) != len(delegation.Instances) {
		return errors.New("deployment delegation does not bind its desired state")
	}
	if envelope, err := dsse.Parse(deployment.CapsuleDSSE); err != nil || envelope.PayloadType != admission.CapsulePayloadType {
		return errors.New("deployment capsule envelope is invalid")
	}
	allowedNodes := make(map[string]struct{}, len(delegation.NodeIDs))
	for _, nodeID := range delegation.NodeIDs {
		allowedNodes[nodeID] = struct{}{}
	}
	for index, instance := range deployment.Instances {
		delegated := delegation.Instances[index]
		if instance.InstanceID != delegated.InstanceID || instance.LineageID != delegated.LineageID ||
			instance.Generation < delegated.MinInstanceGeneration || instance.Generation > delegated.MaxInstanceGeneration ||
			index > 0 && deployment.Instances[index-1].InstanceID >= instance.InstanceID ||
			instance.NodeID != "" && !validRecordID(instance.NodeID, 128) ||
			instance.NodeID != "" && !mapContains(allowedNodes, instance.NodeID) ||
			!validTimestamp(instance.TransitionedAt) || !boundedRetainedText(instance.LastError, 1024) {
			return errors.New("deployment instance identity or placement is invalid")
		}
		switch instance.Phase {
		case DeploymentInstancePending, DeploymentInstanceAdmitting, DeploymentInstanceStarting,
			DeploymentInstanceRunning, DeploymentInstanceStopping, DeploymentInstanceDestroying,
			DeploymentInstanceRemoved, DeploymentInstanceFailed:
		default:
			return errors.New("deployment instance phase is invalid")
		}
		commandEmpty := instance.CommandID == "" && instance.CommandOperation == "" && instance.CommandSequence == 0
		commandCursorOnly := instance.CommandID == "" && instance.CommandOperation == "" && instance.CommandSequence > 0
		commandComplete := validRecordID(instance.CommandID, 256) &&
			validDeploymentOperation(instance.CommandOperation) && instance.CommandSequence > 0
		if !commandEmpty && !commandCursorOnly && !commandComplete {
			return errors.New("deployment instance command cursor is incomplete")
		}
		if instance.Intent != nil {
			if err := instance.Intent.Validate(admission.AuthenticatedIdentity{
				TenantID: instance.Intent.TenantID,
				NodeID:   instance.Intent.NodeID,
			}); err != nil || instance.Intent.TenantID != deployment.TenantID ||
				instance.Intent.NodeID != instance.NodeID || instance.Intent.InstanceID != instance.InstanceID ||
				instance.Intent.LineageID != instance.LineageID || instance.Intent.Generation != instance.Generation ||
				instance.Intent.CapsuleDigest != dsse.Digest(deployment.CapsuleDSSE) {
				return errors.New("deployment instance intent is invalid")
			}
		}
		if instance.Placement != nil {
			placement := instance.Placement
			if placement.NodeID != instance.NodeID || !validRecordID(placement.NodeID, 128) ||
				placement.PreferredLabelMatches == nil || len(placement.PreferredLabelMatches) > 32 ||
				placement.PreferredLabelCount < len(placement.PreferredLabelMatches) || placement.PreferredLabelCount > 32 ||
				placement.SameDeploymentInSpreadDomain < 0 || placement.AssignedWorkloads < 0 ||
				!validTimestamp(placement.DecidedAt) {
				return errors.New("deployment placement decision is invalid")
			}
			for matchIndex, key := range placement.PreferredLabelMatches {
				if !controlprotocol.ValidSchedulingAttribute(key) ||
					matchIndex > 0 && placement.PreferredLabelMatches[matchIndex-1] >= key {
					return errors.New("deployment placement matches are not canonical")
				}
			}
			if placement.SpreadBy == "" {
				if placement.SpreadValue != "" || placement.SpreadLabelPresent || placement.SameDeploymentInSpreadDomain != 0 {
					return errors.New("deployment placement spread explanation is inconsistent")
				}
			} else if !controlprotocol.ValidSchedulingAttribute(placement.SpreadBy) ||
				placement.SpreadLabelPresent && !controlprotocol.ValidSchedulingAttribute(placement.SpreadValue) ||
				!placement.SpreadLabelPresent && placement.SpreadValue != "" {
				return errors.New("deployment placement spread explanation is invalid")
			}
		}
		if instance.Drain != nil {
			if !validRecordID(instance.Drain.RequestID, 128) ||
				!validRecordID(instance.Drain.SourceNodeID, 128) ||
				!mapContains(allowedNodes, instance.Drain.SourceNodeID) ||
				!validTimestamp(instance.Drain.StartedAt) {
				return errors.New("deployment instance drain is invalid")
			}
		}
		if instance.Admission != nil {
			if instance.Intent == nil || instance.Admission.Validate() != nil ||
				instance.Admission.Generation != instance.Generation ||
				instance.Admission.CapsuleDigest != instance.Intent.CapsuleDigest {
				return errors.New("deployment instance admission projection is invalid")
			}
		}
		if instance.LeaseExpiresAt != "" {
			leaseExpiry, parseErr := time.Parse(time.RFC3339Nano, instance.LeaseExpiresAt)
			if parseErr != nil || leaseExpiry.IsZero() ||
				instance.LeaseExpiresAt != leaseExpiry.UTC().Format(time.RFC3339Nano) {
				return errors.New("deployment instance lease expiry is invalid")
			}
		}
	}
	return nil
}

func validDeploymentOperation(operation string) bool {
	switch operation {
	case "admit", "renew", "start", "stop", "destroy":
		return true
	default:
		return false
	}
}

func mapContains(values map[string]struct{}, wanted string) bool {
	_, ok := values[wanted]
	return ok
}

func deploymentKey(tenantID, deploymentID string) string {
	return tenantID + "\x00" + deploymentID
}

func evidenceCaptureUsage(captures map[string]storedEvidenceCapture) (active, reservedBytes int) {
	for _, capture := range captures {
		if capture.State == EvidenceCaptureArmed {
			active++
			reservedBytes += MaxEvidenceCaptureDecodedBytes
		} else {
			reservedBytes += capture.CapturedBytes
		}
	}
	return active, reservedBytes
}

func validateEvidenceCapture(capture storedEvidenceCapture) error {
	if err := evidenceCaptureView(capture).Validate(); err != nil {
		return err
	}
	if !validRecordID(capture.CaptureID, 128) || !validRecordID(capture.RequestID, 128) ||
		!validRecordID(capture.NodeID, 128) || !validRecordID(capture.TenantID, 128) ||
		!validExecutorRuntimeRef(capture.RuntimeRef) || capture.Generation == 0 ||
		!validRecordID(capture.ActivationID, 128) || !validSHA256Digest(capture.ActivationBeginDigest) ||
		!validTimestamp(capture.ArmedAt) ||
		!validTimestamp(capture.ExpiresAt) || capture.BaselineHead.Validate() != nil ||
		capture.FinalHead.Validate() != nil || !sameEvidenceHeadIdentity(capture.BaselineHead, capture.FinalHead) ||
		capture.IdentityProof.Validate() != nil {
		return errors.New("evidence capture identity is invalid")
	}
	claim := capture.IdentityProof.Claim
	if claim.ControlNodeID != capture.NodeID || claim.Stream != capture.BaselineHead.Stream ||
		claim.ReceiptNodeID != capture.BaselineHead.ReceiptNodeID ||
		claim.ReceiptEpoch != capture.BaselineHead.ReceiptEpoch ||
		claim.PublicKeySHA256 != capture.BaselineHead.PublicKeySHA256 {
		return errors.New("evidence capture identity proof does not bind its heads")
	}
	armed, _ := parseTimestamp(capture.ArmedAt)
	expires, _ := parseTimestamp(capture.ExpiresAt)
	if expires.Sub(armed) < MinEvidenceCaptureTTL || expires.Sub(armed) > MaxEvidenceCaptureTTL {
		return errors.New("evidence capture lifetime is invalid")
	}
	frameBytes := 0
	if capture.Frames == nil || capture.FramesBase64 == nil ||
		len(capture.Frames) != len(capture.FramesBase64) ||
		len(capture.Frames) > MaxEvidenceCaptureFrames {
		return errors.New("evidence capture frame count exceeds its limit")
	}
	for index, frame := range capture.Frames {
		if !validNativeEvidenceFrame(frame) || frameBytes > MaxEvidenceCaptureDecodedBytes-len(frame) {
			return errors.New("evidence capture contains invalid or oversized native frames")
		}
		if base64.StdEncoding.EncodeToString(frame) != capture.FramesBase64[index] {
			return errors.New("evidence capture frame encoding is not canonical")
		}
		frameBytes += len(frame)
	}
	if capture.FrameCount != len(capture.Frames) || capture.CapturedBytes != frameBytes ||
		capture.BaselineHead.Sequence > math.MaxUint64-uint64(len(capture.Frames)) ||
		capture.FinalHead.Sequence != capture.BaselineHead.Sequence+uint64(len(capture.Frames)) {
		return errors.New("evidence capture frame coordinates are inconsistent")
	}
	for _, value := range []string{
		capture.ObservedAt, capture.SealedAt, capture.ExpiredAt, capture.FailedAt,
	} {
		if value != "" && !validTimestamp(value) {
			return errors.New("evidence capture terminal timestamp is invalid")
		}
	}
	switch capture.State {
	case EvidenceCaptureArmed:
		if capture.ObservedAt != "" || capture.SealedAt != "" || capture.ExpiredAt != "" ||
			capture.FailedAt != "" || capture.Failure != "" ||
			capture.ActivationCheckpointDigest != "" ||
			capture.CanaryCommandID != "" {
			return errors.New("armed evidence capture contains terminal state")
		}
		if capture.ActivationBeginSequence == 0 {
			if capture.CapsuleDigest != "" || capture.PolicyDigest != "" ||
				capture.ActivationLatestStartSequence != 0 {
				return errors.New("armed evidence capture contains an incomplete activation begin")
			}
		} else if !validSHA256Digest(capture.CapsuleDigest) || !validSHA256Digest(capture.PolicyDigest) ||
			capture.ActivationBeginSequence <= capture.BaselineHead.Sequence ||
			capture.ActivationBeginSequence > capture.FinalHead.Sequence ||
			(capture.ActivationLatestStartSequence != 0 &&
				(capture.ActivationLatestStartSequence <= capture.ActivationBeginSequence ||
					capture.ActivationLatestStartSequence > capture.FinalHead.Sequence)) {
			return errors.New("armed evidence capture activation begin is invalid")
		}
	case EvidenceCaptureObserved, EvidenceCaptureSealed:
		if !validTimestamp(capture.ObservedAt) || !validSHA256Digest(capture.CapsuleDigest) ||
			!validSHA256Digest(capture.PolicyDigest) || !validSHA256Digest(capture.ActivationCheckpointDigest) ||
			capture.ActivationBeginSequence <= capture.BaselineHead.Sequence ||
			capture.ActivationBeginSequence >= capture.FinalHead.Sequence ||
			(capture.ActivationLatestStartSequence != 0 &&
				(capture.ActivationLatestStartSequence <= capture.ActivationBeginSequence ||
					capture.ActivationLatestStartSequence > capture.FinalHead.Sequence)) ||
			capture.FrameCount == 0 || capture.ExpiredAt != "" || capture.FailedAt != "" || capture.Failure != "" {
			return errors.New("observed evidence capture is incomplete")
		}
		observed, _ := parseTimestamp(capture.ObservedAt)
		if observed.Before(armed) || observed.After(expires) {
			return errors.New("evidence capture observation is outside its armed interval")
		}
		if capture.State == EvidenceCaptureObserved {
			if capture.SealedAt != "" || capture.CanaryCommandID != "" {
				return errors.New("unsealed evidence capture contains seal state")
			}
		} else {
			if !validTimestamp(capture.SealedAt) || !validRecordID(capture.CanaryCommandID, 256) {
				return errors.New("sealed evidence capture is missing its command or timestamp")
			}
			sealed, _ := parseTimestamp(capture.SealedAt)
			if sealed.Before(observed) {
				return errors.New("evidence capture seal predates observation")
			}
		}
	case EvidenceCaptureExpired:
		if !validTimestamp(capture.ExpiredAt) || capture.ObservedAt != "" || capture.SealedAt != "" ||
			capture.FailedAt != "" || capture.Failure != "" || capture.CapsuleDigest != "" ||
			capture.PolicyDigest != "" || capture.ActivationBeginSequence != 0 ||
			capture.ActivationLatestStartSequence != 0 ||
			capture.ActivationCheckpointDigest != "" || capture.CanaryCommandID != "" {
			return errors.New("expired evidence capture contains inconsistent state")
		}
		expired, _ := parseTimestamp(capture.ExpiredAt)
		if expired.Before(expires) {
			return errors.New("evidence capture expired before its deadline")
		}
	case EvidenceCaptureFailed:
		if !validTimestamp(capture.FailedAt) || !validEvidenceCaptureFailure(capture.Failure) ||
			capture.ObservedAt != "" || capture.SealedAt != "" || capture.ExpiredAt != "" ||
			capture.CapsuleDigest != "" || capture.PolicyDigest != "" ||
			capture.ActivationBeginSequence != 0 || capture.ActivationLatestStartSequence != 0 ||
			capture.ActivationCheckpointDigest != "" ||
			capture.CanaryCommandID != "" {
			return errors.New("failed evidence capture contains inconsistent state")
		}
		failed, _ := parseTimestamp(capture.FailedAt)
		if failed.Before(armed) {
			return errors.New("evidence capture failure predates arming")
		}
	default:
		return errors.New("evidence capture state is invalid")
	}
	return nil
}

func hydrateStoredEvidenceCapture(capture *storedEvidenceCapture) error {
	if capture == nil || capture.FramesBase64 == nil {
		return errors.New("evidence capture frame collection is missing")
	}
	if capture.Frames != nil {
		if len(capture.Frames) != len(capture.FramesBase64) {
			return errors.New("evidence capture frame collections disagree")
		}
		return nil
	}
	capture.Frames = make([][]byte, len(capture.FramesBase64))
	for index, encoded := range capture.FramesBase64 {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil || base64.StdEncoding.EncodeToString(raw) != encoded {
			return errors.New("evidence capture frame is not canonical base64")
		}
		capture.Frames[index] = raw
	}
	return nil
}

// Validate checks the complete frame-free public capture projection. Store
// validation additionally authenticates the hidden identity proof and exact
// native frames.
func (capture EvidenceCapture) Validate() error {
	if !validRecordID(capture.CaptureID, 128) || !validRecordID(capture.RequestID, 128) ||
		!validRecordID(capture.NodeID, 128) || !validRecordID(capture.TenantID, 128) ||
		!validExecutorRuntimeRef(capture.RuntimeRef) || capture.Generation == 0 ||
		!validRecordID(capture.ActivationID, 128) || !validSHA256Digest(capture.ActivationBeginDigest) ||
		!validTimestamp(capture.ArmedAt) ||
		!validTimestamp(capture.ExpiresAt) || capture.BaselineHead.Validate() != nil ||
		capture.FinalHead.Validate() != nil || !sameEvidenceHeadIdentity(capture.BaselineHead, capture.FinalHead) ||
		capture.FrameCount < 0 || capture.FrameCount > MaxEvidenceCaptureFrames ||
		capture.CapturedBytes < 0 || capture.CapturedBytes > MaxEvidenceCaptureDecodedBytes ||
		capture.BaselineHead.Sequence > math.MaxUint64-uint64(capture.FrameCount) ||
		capture.FinalHead.Sequence != capture.BaselineHead.Sequence+uint64(capture.FrameCount) {
		return errors.New("evidence capture projection identity or coordinates are invalid")
	}
	armed, _ := parseTimestamp(capture.ArmedAt)
	expires, _ := parseTimestamp(capture.ExpiresAt)
	if expires.Sub(armed) < MinEvidenceCaptureTTL || expires.Sub(armed) > MaxEvidenceCaptureTTL {
		return errors.New("evidence capture projection lifetime is invalid")
	}
	for _, value := range []string{
		capture.ObservedAt, capture.SealedAt, capture.ExpiredAt, capture.FailedAt,
	} {
		if value != "" && !validTimestamp(value) {
			return errors.New("evidence capture projection terminal timestamp is invalid")
		}
	}
	switch capture.State {
	case EvidenceCaptureArmed:
		if capture.ObservedAt != "" || capture.SealedAt != "" || capture.ExpiredAt != "" ||
			capture.FailedAt != "" || capture.Failure != "" ||
			capture.ActivationCheckpointDigest != "" ||
			capture.CanaryCommandID != "" {
			return errors.New("armed evidence capture projection contains terminal state")
		}
		if capture.ActivationBeginSequence == 0 {
			if capture.CapsuleDigest != "" || capture.PolicyDigest != "" {
				return errors.New("armed evidence capture projection contains an incomplete activation begin")
			}
		} else if !validSHA256Digest(capture.CapsuleDigest) || !validSHA256Digest(capture.PolicyDigest) ||
			capture.ActivationBeginSequence <= capture.BaselineHead.Sequence ||
			capture.ActivationBeginSequence > capture.FinalHead.Sequence {
			return errors.New("armed evidence capture projection activation begin is invalid")
		}
	case EvidenceCaptureObserved, EvidenceCaptureSealed:
		if !validTimestamp(capture.ObservedAt) || !validSHA256Digest(capture.CapsuleDigest) ||
			!validSHA256Digest(capture.PolicyDigest) || !validSHA256Digest(capture.ActivationCheckpointDigest) ||
			capture.ActivationBeginSequence <= capture.BaselineHead.Sequence ||
			capture.ActivationBeginSequence >= capture.FinalHead.Sequence ||
			capture.FrameCount == 0 || capture.ExpiredAt != "" || capture.FailedAt != "" || capture.Failure != "" {
			return errors.New("observed evidence capture projection is incomplete")
		}
		observed, _ := parseTimestamp(capture.ObservedAt)
		if observed.Before(armed) || observed.After(expires) {
			return errors.New("evidence capture projection observation is outside its armed interval")
		}
		if capture.State == EvidenceCaptureObserved {
			if capture.SealedAt != "" || capture.CanaryCommandID != "" {
				return errors.New("unsealed evidence capture projection contains seal state")
			}
		} else {
			if !validTimestamp(capture.SealedAt) || !validRecordID(capture.CanaryCommandID, 256) {
				return errors.New("sealed evidence capture projection is missing its command or timestamp")
			}
			sealed, _ := parseTimestamp(capture.SealedAt)
			if sealed.Before(observed) {
				return errors.New("evidence capture projection seal predates observation")
			}
		}
	case EvidenceCaptureExpired:
		if !validTimestamp(capture.ExpiredAt) || capture.ObservedAt != "" || capture.SealedAt != "" ||
			capture.FailedAt != "" || capture.Failure != "" || capture.CapsuleDigest != "" ||
			capture.PolicyDigest != "" || capture.ActivationBeginSequence != 0 ||
			capture.ActivationCheckpointDigest != "" || capture.CanaryCommandID != "" {
			return errors.New("expired evidence capture projection contains inconsistent state")
		}
		expired, _ := parseTimestamp(capture.ExpiredAt)
		if expired.Before(expires) {
			return errors.New("evidence capture projection expired before its deadline")
		}
	case EvidenceCaptureFailed:
		if !validTimestamp(capture.FailedAt) || !validEvidenceCaptureFailure(capture.Failure) ||
			capture.ObservedAt != "" || capture.SealedAt != "" || capture.ExpiredAt != "" ||
			capture.CapsuleDigest != "" || capture.PolicyDigest != "" ||
			capture.ActivationBeginSequence != 0 || capture.ActivationCheckpointDigest != "" ||
			capture.CanaryCommandID != "" {
			return errors.New("failed evidence capture projection contains inconsistent state")
		}
		failed, _ := parseTimestamp(capture.FailedAt)
		if failed.Before(armed) {
			return errors.New("evidence capture projection failure predates arming")
		}
	default:
		return errors.New("evidence capture projection state is invalid")
	}
	return nil
}

func validEvidenceCaptureFailure(value EvidenceCaptureFailure) bool {
	switch value {
	case EvidenceCaptureFailureOverflow, EvidenceCaptureFailureCoordinate,
		EvidenceCaptureFailureFinding, EvidenceCaptureFailureContradiction,
		EvidenceCaptureFailureCapacity:
		return true
	default:
		return false
	}
}

func validNativeEvidenceFrame(frame []byte) bool {
	if len(frame) < 5 || len(frame) > evidence.MaxEnvelopeBytes+4 {
		return false
	}
	size := binary.BigEndian.Uint32(frame[:4])
	return size > 0 && uint64(size) == uint64(len(frame)-4)
}

func sameEvidenceHeadIdentity(left, right controlprotocol.ExecutorEvidenceHeadV1) bool {
	return left.Stream == right.Stream && left.ReceiptNodeID == right.ReceiptNodeID &&
		left.ReceiptEpoch == right.ReceiptEpoch && left.PublicKeySHA256 == right.PublicKeySHA256
}

func validExecutorRuntimeRef(value string) bool {
	const prefix = "executor-"
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+64 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, prefix) {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func validateEvidenceWitness(nodeID, nodeCreatedAt string, witness EvidenceWitness) error {
	public, err := controlprotocol.VerifyExecutorEvidenceIdentityProofV1(witness.IdentityProof)
	claim := witness.IdentityProof.Claim
	if err != nil || len(public) != ed25519.PublicKeySize || claim.ControlNodeID != nodeID ||
		claim.Stream != controlprotocol.ExecutorEvidenceStreamV1 || claim.ReceiptNodeID != witness.ReceiptNodeID ||
		claim.ReceiptEpoch != witness.Epoch || claim.PublicKeyBase64 != witness.PublicKeyBase64 ||
		claim.PublicKeySHA256 != witness.PublicKeyDigest || witness.ReceiptNodeID != nodeID || witness.Epoch == 0 ||
		witness.KeyID != evidence.KeyID(ed25519.PublicKey(public)) || witness.PublicKeyDigest != digestBytes(public) ||
		!validTimestamp(witness.PinnedAt) || !validEvidenceCoordinate(witness.Sequence, witness.ChainHash) ||
		witness.RecordsAccepted != witness.Sequence {
		return errors.New("evidence witness identity or coordinate is invalid")
	}
	created, _ := parseTimestamp(nodeCreatedAt)
	pinned, _ := parseTimestamp(witness.PinnedAt)
	if pinned.Before(created) {
		return errors.New("evidence witness predates node creation")
	}
	if witness.Sequence == 0 {
		if witness.AdvancedAt != "" || witness.LastBatchStart != 0 || witness.LastBatchEnd != 0 || witness.LastBatchDigest != "" {
			return errors.New("empty evidence witness contains advancement metadata")
		}
	} else {
		if !validTimestamp(witness.AdvancedAt) || witness.LastBatchStart == 0 || witness.LastBatchStart > witness.LastBatchEnd ||
			witness.LastBatchEnd != witness.Sequence || !validSHA256Digest(witness.LastBatchDigest) {
			return errors.New("advanced evidence witness is missing its retained batch coordinate")
		}
		advanced, _ := parseTimestamp(witness.AdvancedAt)
		if advanced.Before(pinned) {
			return errors.New("evidence witness advancement predates pinning")
		}
	}
	if witness.Finding != nil {
		if err := validateEvidenceFinding(*witness.Finding, pinned, witness.Sequence, witness.ChainHash); err != nil {
			return err
		}
	}
	return nil
}

func validateEvidenceFinding(finding EvidenceFinding, pinned time.Time, currentSequence uint64, currentChainHash string) error {
	if !validEvidenceFindingReason(finding.FirstReason) || !validEvidenceFindingReason(finding.LastReason) ||
		!validEvidenceCoordinate(finding.FirstComparedSequence, finding.FirstComparedChainHash) ||
		!validEvidenceCoordinate(finding.FirstSequence, finding.FirstChainHash) ||
		!validEvidenceCoordinate(finding.LastComparedSequence, finding.LastComparedChainHash) ||
		!validEvidenceCoordinate(finding.LastSequence, finding.LastChainHash) || finding.Count == 0 ||
		finding.CountSaturated != (finding.Count == math.MaxUint64) ||
		!validTimestamp(finding.FirstObservedAt) || !validTimestamp(finding.LastObservedAt) {
		return errors.New("evidence finding is invalid")
	}
	if !validEvidenceFindingComparison(
		finding.FirstReason, finding.FirstComparedSequence, finding.FirstComparedChainHash,
		finding.FirstSequence, finding.FirstChainHash,
	) || !validEvidenceFindingComparison(
		finding.LastReason, finding.LastComparedSequence, finding.LastComparedChainHash,
		finding.LastSequence, finding.LastChainHash,
	) || currentSequence < finding.FirstComparedSequence ||
		(currentSequence == finding.FirstComparedSequence && currentChainHash != finding.FirstComparedChainHash) ||
		currentSequence < finding.LastComparedSequence ||
		(currentSequence == finding.LastComparedSequence && currentChainHash != finding.LastComparedChainHash) {
		return errors.New("evidence finding does not conflict with a retained checkpoint")
	}
	first, _ := parseTimestamp(finding.FirstObservedAt)
	last, _ := parseTimestamp(finding.LastObservedAt)
	if first.Before(pinned) || last.Before(first) {
		return errors.New("evidence finding timestamps are inconsistent")
	}
	return nil
}

func validEvidenceFindingComparison(reason EvidenceFindingReason, comparedSequence uint64, comparedChainHash string, observedSequence uint64, observedChainHash string) bool {
	switch reason {
	case EvidenceRollback:
		return observedSequence < comparedSequence
	case EvidenceFork:
		return observedSequence > comparedSequence ||
			(observedSequence == comparedSequence && observedChainHash != comparedChainHash)
	default:
		return false
	}
}

func validEvidenceFindingReason(reason EvidenceFindingReason) bool {
	return reason == EvidenceRollback || reason == EvidenceFork
}

func validEvidenceCoordinate(sequence uint64, chainHash string) bool {
	if !validSHA256Digest(chainHash) {
		return false
	}
	if sequence == 0 {
		return chainHash == "sha256:"+strings.Repeat("0", 64)
	}
	return chainHash != "sha256:"+strings.Repeat("0", 64)
}

func validSHA256Digest(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	raw := strings.TrimPrefix(value, "sha256:")
	decoded, err := hex.DecodeString(raw)
	return err == nil && len(decoded) == sha256.Size && hex.EncodeToString(decoded) == raw
}

func validateCommand(command Command, limits Limits) error {
	expectedDeliveryID, deliveryIDError := controlprotocol.ExecutorDeliveryID(command.TenantID, command.NodeID, command.ID)
	binding, bindingError := parseCommandBinding(command.CommandDSSE)
	binding = retainedCommandBinding(binding)
	if !validRecordID(command.TenantID, 128) || !validRecordID(command.NodeID, 128) ||
		!validRecordID(command.ID, 256) || !validRecordID(command.DeliveryID, 256) ||
		deliveryIDError != nil || command.DeliveryID != expectedDeliveryID ||
		len(command.CommandDSSE) == 0 || len(command.CommandDSSE) > limits.MaxCommandBytes ||
		command.Digest != digestBytes(command.CommandDSSE) || !validTimestamp(command.CreatedAt) ||
		bindingError != nil || binding.CommandID != command.ID ||
		binding.TenantID != command.TenantID || binding.NodeID != command.NodeID ||
		binding.Kind != command.CommandKind || binding.RuntimeRef != command.SignedRuntimeRef ||
		binding.ClaimGeneration != command.SignedClaimGeneration ||
		binding.InstanceGeneration != command.SignedInstanceGeneration {
		return errors.New("invalid command identity or bytes")
	}
	created, _ := parseTimestamp(command.CreatedAt)
	switch command.State {
	case CommandPending:
		if command.DeliveryProtocol != 0 || command.DeliveryGeneration != 0 ||
			command.LeaseUntil != "" || command.Terminal != nil {
			return errors.New("pending command contains delivery state")
		}
	case CommandLeased:
		if !validExecutorDeliveryProtocol(command.DeliveryProtocol) ||
			command.DeliveryGeneration == 0 || !validTimestamp(command.LeaseUntil) || command.Terminal != nil {
			return errors.New("leased command has invalid delivery state")
		}
		leaseUntil, _ := parseTimestamp(command.LeaseUntil)
		if !leaseUntil.After(created) {
			return errors.New("command lease does not follow submission")
		}
	case CommandTerminal:
		if !validExecutorDeliveryProtocol(command.DeliveryProtocol) ||
			command.DeliveryGeneration == 0 || command.LeaseUntil != "" || command.Terminal == nil {
			return errors.New("terminal command has invalid delivery state")
		}
		if command.Terminal.Report.ProtocolVersion != command.DeliveryProtocol ||
			command.Terminal.Report.DeliveryID != command.DeliveryID ||
			command.Terminal.Report.DeliveryGeneration != command.DeliveryGeneration ||
			command.Terminal.Report.CommandID != command.ID ||
			command.Terminal.Report.CommandDigest != command.Digest || !validTimestamp(command.Terminal.CompletedAt) {
			return errors.New("terminal report does not bind the command")
		}
		raw, err := terminalReportBytes(*command.Terminal)
		if err != nil || len(raw) > limits.MaxReportBytes || command.Terminal.Digest != digestBytes(raw) {
			return errors.New("terminal report digest or size is invalid")
		}
		if command.DeliveryProtocol == controlprotocol.ExecutorProtocolV4 {
			report := executorReportV4FromTerminal(*command.Terminal)
			if err := validateRetainedExecutorReportV4Binding(command, report); err != nil {
				return errors.New("terminal protocol-4 report contradicts its signed command")
			}
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

func validExecutorDeliveryProtocol(version int) bool {
	return version == controlprotocol.ExecutorProtocolV3 || version == controlprotocol.ExecutorProtocolV4
}

func terminalReportBytes(terminal TerminalReport) ([]byte, error) {
	switch terminal.Report.ProtocolVersion {
	case controlprotocol.ExecutorProtocolV3:
		if terminal.Admission != nil || terminal.ActivationCanary != nil {
			return nil, errors.New("protocol-3 terminal report contains a protocol-4 projection")
		}
		if err := terminal.Report.Validate(); err != nil {
			return nil, err
		}
		return json.Marshal(terminal.Report)
	case controlprotocol.ExecutorProtocolV4:
		report := executorReportV4FromTerminal(terminal)
		if err := report.Validate(); err != nil {
			return nil, err
		}
		return json.Marshal(report)
	default:
		return nil, errors.New("terminal report protocol is unsupported")
	}
}

func executorReportV4FromTerminal(terminal TerminalReport) controlprotocol.ExecutorReportV4 {
	report := terminal.Report
	return controlprotocol.ExecutorReportV4{
		ProtocolVersion:    controlprotocol.ExecutorProtocolV4,
		DeliveryID:         report.DeliveryID,
		DeliveryGeneration: report.DeliveryGeneration,
		CommandID:          report.CommandID,
		CommandDigest:      report.CommandDigest,
		Status:             report.Status,
		ReportedStatus:     report.ReportedStatus,
		ClaimGeneration:    report.ClaimGeneration,
		ErrorCode:          report.ErrorCode,
		Result: controlprotocol.ExecutorReportResultV4{
			RuntimeRef:       report.Result.RuntimeRef,
			Error:            report.Result.Error,
			Replayed:         report.Result.Replayed,
			Absent:           report.Result.Absent,
			Admission:        cloneAdmissionProjection(terminal.Admission),
			ActivationCanary: cloneActivationCanaryResult(terminal.ActivationCanary),
		},
	}
}

// validateRetainedExecutorReportV4Binding checks only correlations that are
// already projected into bounded controller state. It deliberately performs
// no public-key work: validateState calls it after every mutation, including
// mutations unrelated to the retained command.
func validateRetainedExecutorReportV4Binding(command Command, report controlprotocol.ExecutorReportV4) error {
	var executorRuntimeRef string
	needsRuntimeBinding := report.Result.Admission != nil ||
		report.Result.ActivationCanary != nil ||
		command.CommandKind == "activation-canary" && report.Status == controlprotocol.ExecutorStatusDone ||
		report.Result.RuntimeRef != ""
	if needsRuntimeBinding {
		var err error
		executorRuntimeRef, err = commandExecutorRuntimeRef(command)
		if err != nil {
			return errors.New("stored command runtime identity is invalid")
		}
	}
	if report.ClaimGeneration != 0 && report.ClaimGeneration != command.SignedClaimGeneration {
		return errors.New("report claim generation differs from signed command")
	}
	if activationCanaryTerminalErrorCode(report.ErrorCode) &&
		(command.CommandKind != "activation-canary" ||
			command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
			!validActivationCanaryTerminalFailure(
				report.Status,
				report.ReportedStatus,
				report.ErrorCode,
				report.Result.Error,
			)) {
		return errors.New("activation canary terminal error code is reserved for a failed canary")
	}
	if report.Result.Admission != nil {
		if command.CommandKind != "admit" ||
			report.ClaimGeneration != command.SignedClaimGeneration ||
			report.Result.Admission.RuntimeRef != executorRuntimeRef ||
			report.Result.Admission.Generation != command.SignedInstanceGeneration {
			return errors.New("admission projection differs from signed admit command")
		}
	}
	if report.Result.ActivationCanary != nil {
		if command.CommandKind != "activation-canary" ||
			command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
			report.ClaimGeneration != command.SignedClaimGeneration ||
			command.SignedInstanceGeneration == 0 ||
			report.Result.RuntimeRef != executorRuntimeRef {
			return errors.New("activation canary projection differs from its signed command")
		}
	}
	if command.CommandKind == "activation-canary" &&
		report.Status == controlprotocol.ExecutorStatusDone &&
		(command.DeliveryProtocol != controlprotocol.ExecutorProtocolV4 ||
			report.ClaimGeneration != command.SignedClaimGeneration ||
			command.SignedInstanceGeneration == 0 ||
			report.ReportedStatus != "running" ||
			report.Result.RuntimeRef != executorRuntimeRef ||
			report.Result.ActivationCanary == nil) {
		return errors.New(
			"successful activation canary report omits its exact running proof",
		)
	}
	if command.CommandKind == "admit" && report.Status == controlprotocol.ExecutorStatusDone &&
		report.Result.RuntimeRef != "" && report.Result.RuntimeRef != executorRuntimeRef {
		return errors.New("successful admit runtime differs from signed command")
	}
	return nil
}

// validateExecutorReportV4Binding authenticates the immutable, nested canary
// command and compares the report with the exact signed permit-derived
// projection. ApplyReportV4 calls it before accepting a new terminal report;
// Open calls it once for each recovered terminal canary. Routine state
// validation uses validateRetainedExecutorReportV4Binding above.
func validateExecutorReportV4Binding(command Command, report controlprotocol.ExecutorReportV4) error {
	if err := validateRetainedExecutorReportV4Binding(command, report); err != nil {
		return err
	}
	if command.CommandKind == "activation-canary" &&
		report.Status == controlprotocol.ExecutorStatusDone {
		statement, err := parseCommandStatement(command.CommandDSSE)
		if err != nil {
			return errors.New("stored activation canary command is invalid")
		}
		parsed, err := activationcanary.ParseCommandV1(statement.Payload)
		if err != nil {
			return errors.New("stored activation canary payload is invalid")
		}
		executorRuntimeRef, runtimeErr := commandExecutorRuntimeRef(command)
		if runtimeErr != nil || parsed.Admission.RuntimeRef != executorRuntimeRef ||
			parsed.Admission.Generation != command.SignedInstanceGeneration {
			return errors.New(
				"activation canary admission differs from its signed outer command",
			)
		}
		verified, err := activationcanary.VerifyHistoricalCommandV1(
			statement.Payload,
			activationcanary.AdmissionContextV1{
				NodeID:     statement.NodeID,
				TenantID:   statement.TenantID,
				InstanceID: statement.InstanceID,
				Projection: parsed.Admission,
			},
			taskpermit.MaxValidity,
		)
		if err != nil {
			return errors.New("stored activation canary payload is invalid")
		}
		commandValue := verified.Command()
		permit := verified.Permit()
		projection := report.Result.ActivationCanary
		if projection.ActivationID != commandValue.ActivationID ||
			projection.AdmissionDigest != commandValue.AdmissionDigest ||
			projection.TaskDigest != taskpermit.TaskDigest(
				permit.Statement.TenantID,
				permit.Statement.InstanceID,
				permit.Statement.TaskID,
			) ||
			projection.PermitDigest != permit.EnvelopeDigest {
			return errors.New(
				"activation canary proof differs from its signed command payload",
			)
		}
	}
	return nil
}

// commandExecutorRuntimeRef derives the opaque host-local Executor identity
// from the signed tenant and instance identity. SignedRuntimeRef remains the
// uplink routing reference (uplink:v2:...); it is deliberately not the local
// runtime returned by the Executor and retained in admission/canary evidence.
func commandExecutorRuntimeRef(command Command) (string, error) {
	// Direct/local protocol-4 tests and older signed commands already carry the
	// opaque Executor identity. Uplink v2 commands instead carry a routable
	// tenant/node/instance tuple and must be projected to the same local value.
	if validExecutorRuntimeRef(command.SignedRuntimeRef) {
		return command.SignedRuntimeRef, nil
	}
	statement, err := parseCommandStatement(command.CommandDSSE)
	if err != nil || statement.TenantID != command.TenantID ||
		statement.NodeID != command.NodeID || statement.RuntimeRef != command.SignedRuntimeRef {
		return "", errors.New("stored command does not match its signed identity")
	}
	digest := sha256.Sum256([]byte(statement.TenantID + "\x00" + statement.InstanceID))
	return "executor-" + hex.EncodeToString(digest[:]), nil
}

func activationCanaryTerminalErrorCode(value string) bool {
	return value == "activation_canary_failed" || value == "activation_canary_cancelled"
}

func validActivationCanaryTerminalFailure(status, reportedStatus, errorCode, detail string) bool {
	if status != controlprotocol.ExecutorStatusFailed || detail == "" {
		return false
	}
	switch errorCode {
	case "activation_canary_failed":
		return reportedStatus == "failed"
	case "activation_canary_cancelled":
		return reportedStatus == "cancelled"
	default:
		return false
	}
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

func boundedRetainedText(value string, limit int) bool {
	return len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\r\n\x00")
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

func reportDigestV4(report controlprotocol.ExecutorReportV4) (string, []byte, error) {
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
