package controlprotocol

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/hardrails/steward/internal/dsse"
)

const (
	ExecutorProtocolV4                      = 4
	ExecutorCapabilityAdmissionProjectionV1 = "admission-projection-v1"
	// ExecutorCapabilityStateSnapshotsV1 means a node has a qualified storage
	// backend and accepts signed cold-snapshot and copy-on-write clone commands.
	ExecutorCapabilityStateSnapshotsV1      = "state-snapshots-v1"
	ExecutorAdmissionProjectionSchemaV1     = "steward.executor-admission-projection.v1"
	MaxExecutorReportBytes                  = 16 << 10
	executorEgressProxyV1                   = "http://steward-relay:8082"
	executorConnectorURLV1                  = "http://steward-relay:8081"
	executorEventURLV1                      = "http://steward-relay:8083/v1/events"
	maxExecutorTaskAuthorities              = 8
	maxExecutorAdmissionRouteOrConnectorIDs = 32
)

// ExecutorPollRequestV4 advertises explicit support for protocol 4. It remains
// a separate type even where fields match protocol 3 so widening this contract
// cannot silently widen an older handler.
type ExecutorPollRequestV4 struct {
	ProtocolVersion int      `json:"protocol_version"`
	NodeID          string   `json:"node_id"`
	CredentialScope string   `json:"credential_scope"`
	Capabilities    []string `json:"capabilities"`
}

// ExecutorPollResponseV4 keeps delivery members opaque until each one is
// independently validated.
type ExecutorPollResponseV4 struct {
	ProtocolVersion int               `json:"protocol_version"`
	Deliveries      []json.RawMessage `json:"deliveries"`
}

// ExecutorDeliveryV4 intentionally retains protocol 3's exact field shape,
// but remains a distinct type to preserve the immutability of both versions.
type ExecutorDeliveryV4 struct {
	DeliveryID         string `json:"delivery_id"`
	DeliveryGeneration uint64 `json:"delivery_generation"`
	CommandID          string `json:"command_id"`
	CommandDigest      string `json:"command_digest"`
	CommandDSSEBase64  string `json:"command_dsse_base64"`
}

// ExecutorTaskAuthorityV1 is the public half of one tenant task-signing key.
// Private task authority never belongs in an Executor report.
type ExecutorTaskAuthorityV1 struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}

// ExecutorAdmissionProjectionV1 is the bounded, non-secret result of one
// successful signed admission. It is an authenticated node observation, not
// independent authorization or cryptographic execution proof.
type ExecutorAdmissionProjectionV1 struct {
	SchemaVersion         string                    `json:"schema_version"`
	RuntimeRef            string                    `json:"runtime_ref"`
	Status                string                    `json:"status"`
	CapsuleDigest         string                    `json:"capsule_digest"`
	PolicyDigest          string                    `json:"policy_digest"`
	Generation            uint64                    `json:"generation"`
	EvidenceKeyID         string                    `json:"evidence_key_id"`
	GrantID               string                    `json:"grant_id,omitempty"`
	ServicePath           string                    `json:"service_path,omitempty"`
	ServiceID             string                    `json:"service_id,omitempty"`
	TaskAuthorities       []ExecutorTaskAuthorityV1 `json:"task_authorities,omitempty"`
	EgressProxy           string                    `json:"egress_proxy,omitempty"`
	EgressRouteIDs        []string                  `json:"egress_route_ids,omitempty"`
	ConnectorURL          string                    `json:"connector_url,omitempty"`
	ConnectorIDs          []string                  `json:"connector_ids,omitempty"`
	EventURL              string                    `json:"event_url,omitempty"`
	RoutePolicyDigest     string                    `json:"route_policy_digest,omitempty"`
	ActivationID          string                    `json:"activation_id,omitempty"`
	ActivationBeginDigest string                    `json:"activation_begin_digest,omitempty"`
}

// ExecutorReportResultV4 adds a bounded admission projection without changing
// the immutable protocol-3 result type.
type ExecutorReportResultV4 struct {
	RuntimeRef       string                            `json:"runtime_ref,omitempty"`
	Error            string                            `json:"error,omitempty"`
	Replayed         bool                              `json:"replayed,omitempty"`
	Absent           bool                              `json:"absent,omitempty"`
	Admission        *ExecutorAdmissionProjectionV1    `json:"admission,omitempty"`
	ActivationCanary *ExecutorActivationCanaryResultV1 `json:"activation_canary,omitempty"`
}

// ExecutorReportV4 binds a terminal observation to one exact delivery lease.
// It is deliberately not an alias of ExecutorReportV3: an existing protocol-3
// handler must reject this record until it explicitly implements version 4.
type ExecutorReportV4 struct {
	ProtocolVersion    int                    `json:"protocol_version"`
	DeliveryID         string                 `json:"delivery_id"`
	DeliveryGeneration uint64                 `json:"delivery_generation"`
	CommandID          string                 `json:"command_id"`
	CommandDigest      string                 `json:"command_digest"`
	Status             string                 `json:"status"`
	ReportedStatus     string                 `json:"reported_status"`
	ClaimGeneration    uint64                 `json:"claim_generation"`
	ErrorCode          string                 `json:"error_code,omitempty"`
	Result             ExecutorReportResultV4 `json:"result"`
}

// ExecutorReportResponseV4 acknowledges one protocol-4 report generation.
type ExecutorReportResponseV4 struct {
	ProtocolVersion int  `json:"protocol_version"`
	Applied         bool `json:"applied"`
}

// DecodeExecutorPollResponseV4 validates only the response container and keeps
// malformed delivery members isolated from valid siblings.
func DecodeExecutorPollResponseV4(raw []byte, limit int) (ExecutorPollResponseV4, error) {
	if limit <= 0 || len(raw) == 0 || len(raw) > limit {
		return ExecutorPollResponseV4{}, errors.New("poll response is empty or exceeds its limit")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return ExecutorPollResponseV4{}, errors.New("poll response must be one JSON object")
	}
	var response ExecutorPollResponseV4
	seen := make(map[string]struct{}, 2)
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return ExecutorPollResponseV4{}, err
		}
		key, ok := keyToken.(string)
		if !ok {
			return ExecutorPollResponseV4{}, errors.New("poll response field name is invalid")
		}
		if _, duplicate := seen[key]; duplicate {
			return ExecutorPollResponseV4{}, fmt.Errorf("poll response contains duplicate field %q", key)
		}
		seen[key] = struct{}{}
		switch key {
		case "protocol_version":
			if err := decoder.Decode(&response.ProtocolVersion); err != nil {
				return ExecutorPollResponseV4{}, fmt.Errorf("decode protocol_version: %w", err)
			}
		case "deliveries":
			if err := decoder.Decode(&response.Deliveries); err != nil {
				return ExecutorPollResponseV4{}, fmt.Errorf("decode deliveries: %w", err)
			}
		default:
			return ExecutorPollResponseV4{}, fmt.Errorf("poll response contains unknown field %q", key)
		}
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return ExecutorPollResponseV4{}, errors.New("poll response object is not terminated")
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ExecutorPollResponseV4{}, errors.New("poll response contains trailing JSON")
	}
	if response.ProtocolVersion != ExecutorProtocolV4 {
		return ExecutorPollResponseV4{}, fmt.Errorf(
			"poll response protocol_version is %d, want %d",
			response.ProtocolVersion,
			ExecutorProtocolV4,
		)
	}
	if response.Deliveries == nil {
		return ExecutorPollResponseV4{}, errors.New("poll response must contain a deliveries array")
	}
	if len(response.Deliveries) > MaxExecutorDeliveries {
		return ExecutorPollResponseV4{}, fmt.Errorf(
			"poll response contains %d deliveries, limit is %d",
			len(response.Deliveries),
			MaxExecutorDeliveries,
		)
	}
	return response, nil
}

func DecodeExecutorDeliveryV4(raw []byte) (ExecutorDeliveryV4, error) {
	var delivery ExecutorDeliveryV4
	if err := dsse.DecodeStrictInto(raw, MaxExecutorDeliveryBytes, &delivery); err != nil {
		return ExecutorDeliveryV4{}, err
	}
	if err := delivery.Validate(); err != nil {
		return ExecutorDeliveryV4{}, err
	}
	return delivery, nil
}

func (delivery ExecutorDeliveryV4) Validate() error {
	return ExecutorDeliveryV3(delivery).Validate()
}

func (projection ExecutorAdmissionProjectionV1) Validate() error {
	if projection.SchemaVersion != ExecutorAdmissionProjectionSchemaV1 ||
		!executorRuntimeRef(projection.RuntimeRef) ||
		!ValidSHA256Digest(projection.CapsuleDigest) ||
		!ValidSHA256Digest(projection.PolicyDigest) ||
		projection.Generation == 0 ||
		!lowerHex(projection.EvidenceKeyID, 32) {
		return errors.New("admission projection identity is invalid")
	}
	switch projection.Status {
	case "created", "running", "exited":
	default:
		return errors.New("admission projection status is invalid")
	}

	hasGrant := projection.GrantID != ""
	if hasGrant && !executorGrantID(projection.GrantID) {
		return errors.New("admission projection grant ID is invalid")
	}
	if !hasGrant && projection.hasRuntimeTopology() {
		return errors.New("admission projection topology requires a grant ID")
	}
	if projection.RoutePolicyDigest != "" && !ValidSHA256Digest(projection.RoutePolicyDigest) {
		return errors.New("admission projection route policy digest is invalid")
	}
	if err := projection.validateService(); err != nil {
		return err
	}
	if err := validateAdmissionRouteSet(
		projection.EgressRouteIDs,
		projection.EgressProxy,
		executorEgressProxyV1,
		"egress",
	); err != nil {
		return err
	}
	if err := validateAdmissionRouteSet(
		projection.ConnectorIDs,
		projection.ConnectorURL,
		executorConnectorURLV1,
		"connector",
	); err != nil {
		return err
	}
	if projection.EventURL != "" && projection.EventURL != executorEventURLV1 {
		return errors.New("admission projection controller event URL is invalid")
	}
	if len(projection.TaskAuthorities) > 0 ||
		len(projection.EgressRouteIDs) > 0 ||
		len(projection.ConnectorIDs) > 0 || projection.EventURL != "" {
		if projection.RoutePolicyDigest == "" {
			return errors.New("admission projection policy-bearing grant requires a route policy digest")
		}
	}

	activationPresent := projection.ActivationID != "" || projection.ActivationBeginDigest != ""
	if activationPresent {
		if !hasGrant || !routeIdentifier(projection.ActivationID) ||
			!ValidSHA256Digest(projection.ActivationBeginDigest) {
			return errors.New("admission projection activation identity is invalid")
		}
	}
	return nil
}

func (projection ExecutorAdmissionProjectionV1) hasRuntimeTopology() bool {
	return projection.ServicePath != "" ||
		projection.ServiceID != "" ||
		projection.TaskAuthorities != nil ||
		projection.EgressProxy != "" ||
		projection.EgressRouteIDs != nil ||
		projection.ConnectorURL != "" ||
		projection.ConnectorIDs != nil ||
		projection.EventURL != "" ||
		projection.RoutePolicyDigest != "" ||
		projection.ActivationID != "" ||
		projection.ActivationBeginDigest != ""
}

func (projection ExecutorAdmissionProjectionV1) validateService() error {
	if projection.ServicePath == "" {
		if projection.ServiceID != "" || projection.TaskAuthorities != nil {
			return errors.New("admission projection service authority requires a service path")
		}
		return nil
	}
	if projection.ServicePath != "/v1/services/"+projection.GrantID+"/" {
		return errors.New("admission projection service path does not match its grant")
	}
	if (projection.ServiceID == "") != (len(projection.TaskAuthorities) == 0) {
		return errors.New("admission projection service ID and task authorities must appear together")
	}
	if projection.TaskAuthorities != nil && len(projection.TaskAuthorities) == 0 {
		return errors.New("admission projection task authorities must be omitted or non-empty")
	}
	if projection.ServiceID == "" {
		return nil
	}
	if !routeIdentifier(projection.ServiceID) {
		return errors.New("admission projection service ID is invalid")
	}
	if len(projection.TaskAuthorities) > maxExecutorTaskAuthorities {
		return fmt.Errorf(
			"admission projection contains %d task authorities, limit is %d",
			len(projection.TaskAuthorities),
			maxExecutorTaskAuthorities,
		)
	}
	seenPublicKeys := make(map[string]struct{}, len(projection.TaskAuthorities))
	for index, authority := range projection.TaskAuthorities {
		if !routeIdentifier(authority.KeyID) ||
			index > 0 && projection.TaskAuthorities[index-1].KeyID >= authority.KeyID {
			return errors.New("admission projection task authorities are invalid or non-canonical")
		}
		public, err := base64.StdEncoding.DecodeString(authority.PublicKey)
		if err != nil || len(public) != ed25519.PublicKeySize ||
			base64.StdEncoding.EncodeToString(public) != authority.PublicKey {
			return errors.New("admission projection task authority public key is not canonical Ed25519")
		}
		if _, duplicate := seenPublicKeys[string(public)]; duplicate {
			return errors.New("admission projection task authority public key is duplicated")
		}
		seenPublicKeys[string(public)] = struct{}{}
	}
	return nil
}

func validateAdmissionRouteSet(ids []string, endpoint, expectedEndpoint, name string) error {
	if ids != nil && len(ids) == 0 {
		return fmt.Errorf("admission projection %s IDs must be omitted or non-empty", name)
	}
	if (len(ids) == 0) != (endpoint == "") {
		return fmt.Errorf("admission projection %s endpoint and IDs must appear together", name)
	}
	if len(ids) == 0 {
		return nil
	}
	if endpoint != expectedEndpoint {
		return fmt.Errorf("admission projection %s endpoint is invalid", name)
	}
	if len(ids) > maxExecutorAdmissionRouteOrConnectorIDs {
		return fmt.Errorf(
			"admission projection contains %d %s IDs, limit is %d",
			len(ids),
			name,
			maxExecutorAdmissionRouteOrConnectorIDs,
		)
	}
	for index, id := range ids {
		if !routeIdentifier(id) || index > 0 && ids[index-1] >= id {
			return fmt.Errorf("admission projection %s IDs are invalid or non-canonical", name)
		}
	}
	return nil
}

func (report ExecutorReportV4) Validate() error {
	if report.ProtocolVersion != ExecutorProtocolV4 ||
		!boundedText(report.DeliveryID, 256) ||
		report.DeliveryGeneration == 0 ||
		!boundedText(report.CommandID, 256) ||
		!ValidSHA256Digest(report.CommandDigest) {
		return errors.New("report delivery identity is invalid")
	}
	switch report.Status {
	case ExecutorStatusDone, ExecutorStatusFailed, ExecutorStatusRejected, ExecutorStatusOutcomeUnknown:
	default:
		return errors.New("report status is invalid")
	}
	if report.Status != ExecutorStatusRejected && report.ClaimGeneration == 0 {
		return errors.New("report claim generation must be positive after command verification")
	}
	if !boundedText(report.ReportedStatus, 64) ||
		len(report.ErrorCode) > 128 ||
		len(report.Result.Error) > 4096 ||
		len(report.Result.RuntimeRef) > 1024 {
		return errors.New("report outcome exceeds its limits")
	}
	if report.Result.Admission != nil {
		if err := report.Result.Admission.Validate(); err != nil {
			return fmt.Errorf("validate admission projection: %w", err)
		}
		if report.Status != ExecutorStatusDone ||
			report.ErrorCode != "" ||
			report.Result.Error != "" ||
			report.Result.Replayed ||
			report.Result.Absent {
			return errors.New("admission projection requires an unambiguous successful report")
		}
		if report.Result.RuntimeRef != report.Result.Admission.RuntimeRef {
			return errors.New("admission projection runtime does not match the report result")
		}
		expectedStatus := "stopped"
		if report.Result.Admission.Status == "running" {
			expectedStatus = "running"
		}
		if report.ReportedStatus != expectedStatus {
			return errors.New("admission projection status does not match the reported status")
		}
	}
	if report.Result.ActivationCanary != nil {
		if err := report.Result.ActivationCanary.Validate(); err != nil {
			return fmt.Errorf("validate activation canary projection: %w", err)
		}
		if report.Status != ExecutorStatusDone || report.ReportedStatus != "running" ||
			report.ErrorCode != "" || report.Result.Error != "" || report.Result.Replayed ||
			report.Result.Absent || report.Result.Admission != nil ||
			!executorRuntimeRef(report.Result.RuntimeRef) {
			return errors.New("activation canary projection requires an unambiguous successful report with its runtime")
		}
	}
	raw, err := json.Marshal(report)
	if err != nil {
		return fmt.Errorf("encode executor report v4: %w", err)
	}
	if len(raw) > MaxExecutorReportBytes {
		return fmt.Errorf(
			"executor report v4 contains %d bytes, limit is %d",
			len(raw),
			MaxExecutorReportBytes,
		)
	}
	return nil
}

func executorRuntimeRef(value string) bool {
	const prefix = "executor-"
	return strings.HasPrefix(value, prefix) &&
		lowerHex(strings.TrimPrefix(value, prefix), 64)
}

func executorGrantID(value string) bool {
	const prefix = "grant-"
	return strings.HasPrefix(value, prefix) &&
		lowerHex(strings.TrimPrefix(value, prefix), 64)
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return true
}

func routeIdentifier(value string) bool {
	if len(value) == 0 || len(value) > 128 {
		return false
	}
	for index, character := range value {
		if character >= 'A' && character <= 'Z' ||
			character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' ||
			index > 0 && (character == '.' || character == '_' || character == '-') {
			continue
		}
		return false
	}
	return true
}

// DecodeExecutorReportV4 applies strict JSON decoding before semantic and
// encoded-size validation.
func DecodeExecutorReportV4(raw []byte) (ExecutorReportV4, error) {
	var report ExecutorReportV4
	if err := dsse.DecodeStrictInto(raw, MaxExecutorReportBytes, &report); err != nil {
		return ExecutorReportV4{}, err
	}
	if err := report.Validate(); err != nil {
		return ExecutorReportV4{}, err
	}
	return report, nil
}
