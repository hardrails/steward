// Package schedulepermit verifies tenant-signed, finite authority for
// deterministic task runs. Control may materialize a run wrapper from a signed
// schedule, but Gateway recomputes every run identity and due time before the
// request can reach an agent.
package schedulepermit

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/taskpermit"
)

const (
	PayloadType       = "application/vnd.steward.task-schedule.v1+json"
	SchemaV1          = "steward.task-schedule.v1"
	RunSchemaV1       = "steward.schedule-run-permit.v1"
	MaxEnvelopeBytes  = 24 << 10
	MaxRunPermitBytes = 32 << 10
	MaxRuns           = 10000
	MaxValidity       = 366 * 24 * time.Hour
	MaxWindow         = 15 * time.Minute
	MaxConcurrency    = 16

	timestampLayout = "2006-01-02T15:04:05Z"
)

var (
	ErrInvalid        = errors.New("invalid task schedule permit")
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	scheduleIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$`)
)

// Statement is finite authority for one exact request repeated at deterministic
// due times. It contains no request body, service address, bearer credential,
// or private key.
type Statement struct {
	SchemaVersion         string `json:"schema_version"`
	ScheduleID            string `json:"schedule_id"`
	NodeID                string `json:"node_id"`
	TenantID              string `json:"tenant_id"`
	InstanceID            string `json:"instance_id"`
	RuntimeRef            string `json:"runtime_ref"`
	GrantID               string `json:"grant_id"`
	Generation            uint64 `json:"generation"`
	CapsuleDigest         string `json:"capsule_digest"`
	PolicyDigest          string `json:"policy_digest"`
	RoutePolicyDigest     string `json:"route_policy_digest"`
	ServiceID             string `json:"service_id"`
	OperationID           string `json:"operation_id"`
	OperationPolicyDigest string `json:"operation_policy_digest"`
	RequestDigest         string `json:"request_digest"`
	RequestBytes          int64  `json:"request_bytes"`
	ContentType           string `json:"content_type"`
	StartsAt              string `json:"starts_at"`
	IntervalSeconds       int64  `json:"interval_seconds"`
	RunCount              uint64 `json:"run_count"`
	WindowSeconds         int64  `json:"window_seconds"`
	MaxConcurrency        int    `json:"max_concurrency"`
	OverlapPolicy         string `json:"overlap_policy"`
	MissedRunPolicy       string `json:"missed_run_policy"`
	ProjectID             string `json:"project_id,omitempty"`
	SessionID             string `json:"session_id,omitempty"`
}

type wireStatement struct {
	SchemaVersion         *string `json:"schema_version"`
	ScheduleID            *string `json:"schedule_id"`
	NodeID                *string `json:"node_id"`
	TenantID              *string `json:"tenant_id"`
	InstanceID            *string `json:"instance_id"`
	RuntimeRef            *string `json:"runtime_ref"`
	GrantID               *string `json:"grant_id"`
	Generation            *uint64 `json:"generation"`
	CapsuleDigest         *string `json:"capsule_digest"`
	PolicyDigest          *string `json:"policy_digest"`
	RoutePolicyDigest     *string `json:"route_policy_digest"`
	ServiceID             *string `json:"service_id"`
	OperationID           *string `json:"operation_id"`
	OperationPolicyDigest *string `json:"operation_policy_digest"`
	RequestDigest         *string `json:"request_digest"`
	RequestBytes          *int64  `json:"request_bytes"`
	ContentType           *string `json:"content_type"`
	StartsAt              *string `json:"starts_at"`
	IntervalSeconds       *int64  `json:"interval_seconds"`
	RunCount              *uint64 `json:"run_count"`
	WindowSeconds         *int64  `json:"window_seconds"`
	MaxConcurrency        *int    `json:"max_concurrency"`
	OverlapPolicy         *string `json:"overlap_policy"`
	MissedRunPolicy       *string `json:"missed_run_policy"`
	ProjectID             *string `json:"project_id"`
	SessionID             *string `json:"session_id"`
}

type Inspected struct {
	Statement      Statement
	KeyID          string
	EnvelopeDigest string
}

type VerifiedRun struct {
	Statement       Statement
	KeyID           string
	EnvelopeDigest  string
	RunPermitDigest string
	TaskID          string
	Ordinal         uint64
	DueAt           time.Time
}

type InspectedRun struct {
	Statement       Statement
	KeyID           string
	EnvelopeDigest  string
	RunPermitDigest string
	TaskID          string
	Ordinal         uint64
	DueAt           time.Time
}

type RunPermit struct {
	SchemaVersion  string `json:"schema_version"`
	ScheduleBase64 string `json:"schedule_base64"`
	Ordinal        uint64 `json:"ordinal"`
	DueAt          string `json:"due_at"`
	TaskID         string `json:"task_id"`
}

func Sign(statement Statement, keyID string, private ed25519.PrivateKey) ([]byte, error) {
	if !identifier(keyID) || len(private) != ed25519.PrivateKeySize {
		return nil, invalid("schedule signing key is invalid")
	}
	if err := statement.Validate(); err != nil {
		return nil, err
	}
	payload, err := json.Marshal(statement)
	if err != nil {
		return nil, invalid("marshal schedule statement")
	}
	envelope, err := dsse.Sign(PayloadType, payload, keyID, private)
	if err != nil {
		return nil, invalid("sign schedule statement")
	}
	raw, err := dsse.Marshal(envelope)
	if err != nil || len(raw) > MaxEnvelopeBytes {
		return nil, invalid("marshal schedule envelope")
	}
	return raw, nil
}

func InspectUnverified(raw []byte) (Inspected, error) {
	statement, keyID, digest, _, err := inspect(raw, nil)
	if err != nil {
		return Inspected{}, err
	}
	return Inspected{Statement: statement, KeyID: keyID, EnvelopeDigest: digest}, nil
}

func BuildRunPermit(schedule []byte, ordinal uint64) ([]byte, error) {
	inspected, err := InspectUnverified(schedule)
	if err != nil {
		return nil, err
	}
	due, taskID, err := inspected.Statement.Run(ordinal)
	if err != nil {
		return nil, err
	}
	value := RunPermit{
		SchemaVersion:  RunSchemaV1,
		ScheduleBase64: base64.StdEncoding.EncodeToString(schedule),
		Ordinal:        ordinal, DueAt: due.Format(timestampLayout), TaskID: taskID,
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw) > MaxRunPermitBytes {
		return nil, invalid("marshal schedule run permit")
	}
	return raw, nil
}

func VerifyRun(
	raw []byte,
	trusted map[string]ed25519.PublicKey,
	now time.Time,
) (VerifiedRun, error) {
	if now.IsZero() {
		return VerifiedRun{}, invalid("node time is unavailable")
	}
	wrapper, schedule, err := decodeRunPermit(raw)
	if err != nil {
		return VerifiedRun{}, err
	}
	statement, keyID, envelopeDigest, _, err := inspect(schedule, trusted)
	if err != nil {
		return VerifiedRun{}, err
	}
	due, taskID, err := statement.Run(wrapper.Ordinal)
	if err != nil || wrapper.DueAt != due.Format(timestampLayout) || wrapper.TaskID != taskID {
		return VerifiedRun{}, invalid("run identity does not match the signed schedule")
	}
	window := time.Duration(statement.WindowSeconds) * time.Second
	if now.Before(due) || !now.Before(due.Add(window)) {
		return VerifiedRun{}, invalid("run is outside its signed dispatch window")
	}
	return VerifiedRun{
		Statement: statement, KeyID: keyID, EnvelopeDigest: envelopeDigest,
		RunPermitDigest: dsse.Digest(raw), TaskID: taskID,
		Ordinal: wrapper.Ordinal, DueAt: due,
	}, nil
}

// InspectRunUnverified validates the wrapper and nested schedule structure
// without authenticating the signature or applying its dispatch window.
func InspectRunUnverified(raw []byte) (InspectedRun, error) {
	wrapper, schedule, err := decodeRunPermit(raw)
	if err != nil {
		return InspectedRun{}, err
	}
	statement, keyID, envelopeDigest, _, err := inspect(schedule, nil)
	if err != nil {
		return InspectedRun{}, err
	}
	due, taskID, err := statement.Run(wrapper.Ordinal)
	if err != nil || wrapper.DueAt != due.Format(timestampLayout) || wrapper.TaskID != taskID {
		return InspectedRun{}, invalid("run identity does not match the signed schedule")
	}
	return InspectedRun{
		Statement: statement, KeyID: keyID, EnvelopeDigest: envelopeDigest,
		RunPermitDigest: dsse.Digest(raw), TaskID: taskID,
		Ordinal: wrapper.Ordinal, DueAt: due,
	}, nil
}

func decodeRunPermit(raw []byte) (RunPermit, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxRunPermitBytes {
		return RunPermit{}, nil, invalid("run permit is empty or oversized")
	}
	var wire struct {
		SchemaVersion  *string `json:"schema_version"`
		ScheduleBase64 *string `json:"schedule_base64"`
		Ordinal        *uint64 `json:"ordinal"`
		DueAt          *string `json:"due_at"`
		TaskID         *string `json:"task_id"`
	}
	if err := dsse.DecodeStrictInto(raw, MaxRunPermitBytes, &wire); err != nil ||
		wire.SchemaVersion == nil || wire.ScheduleBase64 == nil || wire.Ordinal == nil ||
		wire.DueAt == nil || wire.TaskID == nil || *wire.SchemaVersion != RunSchemaV1 {
		return RunPermit{}, nil, invalid("decode schedule run permit")
	}
	schedule, err := base64.StdEncoding.DecodeString(*wire.ScheduleBase64)
	if err != nil || base64.StdEncoding.EncodeToString(schedule) != *wire.ScheduleBase64 {
		return RunPermit{}, nil, invalid("schedule envelope encoding is not canonical")
	}
	return RunPermit{
		SchemaVersion: *wire.SchemaVersion, ScheduleBase64: *wire.ScheduleBase64,
		Ordinal: *wire.Ordinal, DueAt: *wire.DueAt, TaskID: *wire.TaskID,
	}, schedule, nil
}

func (statement Statement) Validate() error {
	start, err := canonicalTime(statement.StartsAt)
	if err != nil {
		return invalid("starts_at: %v", err)
	}
	if statement.SchemaVersion != SchemaV1 || !scheduleIDPattern.MatchString(statement.ScheduleID) ||
		!publicIdentity(statement.NodeID, 128) || !publicIdentity(statement.TenantID, 128) ||
		!publicIdentity(statement.InstanceID, 256) || !prefixedDigest(statement.RuntimeRef, "executor-") ||
		!prefixedDigest(statement.GrantID, "grant-") || statement.Generation == 0 ||
		!digest(statement.CapsuleDigest) || !digest(statement.PolicyDigest) ||
		!digest(statement.RoutePolicyDigest) || !identifier(statement.ServiceID) ||
		!identifier(statement.OperationID) || !digest(statement.OperationPolicyDigest) ||
		!digest(statement.RequestDigest) || statement.RequestBytes <= 0 ||
		statement.RequestBytes > taskpermit.MaxRequestBytes ||
		statement.ContentType != "application/json" || statement.RunCount == 0 ||
		statement.RunCount > MaxRuns || statement.WindowSeconds < 1 ||
		time.Duration(statement.WindowSeconds)*time.Second > MaxWindow ||
		statement.MaxConcurrency < 1 || statement.MaxConcurrency > MaxConcurrency ||
		(statement.OverlapPolicy != "queue" && statement.OverlapPolicy != "skip") ||
		statement.MissedRunPolicy != "skip" ||
		(statement.ProjectID == "") != (statement.SessionID == "") ||
		statement.ProjectID != "" && !identifier(statement.ProjectID) ||
		statement.SessionID != "" && !identifier(statement.SessionID) {
		return invalid("schedule statement contains an invalid binding")
	}
	if statement.IntervalSeconds == 0 {
		if statement.RunCount != 1 {
			return invalid("one-time schedule must contain exactly one run")
		}
	} else if statement.IntervalSeconds < 60 || statement.IntervalSeconds > int64((30*24*time.Hour)/time.Second) {
		return invalid("recurring interval must be from 60 seconds through 30 days")
	}
	last, _, err := statement.Run(statement.RunCount)
	if err != nil || last.Before(start) || last.Add(time.Duration(statement.WindowSeconds)*time.Second).Sub(start) > MaxValidity {
		return invalid("schedule duration exceeds its finite validity bound")
	}
	return nil
}

func (statement Statement) Run(ordinal uint64) (time.Time, string, error) {
	if ordinal == 0 || ordinal > statement.RunCount {
		return time.Time{}, "", invalid("run ordinal is outside the signed schedule")
	}
	start, err := canonicalTime(statement.StartsAt)
	if err != nil {
		return time.Time{}, "", invalid("starts_at: %v", err)
	}
	if statement.IntervalSeconds != 0 &&
		ordinal-1 > uint64(MaxValidity/(time.Duration(statement.IntervalSeconds)*time.Second)) {
		return time.Time{}, "", invalid("run due time overflows its schedule")
	}
	due := start.Add(time.Duration(ordinal-1) * time.Duration(statement.IntervalSeconds) * time.Second)
	taskID := statement.ScheduleID + "-" + strconv.FormatUint(ordinal, 10)
	if !identifier(taskID) {
		return time.Time{}, "", invalid("derived task identity is invalid")
	}
	return due, taskID, nil
}

func inspect(raw []byte, trusted map[string]ed25519.PublicKey) (Statement, string, string, []byte, error) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		return Statement{}, "", "", nil, invalid("schedule envelope is empty or exceeds %d bytes", MaxEnvelopeBytes)
	}
	envelope, err := dsse.Parse(raw)
	if err != nil || envelope.PayloadType != PayloadType || len(envelope.Signatures) != 1 {
		return Statement{}, "", "", nil, invalid("parse canonical single-signature schedule envelope")
	}
	payload, err := base64.StdEncoding.DecodeString(envelope.Payload)
	if err != nil || base64.StdEncoding.EncodeToString(payload) != envelope.Payload || !utf8.Valid(payload) {
		return Statement{}, "", "", nil, invalid("schedule payload is not canonical UTF-8")
	}
	signature, err := base64.StdEncoding.DecodeString(envelope.Signatures[0].Sig)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.StdEncoding.EncodeToString(signature) != envelope.Signatures[0].Sig ||
		!identifier(envelope.Signatures[0].KeyID) {
		return Statement{}, "", "", nil, invalid("schedule signature encoding is invalid")
	}
	canonical, err := dsse.Marshal(envelope)
	if err != nil || !bytes.Equal(canonical, raw) {
		return Statement{}, "", "", nil, invalid("schedule envelope is not canonical")
	}
	if trusted != nil {
		verified, keyID, verifyErr := dsse.Verify(raw, PayloadType, trusted)
		if verifyErr != nil || keyID != envelope.Signatures[0].KeyID || !bytes.Equal(verified, payload) {
			return Statement{}, "", "", nil, invalid("verify schedule envelope")
		}
	}
	var wire wireStatement
	if err := dsse.DecodeStrictInto(payload, MaxEnvelopeBytes, &wire); err != nil {
		return Statement{}, "", "", nil, invalid("decode signed schedule: %v", err)
	}
	statement, ok := wire.statement()
	if !ok {
		return Statement{}, "", "", nil, invalid("signed schedule omits a required field")
	}
	if err := statement.Validate(); err != nil {
		return Statement{}, "", "", nil, err
	}
	return statement, envelope.Signatures[0].KeyID, dsse.Digest(raw), payload, nil
}

func (wire wireStatement) statement() (Statement, bool) {
	if wire.SchemaVersion == nil || wire.ScheduleID == nil || wire.NodeID == nil ||
		wire.TenantID == nil || wire.InstanceID == nil || wire.RuntimeRef == nil ||
		wire.GrantID == nil || wire.Generation == nil || wire.CapsuleDigest == nil ||
		wire.PolicyDigest == nil || wire.RoutePolicyDigest == nil || wire.ServiceID == nil ||
		wire.OperationID == nil || wire.OperationPolicyDigest == nil ||
		wire.RequestDigest == nil || wire.RequestBytes == nil || wire.ContentType == nil ||
		wire.StartsAt == nil || wire.IntervalSeconds == nil || wire.RunCount == nil ||
		wire.WindowSeconds == nil || wire.MaxConcurrency == nil ||
		wire.OverlapPolicy == nil || wire.MissedRunPolicy == nil {
		return Statement{}, false
	}
	projectID, sessionID := "", ""
	if wire.ProjectID != nil {
		projectID = *wire.ProjectID
	}
	if wire.SessionID != nil {
		sessionID = *wire.SessionID
	}
	return Statement{
		SchemaVersion: *wire.SchemaVersion, ScheduleID: *wire.ScheduleID,
		NodeID: *wire.NodeID, TenantID: *wire.TenantID, InstanceID: *wire.InstanceID,
		RuntimeRef: *wire.RuntimeRef, GrantID: *wire.GrantID, Generation: *wire.Generation,
		CapsuleDigest: *wire.CapsuleDigest, PolicyDigest: *wire.PolicyDigest,
		RoutePolicyDigest: *wire.RoutePolicyDigest, ServiceID: *wire.ServiceID,
		OperationID: *wire.OperationID, OperationPolicyDigest: *wire.OperationPolicyDigest,
		RequestDigest: *wire.RequestDigest, RequestBytes: *wire.RequestBytes,
		ContentType: *wire.ContentType, StartsAt: *wire.StartsAt,
		IntervalSeconds: *wire.IntervalSeconds, RunCount: *wire.RunCount,
		WindowSeconds: *wire.WindowSeconds, MaxConcurrency: *wire.MaxConcurrency,
		OverlapPolicy: *wire.OverlapPolicy, MissedRunPolicy: *wire.MissedRunPolicy,
		ProjectID: projectID, SessionID: sessionID,
	}, true
}

func canonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(timestampLayout, value)
	if err != nil || parsed.IsZero() || parsed.UTC().Format(timestampLayout) != value {
		return time.Time{}, errors.New("timestamp must be canonical UTC RFC3339 seconds")
	}
	return parsed, nil
}

func identifier(value string) bool { return identifierPattern.MatchString(value) }

func publicIdentity(value string, limit int) bool {
	return strings.TrimSpace(value) != "" && len(value) <= limit &&
		utf8.ValidString(value) && !strings.ContainsRune(value, '\x00')
}

func prefixedDigest(value, prefix string) bool {
	return strings.HasPrefix(value, prefix) && len(value) == len(prefix)+64 &&
		lowerHex(strings.TrimPrefix(value, prefix))
}

func digest(value string) bool { return prefixedDigest(value, "sha256:") }

func lowerHex(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func invalid(format string, arguments ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, arguments...))
}
