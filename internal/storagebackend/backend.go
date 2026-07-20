// Package storagebackend defines the narrow, provider-neutral persistent-state
// contract used by Executor. Implementations own storage bytes and snapshots;
// Steward owns tenant scope, lineage, generations, authority, and evidence.
package storagebackend

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	SchemaVersion      = "steward.storage-backend.v1"
	MaxIdentifierBytes = 128
	MaxOpaqueRefBytes  = 256
)

var (
	ErrInvalid     = errors.New("storage backend request is invalid")
	ErrNotFound    = errors.New("storage backend object not found")
	ErrConflict    = errors.New("storage backend object conflicts with retained state")
	ErrCapacity    = errors.New("storage backend capacity exceeded")
	ErrInUse       = errors.New("storage backend object is still referenced")
	ErrUnsupported = errors.New("storage backend operation is unsupported")
	ErrUnavailable = errors.New("storage backend is unavailable")
)

// Backend is the complete mutation surface available to Executor. Every
// mutating request has a durable request ID and an expected generation so a
// retry after a lost response cannot silently create a second object.
type Backend interface {
	Capabilities(context.Context) (Capabilities, error)
	InspectVolume(context.Context, VolumeScope) (Volume, error)
	CreateVolume(context.Context, CreateVolumeRequest) (Volume, bool, error)
	DeleteVolume(context.Context, DeleteVolumeRequest) (Volume, bool, error)
	InspectSnapshot(context.Context, SnapshotScope) (Snapshot, error)
	CreateSnapshot(context.Context, CreateSnapshotRequest) (Snapshot, bool, error)
	CloneVolume(context.Context, CloneVolumeRequest) (Volume, bool, error)
	DeleteSnapshot(context.Context, DeleteSnapshotRequest) (Snapshot, bool, error)
}

// Capabilities is a provider claim, not proof. Executor accepts a production
// backend only when all mandatory controls are present and the implementation
// has passed the same conformance suite.
type Capabilities struct {
	SchemaVersion       string `json:"schema_version"`
	BackendID           string `json:"backend_id"`
	HardByteQuota       bool   `json:"hard_byte_quota"`
	HardObjectQuota     bool   `json:"hard_object_quota"`
	ColdSnapshots       bool   `json:"cold_snapshots"`
	ImmutableSnapshots  bool   `json:"immutable_snapshots"`
	CopyOnWriteClones   bool   `json:"copy_on_write_clones"`
	CrashSafeMetadata   bool   `json:"crash_safe_metadata"`
	DockerVolumeHandles bool   `json:"docker_volume_handles"`
}

func (value Capabilities) Validate() error {
	if value.SchemaVersion != SchemaVersion || !validIdentifier(value.BackendID, MaxIdentifierBytes) {
		return fmt.Errorf("%w: backend capability identity", ErrInvalid)
	}
	return nil
}

func (value Capabilities) ProductionQualified() bool {
	return value.Validate() == nil && value.HardByteQuota && value.HardObjectQuota &&
		value.ColdSnapshots && value.ImmutableSnapshots && value.CopyOnWriteClones &&
		value.CrashSafeMetadata && value.DockerVolumeHandles
}

type ObjectState string

const (
	StateReady       ObjectState = "ready"
	StateQuarantined ObjectState = "quarantined"
	StateDeleted     ObjectState = "deleted"
)

// VolumeSpec contains only signed scope and finite limits. A tenant cannot
// choose a host path, dataset, mount option, driver, UID, or GID.
type VolumeSpec struct {
	VolumeID         string `json:"volume_id"`
	TenantID         string `json:"tenant_id"`
	LineageID        string `json:"lineage_id"`
	Generation       uint64 `json:"generation"`
	ByteLimit        int64  `json:"byte_limit"`
	ObjectLimit      int64  `json:"object_limit"`
	ParentSnapshotID string `json:"parent_snapshot_id,omitempty"`
}

// VolumeScope is the complete signed identity required to address a volume.
// The opaque ID alone is never authorization to observe or mutate state.
type VolumeScope struct {
	VolumeID   string `json:"volume_id"`
	TenantID   string `json:"tenant_id"`
	LineageID  string `json:"lineage_id"`
	Generation uint64 `json:"generation"`
}

func (value VolumeScope) Validate() error {
	if !validIdentifier(value.VolumeID, MaxIdentifierBytes) ||
		!validIdentifier(value.TenantID, MaxIdentifierBytes) ||
		!validIdentifier(value.LineageID, MaxIdentifierBytes) || value.Generation == 0 {
		return fmt.Errorf("%w: volume scope", ErrInvalid)
	}
	return nil
}

func (value VolumeSpec) Scope() VolumeScope {
	return VolumeScope{
		VolumeID: value.VolumeID, TenantID: value.TenantID,
		LineageID: value.LineageID, Generation: value.Generation,
	}
}

func (value VolumeSpec) Validate() error {
	if !validIdentifier(value.VolumeID, MaxIdentifierBytes) ||
		!validIdentifier(value.TenantID, MaxIdentifierBytes) ||
		!validIdentifier(value.LineageID, MaxIdentifierBytes) || value.Generation == 0 ||
		value.ByteLimit <= 0 || value.ObjectLimit <= 0 ||
		value.ParentSnapshotID != "" && !validIdentifier(value.ParentSnapshotID, MaxIdentifierBytes) {
		return fmt.Errorf("%w: volume specification", ErrInvalid)
	}
	return nil
}

type Volume struct {
	Spec               VolumeSpec  `json:"spec"`
	State              ObjectState `json:"state"`
	BackendRef         string      `json:"backend_ref"`
	DockerVolumeHandle string      `json:"docker_volume_handle"`
	UsedBytes          int64       `json:"used_bytes"`
	UsedObjects        int64       `json:"used_objects"`
	CreatedAt          string      `json:"created_at"`
	DeletedAt          string      `json:"deleted_at,omitempty"`
}

func (value Volume) Validate() error {
	if err := value.Spec.Validate(); err != nil {
		return err
	}
	if !validObjectState(value.State) || !validOpaque(value.BackendRef) ||
		!validIdentifier(value.DockerVolumeHandle, MaxOpaqueRefBytes) ||
		value.UsedBytes < 0 || value.UsedBytes > value.Spec.ByteLimit ||
		value.UsedObjects < 0 || value.UsedObjects > value.Spec.ObjectLimit || !validTimestamp(value.CreatedAt) {
		return fmt.Errorf("%w: volume projection", ErrInvalid)
	}
	if value.State == StateDeleted {
		if !validTimestamp(value.DeletedAt) {
			return fmt.Errorf("%w: deleted volume timestamp", ErrInvalid)
		}
	} else if value.DeletedAt != "" {
		return fmt.Errorf("%w: live volume has a deletion timestamp", ErrInvalid)
	}
	return nil
}

func (value Volume) Scope() VolumeScope { return value.Spec.Scope() }

type Snapshot struct {
	SnapshotID      string      `json:"snapshot_id"`
	TenantID        string      `json:"tenant_id"`
	SourceVolumeID  string      `json:"source_volume_id"`
	SourceLineageID string      `json:"source_lineage_id"`
	Generation      uint64      `json:"generation"`
	State           ObjectState `json:"state"`
	BackendRef      string      `json:"backend_ref"`
	ContentDigest   string      `json:"content_digest"`
	RetainedBytes   int64       `json:"retained_bytes"`
	ObjectCount     int64       `json:"object_count"`
	CreatedAt       string      `json:"created_at"`
	DeletedAt       string      `json:"deleted_at,omitempty"`
}

// SnapshotScope prevents an opaque snapshot ID from becoming cross-tenant
// read or deletion authority.
type SnapshotScope struct {
	SnapshotID      string `json:"snapshot_id"`
	TenantID        string `json:"tenant_id"`
	SourceVolumeID  string `json:"source_volume_id"`
	SourceLineageID string `json:"source_lineage_id"`
	Generation      uint64 `json:"generation"`
}

func (value SnapshotScope) Validate() error {
	if !validIdentifier(value.SnapshotID, MaxIdentifierBytes) ||
		!validIdentifier(value.TenantID, MaxIdentifierBytes) ||
		!validIdentifier(value.SourceVolumeID, MaxIdentifierBytes) ||
		!validIdentifier(value.SourceLineageID, MaxIdentifierBytes) || value.Generation == 0 {
		return fmt.Errorf("%w: snapshot scope", ErrInvalid)
	}
	return nil
}

func (value Snapshot) Scope() SnapshotScope {
	return SnapshotScope{
		SnapshotID: value.SnapshotID, TenantID: value.TenantID,
		SourceVolumeID:  value.SourceVolumeID,
		SourceLineageID: value.SourceLineageID, Generation: value.Generation,
	}
}

func (value Snapshot) Validate() error {
	if !validIdentifier(value.SnapshotID, MaxIdentifierBytes) ||
		!validIdentifier(value.TenantID, MaxIdentifierBytes) ||
		!validIdentifier(value.SourceVolumeID, MaxIdentifierBytes) ||
		!validIdentifier(value.SourceLineageID, MaxIdentifierBytes) || value.Generation == 0 ||
		!validObjectState(value.State) || !validOpaque(value.BackendRef) ||
		!validDigest(value.ContentDigest) || value.RetainedBytes < 0 || value.ObjectCount < 0 ||
		!validTimestamp(value.CreatedAt) {
		return fmt.Errorf("%w: snapshot projection", ErrInvalid)
	}
	if value.State == StateDeleted {
		if !validTimestamp(value.DeletedAt) {
			return fmt.Errorf("%w: deleted snapshot timestamp", ErrInvalid)
		}
	} else if value.DeletedAt != "" {
		return fmt.Errorf("%w: live snapshot has a deletion timestamp", ErrInvalid)
	}
	return nil
}

type CreateVolumeRequest struct {
	RequestID string     `json:"request_id"`
	Volume    VolumeSpec `json:"volume"`
}

func (value CreateVolumeRequest) Validate() error {
	if !validIdentifier(value.RequestID, MaxIdentifierBytes) {
		return fmt.Errorf("%w: volume request identity", ErrInvalid)
	}
	if err := value.Volume.Validate(); err != nil {
		return err
	}
	if value.Volume.ParentSnapshotID != "" {
		return fmt.Errorf("%w: fresh volume cannot name a parent snapshot", ErrInvalid)
	}
	return nil
}

type DeleteVolumeRequest struct {
	RequestID string      `json:"request_id"`
	Volume    VolumeScope `json:"volume"`
}

func (value DeleteVolumeRequest) Validate() error {
	if !validIdentifier(value.RequestID, MaxIdentifierBytes) {
		return fmt.Errorf("%w: volume deletion", ErrInvalid)
	}
	return value.Volume.Validate()
}

type CreateSnapshotRequest struct {
	RequestID  string      `json:"request_id"`
	SnapshotID string      `json:"snapshot_id"`
	Source     VolumeScope `json:"source"`
}

func (value CreateSnapshotRequest) Validate() error {
	if !validIdentifier(value.RequestID, MaxIdentifierBytes) ||
		!validIdentifier(value.SnapshotID, MaxIdentifierBytes) {
		return fmt.Errorf("%w: snapshot creation", ErrInvalid)
	}
	return value.Source.Validate()
}

type CloneVolumeRequest struct {
	RequestID string        `json:"request_id"`
	Snapshot  SnapshotScope `json:"snapshot"`
	Volume    VolumeSpec    `json:"volume"`
}

func (value CloneVolumeRequest) Validate() error {
	if !validIdentifier(value.RequestID, MaxIdentifierBytes) ||
		value.Volume.ParentSnapshotID != value.Snapshot.SnapshotID {
		return fmt.Errorf("%w: volume clone", ErrInvalid)
	}
	if err := value.Snapshot.Validate(); err != nil {
		return err
	}
	if err := value.Volume.Validate(); err != nil {
		return err
	}
	if value.Volume.TenantID != value.Snapshot.TenantID ||
		value.Volume.LineageID == value.Snapshot.SourceLineageID {
		return fmt.Errorf("%w: clone tenant or lineage", ErrInvalid)
	}
	return nil
}

type DeleteSnapshotRequest struct {
	RequestID string        `json:"request_id"`
	Snapshot  SnapshotScope `json:"snapshot"`
}

func (value DeleteSnapshotRequest) Validate() error {
	if !validIdentifier(value.RequestID, MaxIdentifierBytes) {
		return fmt.Errorf("%w: snapshot deletion", ErrInvalid)
	}
	return value.Snapshot.Validate()
}

func validObjectState(value ObjectState) bool {
	return value == StateReady || value == StateQuarantined || value == StateDeleted
}

func validIdentifier(value string, maximum int) bool {
	if value == "" || len(value) > maximum || !utf8.ValidString(value) || value[0] == '-' || value[len(value)-1] == '-' {
		return false
	}
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' ||
			char >= '0' && char <= '9' || char == '.' || char == '_' || char == '-' {
			continue
		}
		return false
	}
	return true
}

func validOpaque(value string) bool {
	return validIdentifier(value, MaxOpaqueRefBytes) && !strings.ContainsAny(value, `/\\`)
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if char < '0' || char > '9' && char < 'a' || char > 'f' {
			return false
		}
	}
	return true
}

func validTimestamp(value string) bool {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	return err == nil && !parsed.IsZero() && value == parsed.UTC().Format(time.RFC3339Nano)
}
