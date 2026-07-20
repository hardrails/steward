// Package zfsstorage implements Steward's qualified local state contract on
// OpenZFS. It is intended to run in the separately packaged storage worker,
// never in Control or an agent process.
package zfsstorage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/storagebackend"
)

const (
	recordVersion  = 1
	recordProperty = "io.hardrails.steward:record"
	holdTag        = "io.hardrails.steward"
	maxRecordBytes = 16 << 10
)

var (
	ErrBindingNotFound = errors.New("docker volume binding not found")
	ErrBindingConflict = errors.New("docker volume binding conflicts with retained state")
	ErrBindingInUse    = errors.New("docker volume binding is in use")
)

// Binding is the complete worker-generated Docker named-volume mapping. Source
// is derived from the configured mount root; no caller may provide it.
type Binding struct {
	Handle string
	Source string
	Labels map[string]string
}

// VolumeBinder owns only the narrow Docker named-volume lifecycle. A concrete
// implementation must reject an existing handle with a different source or
// labels instead of silently reusing it.
type VolumeBinder interface {
	Ensure(context.Context, Binding) (bool, error)
	Inspect(context.Context, string) (Binding, error)
	Delete(context.Context, string) (bool, error)
}

type Config struct {
	DatasetRoot string
	MountRoot   string
	Runner      Runner
	Binder      VolumeBinder
	Now         func() time.Time
}

type Backend struct {
	root      string
	mountRoot string
	runner    Runner
	binder    VolumeBinder
	now       func() time.Time
	mu        sync.Mutex
}

func New(config Config) (*Backend, error) {
	if !validDataset(config.DatasetRoot) || len(config.DatasetRoot) > 170 ||
		config.MountRoot == "" || !filepath.IsAbs(config.MountRoot) ||
		filepath.Clean(config.MountRoot) != config.MountRoot || config.MountRoot == string(filepath.Separator) ||
		config.Runner == nil || config.Binder == nil {
		return nil, errors.New("zfs backend requires a bounded dataset root, mount root, runner, and volume binder")
	}
	now := config.Now
	if now == nil {
		now = time.Now
	}
	return &Backend{root: config.DatasetRoot, mountRoot: config.MountRoot, runner: config.Runner, binder: config.Binder, now: now}, nil
}

// Initialize verifies the operator-selected root and creates only Steward's two
// fixed child namespaces. It never creates or imports a pool.
func (backend *Backend) Initialize(ctx context.Context) error {
	backend.mu.Lock()
	defer backend.mu.Unlock()
	properties, found, err := backend.get(ctx, backend.root, "type")
	if err != nil {
		return err
	}
	if !found || properties["type"] != "filesystem" {
		return fmt.Errorf("%w: configured ZFS dataset root is unavailable", storagebackend.ErrUnavailable)
	}
	for _, child := range []string{backend.volumesRoot(), backend.tombstonesRoot()} {
		if err := backend.ensureNamespace(ctx, child); err != nil {
			return err
		}
	}
	return nil
}

func (backend *Backend) Capabilities(context.Context) (storagebackend.Capabilities, error) {
	return storagebackend.Capabilities{
		SchemaVersion: storagebackend.SchemaVersion, BackendID: "openzfs-local-v1",
		HardByteQuota: true, HardObjectQuota: true, ColdSnapshots: true,
		ImmutableSnapshots: true, CopyOnWriteClones: true, CrashSafeMetadata: true,
		DockerVolumeHandles: true,
	}, nil
}

func (backend *Backend) PlanVolume(_ context.Context, spec storagebackend.VolumeSpec) (storagebackend.VolumePlan, error) {
	if err := spec.Validate(); err != nil {
		return storagebackend.VolumePlan{}, err
	}
	return storagebackend.VolumePlan{
		Spec: spec, BackendRef: backend.volumeRef(spec.Scope()), DockerVolumeHandle: backend.dockerHandle(spec.Scope()),
	}, nil
}

func (backend *Backend) InspectVolume(ctx context.Context, scope storagebackend.VolumeScope) (storagebackend.Volume, error) {
	if err := scope.Validate(); err != nil {
		return storagebackend.Volume{}, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.inspectVolumeLocked(ctx, scope)
}

func (backend *Backend) CreateVolume(ctx context.Context, request storagebackend.CreateVolumeRequest) (storagebackend.Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Volume{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.createVolumeLocked(ctx, request, "")
}

func (backend *Backend) DeleteVolume(ctx context.Context, request storagebackend.DeleteVolumeRequest) (storagebackend.Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Volume{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	record, location, found, err := backend.findVolumeRecord(ctx, request.Volume)
	if err != nil {
		return storagebackend.Volume{}, false, err
	}
	if !found {
		return storagebackend.Volume{}, false, storagebackend.ErrNotFound
	}
	if record.Volume.Scope() != request.Volume {
		return storagebackend.Volume{}, false, storagebackend.ErrNotFound
	}
	if record.State == storagebackend.StateDeleted {
		if record.DeleteRequestID != request.RequestID {
			return storagebackend.Volume{}, false, storagebackend.ErrConflict
		}
		return record.volumeProjection(0, 0), false, nil
	}
	if record.DeleteRequestID != "" && record.DeleteRequestID != request.RequestID {
		return storagebackend.Volume{}, false, storagebackend.ErrConflict
	}
	if location == backend.volumeDataset(request.Volume) {
		snapshots, err := backend.listSnapshots(ctx, location)
		if err != nil {
			return storagebackend.Volume{}, false, err
		}
		if len(snapshots) != 0 {
			return storagebackend.Volume{}, false, storagebackend.ErrInUse
		}
	}
	if _, err := backend.binder.Delete(ctx, record.DockerHandle); err != nil && !errors.Is(err, ErrBindingNotFound) {
		return storagebackend.Volume{}, false, mapBindingError(err)
	}
	if record.DeleteRequestID == "" {
		record.DeleteRequestID = request.RequestID
		record.State = storagebackend.StateQuarantined
		if err := backend.createTombstone(ctx, backend.volumeTombstone(request.Volume), record); err != nil {
			return storagebackend.Volume{}, false, err
		}
	}
	if location == backend.volumeDataset(request.Volume) {
		if _, err := backend.runner.Run(ctx, "destroy", location); err != nil {
			return storagebackend.Volume{}, false, mapCommandError(err)
		}
	}
	record.State = storagebackend.StateDeleted
	record.DeletedAt = backend.timestamp()
	if err := backend.setRecord(ctx, backend.volumeTombstone(request.Volume), record); err != nil {
		return storagebackend.Volume{}, false, err
	}
	return record.volumeProjection(0, 0), true, nil
}

func (backend *Backend) InspectSnapshot(ctx context.Context, scope storagebackend.SnapshotScope) (storagebackend.Snapshot, error) {
	if err := scope.Validate(); err != nil {
		return storagebackend.Snapshot{}, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	return backend.inspectSnapshotLocked(ctx, scope)
}

func (backend *Backend) CreateSnapshot(ctx context.Context, request storagebackend.CreateSnapshotRequest) (storagebackend.Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	volumeRecord, location, found, err := backend.findVolumeRecord(ctx, request.Source)
	if err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	if !found || location != backend.volumeDataset(request.Source) || volumeRecord.State != storagebackend.StateReady {
		return storagebackend.Snapshot{}, false, storagebackend.ErrNotFound
	}
	scope := storagebackend.SnapshotScope{
		SnapshotID: request.SnapshotID, TenantID: request.Source.TenantID,
		SourceVolumeID: request.Source.VolumeID, SourceLineageID: request.Source.LineageID,
		Generation: request.Source.Generation,
	}
	if existing, _, found, findErr := backend.findSnapshotRecord(ctx, scope); findErr != nil {
		return storagebackend.Snapshot{}, false, findErr
	} else if found {
		if existing.CreateRequestID != request.RequestID || existing.State != storagebackend.StateReady {
			return storagebackend.Snapshot{}, false, storagebackend.ErrConflict
		}
		if err := backend.ensureHold(ctx, backend.snapshotDataset(scope)); err != nil {
			return storagebackend.Snapshot{}, false, err
		}
		projection, err := backend.inspectSnapshotRecord(ctx, backend.snapshotDataset(scope), existing)
		return projection, false, err
	}
	record := persistedRecord{
		Version: recordVersion, Kind: "snapshot", State: storagebackend.StateReady,
		CreateRequestID: request.RequestID, SnapshotScope: scope,
		SourceVolume: volumeRecord.Volume, ProjectID: volumeRecord.ProjectID,
		CreatedAt: backend.timestamp(), BackendRef: backend.snapshotRef(scope),
	}
	encoded, err := encodeRecord(record)
	if err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	target := backend.snapshotDataset(scope)
	if _, err := backend.runner.Run(ctx, "snapshot", "-o", recordProperty+"="+encoded, target); err != nil {
		return storagebackend.Snapshot{}, false, mapCommandError(err)
	}
	if err := backend.ensureHold(ctx, target); err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	projection, err := backend.inspectSnapshotRecord(ctx, target, record)
	return projection, err == nil, err
}

func (backend *Backend) CloneVolume(ctx context.Context, request storagebackend.CloneVolumeRequest) (storagebackend.Volume, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Volume{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	snapshotRecord, snapshotLocation, found, err := backend.findSnapshotRecord(ctx, request.Snapshot)
	if err != nil {
		return storagebackend.Volume{}, false, err
	}
	if !found || snapshotLocation != backend.snapshotDataset(request.Snapshot) || snapshotRecord.State != storagebackend.StateReady {
		return storagebackend.Volume{}, false, storagebackend.ErrNotFound
	}
	return backend.createVolumeLocked(ctx, storagebackend.CreateVolumeRequest{RequestID: request.RequestID, Volume: request.Volume}, snapshotLocation)
}

func (backend *Backend) DeleteSnapshot(ctx context.Context, request storagebackend.DeleteSnapshotRequest) (storagebackend.Snapshot, bool, error) {
	if err := request.Validate(); err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	record, location, found, err := backend.findSnapshotRecord(ctx, request.Snapshot)
	if err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	if !found {
		return storagebackend.Snapshot{}, false, storagebackend.ErrNotFound
	}
	if record.SnapshotScope != request.Snapshot {
		return storagebackend.Snapshot{}, false, storagebackend.ErrNotFound
	}
	if record.State == storagebackend.StateDeleted {
		if record.DeleteRequestID != request.RequestID {
			return storagebackend.Snapshot{}, false, storagebackend.ErrConflict
		}
		return record.snapshotProjection(0, 0, record.ContentDigest), false, nil
	}
	if record.DeleteRequestID != "" && record.DeleteRequestID != request.RequestID {
		return storagebackend.Snapshot{}, false, storagebackend.ErrConflict
	}
	if location == backend.snapshotDataset(request.Snapshot) {
		props, exists, getErr := backend.get(ctx, location, "clones")
		if getErr != nil {
			return storagebackend.Snapshot{}, false, getErr
		}
		if !exists {
			return storagebackend.Snapshot{}, false, storagebackend.ErrNotFound
		}
		if clones := props["clones"]; clones != "" && clones != "-" {
			return storagebackend.Snapshot{}, false, storagebackend.ErrInUse
		}
	}
	if record.DeleteRequestID == "" {
		projection, inspectErr := backend.inspectSnapshotRecord(ctx, location, record)
		if inspectErr != nil {
			return storagebackend.Snapshot{}, false, inspectErr
		}
		record.ContentDigest = projection.ContentDigest
		record.RetainedBytes = projection.RetainedBytes
		record.ObjectCount = projection.ObjectCount
		record.DeleteRequestID = request.RequestID
		record.State = storagebackend.StateQuarantined
		if err := backend.createTombstone(ctx, backend.snapshotTombstone(request.Snapshot), record); err != nil {
			return storagebackend.Snapshot{}, false, err
		}
	}
	if location == backend.snapshotDataset(request.Snapshot) {
		if _, err := backend.runner.Run(ctx, "release", holdTag, location); err != nil && !commandSays(err, "no such tag") {
			return storagebackend.Snapshot{}, false, mapCommandError(err)
		}
		if _, err := backend.runner.Run(ctx, "destroy", location); err != nil {
			return storagebackend.Snapshot{}, false, mapCommandError(err)
		}
	}
	record.State = storagebackend.StateDeleted
	record.DeletedAt = backend.timestamp()
	if err := backend.setRecord(ctx, backend.snapshotTombstone(request.Snapshot), record); err != nil {
		return storagebackend.Snapshot{}, false, err
	}
	return record.snapshotProjection(record.RetainedBytes, record.ObjectCount, record.ContentDigest), true, nil
}

type persistedRecord struct {
	Version         int                          `json:"version"`
	Kind            string                       `json:"kind"`
	State           storagebackend.ObjectState   `json:"state"`
	CreateRequestID string                       `json:"create_request_id"`
	DeleteRequestID string                       `json:"delete_request_id,omitempty"`
	Volume          storagebackend.VolumeSpec    `json:"volume,omitempty"`
	SnapshotScope   storagebackend.SnapshotScope `json:"snapshot,omitempty"`
	SourceVolume    storagebackend.VolumeSpec    `json:"source_volume,omitempty"`
	ProjectID       uint32                       `json:"project_id"`
	DockerHandle    string                       `json:"docker_handle,omitempty"`
	BackendRef      string                       `json:"backend_ref"`
	CreatedAt       string                       `json:"created_at"`
	DeletedAt       string                       `json:"deleted_at,omitempty"`
	ContentDigest   string                       `json:"content_digest,omitempty"`
	RetainedBytes   int64                        `json:"retained_bytes,omitempty"`
	ObjectCount     int64                        `json:"object_count,omitempty"`
}

func (record persistedRecord) validate() error {
	if record.Version != recordVersion || record.CreateRequestID == "" || record.ProjectID == 0 ||
		record.BackendRef == "" || record.CreatedAt == "" {
		return errors.New("invalid ZFS storage record")
	}
	switch record.Kind {
	case "volume":
		if err := record.Volume.Validate(); err != nil || record.DockerHandle == "" {
			return errors.New("invalid ZFS volume record")
		}
	case "snapshot":
		if err := record.SnapshotScope.Validate(); err != nil || record.SourceVolume.Validate() != nil {
			return errors.New("invalid ZFS snapshot record")
		}
	default:
		return errors.New("invalid ZFS storage record kind")
	}
	if record.State != storagebackend.StateReady && record.State != storagebackend.StateQuarantined && record.State != storagebackend.StateDeleted {
		return errors.New("invalid ZFS storage record state")
	}
	if record.State == storagebackend.StateDeleted && (record.DeleteRequestID == "" || record.DeletedAt == "") {
		return errors.New("invalid deleted ZFS storage record")
	}
	return nil
}

func (backend *Backend) createVolumeLocked(ctx context.Context, request storagebackend.CreateVolumeRequest, origin string) (storagebackend.Volume, bool, error) {
	if origin == "" && request.Volume.ParentSnapshotID != "" {
		return storagebackend.Volume{}, false, storagebackend.ErrInvalid
	}
	if origin != "" && request.Volume.ParentSnapshotID == "" {
		return storagebackend.Volume{}, false, storagebackend.ErrInvalid
	}
	if existing, location, found, err := backend.findVolumeRecord(ctx, request.Volume.Scope()); err != nil {
		return storagebackend.Volume{}, false, err
	} else if found {
		if existing.CreateRequestID != request.RequestID || existing.Volume != request.Volume ||
			existing.State != storagebackend.StateReady || location != backend.volumeDataset(request.Volume.Scope()) {
			return storagebackend.Volume{}, false, storagebackend.ErrConflict
		}
		if _, err := backend.ensureBinding(ctx, existing); err != nil {
			return storagebackend.Volume{}, false, err
		}
		projection, err := backend.inspectVolumeRecord(ctx, location, existing)
		return projection, false, err
	}
	scope := request.Volume.Scope()
	record := persistedRecord{
		Version: recordVersion, Kind: "volume", State: storagebackend.StateReady,
		CreateRequestID: request.RequestID, Volume: request.Volume,
		ProjectID: projectID(scope), DockerHandle: backend.dockerHandle(scope),
		BackendRef: backend.volumeRef(scope), CreatedAt: backend.timestamp(),
	}
	encoded, err := encodeRecord(record)
	if err != nil {
		return storagebackend.Volume{}, false, err
	}
	dataset := backend.volumeDataset(scope)
	mountpoint := backend.volumeMountpoint(scope)
	properties := []string{
		"-o", "canmount=on", "-o", "mountpoint=" + mountpoint,
		"-o", "compression=zstd", "-o", "atime=off", "-o", "xattr=sa",
		"-o", "refquota=" + strconv.FormatInt(request.Volume.ByteLimit, 10),
		"-o", fmt.Sprintf("projectquota@%d=%d", record.ProjectID, request.Volume.ByteLimit),
		"-o", fmt.Sprintf("projectobjquota@%d=%d", record.ProjectID, request.Volume.ObjectLimit),
		"-o", recordProperty + "=" + encoded,
	}
	var command []string
	if origin == "" {
		command = append([]string{"create"}, properties...)
		command = append(command, dataset)
	} else {
		command = append([]string{"clone"}, properties...)
		command = append(command, origin, dataset)
	}
	if _, err := backend.runner.Run(ctx, command...); err != nil {
		return storagebackend.Volume{}, false, mapCommandError(err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_, _ = backend.runner.Run(context.Background(), "destroy", dataset)
		}
	}()
	if _, err := backend.runner.Run(ctx, "project", "-p", strconv.FormatUint(uint64(record.ProjectID), 10), "-rs", mountpoint); err != nil {
		return storagebackend.Volume{}, false, mapCommandError(err)
	}
	bindingCreated, err := backend.ensureBinding(ctx, record)
	if err != nil {
		return storagebackend.Volume{}, false, err
	}
	defer func() {
		if cleanup && bindingCreated {
			_, _ = backend.binder.Delete(context.Background(), record.DockerHandle)
		}
	}()
	projection, err := backend.inspectVolumeRecord(ctx, dataset, record)
	if err != nil {
		return storagebackend.Volume{}, false, err
	}
	cleanup = false
	return projection, true, nil
}

func (backend *Backend) inspectVolumeLocked(ctx context.Context, scope storagebackend.VolumeScope) (storagebackend.Volume, error) {
	record, location, found, err := backend.findVolumeRecord(ctx, scope)
	if err != nil {
		return storagebackend.Volume{}, err
	}
	if !found || record.Volume.Scope() != scope {
		return storagebackend.Volume{}, storagebackend.ErrNotFound
	}
	return backend.inspectVolumeRecord(ctx, location, record)
}

func (backend *Backend) inspectVolumeRecord(ctx context.Context, location string, record persistedRecord) (storagebackend.Volume, error) {
	if record.State == storagebackend.StateDeleted {
		return record.volumeProjection(0, 0), nil
	}
	properties, found, err := backend.get(ctx, location,
		"projectused@"+strconv.FormatUint(uint64(record.ProjectID), 10),
		"projectobjused@"+strconv.FormatUint(uint64(record.ProjectID), 10), "mountpoint")
	if err != nil {
		return storagebackend.Volume{}, err
	}
	if !found || properties["mountpoint"] != backend.volumeMountpoint(record.Volume.Scope()) {
		return storagebackend.Volume{}, storagebackend.ErrConflict
	}
	usedBytes, err := parseNonnegative(properties["projectused@"+strconv.FormatUint(uint64(record.ProjectID), 10)])
	if err != nil {
		return storagebackend.Volume{}, err
	}
	usedObjects, err := parseNonnegative(properties["projectobjused@"+strconv.FormatUint(uint64(record.ProjectID), 10)])
	if err != nil {
		return storagebackend.Volume{}, err
	}
	if err := backend.bindingMatches(ctx, record); err != nil {
		if errors.Is(err, ErrBindingNotFound) || errors.Is(err, ErrBindingConflict) {
			record.State = storagebackend.StateQuarantined
		} else {
			return storagebackend.Volume{}, mapBindingError(err)
		}
	}
	projection := record.volumeProjection(usedBytes, usedObjects)
	if err := projection.Validate(); err != nil {
		return storagebackend.Volume{}, storagebackend.ErrConflict
	}
	return projection, nil
}

func (backend *Backend) inspectSnapshotLocked(ctx context.Context, scope storagebackend.SnapshotScope) (storagebackend.Snapshot, error) {
	record, location, found, err := backend.findSnapshotRecord(ctx, scope)
	if err != nil {
		return storagebackend.Snapshot{}, err
	}
	if !found || record.SnapshotScope != scope {
		return storagebackend.Snapshot{}, storagebackend.ErrNotFound
	}
	return backend.inspectSnapshotRecord(ctx, location, record)
}

func (backend *Backend) inspectSnapshotRecord(ctx context.Context, location string, record persistedRecord) (storagebackend.Snapshot, error) {
	if record.State == storagebackend.StateDeleted {
		return record.snapshotProjection(record.RetainedBytes, record.ObjectCount, record.ContentDigest), nil
	}
	project := strconv.FormatUint(uint64(record.ProjectID), 10)
	properties, found, err := backend.get(ctx, location, "referenced", "projectobjused@"+project, "guid")
	if err != nil {
		return storagebackend.Snapshot{}, err
	}
	if !found {
		return storagebackend.Snapshot{}, storagebackend.ErrNotFound
	}
	retained, err := parseNonnegative(properties["referenced"])
	if err != nil {
		return storagebackend.Snapshot{}, err
	}
	objects, err := parseNonnegative(properties["projectobjused@"+project])
	if err != nil {
		return storagebackend.Snapshot{}, err
	}
	guid := properties["guid"]
	if guid == "" || guid == "-" {
		return storagebackend.Snapshot{}, storagebackend.ErrConflict
	}
	digest := sha256.Sum256([]byte("openzfs-guid:" + guid))
	projection := record.snapshotProjection(retained, objects, "sha256:"+hex.EncodeToString(digest[:]))
	if err := projection.Validate(); err != nil {
		return storagebackend.Snapshot{}, storagebackend.ErrConflict
	}
	return projection, nil
}

func (record persistedRecord) volumeProjection(bytes, objects int64) storagebackend.Volume {
	return storagebackend.Volume{
		Spec: record.Volume, State: record.State, BackendRef: record.BackendRef,
		DockerVolumeHandle: record.DockerHandle, UsedBytes: bytes, UsedObjects: objects,
		CreatedAt: record.CreatedAt, DeletedAt: record.DeletedAt,
	}
}

func (record persistedRecord) snapshotProjection(bytes, objects int64, digest string) storagebackend.Snapshot {
	return storagebackend.Snapshot{
		SnapshotID: record.SnapshotScope.SnapshotID, TenantID: record.SnapshotScope.TenantID,
		SourceVolumeID: record.SnapshotScope.SourceVolumeID, SourceLineageID: record.SnapshotScope.SourceLineageID,
		Generation: record.SnapshotScope.Generation, State: record.State, BackendRef: record.BackendRef,
		ContentDigest: digest, RetainedBytes: bytes, ObjectCount: objects,
		CreatedAt: record.CreatedAt, DeletedAt: record.DeletedAt,
	}
}

func (backend *Backend) findVolumeRecord(ctx context.Context, scope storagebackend.VolumeScope) (persistedRecord, string, bool, error) {
	for _, location := range []string{backend.volumeDataset(scope), backend.volumeTombstone(scope)} {
		record, found, err := backend.readRecord(ctx, location)
		if err != nil {
			return persistedRecord{}, "", false, err
		}
		if found {
			return record, location, true, nil
		}
	}
	return persistedRecord{}, "", false, nil
}

func (backend *Backend) findSnapshotRecord(ctx context.Context, scope storagebackend.SnapshotScope) (persistedRecord, string, bool, error) {
	for _, location := range []string{backend.snapshotDataset(scope), backend.snapshotTombstone(scope)} {
		record, found, err := backend.readRecord(ctx, location)
		if err != nil {
			return persistedRecord{}, "", false, err
		}
		if found {
			return record, location, true, nil
		}
	}
	return persistedRecord{}, "", false, nil
}

func (backend *Backend) readRecord(ctx context.Context, target string) (persistedRecord, bool, error) {
	properties, found, err := backend.get(ctx, target, recordProperty)
	if err != nil || !found {
		return persistedRecord{}, found, err
	}
	encoded := properties[recordProperty]
	raw, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || len(raw) == 0 || len(raw) > maxRecordBytes {
		return persistedRecord{}, true, storagebackend.ErrConflict
	}
	var record persistedRecord
	if err := dsse.DecodeStrictInto(raw, maxRecordBytes, &record); err != nil || record.validate() != nil {
		return persistedRecord{}, true, storagebackend.ErrConflict
	}
	return record, true, nil
}

func (backend *Backend) get(ctx context.Context, target string, properties ...string) (map[string]string, bool, error) {
	output, err := backend.runner.Run(ctx, "get", "-Hp", "-o", "property,value", strings.Join(properties, ","), target)
	if err != nil {
		if commandSays(err, "dataset does not exist") || commandSays(err, "no such dataset") {
			return nil, false, nil
		}
		return nil, false, mapCommandError(err)
	}
	result := make(map[string]string, len(properties))
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) != 2 {
			return nil, true, storagebackend.ErrConflict
		}
		result[parts[0]] = parts[1]
	}
	for _, property := range properties {
		if _, ok := result[property]; !ok {
			return nil, true, storagebackend.ErrConflict
		}
	}
	return result, true, nil
}

func (backend *Backend) ensureNamespace(ctx context.Context, dataset string) error {
	properties, found, err := backend.get(ctx, dataset, "type", "canmount", "mountpoint")
	if err != nil {
		return err
	}
	if found {
		if properties["type"] != "filesystem" || properties["canmount"] != "off" || properties["mountpoint"] != "none" {
			return storagebackend.ErrConflict
		}
		return nil
	}
	if _, err := backend.runner.Run(ctx, "create", "-o", "canmount=off", "-o", "mountpoint=none", dataset); err != nil {
		return mapCommandError(err)
	}
	return nil
}

func (backend *Backend) createTombstone(ctx context.Context, dataset string, record persistedRecord) error {
	if existing, found, err := backend.readRecord(ctx, dataset); err != nil {
		return err
	} else if found {
		if existing.CreateRequestID != record.CreateRequestID || existing.DeleteRequestID != record.DeleteRequestID {
			return storagebackend.ErrConflict
		}
		return nil
	}
	encoded, err := encodeRecord(record)
	if err != nil {
		return err
	}
	if _, err := backend.runner.Run(ctx, "create", "-o", "canmount=off", "-o", "mountpoint=none", "-o", recordProperty+"="+encoded, dataset); err != nil {
		return mapCommandError(err)
	}
	return nil
}

func (backend *Backend) setRecord(ctx context.Context, dataset string, record persistedRecord) error {
	encoded, err := encodeRecord(record)
	if err != nil {
		return err
	}
	if _, err := backend.runner.Run(ctx, "set", recordProperty+"="+encoded, dataset); err != nil {
		return mapCommandError(err)
	}
	return nil
}

func encodeRecord(record persistedRecord) (string, error) {
	if err := record.validate(); err != nil {
		return "", err
	}
	raw, err := json.Marshal(record)
	if err != nil || len(raw) > maxRecordBytes {
		return "", errors.New("ZFS storage record exceeds its bounded format")
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (backend *Backend) ensureBinding(ctx context.Context, record persistedRecord) (bool, error) {
	changed, err := backend.binder.Ensure(ctx, backend.binding(record))
	return changed, mapBindingError(err)
}

func (backend *Backend) bindingMatches(ctx context.Context, record persistedRecord) error {
	actual, err := backend.binder.Inspect(ctx, record.DockerHandle)
	if err != nil {
		return err
	}
	want := backend.binding(record)
	if actual.Handle != want.Handle || actual.Source != want.Source || !equalLabels(actual.Labels, want.Labels) {
		return ErrBindingConflict
	}
	return nil
}

func (backend *Backend) binding(record persistedRecord) Binding {
	return Binding{Handle: record.DockerHandle, Source: backend.volumeMountpoint(record.Volume.Scope()), Labels: map[string]string{
		"io.hardrails.steward.managed":     "true",
		"io.hardrails.steward.backend-ref": record.BackendRef,
	}}
}

func equalLabels(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func (backend *Backend) ensureHold(ctx context.Context, snapshot string) error {
	if _, err := backend.runner.Run(ctx, "hold", holdTag, snapshot); err != nil && !commandSays(err, "tag already exists") {
		return mapCommandError(err)
	}
	return nil
}

func (backend *Backend) listSnapshots(ctx context.Context, dataset string) ([]string, error) {
	output, err := backend.runner.Run(ctx, "list", "-H", "-d", "1", "-t", "snapshot", "-o", "name", dataset)
	if err != nil {
		return nil, mapCommandError(err)
	}
	var snapshots []string
	for _, value := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.Contains(value, "@") {
			snapshots = append(snapshots, value)
		}
	}
	return snapshots, nil
}

func parseNonnegative(value string) (int64, error) {
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed < 0 {
		return 0, storagebackend.ErrConflict
	}
	return parsed, nil
}

func mapBindingError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrBindingInUse):
		return storagebackend.ErrInUse
	case errors.Is(err, ErrBindingConflict):
		return storagebackend.ErrConflict
	case errors.Is(err, ErrBindingNotFound):
		return storagebackend.ErrNotFound
	default:
		return fmt.Errorf("%w: Docker volume binding", storagebackend.ErrUnavailable)
	}
}

func mapCommandError(err error) error {
	switch {
	case commandSays(err, "dataset is busy"), commandSays(err, "has dependent clones"), commandSays(err, "snapshot is held"):
		return storagebackend.ErrInUse
	case commandSays(err, "out of space"), commandSays(err, "quota exceeded"), commandSays(err, "no space left"):
		return storagebackend.ErrCapacity
	case commandSays(err, "dataset already exists"):
		return storagebackend.ErrConflict
	default:
		return fmt.Errorf("%w: OpenZFS command failed", storagebackend.ErrUnavailable)
	}
}

func commandSays(err error, fragment string) bool {
	var commandErr *CommandError
	return errors.As(err, &commandErr) && strings.Contains(strings.ToLower(commandErr.Stderr), fragment)
}

func projectID(scope storagebackend.VolumeScope) uint32 {
	digest := objectDigest("project", scope.TenantID, scope.VolumeID, scope.LineageID, strconv.FormatUint(scope.Generation, 10))
	return binary.BigEndian.Uint32(digest[:4]) | 1
}

func (backend *Backend) volumesRoot() string    { return backend.root + "/volumes" }
func (backend *Backend) tombstonesRoot() string { return backend.root + "/tombstones" }

func (backend *Backend) volumeDataset(scope storagebackend.VolumeScope) string {
	return backend.volumesRoot() + "/v-" + digestText("volume", scope.TenantID, scope.VolumeID, scope.LineageID, strconv.FormatUint(scope.Generation, 10))
}

func (backend *Backend) volumeTombstone(scope storagebackend.VolumeScope) string {
	return backend.tombstonesRoot() + "/v-" + digestText("volume", scope.TenantID, scope.VolumeID, scope.LineageID, strconv.FormatUint(scope.Generation, 10))
}

func (backend *Backend) snapshotDataset(scope storagebackend.SnapshotScope) string {
	return backend.volumeDataset(storagebackend.VolumeScope{VolumeID: scope.SourceVolumeID, TenantID: scope.TenantID, LineageID: scope.SourceLineageID, Generation: scope.Generation}) +
		"@s-" + digestText("snapshot", scope.TenantID, scope.SnapshotID, scope.SourceVolumeID, scope.SourceLineageID, strconv.FormatUint(scope.Generation, 10))
}

func (backend *Backend) snapshotTombstone(scope storagebackend.SnapshotScope) string {
	return backend.tombstonesRoot() + "/s-" + digestText("snapshot", scope.TenantID, scope.SnapshotID, scope.SourceVolumeID, scope.SourceLineageID, strconv.FormatUint(scope.Generation, 10))
}

func (backend *Backend) volumeMountpoint(scope storagebackend.VolumeScope) string {
	return filepath.Join(backend.mountRoot, "v-"+digestText("volume", scope.TenantID, scope.VolumeID, scope.LineageID, strconv.FormatUint(scope.Generation, 10)))
}

func (backend *Backend) dockerHandle(scope storagebackend.VolumeScope) string {
	return "steward-zfs-" + digestText("volume", scope.TenantID, scope.VolumeID, scope.LineageID, strconv.FormatUint(scope.Generation, 10))
}

func (backend *Backend) volumeRef(scope storagebackend.VolumeScope) string {
	return "zfs-volume-" + digestText("volume", scope.TenantID, scope.VolumeID, scope.LineageID, strconv.FormatUint(scope.Generation, 10))
}

func (backend *Backend) snapshotRef(scope storagebackend.SnapshotScope) string {
	return "zfs-snapshot-" + digestText("snapshot", scope.TenantID, scope.SnapshotID, scope.SourceVolumeID, scope.SourceLineageID, strconv.FormatUint(scope.Generation, 10))
}

func digestText(parts ...string) string {
	digest := objectDigest(parts...)
	return hex.EncodeToString(digest[:])
}

func objectDigest(parts ...string) [sha256.Size]byte {
	hash := sha256.New()
	for _, part := range parts {
		_, _ = hash.Write([]byte(strconv.Itoa(len(part))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write([]byte(part))
	}
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func (backend *Backend) timestamp() string { return backend.now().UTC().Format(time.RFC3339Nano) }

func validDataset(value string) bool {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) || strings.ContainsAny(value, "@#% \\\t\r\n") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
		for _, char := range segment {
			if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' ||
				char == '-' || char == '_' || char == '.' || char == ':' {
				continue
			}
			return false
		}
	}
	return true
}
