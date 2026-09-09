package zfsstorage

import (
	"context"
	"fmt"
	"strconv"

	"github.com/hardrails/steward/internal/storagebackend"
)

// MigrateVolumeAccess is an operator-only offline operation, not part of the
// storage HTTP protocol. The caller must hold the worker's lifetime lock and
// quiesce Executor and any other host/container writers. Only the selected
// retained root's legacy mode changes; contents and storage metadata do not.
func (backend *Backend) MigrateVolumeAccess(ctx context.Context, scope storagebackend.VolumeScope) error {
	if err := scope.Validate(); err != nil {
		return err
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	usage, ok := backend.binder.(interface {
		CheckUnused(context.Context, string) error
	})
	if !ok {
		return storagebackend.ErrUnsupported
	}
	access, ok := backend.mountAccess.(interface{ MigrateLegacy(string) error })
	if !ok {
		return storagebackend.ErrUnsupported
	}
	record, location, found, err := backend.findVolumeRecord(ctx, scope)
	if err != nil {
		return err
	}
	if !found {
		return storagebackend.ErrNotFound
	}
	if record.Kind != "volume" || record.Volume.Scope() != scope || record.State != storagebackend.StateReady ||
		location != backend.volumeDataset(scope) || record.BackendRef != backend.volumeRef(scope) ||
		record.DockerHandle != backend.dockerHandle(scope) || record.ProjectID != projectID(scope) {
		return storagebackend.ErrConflict
	}
	project := strconv.FormatUint(uint64(record.ProjectID), 10)
	expected := map[string]string{
		"type": "filesystem", "mountpoint": backend.volumeMountpoint(scope),
		"refquota":                   strconv.FormatInt(record.Volume.ByteLimit, 10),
		"projectquota@" + project:    strconv.FormatInt(record.Volume.ByteLimit, 10),
		"projectobjquota@" + project: strconv.FormatInt(record.Volume.ObjectLimit, 10),
	}
	properties, found, err := backend.get(ctx, location, "type", "mountpoint", "refquota", "projectquota@"+project, "projectobjquota@"+project)
	if err != nil {
		return err
	}
	if !found {
		return storagebackend.ErrNotFound
	}
	for key, want := range expected {
		if properties[key] != want {
			return fmt.Errorf("%w: retained %s differs; migration does not repair storage configuration", storagebackend.ErrConflict, key)
		}
	}
	if err := backend.bindingMatches(ctx, record); err != nil {
		return mapBindingError(err)
	}
	if err := usage.CheckUnused(ctx, record.DockerHandle); err != nil {
		return mapBindingError(err)
	}
	if err := access.MigrateLegacy(properties["mountpoint"]); err != nil {
		return fmt.Errorf("migrate retained root access: %w", err)
	}
	observed, err := backend.inspectVolumeRecord(ctx, location, record)
	if err != nil {
		return err
	}
	if observed.State != storagebackend.StateReady {
		return storagebackend.ErrConflict
	}
	return nil
}
