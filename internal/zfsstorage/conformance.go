package zfsstorage

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/hardrails/steward/internal/storagebackend"
)

const (
	conformanceByteLimit   = int64(8 << 20)
	conformanceObjectLimit = int64(64)
)

// QuotaProbe proves that the mounted filesystem actually enforces the byte and
// object limits configured by Backend. A production worker uses
// FilesystemQuotaProbe; the interface keeps the destructive lifecycle test
// deterministic without pretending a fake filesystem enforces kernel quotas.
type QuotaProbe interface {
	Verify(context.Context, string, int64, int64) error
}

// VerifyConformance creates one random, bounded scratch lineage and exercises
// the real quota, snapshot, clone, Docker binding, and deletion path. The
// scratch datasets and durable tombstones are removed before return. Call this
// before serving requests, while Backend has no concurrent users.
func (backend *Backend) VerifyConformance(ctx context.Context) error {
	if ctx == nil {
		return errors.New("ZFS conformance requires a context")
	}
	suffix, err := randomConformanceSuffix()
	if err != nil {
		return fmt.Errorf("generate ZFS conformance identity: %w", err)
	}
	parentSpec := storagebackend.VolumeSpec{
		VolumeID: "conformance-parent-" + suffix, TenantID: "steward-conformance",
		LineageID: "conformance-parent-" + suffix, Generation: 1,
		ByteLimit: conformanceByteLimit, ObjectLimit: conformanceObjectLimit,
	}
	parentScope := parentSpec.Scope()
	snapshotID := "conformance-snapshot-" + suffix
	snapshotScope := storagebackend.SnapshotScope{
		SnapshotID: snapshotID, TenantID: parentScope.TenantID,
		SourceVolumeID: parentScope.VolumeID, SourceLineageID: parentScope.LineageID,
		Generation: parentScope.Generation,
	}
	childSpec := storagebackend.VolumeSpec{
		VolumeID: "conformance-child-" + suffix, TenantID: parentScope.TenantID,
		LineageID: "conformance-child-" + suffix, Generation: 1,
		ByteLimit: conformanceByteLimit, ObjectLimit: conformanceObjectLimit,
		ParentSnapshotID: snapshotID,
	}
	defer func() {
		cleanupContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		backend.removeConformanceArtifacts(cleanupContext, parentScope, snapshotScope, childSpec.Scope())
	}()

	parent, changed, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{
		RequestID: "conformance-create-parent-" + suffix, Volume: parentSpec,
	})
	if err != nil || !changed || parent.State != storagebackend.StateReady {
		return fmt.Errorf("create conformance volume: %w", conformanceError(err))
	}
	if err := backend.quotaProbe.Verify(
		ctx, backend.volumeMountpoint(parentScope), conformanceByteLimit, conformanceObjectLimit,
	); err != nil {
		return fmt.Errorf("verify mounted ZFS quotas: %w", err)
	}
	snapshot, changed, err := backend.CreateSnapshot(ctx, storagebackend.CreateSnapshotRequest{
		RequestID:  "conformance-create-snapshot-" + suffix,
		SnapshotID: snapshotID, Source: parentScope,
	})
	if err != nil || !changed || snapshot.State != storagebackend.StateReady || snapshot.Scope() != snapshotScope {
		return fmt.Errorf("create conformance snapshot: %w", conformanceError(err))
	}
	child, changed, err := backend.CloneVolume(ctx, storagebackend.CloneVolumeRequest{
		RequestID: "conformance-clone-" + suffix, Snapshot: snapshotScope, Volume: childSpec,
	})
	if err != nil || !changed || child.State != storagebackend.StateReady || child.Spec != childSpec {
		return fmt.Errorf("clone conformance snapshot: %w", conformanceError(err))
	}
	if _, changed, err = backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{
		RequestID: "conformance-delete-child-" + suffix, Volume: child.Scope(),
	}); err != nil || !changed {
		return fmt.Errorf("delete conformance clone: %w", conformanceError(err))
	}
	if _, changed, err = backend.DeleteSnapshot(ctx, storagebackend.DeleteSnapshotRequest{
		RequestID: "conformance-delete-snapshot-" + suffix, Snapshot: snapshotScope,
	}); err != nil || !changed {
		return fmt.Errorf("delete conformance snapshot: %w", conformanceError(err))
	}
	if _, changed, err = backend.DeleteVolume(ctx, storagebackend.DeleteVolumeRequest{
		RequestID: "conformance-delete-parent-" + suffix, Volume: parentScope,
	}); err != nil || !changed {
		return fmt.Errorf("delete conformance volume: %w", conformanceError(err))
	}
	return nil
}

func conformanceError(err error) error {
	if err != nil {
		return err
	}
	return errors.New("backend returned an unexpected projection")
}

func randomConformanceSuffix() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

// removeConformanceArtifacts is intentionally stronger than normal deletion:
// conformance identities are random and never become tenant authority, so their
// tombstones must not accumulate on every worker restart.
func (backend *Backend) removeConformanceArtifacts(
	ctx context.Context,
	parent storagebackend.VolumeScope,
	snapshot storagebackend.SnapshotScope,
	child storagebackend.VolumeScope,
) {
	_, _ = backend.binder.Delete(ctx, backend.dockerHandle(child))
	_, _ = backend.binder.Delete(ctx, backend.dockerHandle(parent))
	_, _ = backend.runner.Run(ctx, "release", holdTag, backend.snapshotDataset(snapshot))
	for _, dataset := range []string{
		backend.volumeDataset(child), backend.snapshotDataset(snapshot), backend.volumeDataset(parent),
		backend.volumeTombstone(child), backend.snapshotTombstone(snapshot), backend.volumeTombstone(parent),
	} {
		_, _ = backend.runner.Run(ctx, "destroy", "-r", dataset)
	}
}

// FilesystemQuotaProbe writes ordinary allocated bytes and ordinary files. It
// succeeds only after both operations receive a kernel quota error before they
// exceed the configured hard limits.
type FilesystemQuotaProbe struct{}

func (FilesystemQuotaProbe) Verify(ctx context.Context, mountpoint string, byteLimit, objectLimit int64) error {
	if ctx == nil || !filepath.IsAbs(mountpoint) || filepath.Clean(mountpoint) != mountpoint ||
		byteLimit <= 0 || objectLimit <= 0 || objectLimit > 4096 || byteLimit > 1<<30 {
		return errors.New("quota probe has invalid bounds")
	}
	info, err := os.Lstat(mountpoint)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("quota probe mountpoint is not a real directory")
	}
	objectRoot := filepath.Join(mountpoint, ".steward-conformance-objects")
	if err := os.Mkdir(objectRoot, 0o700); err != nil {
		return err
	}
	defer os.RemoveAll(objectRoot)
	objectLimited := false
	for index := int64(0); index < objectLimit+32; index++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		file, createErr := os.OpenFile(filepath.Join(objectRoot, fmt.Sprintf("object-%04d", index)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if createErr != nil {
			if quotaError(createErr) {
				objectLimited = true
				break
			}
			return createErr
		}
		if err := file.Close(); err != nil {
			return err
		}
	}
	if !objectLimited {
		return errors.New("ZFS object quota did not stop the conformance workload")
	}
	if err := os.RemoveAll(objectRoot); err != nil {
		return err
	}

	bytePath := filepath.Join(mountpoint, ".steward-conformance-bytes")
	file, err := os.OpenFile(bytePath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close(); _ = os.Remove(bytePath) }()
	block := make([]byte, 1<<20)
	byteLimited := false
	for written := int64(0); written < byteLimit+(4<<20); written += int64(len(block)) {
		if err := ctx.Err(); err != nil {
			return err
		}
		count, writeErr := file.Write(block)
		if writeErr != nil || count != len(block) {
			if quotaError(writeErr) {
				byteLimited = true
				break
			}
			if writeErr == nil {
				return io.ErrShortWrite
			}
			return writeErr
		}
	}
	if syncErr := file.Sync(); syncErr != nil {
		if quotaError(syncErr) {
			byteLimited = true
		} else {
			return syncErr
		}
	}
	if !byteLimited {
		return errors.New("ZFS byte quota did not stop the conformance workload")
	}
	return nil
}

func quotaError(err error) bool {
	return errors.Is(err, syscall.EDQUOT) || errors.Is(err, syscall.ENOSPC)
}
