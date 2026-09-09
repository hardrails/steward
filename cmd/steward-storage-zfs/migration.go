package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/hardrails/steward/internal/dsse"
	"github.com/hardrails/steward/internal/securefile"
	"github.com/hardrails/steward/internal/storagebackend"
	"github.com/hardrails/steward/internal/zfsstorage"
)

func readMigrationScope(path string) (storagebackend.VolumeScope, error) {
	var scope storagebackend.VolumeScope
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
		return scope, errors.New("migration scope requires a clean absolute file path")
	}
	raw, err := securefile.Read(path, maxConfigSize, securefile.OwnerOnly)
	if err != nil {
		return scope, err
	}
	if err := dsse.DecodeStrictInto(raw, maxConfigSize, &scope); err != nil {
		return scope, err
	}
	return scope, scope.Validate()
}

// The caller holds the same lifetime lock used by the serving worker. No server,
// conformance scratch dataset, or automatic namespace creation occurs here.
func migrateVolume(ctx context.Context, backend *zfsstorage.Backend, path string, stdout, stderr io.Writer) int {
	if os.Geteuid() != 0 {
		fmt.Fprintln(stderr, "steward-storage-zfs: migration requires root, stopped Executor/worker, and quiesced host/container writers")
		return 2
	}
	scope, err := readMigrationScope(path)
	if err != nil {
		fmt.Fprintln(stderr, "steward-storage-zfs: migration scope:", err)
		return 2
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	if err := backend.MigrateVolumeAccess(bounded, scope); err != nil {
		fmt.Fprintln(stderr, "steward-storage-zfs: offline volume migration refused:", err)
		return 1
	}
	fmt.Fprintln(stdout, "Retained volume root access verified; volume identity, contents, quotas, and snapshots preserved")
	return 0
}
