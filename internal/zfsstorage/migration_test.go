package zfsstorage

import (
	"context"
	"errors"
	"maps"
	"testing"

	"github.com/hardrails/steward/internal/storagebackend"
)

type migrationBinder struct {
	*fakeBinder
	unusedErr error
	checked   []string
}

func (binder *migrationBinder) CheckUnused(_ context.Context, handle string) error {
	binder.checked = append(binder.checked, handle)
	return binder.unusedErr
}

type migrationAccess struct {
	*fakeMountAccess
	migrated []string
	err      error
}

func (access *migrationAccess) MigrateLegacy(path string) error {
	access.migrated = append(access.migrated, path)
	if access.err == nil {
		access.verifyErr = nil
	}
	return access.err
}

func TestRetainedVolumeMigrationIsExplicitScopedAndReadOnlyExceptRootMode(t *testing.T) {
	for _, scenario := range []string{"legacy", "replay", "in-use", "docker-unavailable", "wrong-tenant", "wrong-generation", "missing-binding", "wrong-binding", "wrong-mount", "wrong-quota", "wrong-project", "wrong-record", "quarantined", "unexpected-permissions"} {
		t.Run(scenario, func(t *testing.T) {
			backend, runner, original := newBackendFixture(t)
			binder := &migrationBinder{fakeBinder: original}
			access := &migrationAccess{fakeMountAccess: &fakeMountAccess{}}
			backend.binder, backend.mountAccess = binder, access
			ctx := context.Background()
			request := storagebackend.CreateVolumeRequest{RequestID: "create", Volume: storagebackend.VolumeSpec{
				VolumeID: "retained", TenantID: "tenant", LineageID: "lineage", Generation: 1, ByteLimit: 1 << 20, ObjectLimit: 256}}
			volume, _, err := backend.CreateVolume(ctx, request)
			if err != nil {
				t.Fatal(err)
			}
			access.verifyErr = errors.New("legacy permissions")
			if _, err := backend.InspectVolume(ctx, volume.Scope()); err == nil {
				t.Fatal("inspection repaired legacy permissions")
			}
			if _, _, err := backend.CreateVolume(ctx, request); err == nil {
				t.Fatal("create replay repaired legacy permissions")
			}
			scope := volume.Scope()
			dataset := runner.datasets[backend.volumeDataset(scope)]
			switch scenario {
			case "replay":
				access.verifyErr = nil
			case "in-use":
				binder.unusedErr = ErrBindingInUse
			case "docker-unavailable":
				binder.unusedErr = errors.New("unavailable")
			case "wrong-tenant":
				scope.TenantID = "other"
			case "wrong-generation":
				scope.Generation++
			case "missing-binding":
				delete(original.bindings, volume.DockerVolumeHandle)
			case "wrong-binding":
				binding := original.bindings[volume.DockerVolumeHandle]
				binding.Source = "/other"
				original.bindings[volume.DockerVolumeHandle] = binding
			case "wrong-mount":
				dataset.properties["mountpoint"] = "/other"
			case "wrong-quota":
				dataset.properties["refquota"] = "none"
			case "wrong-project", "wrong-record", "quarantined":
				record, _, _, err := backend.findVolumeRecord(ctx, scope)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "wrong-project" {
					record.ProjectID++
				}
				if scenario == "wrong-record" {
					record.BackendRef = "other"
				}
				if scenario == "quarantined" {
					record.State = storagebackend.StateQuarantined
				}
				if err := backend.setRecord(ctx, backend.volumeDataset(scope), record); err != nil {
					t.Fatal(err)
				}
			case "unexpected-permissions":
				access.err = errors.New("unexpected root permissions")
			}
			before := maps.Clone(dataset.properties)
			err = backend.MigrateVolumeAccess(ctx, scope)
			success := scenario == "legacy" || scenario == "replay"
			if (err == nil) != success {
				t.Fatalf("migration error=%v", err)
			}
			if !maps.Equal(before, dataset.properties) {
				t.Fatal("migration rewrote retained ZFS properties")
			}
			if len(access.prepared) != 1 {
				t.Fatal("migration reused unrestricted new-root preparation")
			}
			if !success && scenario != "unexpected-permissions" && len(access.migrated) != 0 {
				t.Fatal("unsafe root reached migration")
			}
			if success {
				if err := backend.MigrateVolumeAccess(ctx, scope); err != nil {
					t.Fatal(err)
				}
				after, err := backend.InspectVolume(ctx, scope)
				if err != nil || after != volume {
					t.Fatalf("retained identity changed: %+v %v", after, err)
				}
			}
		})
	}
}
