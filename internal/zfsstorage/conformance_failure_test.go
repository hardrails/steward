package zfsstorage

import (
	"context"
	"errors"
	"maps"
	"strings"
	"testing"

	"github.com/hardrails/steward/internal/storagebackend"
)

func TestConformanceFailureCleansOnlyItsScratchLineage(t *testing.T) {
	for _, scenario := range []struct {
		command string
		nth     int
		stage   string
	}{
		{"create", 1, "create conformance volume"},
		{"project", 1, "create conformance volume"},
		{"set", 1, "delete conformance clone"},
		{"snapshot", 1, "create conformance snapshot"},
		{"hold", 1, "create conformance snapshot"},
		{"clone", 1, "clone conformance snapshot"},
		{"destroy", 1, "delete conformance clone"},
		{"release", 1, "delete conformance snapshot"},
		{"destroy", 2, "delete conformance snapshot"},
		{"destroy", 3, "delete conformance volume"},
	} {
		t.Run(scenario.command+"/"+scenario.stage, func(t *testing.T) {
			backend, runner, binder := newBackendFixture(t)
			ctx := context.Background()
			retained, _, err := backend.CreateVolume(ctx, storagebackend.CreateVolumeRequest{
				RequestID: "retained-create", Volume: storagebackend.VolumeSpec{
					VolumeID: "retained", TenantID: "customer", LineageID: "retained", Generation: 1,
					ByteLimit: 1 << 20, ObjectLimit: 256,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			before := maps.Clone(runner.datasets)
			properties := maps.Clone(runner.datasets[backend.volumeDataset(retained.Scope())].properties)
			backend.quotaProbe = &recordingQuotaProbe{}
			seen, failed := 0, false
			backend.runner = runnerFunc(func(ctx context.Context, args ...string) ([]byte, error) {
				if args[0] == scenario.command {
					seen++
					if seen == scenario.nth {
						failed = true
						return nil, zfsError(args, "I/O failure")
					}
				}
				return runner.Run(ctx, args...)
			})
			err = backend.VerifyConformance(ctx)
			if !failed || !errors.Is(err, storagebackend.ErrUnavailable) || !strings.Contains(err.Error(), scenario.stage) {
				t.Fatalf("fault reached=%v, conformance error=%v, want stage %q", failed, err, scenario.stage)
			}
			if !maps.Equal(before, runner.datasets) || !maps.Equal(properties, runner.datasets[backend.volumeDataset(retained.Scope())].properties) {
				t.Fatal("failed conformance leaked scratch datasets or changed retained data")
			}
			if len(binder.bindings) != 1 {
				t.Fatalf("failed conformance changed retained binding count: %d", len(binder.bindings))
			}
			if observed, err := backend.InspectVolume(ctx, retained.Scope()); err != nil || observed != retained {
				t.Fatalf("retained volume changed: %+v, %v", observed, err)
			}
		})
	}
}
