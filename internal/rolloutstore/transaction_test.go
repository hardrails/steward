package rolloutstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestArtifactTransactionRecoversEveryCrashBoundary(t *testing.T) {
	tests := []struct {
		name      string
		published bool
		install   func(*writeTransactionHooks, func(*os.File) error)
	}{
		{
			name: "stage created",
			install: func(hooks *writeTransactionHooks, fail func(*os.File) error) {
				hooks.afterStageCreate = fail
			},
		},
		{
			name: "data synced",
			install: func(hooks *writeTransactionHooks, fail func(*os.File) error) {
				hooks.afterDataSync = fail
			},
		},
		{
			name: "publication mode synced",
			install: func(hooks *writeTransactionHooks, fail func(*os.File) error) {
				hooks.afterPreparedSync = fail
			},
		},
		{
			name:      "final name linked",
			published: true,
			install: func(hooks *writeTransactionHooks, fail func(*os.File) error) {
				hooks.afterLink = fail
			},
		},
		{
			name:      "publication directory synced",
			published: true,
			install: func(hooks *writeTransactionHooks, fail func(*os.File) error) {
				hooks.afterPublishSync = fail
			},
		},
		{
			name:      "staging name removed",
			published: true,
			install: func(hooks *writeTransactionHooks, fail func(*os.File) error) {
				hooks.afterStageRemove = fail
			},
		},
		{
			name:      "cleanup directory synced",
			published: true,
			install: func(hooks *writeTransactionHooks, fail func(*os.File) error) {
				hooks.afterCleanupSync = fail
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := testWorkspace(t)
			store := mustOpenStore(t, directory)
			prior := []byte("prior-proof")
			if err := store.WriteOnce(ProofFileName, prior); err != nil {
				t.Fatal(err)
			}
			raw := []byte("exact-plan-bytes")
			injected := errors.New("simulated process stop")
			hooks := &writeTransactionHooks{}
			test.install(hooks, func(*os.File) error { return injected })

			store.mu.Lock()
			snapshot, err := store.auditLocked()
			if err == nil {
				err = store.createTransactionWithSnapshotLocked(PlanFileName, raw, snapshot, hooks)
			}
			store.mu.Unlock()
			if !errors.Is(err, injected) || !errors.Is(err, ErrPoisoned) || !store.poisoned {
				t.Fatalf("transaction error = %v, poisoned=%v", err, store.poisoned)
			}
			if err := store.Close(); err != nil {
				t.Fatal(err)
			}

			reopened, err := Open(directory)
			if err != nil {
				t.Fatalf("Open() after %s error = %v", test.name, err)
			}
			defer func() { _ = reopened.Close() }()
			stageName, err := stagingName(PlanFileName)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(directory, stageName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("staging entry survived recovery: %v", err)
			}
			gotPrior, err := reopened.Read(ProofFileName, MaxArtifactBytes)
			if err != nil || !bytes.Equal(gotPrior, prior) {
				t.Fatalf("prior artifact = (%q, %v), want %q", gotPrior, err, prior)
			}

			if test.published {
				got, err := reopened.Read(PlanFileName, MaxArtifactBytes)
				if err != nil || !bytes.Equal(got, raw) {
					t.Fatalf("published artifact = (%q, %v), want %q", got, err, raw)
				}
				if err := reopened.WriteOnce(PlanFileName, []byte("replacement")); !errors.Is(err, ErrAlreadyExists) {
					t.Fatalf("replacement error = %v, want ErrAlreadyExists", err)
				}
				return
			}

			if _, err := os.Lstat(filepath.Join(directory, PlanFileName)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("unpublished artifact exists after recovery: %v", err)
			}
			if err := reopened.WriteOnce(PlanFileName, raw); err != nil {
				t.Fatalf("workspace is not writable after recovery: %v", err)
			}
			got, err := reopened.Read(PlanFileName, MaxArtifactBytes)
			if err != nil || !bytes.Equal(got, raw) {
				t.Fatalf("artifact after retry = (%q, %v), want %q", got, err, raw)
			}
		})
	}
}

func TestOpenReconcilesOnlyValidOwnedStaging(t *testing.T) {
	t.Run("unpublished write-only staging", func(t *testing.T) {
		directory := testWorkspace(t)
		stageName := mustStagingName(t, PlanFileName)
		writeTestFile(t, directory, stageName, []byte("partial"), 0o200)
		store, err := Open(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()
		if _, err := os.Lstat(filepath.Join(directory, stageName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging entry survived Open: %v", err)
		}
		if _, err := os.Lstat(filepath.Join(directory, PlanFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("partial staging was published: %v", err)
		}
	})

	t.Run("unpublished prepared staging", func(t *testing.T) {
		directory := testWorkspace(t)
		stageName := mustStagingName(t, PlanFileName)
		writeTestFile(t, directory, stageName, []byte("prepared"), 0o600)
		store, err := Open(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()
		if _, err := os.Lstat(filepath.Join(directory, stageName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging entry survived Open: %v", err)
		}
	})

	t.Run("linked publication", func(t *testing.T) {
		directory := testWorkspace(t)
		stageName := mustStagingName(t, PlanFileName)
		raw := []byte("published")
		writeTestFile(t, directory, stageName, raw, 0o600)
		if err := os.Link(
			filepath.Join(directory, stageName),
			filepath.Join(directory, PlanFileName),
		); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		store, err := Open(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = store.Close() }()
		if _, err := os.Lstat(filepath.Join(directory, stageName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("staging entry survived Open: %v", err)
		}
		got, err := store.Read(PlanFileName, MaxArtifactBytes)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("recovered final = (%q, %v), want %q", got, err, raw)
		}
	})

	tests := []struct {
		name  string
		setup func(*testing.T, string, string)
	}{
		{
			name: "symlink",
			setup: func(t *testing.T, directory, stageName string) {
				external := filepath.Join(t.TempDir(), "external")
				writeTestFile(t, filepath.Dir(external), filepath.Base(external), []byte("external"), 0o600)
				if err := os.Symlink(external, filepath.Join(directory, stageName)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "external hard link",
			setup: func(t *testing.T, directory, stageName string) {
				external := filepath.Join(t.TempDir(), "external")
				writeTestFile(t, filepath.Dir(external), filepath.Base(external), []byte("external"), 0o600)
				if err := os.Link(external, filepath.Join(directory, stageName)); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			},
		},
		{
			name: "wrong permissions",
			setup: func(t *testing.T, directory, stageName string) {
				writeTestFile(t, directory, stageName, []byte("unsafe"), 0o640)
			},
		},
		{
			name: "independent final",
			setup: func(t *testing.T, directory, stageName string) {
				writeTestFile(t, directory, stageName, []byte("staged"), 0o600)
				writeTestFile(t, directory, PlanFileName, []byte("existing"), 0o600)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := testWorkspace(t)
			stageName := mustStagingName(t, PlanFileName)
			test.setup(t, directory, stageName)
			store, err := Open(directory)
			if store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatalf("Open() = (%v, %v), want ErrUnsafeWorkspace", store, err)
			}
			if _, err := os.Lstat(filepath.Join(directory, stageName)); err != nil {
				t.Fatalf("unsafe staging entry was removed: %v", err)
			}
		})
	}
}

func TestPublicationNeverReplacesFinalName(t *testing.T) {
	t.Run("preexisting", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		raw := []byte("original")
		if err := store.WriteOnce(PlanFileName, raw); err != nil {
			t.Fatal(err)
		}
		if err := store.WriteOnce(PlanFileName, []byte("replacement")); !errors.Is(err, ErrAlreadyExists) {
			t.Fatalf("replacement error = %v, want ErrAlreadyExists", err)
		}
		got, err := store.Read(PlanFileName, MaxArtifactBytes)
		if err != nil || !bytes.Equal(got, raw) {
			t.Fatalf("final bytes = (%q, %v), want %q", got, err, raw)
		}
		stageName := mustStagingName(t, PlanFileName)
		if _, err := os.Lstat(filepath.Join(directory, stageName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("duplicate write created staging entry: %v", err)
		}
	})

	t.Run("appears before link", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		existing := []byte("independently-created-final")
		hooks := &writeTransactionHooks{
			afterPreparedSync: func(*os.File) error {
				path := filepath.Join(directory, PlanFileName)
				if err := os.WriteFile(path, existing, 0o600); err != nil {
					return err
				}
				return os.Chmod(path, 0o600)
			},
		}
		store.mu.Lock()
		snapshot, err := store.auditLocked()
		if err == nil {
			err = store.createTransactionWithSnapshotLocked(
				PlanFileName,
				[]byte("attempted-replacement"),
				snapshot,
				hooks,
			)
		}
		store.mu.Unlock()
		if err == nil || !errors.Is(err, ErrPoisoned) {
			t.Fatalf("link-time collision error = %v, want ErrPoisoned", err)
		}
		got, readErr := os.ReadFile(filepath.Join(directory, PlanFileName))
		if readErr != nil || !bytes.Equal(got, existing) {
			t.Fatalf("final bytes = (%q, %v), want untouched %q", got, readErr, existing)
		}
	})
}

func TestStagingNamesAreBoundedAndReserved(t *testing.T) {
	for _, finalName := range []string{
		PlanFileName,
		mustTargetArtifactName(t, MaxTargetIndex, TargetCaptureExportKind),
		mustTargetStateName(t, MaxTargetIndex, MaxTargetStateSequence),
	} {
		stageName := mustStagingName(t, finalName)
		parsed, ok := parseStagingName(stageName)
		if !ok || parsed != finalName {
			t.Fatalf("parseStagingName(%q) = (%q, %v), want %q", stageName, parsed, ok, finalName)
		}
		if classifyName(stageName) != artifactInvalid {
			t.Fatalf("staging name %q is exposed as a public artifact", stageName)
		}
	}
	for _, name := range []string{
		stagingPrefix,
		stagingPrefix + LockFileName,
		stagingPrefix + "../" + PlanFileName,
		stagingPrefix + "unknown.json",
	} {
		if finalName, ok := parseStagingName(name); ok {
			t.Fatalf("invalid staging name %q parsed as %q", name, finalName)
		}
	}
}

func mustStagingName(t *testing.T, finalName string) string {
	t.Helper()
	name, err := stagingName(finalName)
	if err != nil {
		t.Fatal(err)
	}
	return name
}
