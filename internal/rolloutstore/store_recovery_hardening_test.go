package rolloutstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreFailClosedAtAdditionalPathAndPermissionBoundaries(t *testing.T) {
	t.Run("create rejects an unstatable destination", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), strings.Repeat("x", 300))
		store, err := Create(path)
		if store != nil || err == nil {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Create(overlong path) = (%v, %v), want an error", store, err)
		}
	})

	t.Run("create rejects a missing parent", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "missing", "rollout")
		store, err := Create(path)
		if store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Create(missing parent) = (%v, %v), want ErrUnsafeWorkspace", store, err)
		}
	})

	t.Run("create cannot write through a read-only trusted parent", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "parent")
		if err := os.Mkdir(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(parent, 0o500); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(parent, 0o700) })

		store, err := Create(filepath.Join(parent, "rollout"))
		if os.Geteuid() == 0 {
			if store != nil {
				_ = store.Close()
			}
			t.Skip("root can create in an owner read-only directory")
		}
		if store != nil || err == nil {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Create(read-only parent) = (%v, %v), want an error", store, err)
		}
	})

	t.Run("open rejects a missing workspace", func(t *testing.T) {
		store, err := Open(filepath.Join(t.TempDir(), "missing"))
		if store != nil || err == nil {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(missing) = (%v, %v), want an error", store, err)
		}
	})

	t.Run("open rejects a directory lock that is not a regular file", func(t *testing.T) {
		directory := testWorkspace(t)
		if err := os.Mkdir(filepath.Join(directory, LockFileName), 0o700); err != nil {
			t.Fatal(err)
		}
		store, err := Open(directory)
		if store != nil || err == nil {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(directory lock) = (%v, %v), want an error", store, err)
		}
	})

	t.Run("open rejects a permissive directory lock", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, LockFileName, nil, 0o640)
		store, err := Open(directory)
		if store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(permissive lock) = (%v, %v), want ErrUnsafeWorkspace", store, err)
		}
	})
}

func TestStoreReadFailuresRemainBoundedAndDetectMutation(t *testing.T) {
	var nilStore *Store
	if _, err := nilStore.Read(PlanFileName, 1); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil Read() error = %v, want ErrClosed", err)
	}
	if err := nilStore.WriteOnce(PlanFileName, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil WriteOnce() error = %v, want ErrClosed", err)
	}
	if _, err := nilStore.AppendTargetState(0, 0, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil AppendTargetState() error = %v, want ErrClosed", err)
	}
	if _, err := nilStore.AppendTargetState(MaxTargets, 0, nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("invalid nil AppendTargetState() error = %v, want ErrInvalidName", err)
	}
	if _, err := nilStore.ListTargetStates(0); !errors.Is(err, ErrClosed) {
		t.Fatalf("nil ListTargetStates() error = %v, want ErrClosed", err)
	}

	t.Run("missing artifact", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		if _, err := store.Read(PlanFileName, 1); err == nil || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("Read(missing) error = %v, want os.ErrNotExist", err)
		}
	})

	t.Run("artifact larger than caller limit", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		if err := store.WriteOnce(PlanFileName, []byte("bounded")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(PlanFileName, 3); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("Read(small limit) error = %v, want ErrCapacityExceeded", err)
		}
	})

	t.Run("hook failure closes the anchored descriptor", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		if err := store.WriteOnce(PlanFileName, []byte("stable")); err != nil {
			t.Fatal(err)
		}
		injected := errors.New("injected read stop")
		var anchored *os.File
		store.mu.Lock()
		_, err := store.readLocked(PlanFileName, MaxArtifactBytes, func(file *os.File) error {
			anchored = file
			return injected
		})
		store.mu.Unlock()
		if !errors.Is(err, injected) {
			t.Fatalf("readLocked(hook failure) error = %v, want injected error", err)
		}
		if anchored == nil {
			t.Fatal("read hook did not receive the anchored descriptor")
		}
		if _, err := anchored.Stat(); !errors.Is(err, os.ErrClosed) {
			t.Fatalf("anchored descriptor remained usable after hook failure: %v", err)
		}
	})

	t.Run("closed descriptor during read", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		if err := store.WriteOnce(PlanFileName, []byte("stable")); err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		_, err := store.readLocked(PlanFileName, MaxArtifactBytes, func(file *os.File) error {
			return file.Close()
		})
		store.mu.Unlock()
		if err == nil {
			t.Fatal("readLocked(closed descriptor) succeeded")
		}
	})

	t.Run("permission mutation while reading", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := store.WriteOnce(PlanFileName, []byte("stable")); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(directory, PlanFileName)
		store.mu.Lock()
		_, err := store.readLocked(PlanFileName, MaxArtifactBytes, func(file *os.File) error {
			return file.Chmod(0o400)
		})
		store.mu.Unlock()
		if chmodErr := os.Chmod(path, 0o600); chmodErr != nil {
			t.Fatal(chmodErr)
		}
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("readLocked(permission mutation) error = %v, want ErrUnsafeWorkspace", err)
		}
	})

	t.Run("direct open never follows a missing name", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		store.mu.Lock()
		_, err := store.readArtifactLocked(PlanFileName, 1, nil, nil)
		store.mu.Unlock()
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("readArtifactLocked(missing) error = %v, want os.ErrNotExist", err)
		}
	})
}

func TestArtifactTransactionRejectsBoundaryTampering(t *testing.T) {
	tests := []struct {
		name    string
		install func(*testing.T, string, string, *writeTransactionHooks, *bool)
	}{
		{
			name: "staging permissions change before write",
			install: func(_ *testing.T, _, _ string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterStageCreate = func(file *os.File) error {
					if err := file.Chmod(0o600); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
		{
			name: "staging gains an external link after data sync",
			install: func(t *testing.T, directory, stageName string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterDataSync = func(*os.File) error {
					if err := os.Link(filepath.Join(directory, stageName), filepath.Join(t.TempDir(), "external")); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
		{
			name: "workspace permissions change before publication",
			install: func(_ *testing.T, directory, _ string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterPreparedSync = func(*os.File) error {
					if err := os.Chmod(directory, 0o750); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
		{
			name: "staging inode is replaced before publication",
			install: func(_ *testing.T, directory, stageName string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterPreparedSync = func(*os.File) error {
					path := filepath.Join(directory, stageName)
					if err := os.Remove(path); err != nil {
						return err
					}
					if err := os.WriteFile(path, []byte("exact"), 0o600); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
		{
			name: "final permissions change after link",
			install: func(_ *testing.T, directory, _ string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterLink = func(*os.File) error {
					if err := os.Chmod(filepath.Join(directory, PlanFileName), 0o400); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
		{
			name: "final disappears after publication sync",
			install: func(_ *testing.T, directory, _ string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterPublishSync = func(*os.File) error {
					if err := os.Remove(filepath.Join(directory, PlanFileName)); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
		{
			name: "final permissions change after stage cleanup",
			install: func(_ *testing.T, directory, _ string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterStageRemove = func(*os.File) error {
					if err := os.Chmod(filepath.Join(directory, PlanFileName), 0o400); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
		{
			name: "final disappears after cleanup sync",
			install: func(_ *testing.T, directory, _ string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterCleanupSync = func(*os.File) error {
					if err := os.Remove(filepath.Join(directory, PlanFileName)); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
		{
			name: "unexpected entry appears before final audit",
			install: func(_ *testing.T, directory, _ string, hooks *writeTransactionHooks, injected *bool) {
				hooks.afterStageRemove = func(*os.File) error {
					if err := os.WriteFile(filepath.Join(directory, "unexpected"), nil, 0o600); err != nil {
						return err
					}
					*injected = true
					return nil
				}
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := testWorkspace(t)
			store, err := Open(directory)
			if err != nil {
				t.Fatal(err)
			}
			stageName := mustStagingName(t, PlanFileName)
			hooks := &writeTransactionHooks{}
			injected := false
			test.install(t, directory, stageName, hooks, &injected)

			store.mu.Lock()
			snapshot, snapshotErr := store.auditLocked()
			if snapshotErr == nil {
				snapshotErr = store.createTransactionWithSnapshotLocked(
					PlanFileName,
					[]byte("exact"),
					snapshot,
					hooks,
				)
			}
			store.mu.Unlock()
			_ = os.Chmod(directory, 0o700)
			_ = os.Chmod(filepath.Join(directory, PlanFileName), 0o600)
			if !injected {
				t.Fatal("tamper injection did not complete")
			}
			if !errors.Is(snapshotErr, ErrPoisoned) || !store.poisoned {
				t.Fatalf("tampered transaction error = %v, poisoned=%v, want ErrPoisoned", snapshotErr, store.poisoned)
			}
			if closeErr := store.Close(); closeErr != nil {
				t.Fatalf("Close() after tampering error = %v", closeErr)
			}
		})
	}
}

func TestTransactionGuardsRejectInvalidPrepublicationState(t *testing.T) {
	store := mustOpenStore(t, testWorkspace(t))
	store.mu.Lock()
	snapshot, err := store.auditLocked()
	if err != nil {
		store.mu.Unlock()
		t.Fatal(err)
	}
	if err := store.createTransactionWithSnapshotLocked("unknown", nil, snapshot, nil); !errors.Is(err, ErrInvalidName) {
		store.mu.Unlock()
		t.Fatalf("invalid transaction name error = %v, want ErrInvalidName", err)
	}
	if err := store.createTransactionWithSnapshotLocked(
		PlanFileName,
		make([]byte, maxRolloutPlanBytes+1),
		snapshot,
		nil,
	); !errors.Is(err, ErrCapacityExceeded) {
		store.mu.Unlock()
		t.Fatalf("oversize transaction error = %v, want ErrCapacityExceeded", err)
	}
	stageName := mustStagingName(t, PlanFileName)
	writeTestFile(t, store.directory, stageName, nil, 0o200)
	if err := store.createTransactionWithSnapshotLocked(PlanFileName, nil, snapshot, nil); !errors.Is(err, ErrUnsafeWorkspace) {
		store.mu.Unlock()
		t.Fatalf("preexisting staging error = %v, want ErrUnsafeWorkspace", err)
	}
	if removeErr := os.Remove(filepath.Join(store.directory, stageName)); removeErr != nil {
		store.mu.Unlock()
		t.Fatal(removeErr)
	}
	store.mu.Unlock()
}

func TestOpenPreservesMalformedRecoveryEvidence(t *testing.T) {
	t.Run("multiple staging transactions", func(t *testing.T) {
		directory := testWorkspace(t)
		first := mustStagingName(t, PlanFileName)
		second := mustStagingName(t, ProofFileName)
		writeTestFile(t, directory, first, []byte("one"), 0o600)
		writeTestFile(t, directory, second, []byte("two"), 0o600)
		store, err := Open(directory)
		if store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(multiple staging) = (%v, %v), want ErrUnsafeWorkspace", store, err)
		}
		for _, name := range []string{first, second} {
			if _, statErr := os.Lstat(filepath.Join(directory, name)); statErr != nil {
				t.Fatalf("recovery evidence %q was removed: %v", name, statErr)
			}
		}
	})

	t.Run("staging entry with three links", func(t *testing.T) {
		directory := testWorkspace(t)
		stageName := mustStagingName(t, PlanFileName)
		stagePath := filepath.Join(directory, stageName)
		writeTestFile(t, directory, stageName, []byte("evidence"), 0o600)
		for _, name := range []string{"external-one", "external-two"} {
			if err := os.Link(stagePath, filepath.Join(t.TempDir(), name)); err != nil {
				t.Skipf("hard links unavailable: %v", err)
			}
		}
		store, err := Open(directory)
		if store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(three-link staging) = (%v, %v), want ErrUnsafeWorkspace", store, err)
		}
		if _, statErr := os.Lstat(stagePath); statErr != nil {
			t.Fatalf("three-link staging evidence was removed: %v", statErr)
		}
	})

	t.Run("oversize staging entry", func(t *testing.T) {
		directory := testWorkspace(t)
		stageName := mustStagingName(t, PlanFileName)
		truncateTestFile(t, directory, stageName, maxRolloutPlanBytes+1)
		store, err := Open(directory)
		if store != nil || !errors.Is(err, ErrCapacityExceeded) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(oversize staging) = (%v, %v), want ErrCapacityExceeded", store, err)
		}
		if _, statErr := os.Lstat(filepath.Join(directory, stageName)); statErr != nil {
			t.Fatalf("oversize staging evidence was removed: %v", statErr)
		}
	})

	t.Run("nonempty lifetime lock", func(t *testing.T) {
		directory := testWorkspace(t)
		writeTestFile(t, directory, LockFileName, []byte("not-a-lock"), 0o600)
		store, err := Open(directory)
		if store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(nonempty lock) = (%v, %v), want ErrUnsafeWorkspace", store, err)
		}
	})

	t.Run("missing staging entry is never synthesized", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		store.mu.Lock()
		err := store.recoverStagingEntryLocked(mustStagingName(t, PlanFileName), PlanFileName)
		store.mu.Unlock()
		if err == nil || !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("recoverStagingEntryLocked(missing) error = %v, want os.ErrNotExist", err)
		}
	})
}

func TestStoreDescriptorAndInventoryReplacementFailClosed(t *testing.T) {
	t.Run("nil descriptor state", func(t *testing.T) {
		store := &Store{}
		if err := store.checkDirectoryLocked(); !errors.Is(err, ErrClosed) {
			t.Fatalf("checkDirectoryLocked(nil) error = %v, want ErrClosed", err)
		}
		if _, err := store.auditLocked(); !errors.Is(err, ErrClosed) {
			t.Fatalf("auditLocked(nil) error = %v, want ErrClosed", err)
		}
		if err := store.syncDirectoryLocked(); !errors.Is(err, ErrClosed) {
			t.Fatalf("syncDirectoryLocked(nil) error = %v, want ErrClosed", err)
		}
		if err := syncRoot(nil); !errors.Is(err, ErrClosed) {
			t.Fatalf("syncRoot(nil) error = %v, want ErrClosed", err)
		}
	})

	t.Run("root and pathname identify different directories", func(t *testing.T) {
		first := canonicalRolloutstoreTestPath(t, testWorkspace(t))
		second := canonicalRolloutstoreTestPath(t, testWorkspace(t))
		root, err := os.OpenRoot(first)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		identity, err := os.Lstat(second)
		if err != nil {
			t.Fatal(err)
		}
		store := &Store{directory: first, identity: identity, root: root}
		if err := store.checkDirectoryLocked(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("checkDirectoryLocked(identity replacement) error = %v, want ErrUnsafeWorkspace", err)
		}
	})

	t.Run("directory lock identifies another inode", func(t *testing.T) {
		first := canonicalRolloutstoreTestPath(t, testWorkspace(t))
		second := canonicalRolloutstoreTestPath(t, testWorkspace(t))
		root, err := os.OpenRoot(first)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		identity, err := os.Lstat(first)
		if err != nil {
			t.Fatal(err)
		}
		other, err := os.Open(second)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = other.Close() }()
		store := &Store{directory: first, identity: identity, root: root, directoryLock: other}
		if err := store.checkDirectoryLocked(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("checkDirectoryLocked(lock replacement) error = %v, want ErrUnsafeWorkspace", err)
		}
	})

	t.Run("lifetime lock name is replaced", func(t *testing.T) {
		directory := canonicalRolloutstoreTestPath(t, testWorkspace(t))
		writeTestFile(t, directory, LockFileName, nil, 0o600)
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		identity, err := os.Lstat(directory)
		if err != nil {
			t.Fatal(err)
		}
		lock, err := root.OpenFile(LockFileName, os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = lock.Close() }()
		if err := os.Remove(filepath.Join(directory, LockFileName)); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, directory, LockFileName, nil, 0o600)
		store := &Store{directory: directory, identity: identity, root: root, lock: lock}
		if err := store.checkDirectoryLocked(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("checkDirectoryLocked(lifetime lock replacement) error = %v, want ErrUnsafeWorkspace", err)
		}
	})

	t.Run("audit requires a lifetime lock entry", func(t *testing.T) {
		directory := canonicalRolloutstoreTestPath(t, testWorkspace(t))
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = root.Close() }()
		identity, err := os.Lstat(directory)
		if err != nil {
			t.Fatal(err)
		}
		store := &Store{directory: directory, identity: identity, root: root}
		if _, err := store.auditLocked(); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("auditLocked(no lock entry) error = %v, want ErrUnsafeWorkspace", err)
		}
	})

	t.Run("closed root operations return errors", func(t *testing.T) {
		directory := canonicalRolloutstoreTestPath(t, testWorkspace(t))
		root, err := os.OpenRoot(directory)
		if err != nil {
			t.Fatal(err)
		}
		identity, err := os.Lstat(directory)
		if err != nil {
			t.Fatal(err)
		}
		if err := root.Close(); err != nil {
			t.Fatal(err)
		}
		store := &Store{directory: directory, identity: identity, root: root}
		if _, err := store.acquireDirectoryLock(); err == nil {
			t.Fatal("acquireDirectoryLock(closed root) succeeded")
		}
		if _, err := store.acquireLock(); err == nil {
			t.Fatal("acquireLock(closed root) succeeded")
		}
		if _, err := store.readEntryNamesLocked(); err == nil {
			t.Fatal("readEntryNamesLocked(closed root) succeeded")
		}
		if _, err := store.readRecoveryEntryNamesLocked(); err == nil {
			t.Fatal("readRecoveryEntryNamesLocked(closed root) succeeded")
		}
		if err := syncRoot(root); err == nil {
			t.Fatal("syncRoot(closed root) succeeded")
		}
	})
}

func TestCloseAggregatesDescriptorFailures(t *testing.T) {
	directory := testWorkspace(t)
	lock, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	directoryLock, err := os.Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := directoryLock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	store := &Store{lock: lock, directoryLock: directoryLock, root: root}
	if err := store.closeLocked(); err == nil {
		t.Fatal("closeLocked(closed descriptors) succeeded")
	}
	if store.lock != nil || store.directoryLock != nil || store.root != nil || !store.closed {
		t.Fatalf("closeLocked did not clear descriptor state: %#v", store)
	}
}

func TestTransactionValidatorsRejectAliasingAndCapacityViolations(t *testing.T) {
	directory := t.TempDir()
	stagePath := filepath.Join(directory, "stage")
	finalPath := filepath.Join(directory, "final")
	writeTestFile(t, directory, "stage", []byte("exact"), 0o600)
	if err := os.Link(stagePath, finalPath); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	file, err := os.Open(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	staged, err := os.Lstat(stagePath)
	if err != nil {
		t.Fatal(err)
	}
	final, err := os.Lstat(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateTransactionFile("stage", staged, 0o600, 2, int64(len("exact")-1)); !errors.Is(err, ErrCapacityExceeded) {
		t.Fatalf("validateTransactionFile(oversize) error = %v, want ErrCapacityExceeded", err)
	}
	if err := validateTransactionFile("stage", nil, 0o600, 2, MaxArtifactBytes); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("validateTransactionFile(nil) error = %v, want ErrUnsafeWorkspace", err)
	}
	if err := validateLinkedPublication(PlanFileName, nil, staged, final, MaxArtifactBytes); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("validateLinkedPublication(nil opened) error = %v, want ErrUnsafeWorkspace", err)
	}
	if err := validateLinkedPublication(PlanFileName, opened, nil, final, MaxArtifactBytes); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("validateLinkedPublication(nil staged) error = %v, want ErrUnsafeWorkspace", err)
	}
	if err := validateLinkedPublication(PlanFileName, opened, staged, nil, MaxArtifactBytes); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("validateLinkedPublication(nil final) error = %v, want ErrUnsafeWorkspace", err)
	}

	otherDirectory := t.TempDir()
	otherStage := filepath.Join(otherDirectory, "stage")
	otherFinal := filepath.Join(otherDirectory, "final")
	writeTestFile(t, otherDirectory, "stage", []byte("exact"), 0o600)
	if err := os.Link(otherStage, otherFinal); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	otherStaged, err := os.Lstat(otherStage)
	if err != nil {
		t.Fatal(err)
	}
	otherFinalInfo, err := os.Lstat(otherFinal)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLinkedPublication(
		PlanFileName,
		opened,
		otherStaged,
		otherFinalInfo,
		MaxArtifactBytes,
	); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("validateLinkedPublication(different inode) error = %v, want ErrUnsafeWorkspace", err)
	}
	if sameFileIgnoringLinks(opened, otherStaged) {
		t.Fatal("sameFileIgnoringLinks accepted different inodes")
	}
}

func TestArtifactLimitsAndPrimitiveGuardsCoverEverySecurityClass(t *testing.T) {
	for _, name := range []string{
		PlanFileName,
		ReleaseFileName,
		PolicyFileName,
		ControllerWitnessPublicKeyFileName,
		ProofFileName,
		mustTargetStateName(t, 0, 0),
		mustTargetArtifactName(t, 0, TargetServiceTrustKind),
		mustTargetArtifactName(t, 0, TargetActivationPlanKind),
		mustTargetArtifactName(t, 0, TargetExecutorBeginKind),
		mustTargetArtifactName(t, 0, TargetActivationStateKind),
		mustTargetArtifactName(t, 0, TargetActivationProofKind),
		mustTargetArtifactName(t, 0, TargetGatewayReceiptPublicKeyKind),
		mustTargetArtifactName(t, 0, TargetIntentKind),
	} {
		if maximum := artifactByteLimit(name); maximum <= 0 || maximum > MaxArtifactBytes {
			t.Fatalf("artifactByteLimit(%q) = %d", name, maximum)
		}
	}
	if artifactByteLimit(LockFileName) != 0 || artifactByteLimit("unknown") != 0 {
		t.Fatal("lock or unknown artifact unexpectedly has a payload allowance")
	}
	if artifactByteLimit(PlanAuthorizationFileName) != maxPlanAuthorizationBytes ||
		classifyName(PlanAuthorizationFileName) != artifactFixed {
		t.Fatal("signed plan authorization is not classified as a bounded fixed artifact")
	}
	if _, err := stagingName("unknown"); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("stagingName(unknown) error = %v, want ErrInvalidName", err)
	}
	if _, ok := parseFixedDecimal(""); ok {
		t.Fatal("parseFixedDecimal accepted an empty value")
	}

	directory := t.TempDir()
	writeTestFile(t, directory, LockFileName, []byte("x"), 0o600)
	info, err := os.Lstat(filepath.Join(directory, LockFileName))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateArtifact(LockFileName, info); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("validateArtifact(nonempty lock) error = %v, want ErrUnsafeWorkspace", err)
	}
	if _, _, ok := ownerAndLinks(nil); ok {
		t.Fatal("ownerAndLinks accepted nil metadata")
	}
	if _, _, ok := ownerAndLinks(syntheticFileInfo{system: "not-stat"}); ok {
		t.Fatal("ownerAndLinks accepted non-native metadata")
	}
	var nilSystem *struct{ Ctime int64 }
	if _, _, ok := changeTime(syntheticFileInfo{system: nilSystem}); ok {
		t.Fatal("changeTime accepted a nil metadata pointer")
	}
	if _, _, ok := changeTime(syntheticFileInfo{system: "not-a-struct"}); ok {
		t.Fatal("changeTime accepted non-struct metadata")
	}
	if _, _, ok := changeTime(syntheticFileInfo{system: struct{ Value int }{}}); ok {
		t.Fatal("changeTime accepted metadata without a change timestamp")
	}
	if equalNames([]string{"a"}, nil) || equalNames([]string{"a"}, []string{"b"}) {
		t.Fatal("equalNames accepted different inventories")
	}
	if sameInventory(
		workspaceSnapshot{entries: 1},
		workspaceSnapshot{entries: 2},
	) {
		t.Fatal("sameInventory accepted different counts")
	}

	closed, err := os.CreateTemp(t.TempDir(), "closed")
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if err := writeAll(closed, []byte("x")); err == nil {
		t.Fatal("writeAll(closed file) succeeded")
	}
	if _, _, ok := changeTime(nil); ok {
		t.Fatal("changeTime accepted nil metadata")
	}
	if _, _, ok := parseTargetStateName("target-064-state-000000000000.json"); ok {
		t.Fatal("parseTargetStateName accepted an out-of-range target")
	}
	if err := validateTrustedAncestors(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("validateTrustedAncestors accepted a missing ancestor")
	}
}

func TestLiveOperationsRejectLateInventoryAndCapacityChanges(t *testing.T) {
	t.Run("read reaudits after taking a stable snapshot", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := store.WriteOnce(PlanFileName, []byte("plan")); err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		_, err := store.readLocked(PlanFileName, MaxArtifactBytes, func(*os.File) error {
			writeTestFile(t, directory, ProofFileName, []byte("appeared"), 0o600)
			return nil
		})
		store.mu.Unlock()
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("readLocked(late inventory) error = %v, want ErrUnsafeWorkspace", err)
		}
	})

	t.Run("append rejects an out-of-band inventory", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		writeTestFile(t, directory, ProofFileName, []byte("appeared"), 0o600)
		if _, err := store.AppendTargetState(0, 0, nil); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("AppendTargetState(out-of-band inventory) error = %v, want ErrUnsafeWorkspace", err)
		}
	})

	t.Run("append enforces the checkpoint byte limit", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		if _, err := store.AppendTargetState(
			0,
			0,
			make([]byte, maxTargetStateBytes+1),
		); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("AppendTargetState(oversize) error = %v, want ErrCapacityExceeded", err)
		}
	})

	t.Run("audit identifies a missing expected artifact at equal cardinality", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := store.WriteOnce(PlanFileName, []byte("plan")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(directory, PlanFileName)); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, directory, ProofFileName, []byte("substitute"), 0o600)
		store.mu.Lock()
		_, err := store.auditLocked()
		store.mu.Unlock()
		if !errors.Is(err, ErrUnsafeWorkspace) || !strings.Contains(err.Error(), "disappeared") {
			t.Fatalf("auditLocked(substitution) error = %v, want disappeared ErrUnsafeWorkspace", err)
		}
	})

	t.Run("audit identifies an untracked artifact at equal cardinality", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		if err := store.WriteOnce(PlanFileName, []byte("plan")); err != nil {
			t.Fatal(err)
		}
		store.mu.Lock()
		store.digests = map[string][32]byte{LockFileName: {}}
		_, err := store.auditLocked()
		store.mu.Unlock()
		if !errors.Is(err, ErrUnsafeWorkspace) || !strings.Contains(err.Error(), "appeared") {
			t.Fatalf("auditLocked(untracked artifact) error = %v, want appeared ErrUnsafeWorkspace", err)
		}
	})

	t.Run("artifact metadata enforces its name-specific byte limit", func(t *testing.T) {
		directory := t.TempDir()
		truncateTestFile(t, directory, PlanFileName, maxRolloutPlanBytes+1)
		info, err := os.Lstat(filepath.Join(directory, PlanFileName))
		if err != nil {
			t.Fatal(err)
		}
		if err := validateArtifact(PlanFileName, info); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("validateArtifact(oversize plan) error = %v, want ErrCapacityExceeded", err)
		}
	})
}

func TestRecoveryCleanupRejectsChangedAnchors(t *testing.T) {
	t.Run("unpublished staging changes before cleanup", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		stageName := mustStagingName(t, PlanFileName)
		writeTestFile(t, directory, stageName, []byte("staged"), 0o600)
		file, err := store.root.OpenFile(stageName, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := file.Stat()
		if err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(directory, stageName), 0o400); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		store.mu.Lock()
		err = store.removeUnpublishedStagingLocked(
			stageName,
			PlanFileName,
			file,
			opened,
			0o600,
			maxRolloutPlanBytes,
		)
		store.mu.Unlock()
		_ = os.Chmod(filepath.Join(directory, stageName), 0o600)
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("removeUnpublishedStagingLocked(changed stage) error = %v, want ErrUnsafeWorkspace", err)
		}
	})

	t.Run("unpublished staging never replaces a final", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		stageName := mustStagingName(t, PlanFileName)
		writeTestFile(t, directory, stageName, []byte("staged"), 0o600)
		file, err := store.root.OpenFile(stageName, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := file.Stat()
		if err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		writeTestFile(t, directory, PlanFileName, []byte("existing"), 0o600)
		store.mu.Lock()
		err = store.removeUnpublishedStagingLocked(
			stageName,
			PlanFileName,
			file,
			opened,
			0o600,
			maxRolloutPlanBytes,
		)
		store.mu.Unlock()
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("removeUnpublishedStagingLocked(existing final) error = %v, want ErrUnsafeWorkspace", err)
		}
		got, readErr := os.ReadFile(filepath.Join(directory, PlanFileName))
		if readErr != nil || !bytes.Equal(got, []byte("existing")) {
			t.Fatalf("existing final = (%q, %v), want unchanged", got, readErr)
		}
	})

	t.Run("linked publication changes before cleanup", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		stageName := mustStagingName(t, PlanFileName)
		stagePath := filepath.Join(directory, stageName)
		finalPath := filepath.Join(directory, PlanFileName)
		writeTestFile(t, directory, stageName, []byte("published"), 0o600)
		if err := os.Link(stagePath, finalPath); err != nil {
			t.Skipf("hard links unavailable: %v", err)
		}
		file, err := store.root.OpenFile(stageName, os.O_RDONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		opened, err := file.Stat()
		if err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		if err := os.Chmod(finalPath, 0o400); err != nil {
			_ = file.Close()
			t.Fatal(err)
		}
		store.mu.Lock()
		err = store.finishLinkedPublicationLocked(
			stageName,
			PlanFileName,
			file,
			opened,
			maxRolloutPlanBytes,
		)
		store.mu.Unlock()
		_ = os.Chmod(finalPath, 0o600)
		if !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("finishLinkedPublicationLocked(changed link) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
}

func canonicalRolloutstoreTestPath(t *testing.T, path string) string {
	t.Helper()
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

type syntheticFileInfo struct {
	system any
}

func (syntheticFileInfo) Name() string       { return "synthetic" }
func (syntheticFileInfo) Size() int64        { return 0 }
func (syntheticFileInfo) Mode() os.FileMode  { return 0o600 }
func (syntheticFileInfo) ModTime() time.Time { return time.Time{} }
func (syntheticFileInfo) IsDir() bool        { return false }
func (info syntheticFileInfo) Sys() any      { return info.system }
