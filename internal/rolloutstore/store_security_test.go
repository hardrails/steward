package rolloutstore

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

func TestOpenRejectsUnsafeDirectoryBoundaries(t *testing.T) {
	for _, directory := range []string{"", "relative", string(filepath.Separator)} {
		if store, err := Open(directory); store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(%q) = (%v, %v), want ErrUnsafeWorkspace", directory, store, err)
		}
		if store, err := Create(directory); store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Create(%q) = (%v, %v), want ErrUnsafeWorkspace", directory, store, err)
		}
	}
	t.Run("unclean path", func(t *testing.T) {
		directory := testWorkspace(t)
		unclean := directory + string(filepath.Separator) + "."
		if _, err := Open(unclean); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(unclean) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("directory symlink", func(t *testing.T) {
		parent := t.TempDir()
		target := filepath.Join(parent, "target")
		if err := os.Mkdir(target, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(target, 0o700); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(parent, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(link); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(symlink) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("wrong mode", func(t *testing.T) {
		directory := testWorkspace(t)
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(directory); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(0750) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("file instead of directory", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "rollout")
		writeTestFile(t, filepath.Dir(path), filepath.Base(path), []byte("file"), 0o700)
		if _, err := Open(path); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(file) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("replaceable owner ancestor", func(t *testing.T) {
		base := t.TempDir()
		ancestor := filepath.Join(base, "replaceable")
		directory := filepath.Join(ancestor, "rollout")
		if err := os.Mkdir(ancestor, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(ancestor, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(directory); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("Open(replaceable ancestor) error = %v, want ErrUnsafeWorkspace", err)
		}
	})
}

func TestOpenRejectsUnsafeEntries(t *testing.T) {
	tests := []struct {
		name  string
		setup func(*testing.T, string)
	}{
		{
			name: "unexpected",
			setup: func(t *testing.T, directory string) {
				writeTestFile(t, directory, "surprise.json", nil, 0o600)
			},
		},
		{
			name: "symlink",
			setup: func(t *testing.T, directory string) {
				target := filepath.Join(t.TempDir(), "target")
				writeTestFile(t, filepath.Dir(target), filepath.Base(target), []byte("plan"), 0o600)
				if err := os.Symlink(target, filepath.Join(directory, PlanFileName)); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "hardlink",
			setup: func(t *testing.T, directory string) {
				source := filepath.Join(t.TempDir(), "source")
				writeTestFile(t, filepath.Dir(source), filepath.Base(source), []byte("plan"), 0o600)
				if err := os.Link(source, filepath.Join(directory, PlanFileName)); err != nil {
					t.Skipf("hard links unavailable: %v", err)
				}
			},
		},
		{
			name: "fifo",
			setup: func(t *testing.T, directory string) {
				if err := syscall.Mkfifo(filepath.Join(directory, PlanFileName), 0o600); err != nil {
					t.Skipf("FIFO unavailable: %v", err)
				}
			},
		},
		{
			name: "directory",
			setup: func(t *testing.T, directory string) {
				if err := os.Mkdir(filepath.Join(directory, PlanFileName), 0o700); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "wrong permissions",
			setup: func(t *testing.T, directory string) {
				writeTestFile(t, directory, PlanFileName, []byte("plan"), 0o640)
			},
		},
		{
			name: "incomplete output",
			setup: func(t *testing.T, directory string) {
				writeTestFile(t, directory, PlanFileName, []byte("partial"), 0o200)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			directory := testWorkspace(t)
			test.setup(t, directory)
			store, err := Open(directory)
			if store != nil || !errors.Is(err, ErrUnsafeWorkspace) {
				if store != nil {
					_ = store.Close()
				}
				t.Fatalf("Open() = (%v, %v), want ErrUnsafeWorkspace", store, err)
			}
		})
	}
	if device, err := os.Stat("/dev/null"); err == nil {
		if err := validateArtifact(PlanFileName, device); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("validateArtifact(device) error = %v, want ErrUnsafeWorkspace", err)
		}
	}
}

func TestMethodsRejectTraversalAndInvalidNames(t *testing.T) {
	store := mustOpenStore(t, testWorkspace(t))
	for _, name := range []string{
		"",
		"../plan.json",
		"subdir/plan.json",
		"unknown.json",
		LockFileName,
		"target-064-intent.json",
	} {
		if err := store.WriteOnce(name, nil); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("WriteOnce(%q) error = %v, want ErrInvalidName", name, err)
		}
		if err := store.Import(name, nil); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Import(%q) error = %v, want ErrInvalidName", name, err)
		}
		if _, err := store.Read(name, 1); !errors.Is(err, ErrInvalidName) {
			t.Fatalf("Read(%q) error = %v, want ErrInvalidName", name, err)
		}
	}
	stateName := mustTargetStateName(t, 0, 0)
	if err := store.WriteOnce(stateName, nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("WriteOnce(state) error = %v, want ErrInvalidName", err)
	}
	if err := store.Import(stateName, nil); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("Import(state) error = %v, want ErrInvalidName", err)
	}
	for _, limit := range []int64{0, -1, MaxArtifactBytes + 1} {
		if _, err := store.Read(PlanFileName, limit); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("Read(limit=%d) error = %v, want ErrCapacityExceeded", limit, err)
		}
	}
	if _, err := store.ListTargetStates(MaxTargets); !errors.Is(err, ErrInvalidName) {
		t.Fatalf("ListTargetStates(oversize) error = %v, want ErrInvalidName", err)
	}
}

func TestCapacityBounds(t *testing.T) {
	t.Run("single artifact", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		if err := store.WriteOnce(PlanFileName, make([]byte, maxRolloutPlanBytes+1)); !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("oversize WriteOnce() error = %v, want ErrCapacityExceeded", err)
		}
		if _, err := os.Lstat(filepath.Join(store.directory, PlanFileName)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("oversize artifact exists or stat failed: %v", err)
		}
	})
	t.Run("aggregate audit", func(t *testing.T) {
		directory := testWorkspace(t)
		largeKinds := []string{
			TargetIntentKind,
			TargetAdmitCommandKind,
			TargetAdmissionKind,
			TargetStartCommandKind,
			TargetCanaryCommandKind,
			TargetCanaryResultKind,
			TargetCaptureExportKind,
		}
		written := 0
		for target := uint16(0); target < MaxTargets && written < 257; target++ {
			for _, kind := range largeKinds {
				if written == 257 {
					break
				}
				name := mustTargetArtifactName(t, target, kind)
				truncateTestFile(t, directory, name, MaxArtifactBytes)
				written++
			}
		}
		if written != 257 {
			t.Fatalf("aggregate fixture files = %d, want 257", written)
		}
		store, err := Open(directory)
		if store != nil || !errors.Is(err, ErrCapacityExceeded) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(over aggregate cap) = (%v, %v), want ErrCapacityExceeded", store, err)
		}
	})
	t.Run("entry audit", func(t *testing.T) {
		directory := testWorkspace(t)
		for sequence := uint64(0); sequence < MaxWorkspaceEntries; sequence++ {
			name := mustTargetStateName(t, 0, sequence)
			file, err := os.OpenFile(
				filepath.Join(directory, name),
				os.O_WRONLY|os.O_CREATE|os.O_EXCL,
				0o600,
			)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
		}
		store, err := Open(directory)
		if store != nil || !errors.Is(err, ErrCapacityExceeded) {
			if store != nil {
				_ = store.Close()
			}
			t.Fatalf("Open(over entry cap) = (%v, %v), want ErrCapacityExceeded", store, err)
		}
	})
	t.Run("live aggregate and entry guards", func(t *testing.T) {
		store := mustOpenStore(t, testWorkspace(t))
		store.mu.Lock()
		err := store.createWithSnapshotLocked(
			PlanFileName,
			[]byte("x"),
			workspaceSnapshot{entries: 1, bytes: MaxWorkspaceBytes},
			nil,
		)
		store.mu.Unlock()
		if !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("aggregate guard error = %v, want ErrCapacityExceeded", err)
		}
		store.mu.Lock()
		err = store.createWithSnapshotLocked(
			PlanFileName,
			nil,
			workspaceSnapshot{entries: MaxWorkspaceEntries},
			nil,
		)
		store.mu.Unlock()
		if !errors.Is(err, ErrCapacityExceeded) {
			t.Fatalf("entry guard error = %v, want ErrCapacityExceeded", err)
		}
	})
}

func TestReadRejectsDigestMutation(t *testing.T) {
	directory := testWorkspace(t)
	store := mustOpenStore(t, directory)
	if err := store.WriteOnce(PlanFileName, []byte("alpha")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, directory, PlanFileName, []byte("bravo"), 0o600)
	if _, err := store.Read(PlanFileName, 5); !errors.Is(err, ErrUnsafeWorkspace) {
		t.Fatalf("Read(mutated bytes) error = %v, want ErrUnsafeWorkspace", err)
	}
}

func TestStoreRejectsOutOfBandInventoryChanges(t *testing.T) {
	t.Run("deletion", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		if err := store.WriteOnce(PlanFileName, []byte("plan")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(directory, PlanFileName)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.ListTargetStates(0); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("ListTargetStates after deletion error = %v, want ErrUnsafeWorkspace", err)
		}
		if err := store.WriteOnce(PlanFileName, []byte("replacement")); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("WriteOnce after deletion error = %v, want ErrUnsafeWorkspace", err)
		}
	})
	t.Run("addition", func(t *testing.T) {
		directory := testWorkspace(t)
		store := mustOpenStore(t, directory)
		name := mustTargetArtifactName(t, 0, TargetIntentKind)
		writeTestFile(t, directory, name, []byte("out-of-band"), 0o600)
		if _, err := store.ListTargetStates(0); !errors.Is(err, ErrUnsafeWorkspace) {
			t.Fatalf("ListTargetStates after addition error = %v, want ErrUnsafeWorkspace", err)
		}
	})
}

func TestAmbiguousWritePoisonsUntilOpenRemovesPartialStaging(t *testing.T) {
	directory := testWorkspace(t)
	store := mustOpenStore(t, directory)
	injected := errors.New("injected post-create failure")
	err := store.writeOnce(PlanFileName, []byte("complete"), func(file *os.File) error {
		if _, err := file.Write([]byte("partial")); err != nil {
			return err
		}
		return injected
	})
	if !errors.Is(err, injected) || !errors.Is(err, ErrPoisoned) || !store.poisoned {
		t.Fatalf("writeOnce() error = %v, poisoned=%v", err, store.poisoned)
	}
	stageName, nameErr := stagingName(PlanFileName)
	if nameErr != nil {
		t.Fatal(nameErr)
	}
	info, statErr := os.Lstat(filepath.Join(directory, stageName))
	if statErr != nil {
		t.Fatalf("partial staging entry missing: %v", statErr)
	}
	if info.Size() != int64(len("partial")) || info.Mode().Perm() != 0o200 {
		t.Fatalf("partial staging entry size=%d mode=%v", info.Size(), info.Mode())
	}
	if _, err := os.Lstat(filepath.Join(directory, PlanFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("final artifact was published before recovery: %v", err)
	}
	if err := store.WriteOnce(ProofFileName, nil); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("write after ambiguity error = %v, want ErrPoisoned", err)
	}
	if _, err := store.ListTargetStates(0); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("list after ambiguity error = %v, want ErrPoisoned", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory)
	if err != nil {
		t.Fatalf("Open(partial staging) error = %v", err)
	}
	defer func() { _ = reopened.Close() }()
	if _, err := os.Lstat(filepath.Join(directory, stageName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("partial staging entry survived recovery: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(directory, PlanFileName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("recovery published a partial artifact: %v", err)
	}
	if err := reopened.WriteOnce(PlanFileName, []byte("complete")); err != nil {
		t.Fatalf("workspace was not usable after staging recovery: %v", err)
	}
}

func TestStateOrderingIsPerTargetAndSurvivesReopen(t *testing.T) {
	directory := testWorkspace(t)
	for target := uint16(0); target < 2; target++ {
		for sequence := uint64(0); sequence < 3; sequence++ {
			writeTestFile(
				t,
				directory,
				mustTargetStateName(t, target, sequence),
				[]byte{byte(target), byte(sequence)},
				0o600,
			)
		}
	}
	store := mustOpenStore(t, directory)
	for target := uint16(0); target < 2; target++ {
		states, err := store.ListTargetStates(target)
		want := []string{
			mustTargetStateName(t, target, 0),
			mustTargetStateName(t, target, 1),
			mustTargetStateName(t, target, 2),
		}
		if err != nil || !reflect.DeepEqual(states, want) {
			t.Fatalf("ListTargetStates(%d) = (%#v, %v), want %#v", target, states, err, want)
		}
	}
	if _, err := store.AppendTargetState(1, 3, []byte("next")); err != nil {
		t.Fatalf("AppendTargetState after reopen error = %v", err)
	}

	gapped := testWorkspace(t)
	writeTestFile(t, gapped, mustTargetStateName(t, 2, 1), []byte("gap"), 0o600)
	if opened, err := Open(gapped); opened != nil || !errors.Is(err, ErrStateOrder) {
		if opened != nil {
			_ = opened.Close()
		}
		t.Fatalf("Open(gapped states) = (%v, %v), want ErrStateOrder", opened, err)
	}
}
