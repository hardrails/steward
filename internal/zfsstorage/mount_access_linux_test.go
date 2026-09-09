package zfsstorage

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestLegacyRootMigrationAllowsOnlyKnownPermissionStates(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to exercise exact ownership transitions")
	}
	for _, scenario := range []struct {
		name     string
		uid, gid int
		mode     os.FileMode
		allowed  bool
	}{
		{"legacy", 0, 0, 0o755, true},
		{"interrupted-chown", 0, 65532, 0o755, true},
		{"migrated", 0, 65532, 0o770, true},
		{"other-group", 0, 1, 0o755, false},
		{"other-owner", 65532, 0, 0o755, false},
		{"world-writable", 0, 0, 0o777, false},
		{"unexpected-mode", 0, 0, 0o770, false},
		{"special-bit", 0, 0, os.ModeSticky | 0o755, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "root")
			if err := os.Mkdir(path, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, scenario.uid, scenario.gid); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, scenario.mode); err != nil {
				t.Fatal(err)
			}
			file, err := os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			before, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			err = migrateLegacyRoot(file)
			if (err == nil) != scenario.allowed {
				t.Fatalf("migration error=%v", err)
			}
			after, err := file.Stat()
			if err != nil {
				t.Fatal(err)
			}
			stat := after.Sys().(*syscall.Stat_t)
			if scenario.allowed {
				if stat.Uid != 0 || stat.Gid != 65532 || stat.Mode&0o7777 != 0o770 {
					t.Fatal("migration did not enforce sandbox root access")
				}
			} else if after.Mode() != before.Mode() || stat.Uid != uint32(scenario.uid) || stat.Gid != uint32(scenario.gid) {
				t.Fatal("refused migration changed root")
			}
		})
	}
}
