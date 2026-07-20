//go:build unix

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

func TestSiteInitPublishesExactModesUnderRestrictiveUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	directory := filepath.Join(t.TempDir(), "site")
	if err := siteCommand([]string{"init", directory}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	for _, check := range []struct {
		path string
		mode os.FileMode
	}{
		{"public/site-root.public", 0o644},
		{"public/site-policy.dsse.json", 0o644},
		{"private/site-root.private.pem", 0o600},
		{"inventory.dsse.json", 0o644},
	} {
		info, err := os.Stat(filepath.Join(directory, check.path))
		if err != nil {
			t.Fatalf("stat %s: %v", check.path, err)
		}
		if info.Mode().Perm() != check.mode {
			t.Fatalf("%s mode=%v", check.path, info.Mode().Perm())
		}
	}
	if err := siteCommand([]string{"verify", directory}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
}
