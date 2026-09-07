package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestTaskIssuerRejectsInvalidConfigurationBeforeBindingStore(t *testing.T) {
	for _, change := range []struct {
		name string
		edit func(*taskIssuerConfig)
	}{
		{"unadmitted-key", func(c *taskIssuerConfig) { c.KeyID = "other-key" }},
		{"unknown-operation", func(c *taskIssuerConfig) { c.Operations = []string{"other.operation"} }},
		{"duplicate-operation", func(c *taskIssuerConfig) { c.Operations = []string{"hermes.run", "hermes.run"} }},
		{"operation-validity", func(c *taskIssuerConfig) { c.Validity = 15 * time.Minute }},
		{"fractional-validity", func(c *taskIssuerConfig) { c.Validity = 15500 * time.Millisecond }},
		{"unbounded-capacity", func(c *taskIssuerConfig) { c.Capacity = 4097 }},
	} {
		t.Run(change.name, func(t *testing.T) {
			_, config := newTaskIssuerFixture(t)
			change.edit(&config)
			if issuer, err := openTaskIssuer(config); err == nil {
				_ = issuer.Close()
				t.Fatal("invalid configuration opened")
			}
			if _, err := os.Stat(filepath.Join(config.Store, "BINDING")); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("invalid configuration bound the store: %v", err)
			}
		})
	}
}

func TestTaskIssuerDoesNotRepairAmbiguousRetainedAuthority(t *testing.T) {
	for _, mode := range []string{"partial", "symlink", "permissions"} {
		t.Run(mode, func(t *testing.T) {
			fixture, config := newTaskIssuerFixture(t)
			issuer, err := openTaskIssuer(config)
			if err != nil {
				t.Fatal(err)
			}
			defer issuer.Close()
			request := issuerRequest(fixture)
			nameDigest := sha256.Sum256([]byte(request.TaskID))
			path := filepath.Join(config.Store, hex.EncodeToString(nameDigest[:])+".json")
			if mode == "symlink" {
				err = os.Symlink(filepath.Join(fixture.directory, "absent"), path)
			} else {
				err = os.WriteFile(path, []byte("partial-authority"), 0o600)
				if err == nil && mode == "permissions" {
					err = os.Chmod(path, 0o644)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			for attempt := 0; attempt < 2; attempt++ {
				if _, err := issuer.issue(request); !errors.Is(err, errTaskIssuerConflict) {
					t.Fatal("ambiguous authority was replaced")
				}
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) || before.Mode() != after.Mode() {
				t.Fatalf("retained artifact changed: %v", err)
			}
		})
	}
}

func TestTaskIssuerRefusesValidAuthorityFromDifferentRuntime(t *testing.T) {
	fixture, config := newTaskIssuerFixture(t)
	issuer, err := openTaskIssuer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer issuer.Close()
	foreignConfig := config
	foreignConfig.Store = filepath.Join(fixture.directory, "foreign-issuer")
	if err = os.Mkdir(foreignConfig.Store, 0o700); err != nil {
		t.Fatal(err)
	}
	changed := fixture.admitted
	changed.RuntimeRef = "executor-" + strings.Repeat("f", 64)
	foreignConfig.Admission = writePermitJSON(t, fixture.directory, "foreign-admission.json", changed)
	foreign, err := openTaskIssuer(foreignConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	request := issuerRequest(fixture)
	bundle, err := foreign.issue(request)
	if err != nil {
		t.Fatal(err)
	}
	nameDigest := sha256.Sum256([]byte(request.TaskID))
	path := filepath.Join(config.Store, hex.EncodeToString(nameDigest[:])+".json")
	if err = os.WriteFile(path, bundle, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = issuer.issue(request); !errors.Is(err, errTaskIssuerConflict) {
		t.Fatalf("same-key foreign runtime was adopted: %v", err)
	}
	if retained, err := os.ReadFile(path); err != nil || !bytes.Equal(retained, bundle) {
		t.Fatalf("foreign authority was replaced: %v", err)
	}
}
