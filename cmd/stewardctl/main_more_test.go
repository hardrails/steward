package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRunVersionAndRejectsInvalidCommands(t *testing.T) {
	var output bytes.Buffer
	if err := run([]string{"-version"}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(output.String(), "stewardctl ") {
		t.Fatalf("version output=%q", output.String())
	}
	var help bytes.Buffer
	if err := run(nil, &help, &bytes.Buffer{}); err != nil || !strings.Contains(help.String(), "external action authority") {
		t.Fatalf("top-level help error=%v output=%q", err, help.String())
	}
	help.Reset()
	if err := run([]string{"help", "permit"}, &help, &bytes.Buffer{}); err != nil || !strings.Contains(help.String(), "canonical connector request") {
		t.Fatalf("permit help error=%v output=%q", err, help.String())
	}
	help.Reset()
	if err := run([]string{"help", "executor-command"}, &help, &bytes.Buffer{}); err != nil || !strings.Contains(help.String(), "stewardctl executor-command issue|verify") {
		t.Fatalf("executor-command help error=%v output=%q", err, help.String())
	}
	for _, arguments := range [][]string{
		{"unknown"},
		{"help", "unknown"},
		{"agent-release"},
		{"agent-catalog"},
		{"activation"},
		{"rollout"},
		{"keygen"},
		{"capsule"},
		{"policy", "unknown"},
		{"evidence"},
		{"evidence", "verify", "-in", "missing"},
		{"image"},
		{"image", "inspect"},
		{"image", "import"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid command accepted: %#v", arguments)
		}
	}
}

func TestCLIRejectsExistingOutputsAndInvalidInputs(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "private.pem")
	publicPath := filepath.Join(directory, "public.key")
	if err := run([]string{"keygen", "-private-out", privatePath, "-public-out", publicPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"keygen", "-private-out", privatePath, "-public-out", filepath.Join(directory, "second.key")}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("keygen overwrote existing private key")
	}
	if err := writeNewFile("../escape", []byte("x"), 0o600); err == nil {
		t.Fatal("unsafe relative output path accepted")
	}
	empty := filepath.Join(directory, "empty")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readBounded(empty); err == nil {
		t.Fatal("empty input accepted")
	}
	badPublic := filepath.Join(directory, "bad.public")
	if err := os.WriteFile(badPublic, []byte("not-base64\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readPublicKey(badPublic); err == nil {
		t.Fatal("invalid public key accepted")
	}
	if _, err := readPrivateKey(badPublic); err == nil {
		t.Fatal("invalid private key accepted")
	}
}
