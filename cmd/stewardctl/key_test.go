package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestKeyMatchAcceptsGeneratedPairWithoutChangingIt(t *testing.T) {
	directory := t.TempDir()
	privatePath, publicPath := generateTestKeyPair(t, directory, "matching")
	privateBefore, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicBefore, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}

	var output bytes.Buffer
	if err := run([]string{"key", "match", "-private-key", privatePath, "-public-key", publicPath}, &output, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if output.String() != "Ed25519 key pair matches\n" {
		t.Fatalf("output=%q", output.String())
	}
	privateAfter, err := os.ReadFile(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	publicAfter, err := os.ReadFile(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(privateBefore, privateAfter) || !bytes.Equal(publicBefore, publicAfter) {
		t.Fatal("key match changed an input file")
	}
}

func TestKeyMatchRejectsMismatchedPair(t *testing.T) {
	directory := t.TempDir()
	privatePath, _ := generateTestKeyPair(t, directory, "first")
	_, otherPublicPath := generateTestKeyPair(t, directory, "second")

	err := run([]string{"key", "match", "-private-key", privatePath, "-public-key", otherPublicPath}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "do not match") {
		t.Fatalf("mismatched pair error=%v", err)
	}
}

func TestKeyMatchRejectsIncompleteAndUnknownCommands(t *testing.T) {
	for _, arguments := range [][]string{
		{"key"},
		{"key", "unknown"},
		{"key", "match"},
		{"key", "match", "-private-key", "private.pem"},
		{"key", "match", "-public-key", "public.key"},
		{"key", "match", "-private-key", "private.pem", "-public-key", "public.key", "extra"},
	} {
		if err := run(arguments, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
			t.Fatalf("invalid command accepted: %#v", arguments)
		}
	}
}

func TestUsageDocumentsKeyMatch(t *testing.T) {
	var usageOutput bytes.Buffer
	if err := run(nil, &bytes.Buffer{}, &usageOutput); err == nil {
		t.Fatal("empty command unexpectedly succeeded")
	}
	if !strings.Contains(usageOutput.String(), "stewardctl key match -private-key FILE -public-key FILE") {
		t.Fatalf("usage does not document key match:\n%s", usageOutput.String())
	}
}

func generateTestKeyPair(t *testing.T, directory, prefix string) (string, string) {
	t.Helper()
	privatePath := filepath.Join(directory, prefix+".private.pem")
	publicPath := filepath.Join(directory, prefix+".public")
	if err := run([]string{"keygen", "-private-out", privatePath, "-public-out", publicPath}, &bytes.Buffer{}, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	return privatePath, publicPath
}
