package adapterfixture

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestHermesQualificationIsMandatoryForCIAndRelease(t *testing.T) {
	root := filepath.Join(hermesAdapterRoot(t), "..", "..")
	ci := string(readBounded(t, filepath.Join(root, ".github", "workflows", "ci.yml"), 2<<20))
	for _, required := range []string{
		"run: go test -race -tags=qualification ./...",
		"go test -tags=qualification ./internal/adapterfixture \\",
		"-run '^TestHermesQualificationEvidenceBindsCurrentInputs$'",
	} {
		if !strings.Contains(ci, required) {
			t.Fatalf("CI is missing mandatory qualification command %q", required)
		}
	}
	release := string(readBounded(t, filepath.Join(root, "scripts", "release.sh"), 2<<20))
	gate := strings.Index(release, "\ngo test -tags=qualification ./internal/adapterfixture -run '^TestHermesQualificationEvidenceBindsCurrentInputs$' -count=1\n")
	build := strings.Index(release, "go build ")
	if gate < 0 || build < 0 || gate >= build {
		t.Fatal("release must verify exact-source evidence before building artifacts")
	}
	tagged := string(readBounded(t, filepath.Join(root, "internal", "adapterfixture", "hermes_qualification_test.go"), 4096))
	if !strings.HasPrefix(tagged, "//go:build qualification\n") ||
		!strings.Contains(tagged, "func TestHermesQualificationEvidenceBindsCurrentInputs(t *testing.T)") ||
		!strings.Contains(tagged, "verifyHermesQualificationEvidence(t)") {
		t.Fatal("qualification tag must execute the exact-source evidence verifier")
	}
}
