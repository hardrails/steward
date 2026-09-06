package adapterfixture

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHermesQualificationIsMandatoryForCIAndRelease(t *testing.T) {
	root := filepath.Join(hermesAdapterRoot(t), "..", "..")
	ci := string(readBounded(t, filepath.Join(root, ".github", "workflows", "ci.yml"), 2<<20))
	for _, required := range []string{
		"run: GOENV=off GOFLAGS= go test -race -tags=qualification -skip= ./...",
		"GOENV=off GOFLAGS= go test -tags=qualification ./internal/adapterfixture \\",
		"-run '^TestHermesQualificationEvidenceBindsCurrentInputs$'",
	} {
		if !strings.Contains(ci, required) {
			t.Fatalf("CI is missing mandatory qualification command %q", required)
		}
	}
	release := string(readBounded(t, filepath.Join(root, "scripts", "release.sh"), 2<<20))
	gate := strings.Index(release, "\nGOENV=off GOFLAGS= go test -tags=qualification ./internal/adapterfixture -run '^TestHermesQualificationEvidenceBindsCurrentInputs$' -skip= -count=1\n")
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

func TestHermesReleaseGateIgnoresAmbientTestFlags(t *testing.T) {
	root := filepath.Join(hermesAdapterRoot(t), "..", "..")
	release := string(readBounded(t, filepath.Join(root, "scripts", "release.sh"), 2<<20))
	var command string
	for _, line := range strings.Split(release, "\n") {
		if strings.Contains(line, "go test -tags=qualification ") {
			command = line
			break
		}
	}
	if command == "" {
		t.Fatal("release qualification command missing")
	}
	directory := t.TempDir()
	// Intercept the exact release command without building artifacts or recursively
	// running this suite. The real evidence verifier is separately exercised by CI.
	probe := "#!/bin/sh\nset -eu\ntest \"${GOENV:-}\" = off\ntest -z \"${GOFLAGS:-}\"\nprintf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(directory, "go"), []byte(probe), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", directory+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("GOENV", filepath.Join(directory, "hostile-goenv"))
	t.Setenv("GOFLAGS", "-skip=^TestHermesQualificationEvidenceBindsCurrentInputs$")
	output, err := exec.Command("/bin/sh", "-c", command).CombinedOutput()
	if err != nil {
		t.Fatalf("release gate inherited ambient test authority: %v\n%s", err, output)
	}
	for _, argument := range []string{"-tags=qualification", "^TestHermesQualificationEvidenceBindsCurrentInputs$", "-skip=", "-count=1"} {
		if !strings.Contains("\n"+string(output), "\n"+argument+"\n") {
			t.Fatalf("release gate is missing exact argument %q: %s", argument, output)
		}
	}
}

func TestHermesReleaseGateExecutesDespiteHostileGoSettings(t *testing.T) {
	root := filepath.Join(hermesAdapterRoot(t), "..", "..")
	release := string(readBounded(t, filepath.Join(root, "scripts", "release.sh"), 2<<20))
	var gate string
	for _, line := range strings.Split(release, "\n") {
		if strings.Contains(line, "go test -tags=qualification ") {
			gate = line
			break
		}
	}
	if gate == "" {
		t.Fatal("release qualification command missing")
	}
	fixture := t.TempDir()
	if err := os.MkdirAll(filepath.Join(fixture, "internal", "adapterfixture"), 0o700); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"go.mod":                                "module qualification-fixture\n\ngo 1.24\n",
		"internal/adapterfixture/probe_test.go": "//go:build qualification\n\npackage adapterfixture\nimport \"testing\"\nfunc TestHermesQualificationEvidenceBindsCurrentInputs(t *testing.T) { t.Fatal(\"qualification-sentinel-executed\") }\n",
		"hostile-goenv":                         "GOFLAGS=-list=.\n",
	} {
		if err := os.WriteFile(filepath.Join(fixture, path), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("GOWORK", "off")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOENV", filepath.Join(fixture, "hostile-goenv"))
	for _, flags := range []string{"-skip=^TestHermesQualificationEvidenceBindsCurrentInputs$", "-list=.", ""} {
		t.Run(flags, func(t *testing.T) {
			t.Setenv("GOFLAGS", flags)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, "/bin/sh", "-c", gate)
			command.Dir = fixture
			output, err := command.CombinedOutput()
			if err == nil || !strings.Contains(string(output), "qualification-sentinel-executed") {
				t.Fatalf("hostile flags suppressed qualification: %v\n%s", err, output)
			}
		})
	}
}

func TestHermesFailedQualificationStopsReleaseBeforePackaging(t *testing.T) {
	root := filepath.Join(hermesAdapterRoot(t), "..", "..")
	fixture := t.TempDir()
	if err := os.Mkdir(filepath.Join(fixture, "scripts"), 0o700); err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"scripts/release.sh": readBounded(t, filepath.Join(root, "scripts", "release.sh"), 2<<20),
		"go":                 []byte("#!/bin/sh\nset -eu\nif [ \"$1\" = test ]; then echo qualification-refused; exit 23; fi\necho unexpected-build; exit 24\n"),
	}
	for _, check := range []string{"check-release-inventory", "check-docs-consistency", "check-cli-docs-contract"} {
		files["scripts/"+check+".sh"] = []byte("#!/bin/sh\nexit 0\n")
	}
	for path, body := range files {
		if err := os.WriteFile(filepath.Join(fixture, path), body, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", fixture+string(os.PathListSeparator)+os.Getenv("PATH"))
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "/bin/bash", "-p", filepath.Join(fixture, "scripts", "release.sh")).CombinedOutput()
	var exitError *exec.ExitError
	if !errors.As(err, &exitError) || exitError.ExitCode() != 23 || string(output) != "qualification-refused\n" {
		t.Fatalf("release did not stop at failed qualification: %v\n%s", err, output)
	}
	if _, err := os.Stat(filepath.Join(fixture, "dist")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("release created packaging output despite failed qualification: %v", err)
	}
}
