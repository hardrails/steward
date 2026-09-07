package adapterfixture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func isolatedGitEnvironment() []string {
	environment := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "GIT_") {
			environment = append(environment, entry)
		}
	}
	return environment
}

// Compare production trees as well as the actual compiler/embed inventory.
// The latter catches untracked (even gitignored) files that git diff omits.
func verifyHermesRuntimeSource(root, qualifiedTreeSHA256 string) error {
	if !validSHA256Hex(qualifiedTreeSHA256) {
		return fmt.Errorf("invalid qualified runtime tree digest")
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("cannot resolve qualified checkout: %w", err)
	}
	root, err = filepath.Abs(resolved)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	run := func(name string, args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, name, args...)
		command.Dir = root
		command.Env = append(isolatedGitEnvironment(), "GOENV=off", "GOFLAGS=", "GOWORK=off", "GOTOOLCHAIN=local",
			"GOPROXY=off", "GOSUMDB=off", "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
		return command.Output()
	}
	// A squash merge can remove the qualified commit from reachable history.
	// These content-addressed subtrees survive metadata-only retention and merge.
	snapshot, err := run("git", "ls-tree", "HEAD", "--", "go.mod", "go.sum", "cmd", "internal")
	if err != nil || fmt.Sprintf("%x", sha256.Sum256(snapshot)) != qualifiedTreeSHA256 {
		return fmt.Errorf("Steward runtime tree differs from qualification or cannot be read")
	}
	if _, err := run("git", "diff", "--quiet", "--no-ext-diff", "--no-textconv", "HEAD", "--", "go.mod", "go.sum", "cmd", "internal"); err != nil {
		return fmt.Errorf("Steward runtime has unqualified working-tree changes: %w", err)
	}
	raw, err := run("go", "list", "-deps", "-json", "./cmd/stewardctl", "./cmd/steward-executor", "./cmd/steward-gateway", "./cmd/steward-relay")
	if err != nil {
		return fmt.Errorf("cannot enumerate qualified runtime inputs: %w", err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	files := []string{"go.mod"}
	for {
		var pkg struct {
			Dir, ImportPath                                                                                                     string
			Standard                                                                                                            bool
			Module                                                                                                              *struct{ Path string }
			GoFiles, CgoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles, SwigFiles, SwigCXXFiles, SysoFiles, EmbedFiles []string
		}
		if err := decoder.Decode(&pkg); err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("cannot decode runtime compiler inventory: %w", err)
		}
		if pkg.Standard {
			continue
		}
		if pkg.Module == nil || pkg.Module.Path != "github.com/hardrails/steward" {
			return fmt.Errorf("runtime input belongs to an unqualified module: %s", pkg.ImportPath)
		}
		for _, group := range [][]string{pkg.GoFiles, pkg.CgoFiles, pkg.CFiles, pkg.CXXFiles, pkg.MFiles, pkg.HFiles, pkg.FFiles, pkg.SFiles, pkg.SwigFiles, pkg.SwigCXXFiles, pkg.SysoFiles, pkg.EmbedFiles} {
			for _, name := range group {
				path := filepath.Join(pkg.Dir, name)
				relative, err := filepath.Rel(root, path)
				if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					return fmt.Errorf("runtime input escaped its qualified checkout")
				}
				info, err := os.Lstat(path)
				if err != nil || !info.Mode().IsRegular() {
					return fmt.Errorf("runtime input is not a regular file: %s", relative)
				}
				files = append(files, filepath.ToSlash(relative))
			}
		}
	}
	args := append([]string{"ls-files", "--error-unmatch", "--"}, files...)
	if _, err := run("git", args...); err != nil {
		return fmt.Errorf("runtime contains compiler or embedded inputs absent from qualification: %w", err)
	}
	return nil
}

func TestHermesRuntimeSourceBinding(t *testing.T) {
	root := t.TempDir()
	// Git exports these into commit hooks. A fixture must never inherit authority
	// over the invoking checkout merely because its working directory is changed.
	t.Setenv("GIT_DIR", filepath.Join(root, "not-the-fixture"))
	t.Setenv("GIT_WORK_TREE", filepath.Join(root, "not-the-worktree"))
	t.Setenv("GIT_INDEX_FILE", filepath.Join(root, "not-the-index"))
	write := func(name, content string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	git := func(args ...string) string {
		t.Helper()
		command := exec.Command("git", args...)
		command.Dir = root
		command.Env = isolatedGitEnvironment()
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("git fixture failed: %v\n%s", err, output)
		}
		return strings.TrimSpace(string(output))
	}
	write("go.mod", "module github.com/hardrails/steward\n\ngo 1.24\n")
	for _, binary := range []string{"stewardctl", "steward-executor", "steward-gateway", "steward-relay"} {
		write("cmd/"+binary+"/main.go", "package main\nimport _ \"github.com/hardrails/steward/internal/shared\"\nfunc main() {}\n")
	}
	shared := "package shared\nimport \"embed\"\n//go:embed data/*\nvar Data embed.FS\n"
	write("internal/shared/shared.go", shared)
	write("internal/shared/data/proof.txt", "qualified")
	write(".gitignore", "hidden.go\nignored.txt\n")
	git("init", "-q")
	git("add", ".")
	git("-c", "user.name=Qualification fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", "Qualified fixture")
	commit := git("rev-parse", "HEAD")
	snapshot := git("ls-tree", "HEAD", "--", "go.mod", "go.sum", "cmd", "internal") + "\n"
	qualifiedTree := fmt.Sprintf("%x", sha256.Sum256([]byte(snapshot)))
	if err := verifyHermesRuntimeSource(root, qualifiedTree); err != nil {
		t.Fatal(err)
	}
	write("docs/reference/evidence/record.json", "new retained evidence")
	if err := verifyHermesRuntimeSource(root, qualifiedTree); err != nil {
		t.Fatalf("retaining evidence invalidated runtime source: %v", err)
	}
	for _, test := range []struct{ name, content, restore string }{
		{"internal/shared/shared.go", shared + "const Changed = true\n", shared},
		{"internal/shared/data/proof.txt", "changed embedded data", "qualified"},
		{"internal/shared/added.go", "package shared\nconst Added = true\n", ""},
		{"internal/shared/hidden.go", "package shared\nconst Hidden = true\n", ""},
		{"internal/shared/data/ignored.txt", "untracked embedded data", ""},
	} {
		t.Run(test.name, func(t *testing.T) {
			write(test.name, test.content)
			if err := verifyHermesRuntimeSource(root, qualifiedTree); err == nil {
				t.Fatal("changed runtime input accepted")
			}
			if test.restore != "" {
				write(test.name, test.restore)
			} else if err := os.Remove(filepath.Join(root, test.name)); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, digest := range []string{"", "invalid", strings.Repeat("0", 64)} {
		if err := verifyHermesRuntimeSource(root, digest); err == nil {
			t.Fatal("missing or incorrect qualified tree accepted")
		}
	}
	git("add", "docs")
	git("-c", "user.name=Qualification fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", "Retain qualification evidence")
	clone := t.TempDir()
	git("clone", "--no-local", "--depth=1", root, clone)
	probe := exec.Command("git", "cat-file", "-e", commit+"^{commit}")
	probe.Dir = clone
	probe.Env = isolatedGitEnvironment()
	if err := probe.Run(); err == nil {
		t.Fatal("negative control: qualified commit still exists in shallow clone")
	}
	if err := verifyHermesRuntimeSource(clone, qualifiedTree); err != nil {
		t.Fatalf("unchanged shallow/squashed release cannot use retained tree evidence: %v", err)
	}
	write("internal/shared/shared.go", shared+"const CommittedChange = true\n")
	git("add", "internal/shared/shared.go")
	git("-c", "user.name=Qualification fixture", "-c", "user.email=fixture@example.invalid", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgsign=false", "commit", "-qm", "Change runtime source")
	if err := verifyHermesRuntimeSource(root, qualifiedTree); err == nil {
		t.Fatal("committed source change reused old tree qualification")
	}
}
