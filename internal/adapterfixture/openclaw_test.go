package adapterfixture

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	openClawRevision       = "2d2ddc43d0dcf71f31283d780f9fe9ff4cc04fe4"
	openClawImageIndex     = "sha256:6a31d44b2944e7adcd2b582bf6fb463111264ebca97a0201795b799135bd102c"
	openClawAMD64Manifest  = "sha256:165b4992f1b4b74ffdd7a02c887ba006f9f5dc951eca420eef573a8b233b543f"
	openClawFixtureModel   = "steward-openclaw-fixture"
	openClawAuditResultSHA = "8a88036085cd27e3e0a85ab10f3fbfed492633fa76fd18a85bb478747c4d56d5"
)

type openClawAdapterManifest struct {
	SchemaVersion   string   `json:"schema_version"`
	AdapterContract string   `json:"adapter_contract"`
	Platforms       []string `json:"qualified_platforms"`
	Upstream        struct {
		Repository string `json:"repository"`
		Release    string `json:"release"`
		Revision   string `json:"revision"`
		License    string `json:"license"`
		LicenseSHA string `json:"license_sha256"`
	} `json:"upstream"`
	BaseImages []struct {
		Reference     string `json:"reference"`
		AMD64Manifest string `json:"linux_amd64_manifest_digest"`
		Purpose       string `json:"purpose"`
	} `json:"base_images"`
	Runtime struct {
		UID         int      `json:"uid"`
		GID         int      `json:"gid"`
		StatePath   string   `json:"state_path"`
		Home        string   `json:"home"`
		WorkDir     string   `json:"workdir"`
		TmpPath     string   `json:"tmp_path"`
		Command     []string `json:"command"`
		ServicePort int      `json:"service_port"`
	} `json:"runtime"`
	ServiceSurface struct {
		NegotiationPath  string   `json:"negotiation_path"`
		Operations       []string `json:"operations"`
		RunIDPattern     string   `json:"run_id_pattern"`
		Events           bool     `json:"events"`
		MaxRequestBytes  int      `json:"max_request_body_bytes"`
		MaxResponseBytes int      `json:"max_response_body_bytes"`
		TimeoutSeconds   int      `json:"timeout_seconds"`
	} `json:"service_surface"`
	QualifiedSkill struct {
		Name         string `json:"name"`
		Workspace    string `json:"workspace_root"`
		Network      bool   `json:"network"`
		ResultSchema string `json:"result_schema"`
	} `json:"qualified_skill_fixture"`
	Limits []string `json:"deliberate_limits"`
}

func TestOpenClawAdapterManifestPinsQualifiedSurface(t *testing.T) {
	content := readBounded(t, filepath.Join(openClawAdapterRoot(t), "adapter.json"), 32<<10)
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	var manifest openClawAdapterManifest
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode OpenClaw adapter manifest: %v", err)
	}
	if err := requireEOF(decoder); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "steward.adapter-source.v1" || manifest.AdapterContract != "steward.openclaw.v1" ||
		len(manifest.Platforms) != 1 || manifest.Platforms[0] != "linux/amd64" ||
		manifest.Upstream.Repository != "https://github.com/openclaw/openclaw.git" ||
		manifest.Upstream.Release != "v2026.7.1" || manifest.Upstream.Revision != openClawRevision ||
		manifest.Upstream.License != "MIT" || len(manifest.Upstream.LicenseSHA) != 64 {
		t.Fatalf("unexpected source authority: %#v", manifest)
	}
	if len(manifest.BaseImages) != 1 ||
		manifest.BaseImages[0].Reference != "ghcr.io/openclaw/openclaw:2026.7.1@"+openClawImageIndex ||
		manifest.BaseImages[0].AMD64Manifest != openClawAMD64Manifest || manifest.BaseImages[0].Purpose != "upstream runtime" {
		t.Fatalf("unexpected base image authority: %#v", manifest.BaseImages)
	}
	if manifest.Runtime.UID != 65532 || manifest.Runtime.GID != 65532 ||
		manifest.Runtime.StatePath != "/home/node/.openclaw" || manifest.Runtime.Home != "/home/node" ||
		manifest.Runtime.WorkDir != "/home/node/.openclaw/workspace" || manifest.Runtime.TmpPath != "/tmp" ||
		len(manifest.Runtime.Command) != 1 || manifest.Runtime.Command[0] != "serve" || manifest.Runtime.ServicePort != 18789 {
		t.Fatalf("unexpected runtime contract: %#v", manifest.Runtime)
	}
	if manifest.ServiceSurface.NegotiationPath != "/steward/v1/negotiation" ||
		len(manifest.ServiceSurface.Operations) != 3 || manifest.ServiceSurface.Events ||
		manifest.ServiceSurface.RunIDPattern != "^run_[a-f0-9]{32}$" ||
		manifest.ServiceSurface.MaxRequestBytes != 64<<10 || manifest.ServiceSurface.MaxResponseBytes != 1<<20 ||
		manifest.ServiceSurface.TimeoutSeconds != 120 {
		t.Fatalf("unexpected service contract: %#v", manifest.ServiceSurface)
	}
	if manifest.QualifiedSkill.Name != "steward-workspace-audit" || manifest.QualifiedSkill.Network ||
		manifest.QualifiedSkill.ResultSchema != "steward.workspace-audit.result.v1" || len(manifest.Limits) != 3 {
		t.Fatalf("unexpected qualified skill or limits: %#v %#v", manifest.QualifiedSkill, manifest.Limits)
	}
}

func TestOpenClawAdapterRecipeKeepsTheClosedRuntimeBoundary(t *testing.T) {
	root := openClawAdapterRoot(t)
	dockerfile := string(readBounded(t, filepath.Join(root, "Dockerfile"), 32<<10))
	entrypoint := string(readBounded(t, filepath.Join(root, "entrypoint.mjs"), 128<<10))
	for _, required := range []string{
		"ghcr.io/openclaw/openclaw:2026.7.1@" + openClawImageIndex,
		"USER 65532:65532",
		"ENTRYPOINT [\"tini\", \"-s\", \"--\", \"node\", \"/opt/steward/entrypoint.mjs\"]",
		"OPENCLAW_DISABLE_BONJOUR=1",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("Dockerfile is missing %q", required)
		}
	}
	for _, forbidden := range []string{"apt-get", "curl ", "git clone", "VOLUME ", "--privileged", "/var/run/docker.sock"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Fatalf("Dockerfile contains forbidden authority %q", forbidden)
		}
	}
	for _, required := range []string{
		`process.getuid?.() !== 65532`,
		`process.env.OPENAI_BASE_URL !== "http://steward-relay:8080/v1"`,
		`process.env.OPENAI_API_KEY !== "steward-local"`,
		`allow: ["exec", "read"]`,
		`activeRuns >= 1`,
		`server.maxConnections = 32`,
		`sanitizeOpenClawResult`,
	} {
		if !strings.Contains(entrypoint, required) {
			t.Fatalf("entrypoint is missing %q", required)
		}
	}
	for _, forbidden := range []string{"gateway.auth", "dangerouslyDisable", "child_process.exec(", "shell: true", "process.env.HTTP_PROXY"} {
		if strings.Contains(entrypoint, forbidden) {
			t.Fatalf("entrypoint contains forbidden authority %q", forbidden)
		}
	}
}

func TestOpenClawAdapterSourceInventoryIsExact(t *testing.T) {
	root := openClawAdapterRoot(t)
	manifest := string(readBounded(t, filepath.Join(root, "source-inputs.sha256"), 16<<10))
	expected := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(manifest), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || len(fields[0]) != 64 || !strings.HasPrefix(fields[1], "./") {
			t.Fatalf("invalid source inventory row %q", line)
		}
		path := strings.TrimPrefix(fields[1], "./")
		if _, found := expected[path]; found {
			t.Fatalf("duplicate source inventory path %q", path)
		}
		expected[path] = fields[0]
	}
	observed := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || entry.Name() == "source-inputs.sha256" {
			return nil
		}
		if entry.Type()&os.ModeType != 0 {
			return fmt.Errorf("adapter source contains a non-regular file: %s", path)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		observed[filepath.ToSlash(relative)] = sha256File(t, path)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(observed) != len(expected) {
		t.Fatalf("source inventory count = %d, files = %d", len(expected), len(observed))
	}
	for path, digest := range observed {
		if expected[path] != digest {
			t.Fatalf("source inventory mismatch for %s: got %s want %s", path, digest, expected[path])
		}
	}
}

func TestOpenClawFixtureInputsHaveStableAuditIdentity(t *testing.T) {
	root := filepath.Join(openClawAdapterRoot(t), "fixtures", "workspace", "qualification", "input")
	alpha := readBounded(t, filepath.Join(root, "alpha.txt"), 1<<10)
	nested := readBounded(t, filepath.Join(root, "nested.json"), 1<<10)
	if string(alpha) != "Steward OpenClaw qualification fixture.\n" ||
		string(nested) != "{\"action\":\"audit\",\"expected\":\"deterministic\",\"schema_version\":\"steward.openclaw-fixture.v1\"}\n" {
		t.Fatal("OpenClaw qualification input drifted")
	}
	if openClawAuditResultSHA != "8a88036085cd27e3e0a85ab10f3fbfed492633fa76fd18a85bb478747c4d56d5" {
		t.Fatal("qualification result digest constant drifted")
	}
}

func TestOpenClawBuildAndQualificationHarnessesAreFailClosed(t *testing.T) {
	root := filepath.Clean(filepath.Join(openClawAdapterRoot(t), "..", ".."))
	builderPath := filepath.Join(root, "scripts", "build-openclaw-adapter.sh")
	gatePath := filepath.Join(root, "scripts", "openclaw-feasibility.sh")
	builder := string(readBounded(t, builderPath, 128<<10))
	gate := string(readBounded(t, gatePath, 256<<10))
	for _, path := range []string{builderPath, gatePath} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode = %o", path, info.Mode().Perm())
		}
	}
	for _, required := range []string{
		"git -C \"$root\" archive",
		"sha256sum -c source-inputs.sha256",
		"--network=none --pull=false --platform=linux/amd64 --provenance=false",
		"pinned-base-pull;docker-build-network-none",
		"os.rename(source, destination)",
		"contains_agent_content\": False",
	} {
		if !strings.Contains(builder, required) {
			t.Fatalf("builder is missing %q", required)
		}
	}
	for _, required := range []string{
		"STEWARD_ACCEPT_DISPOSABLE_HOST_RISK",
		"docker network create --internal",
		"--runtime runsc",
		"--read-only --cap-drop ALL",
		"no-new-privileges:true",
		"response.status !== 413",
		"persisted skill drifted",
		"contains_agent_content\": False",
	} {
		if !strings.Contains(gate, required) {
			t.Fatalf("qualification gate is missing %q", required)
		}
	}
	for name, content := range map[string]string{"builder": builder, "gate": gate} {
		for _, forbidden := range []string{"--privileged", "--network=host", "/var/run/docker.sock", "curl | sh"} {
			if strings.Contains(content, forbidden) {
				t.Fatalf("%s contains forbidden authority %q", name, forbidden)
			}
		}
	}
	if bash, err := exec.LookPath("bash"); err == nil {
		command := exec.Command(bash, "-n", builderPath, gatePath)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("shell syntax: %v\n%s", err, output)
		}
	}
}

func TestOpenClawFixtureModelRequiresTheExecResult(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not available")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, filepath.Join(openClawAdapterRoot(t), "fixture_model.mjs"))
	command.Env = append(os.Environ(), "STEWARD_FIXTURE_MODEL_PORT="+strconv.Itoa(port))
	discard, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer discard.Close()
	command.Stdout = discard
	command.Stderr = discard
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cancel()
		_ = command.Process.Kill()
		_ = command.Wait()
	}()

	client := &http.Client{Timeout: 2 * time.Second}
	baseURL := fmt.Sprintf("http://127.0.0.1:%d", port)
	for {
		request, _ := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+"/health", nil)
		response, requestErr := client.Do(request)
		if requestErr == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusOK {
				break
			}
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture model did not start")
		case <-time.After(25 * time.Millisecond):
		}
	}

	first := postOpenClawFixture(t, client, baseURL, map[string]any{
		"model":    openClawFixtureModel,
		"messages": []map[string]string{{"role": "user", "content": "audit"}},
		"tools":    []map[string]any{{"type": "function", "function": map[string]any{"name": "exec"}}},
	})
	choices := first["choices"].([]any)
	message := choices[0].(map[string]any)["message"].(map[string]any)
	toolCalls := message["tool_calls"].([]any)
	function := toolCalls[0].(map[string]any)["function"].(map[string]any)
	if function["name"] != "exec" || !strings.Contains(function["arguments"].(string), "workspace_audit.mjs") {
		t.Fatalf("unexpected tool call: %#v", function)
	}

	second := postOpenClawFixture(t, client, baseURL, map[string]any{
		"model": openClawFixtureModel,
		"messages": []map[string]string{
			{"role": "user", "content": "audit"},
			{"role": "tool", "content": `{"schema_version":"steward.workspace-audit.result.v1"}`},
		},
		"tools": []map[string]any{{"type": "function", "function": map[string]any{"name": "exec"}}},
	})
	choices = second["choices"].([]any)
	message = choices[0].(map[string]any)["message"].(map[string]any)
	if message["content"] != "STEWARD_OPENCLAW_WORKSPACE_AUDIT_OK" {
		t.Fatalf("unexpected completion: %#v", message)
	}
}

func postOpenClawFixture(t *testing.T, client *http.Client, baseURL string, document map[string]any) map[string]any {
	t.Helper()
	encoded, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer steward-local")
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("fixture status = %d", response.StatusCode)
	}
	var result map[string]any
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	return result
}

func openClawAdapterRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "adapters", "openclaw")
}
