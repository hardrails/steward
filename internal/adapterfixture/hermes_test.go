package adapterfixture

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const hermesSkillKeySHA256 = "c04a414ffd37a361ea1e16a5c9fcf58b5db2fb7052aa9f981e2d6e8b9bbe750b"

type skillManifest struct {
	Entrypoint    string         `json:"entrypoint"`
	Files         []skillFile    `json:"files"`
	Limits        map[string]int `json:"limits"`
	Name          string         `json:"name"`
	Network       bool           `json:"network"`
	SchemaVersion string         `json:"schema_version"`
	Version       string         `json:"version"`
	WorkspaceRoot string         `json:"workspace_root"`
}

type skillFile struct {
	Mode   string `json:"mode"`
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func TestHermesWorkspaceSkillSignatureAndInventory(t *testing.T) {
	root := hermesSkillRoot(t)
	manifestBytes := readBounded(t, filepath.Join(root, "manifest.json"), 16<<10)
	signatureText := readBounded(t, filepath.Join(root, "manifest.sig"), 256)
	publicPEM := readBounded(t, filepath.Join(root, "public.pem"), 1<<10)
	if digest := sha256.Sum256(publicPEM); hex.EncodeToString(digest[:]) != hermesSkillKeySHA256 {
		t.Fatalf("public-key digest = %x", digest)
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		t.Fatal("public key is not one canonical PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T", parsed)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(publicKey, manifestBytes, signature) {
		t.Fatal("skill signature is invalid")
	}
	tampered := append([]byte(nil), manifestBytes...)
	tampered[len(tampered)/2] ^= 1
	if ed25519.Verify(publicKey, tampered, signature) {
		t.Fatal("signature accepted a changed manifest")
	}

	var generic any
	if err := json.Unmarshal(manifestBytes, &generic); err != nil {
		t.Fatalf("decode generic manifest: %v", err)
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal canonical manifest: %v", err)
	}
	canonical = append(canonical, '\n')
	if !bytes.Equal(manifestBytes, canonical) {
		t.Fatal("manifest is not canonical field-sorted JSON")
	}

	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest skillManifest
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode manifest: %v", err)
	}
	if err := requireEOF(decoder); err != nil {
		t.Fatal(err)
	}
	if manifest.SchemaVersion != "steward.fixture-skill-manifest.v1" || manifest.Name != "steward.workspace-audit" ||
		manifest.Version != "1" || manifest.Network || manifest.Entrypoint != "workspace_audit.py" ||
		manifest.WorkspaceRoot != "/opt/data/workspace" {
		t.Fatalf("unexpected manifest authority: %#v", manifest)
	}
	if len(manifest.Files) != 3 {
		t.Fatalf("file count = %d", len(manifest.Files))
	}
	prior := ""
	for _, file := range manifest.Files {
		if file.Path <= prior || (file.Mode != "read" && file.Mode != "execute") {
			t.Fatalf("invalid file descriptor: %#v", file)
		}
		content := readBounded(t, filepath.Join(root, file.Path), 1<<20)
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			t.Fatalf("digest mismatch for %s", file.Path)
		}
		prior = file.Path
	}
}

func TestHermesWorkspaceAuditDoesUsefulBoundedWork(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	root := hermesSkillRoot(t)
	workspace := t.TempDir()
	if err := os.WriteFile(filepath.Join(workspace, "alpha.txt"), []byte("alpha\n"), 0o600); err != nil {
		t.Fatalf("write alpha: %v", err)
	}
	if err := os.Mkdir(filepath.Join(workspace, "nested"), 0o700); err != nil {
		t.Fatalf("mkdir nested: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "nested", "beta.txt"), []byte("beta\n"), 0o600); err != nil {
		t.Fatalf("write beta: %v", err)
	}

	result := runAudit(t, python, filepath.Join(root, "workspace_audit.py"), workspace, true)
	var got map[string]any
	if err := json.Unmarshal(result, &got); err != nil {
		t.Fatalf("decode audit result: %v", err)
	}
	contractBytes := readBounded(t, filepath.Join(root, "workspace-fixture-contract.json"), 16<<10)
	var contract map[string]any
	if err := json.Unmarshal(contractBytes, &contract); err != nil {
		t.Fatalf("decode fixture contract: %v", err)
	}
	for _, key := range []string{"entries", "file_count", "manifest_digest", "root", "total_bytes"} {
		if !valuesEqual(got[key], contract[key]) {
			t.Fatalf("%s = %#v, want %#v", key, got[key], contract[key])
		}
	}
	if got["schema_version"] != "steward.workspace-audit.result.v1" {
		t.Fatalf("schema = %#v", got["schema_version"])
	}

	if err := os.Symlink("alpha.txt", filepath.Join(workspace, "escape")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	failed := runAudit(t, python, filepath.Join(root, "workspace_audit.py"), workspace, false)
	if !bytes.Contains(failed, []byte("symlink_rejected")) {
		t.Fatalf("symlink failure = %s", failed)
	}
}

func TestHermesFixtureModelProtocols(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	root := hermesAdapterRoot(t)
	program := `
import http.server, importlib.util, json, sys, threading, urllib.request
spec = importlib.util.spec_from_file_location("fixture_model", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

contract = json.load(open(sys.argv[2], encoding="utf-8"))
result = {key: value for key, value in contract.items() if key != "fixture_id"}
result["schema_version"] = "steward.workspace-audit.result.v1"
canonical = json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
envelope = json.dumps({"error": None, "exit_code": 0, "output": canonical}, separators=(",", ":"))
assert module.validated_workspace_audit(envelope) == canonical
for rejected in (
    canonical,
    json.dumps({"error": None, "exit_code": False, "output": canonical}),
    json.dumps({"error": None, "exit_code": 1, "output": canonical}),
    json.dumps({"error": "failed", "exit_code": 0, "output": canonical}),
    json.dumps({"error": None, "exit_code": 0, "output": "not-json"}),
):
    assert module.validated_workspace_audit(rejected) is None

mcp_result = module.MCP_RESULT_PREFIX + json.dumps({"result": module.NONCE}) + module.MCP_RESULT_SUFFIX
assert module.validated_mcp_result(mcp_result) == module.NONCE
assert module.validated_mcp_result(mcp_result.replace(module.NONCE, "changed")) is None
assert module.validated_mcp_result(json.dumps({"result": module.NONCE})) is None

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    def complete(text, stream):
        body = json.dumps({"messages": [{"role": "user", "content": text}], "stream": stream}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.headers.get_content_type(), response.read()

    content_type, wire = complete("STEWARD_TASK_FIXTURE", True)
    assert content_type == "text/event-stream"
    events = [event for event in wire.decode().split("\n\n") if event]
    assert events[-1] == "data: [DONE]"
    chunk = json.loads(events[0].removeprefix("data: "))
    assert chunk["object"] == "chat.completion.chunk"
    assert chunk["choices"][0]["finish_reason"] == "stop"
    assert chunk["choices"][0]["delta"]["content"].startswith("steward-task:")

    _, wire = complete("STEWARD_WORKSPACE_AUDIT", True)
    chunk = json.loads(wire.decode().split("\n\n", 1)[0].removeprefix("data: "))
    tool_call = chunk["choices"][0]["delta"]["tool_calls"][0]
    assert tool_call["index"] == 0 and tool_call["function"]["name"] == "terminal"

    content_type, wire = complete("STEWARD_TASK_FIXTURE", False)
    assert content_type == "application/json"
    assert json.loads(wire)["object"] == "chat.completion"
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
`
	command := exec.Command(
		python,
		"-c",
		program,
		filepath.Join(root, "fixture_model.py"),
		filepath.Join(root, "fixtures", "skill", "workspace-fixture-contract.json"),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fixture model protocol test failed: %v\n%s", err, output)
	}
}

func runAudit(t *testing.T, python, script, workspace string, wantSuccess bool) []byte {
	t.Helper()
	program := `
import importlib.util, json, pathlib, sys
spec = importlib.util.spec_from_file_location("workspace_audit", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
try:
    result = module.audit_directory(pathlib.Path(sys.argv[2]))
except module.AuditError as error:
    print(error.code, file=sys.stderr)
    raise SystemExit(1)
print(json.dumps(result, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
`
	command := exec.Command(python, "-c", program, script, workspace)
	output, err := command.CombinedOutput()
	if wantSuccess && err != nil {
		t.Fatalf("workspace audit failed: %v\n%s", err, output)
	}
	if !wantSuccess && err == nil {
		t.Fatalf("workspace audit unexpectedly succeeded: %s", output)
	}
	return bytes.TrimSpace(output)
}

func hermesSkillRoot(t *testing.T) string {
	t.Helper()
	return filepath.Join(hermesAdapterRoot(t), "fixtures", "skill")
}

func hermesAdapterRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test file")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "adapters", "hermes-agent")
}

func readBounded(t *testing.T, path string, maximum int64) []byte {
	t.Helper()
	file, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer file.Close()
	content, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if int64(len(content)) > maximum {
		t.Fatalf("%s exceeds %d bytes", path, maximum)
	}
	return content
}

func requireEOF(decoder *json.Decoder) error {
	var extra json.RawMessage
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("manifest has trailing JSON")
	}
	return nil
}

func valuesEqual(left, right any) bool {
	leftJSON, leftErr := json.Marshal(left)
	rightJSON, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftJSON, rightJSON)
}
