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
	"sort"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

const (
	hermesSkillKeySHA256          = "183e8cd011fa5e5f044700be4a61f3bc22e2eb61ad34469e62433d42f5af2452"
	hermesConnectorKeySHA256      = "6eceb945f87b1979b2d5fde2235ddb493c38ae2fa2694c2c6d7dbd0a61a5e564"
	hermesConnectorLogicalBaseURL = "http://steward-relay:8081"
)

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

type connectorSkillManifest struct {
	Connector     map[string]string `json:"connector"`
	Entrypoint    string            `json:"entrypoint"`
	Files         []skillFile       `json:"files"`
	Limits        map[string]int    `json:"limits"`
	Name          string            `json:"name"`
	Network       bool              `json:"network"`
	SchemaVersion string            `json:"schema_version"`
	Version       string            `json:"version"`
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

func TestHermesConnectorSkillSignatureAndInventory(t *testing.T) {
	root := filepath.Join(hermesAdapterRoot(t), "fixtures", "connector-skill")
	manifestBytes := readBounded(t, filepath.Join(root, "manifest.json"), 16<<10)
	signatureText := readBounded(t, filepath.Join(root, "manifest.sig"), 256)
	publicPEM := readBounded(t, filepath.Join(root, "public.pem"), 1<<10)
	if digest := sha256.Sum256(publicPEM); hex.EncodeToString(digest[:]) != hermesConnectorKeySHA256 {
		t.Fatalf("connector public-key digest = %x", digest)
	}
	block, rest := pem.Decode(publicPEM)
	if block == nil || len(rest) != 0 || block.Type != "PUBLIC KEY" {
		t.Fatal("connector public key is not one canonical PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse connector public key: %v", err)
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("connector public key type = %T", parsed)
	}
	signature, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(signatureText)))
	if err != nil || !ed25519.Verify(publicKey, manifestBytes, signature) {
		t.Fatalf("connector skill signature is invalid: %v", err)
	}

	var generic any
	if err := json.Unmarshal(manifestBytes, &generic); err != nil {
		t.Fatalf("decode connector manifest: %v", err)
	}
	canonical, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("marshal connector manifest: %v", err)
	}
	if !bytes.Equal(manifestBytes, append(canonical, '\n')) {
		t.Fatal("connector manifest is not canonical field-sorted JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(manifestBytes))
	decoder.DisallowUnknownFields()
	var manifest connectorSkillManifest
	if err := decoder.Decode(&manifest); err != nil {
		t.Fatalf("decode strict connector manifest: %v", err)
	}
	if err := requireEOF(decoder); err != nil {
		t.Fatal(err)
	}
	wantConnector := map[string]string{
		"id": "local-work", "logical_base_url": hermesConnectorLogicalBaseURL,
		"operation_id": "perform", "operation_path": "/v1/connectors/local-work/operations/perform",
	}
	wantLimits := map[string]int{"max_request_bytes": 4096, "max_response_bytes": 4096, "timeout_seconds": 10}
	if manifest.SchemaVersion != "steward.fixture-skill-manifest.v1" || manifest.Name != "steward.connector-work" ||
		manifest.Version != "1" || !manifest.Network || manifest.Entrypoint != "connector_work.py" ||
		!valuesEqual(manifest.Connector, wantConnector) || !valuesEqual(manifest.Limits, wantLimits) || len(manifest.Files) != 3 {
		t.Fatalf("unexpected connector manifest authority: %#v", manifest)
	}
	prior := ""
	for _, file := range manifest.Files {
		if file.Path <= prior || (file.Mode != "read" && file.Mode != "execute") {
			t.Fatalf("invalid connector file descriptor: %#v", file)
		}
		content := readBounded(t, filepath.Join(root, file.Path), 1<<20)
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != file.SHA256 {
			t.Fatalf("connector digest mismatch for %s", file.Path)
		}
		prior = file.Path
	}
}

func TestHermesAdapterUsesImmutableSkillAndAssembleOnlyDockerfile(t *testing.T) {
	root := hermesAdapterRoot(t)
	dockerfile := string(readBounded(t, filepath.Join(root, "Dockerfile"), 64<<10))
	entrypoint := string(readBounded(t, filepath.Join(root, "entrypoint.py"), 1<<20))
	model := string(readBounded(t, filepath.Join(root, "fixture_model.py"), 1<<20))
	builder := string(readBounded(t, filepath.Join(root, "..", "..", "scripts", "build-hermes-adapter.sh"), 1<<20))

	for _, required := range []string{
		"/opt/steward/skills/steward.workspace-audit/",
		"/opt/steward/skills/steward.connector-work/",
		"COPY --chown=0:0 --chmod=0555",
	} {
		if !strings.Contains(dockerfile, required) {
			t.Fatalf("Dockerfile does not bind immutable skill property %q", required)
		}
	}
	for _, forbidden := range []string{"uv sync", "uv pip install", "/opt/steward/fixtures/skill"} {
		if strings.Contains(dockerfile, forbidden) {
			t.Fatalf("Dockerfile executes or installs through forbidden path %q", forbidden)
		}
	}
	if strings.Contains(dockerfile, "# syntax=") {
		t.Fatal("Dockerfile unexpectedly delegates parsing to an external frontend")
	}
	for _, line := range strings.Split(dockerfile, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "RUN ") {
			t.Fatalf("assemble-only Dockerfile contains build command %q", line)
		}
	}
	for _, required := range []string{
		"--runtime runsc", "--network=none", "--read-only", "--cap-drop ALL",
		"--security-opt no-new-privileges:true", "--pids-limit", "--memory-swap",
		"target=/input/upstream,readonly", "target=/input/wheelhouse,readonly",
		"--offline --no-index --find-links /input/wheelhouse", "--no-build-isolation",
		"urllib.request.ProxyHandler({})", "RejectRedirects", "files.pythonhosted.org",
		"qualified only on linux/amd64",
		"docker build --network=none",
		`GIT_NO_REPLACE_OBJECTS=1`, `-c core.fsmonitor=false`,
	} {
		if !strings.Contains(builder, required) {
			t.Fatalf("builder does not enforce isolation property %q", required)
		}
	}
	for _, forbidden := range []string{"docker network create", "--add-host", "socket.getaddrinfo"} {
		if strings.Contains(builder, forbidden) {
			t.Fatalf("builder retains network-capable hook path %q", forbidden)
		}
	}
	for _, line := range strings.Split(builder, "\n") {
		if strings.Contains(line, "python3 -") && !strings.Contains(line, "python3 -I") {
			t.Fatalf("builder runs host or planning Python without isolated imports: %q", line)
		}
	}
	for _, required := range []string{
		`FIXTURE = pathlib.Path("/opt/steward/skills/steward.workspace-audit")`,
		`CONNECTOR_FIXTURE = pathlib.Path("/opt/steward/skills/steward.connector-work")`,
		`{"id": "skill", "fixture_id": "steward.connector-work"}`,
		"skills:\n  external_dirs:\n    - /opt/steward/skills",
	} {
		if !strings.Contains(entrypoint, required) {
			t.Fatalf("entrypoint does not bind immutable skill property %q", required)
		}
	}
	immutableCommand := "/opt/steward/skills/steward.workspace-audit/workspace_audit.py"
	if !strings.Contains(model, immutableCommand) || strings.Contains(model, "/opt/data/skills/steward.workspace-audit") {
		t.Fatal("fixture model does not execute the immutable signed skill path")
	}
	connectorCommand := "/opt/steward/skills/steward.connector-work/connector_work.py"
	if !strings.Contains(model, connectorCommand) || strings.Contains(model, "/opt/data/skills/steward.connector-work") {
		t.Fatal("fixture model does not execute the immutable signed connector skill path")
	}
}

func TestHermesQualificationEvidenceBindsCurrentInputs(t *testing.T) {
	root := hermesAdapterRoot(t)
	repositoryRoot := filepath.Join(root, "..", "..")
	for _, name := range []string{"build-hermes-adapter.sh", "hermes-feasibility.sh", "hermes-steward-acceptance.sh"} {
		script := string(readBounded(t, filepath.Join(repositoryRoot, "scripts", name), 2<<20))
		for _, line := range strings.Split(script, "\n") {
			if strings.Contains(line, "python3 -") && !strings.Contains(line, "python3 -I") {
				t.Fatalf("%s runs Python without isolated imports: %q", name, line)
			}
		}
	}
	acceptanceScript := string(readBounded(t, filepath.Join(repositoryRoot, "scripts", "hermes-steward-acceptance.sh"), 2<<20))
	for _, contract := range []string{
		"--check-layout",
		"evidence output requires the adapter build attestation",
		`type(p.get("imported")) is bool`,
		"if [[ $image_imported == true ]]",
		"for path in /opt/data /tmp /workspace /dev/shm",
		"agent writable mount topology is unexpected",
		"release_root=$root",
		`release_root=$(cd "$root/.." && pwd -P)`,
		"steward-integration-$run_id-generation-2",
	} {
		if !strings.Contains(acceptanceScript, contract) {
			t.Fatalf("Hermes acceptance is missing adversarial contract %q", contract)
		}
	}
	connectorKeyContract := `re.fullmatch(r"sha256:[a-f0-9]{64}", str(connector_head.get("key_id", "")))`
	if !strings.Contains(acceptanceScript, connectorKeyContract) {
		t.Fatal("Hermes acceptance does not validate the connector receipt key ID emitted by stewardctl")
	}

	var feasibility struct {
		SchemaVersion        string `json:"schema_version"`
		Overall              string `json:"overall"`
		ContainsContent      bool   `json:"contains_agent_content"`
		Runtime              string `json:"runtime"`
		Platform             string `json:"platform"`
		HarnessSHA256        string `json:"harness_sha256"`
		UpstreamRevision     string `json:"upstream_revision"`
		SourceTree           string `json:"source_tree"`
		SourceArchiveSHA256  string `json:"source_archive_sha256"`
		AdapterStewardCommit string `json:"adapter_steward_commit"`
		AdapterTree          string `json:"adapter_tree"`
		AdapterArchiveSHA256 string `json:"adapter_archive_sha256"`
		ImageManifestDigest  string `json:"image_manifest_digest"`
		ImageConfigDigest    string `json:"image_config_digest"`
		RuntimeImageID       string `json:"runtime_image_id"`
		Checks               []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	decodeEvidence(t, filepath.Join(repositoryRoot, "docs", "reference", "evidence", "hermes-feasibility.json"), &feasibility)
	if feasibility.SchemaVersion != "steward.agent-feasibility.v1" || feasibility.Overall != "passed" ||
		feasibility.ContainsContent || feasibility.Runtime != "runsc" || feasibility.Platform != "linux/amd64" ||
		feasibility.UpstreamRevision != "095b9eed3801c251796df93f48a8f2a527ff6e70" {
		t.Fatalf("invalid Hermes feasibility evidence authority: %#v", feasibility)
	}
	if !validSHA256Hex(feasibility.AdapterArchiveSHA256) ||
		!validHexObjectID(feasibility.AdapterStewardCommit) ||
		!validSHA256Digest(feasibility.ImageManifestDigest) || !validSHA256Digest(feasibility.ImageConfigDigest) ||
		!validSHA256Digest(feasibility.RuntimeImageID) ||
		(feasibility.RuntimeImageID != feasibility.ImageManifestDigest && feasibility.RuntimeImageID != feasibility.ImageConfigDigest) {
		t.Fatalf("invalid Hermes feasibility artifact identity: %#v", feasibility)
	}
	requiredChecks := []string{
		"source.inputs", "image.build", "image.contract", "network.internal",
		"fixture.services", "fixture.network", "runtime.policy", "agent.readiness",
		"adapter.negotiation", "service.boundary", "runtime.identity", "runtime.filesystem",
		"runtime.network", "fixture.workspace", "task.basic", "task.skill", "task.mcp",
		"restart.readiness", "task.restart", "restart.state", "feasibility.complete",
		"evidence.coverage",
	}
	if len(feasibility.Checks) != len(requiredChecks) {
		t.Fatalf("Hermes feasibility check count = %d, want %d", len(feasibility.Checks), len(requiredChecks))
	}
	passed := make(map[string]int, len(feasibility.Checks))
	for _, check := range feasibility.Checks {
		if check.Status != "passed" {
			t.Fatalf("Hermes feasibility check %q has status %q", check.ID, check.Status)
		}
		passed[check.ID]++
	}
	for _, required := range requiredChecks {
		if passed[required] != 1 {
			t.Fatalf("Hermes feasibility check %q passed %d times", required, passed[required])
		}
	}

	var integration struct {
		SchemaVersion   string `json:"schema_version"`
		Overall         string `json:"overall"`
		ContainsContent bool   `json:"contains_agent_content"`
		Acceptance      struct {
			CompletedSteps      []string `json:"completed_steps"`
			Runtime             string   `json:"runtime"`
			SignedAdmission     bool     `json:"signed_admission"`
			SignedConnectorWork bool     `json:"signed_connector_work"`
		} `json:"acceptance"`
		Provenance struct {
			AcceptanceScriptSHA256 string `json:"acceptance_script_sha256"`
			Archive                struct {
				Platform string `json:"platform"`
			} `json:"archive"`
			BuildAttestation struct {
				Adapter struct {
					FileSetSHA256 string `json:"file_set_sha256"`
					GitTree       string `json:"git_tree"`
					StewardCommit string `json:"steward_commit"`
				} `json:"adapter"`
				BuildRecipe struct {
					BuilderSHA256      string `json:"builder_sha256"`
					DockerfileSHA256   string `json:"dockerfile_sha256"`
					SourceInputsSHA256 string `json:"source_inputs_sha256"`
				} `json:"build_recipe"`
				Source struct {
					ArchiveSHA256 string `json:"archive_sha256"`
					GitTree       string `json:"git_tree"`
					Revision      string `json:"revision"`
				} `json:"source"`
			} `json:"build_attestation"`
		} `json:"provenance"`
		ReceiptChain struct {
			Verified bool `json:"verified"`
			Head     struct {
				Sequence uint64 `json:"sequence"`
			} `json:"head"`
		} `json:"receipt_chain"`
		ConnectorReceiptChain struct {
			Verified bool `json:"verified"`
			Head     struct {
				Sequence uint64 `json:"sequence"`
			} `json:"head"`
		} `json:"connector_receipt_chain"`
	}
	decodeEvidence(t, filepath.Join(repositoryRoot, "docs", "reference", "evidence", "hermes-integration.json"), &integration)
	expectedSteps := []string{
		"image_imported", "executor_ready", "generation_1_admitted", "generation_1_started",
		"generation_1_ready", "state_volume_observed", "workspace_seeded", "generation_1_skill_passed",
		"generation_1_connector_skill_passed", "connector_replay_denied", "connector_forbidden_denied",
		"connector_fixture_effect_verified", "connector_secret_absence_verified",
		"generation_1_destroyed", "generation_2_admitted", "generation_2_started", "generation_2_ready",
		"generation_2_skill_passed", "generation_2_destroyed", "state_purged", "evidence_chain_verified",
		"connector_evidence_chain_verified", "acceptance_complete",
	}
	if integration.SchemaVersion != "steward.hermes-integration-evidence.v1" || integration.Overall != "passed" ||
		integration.ContainsContent || integration.Acceptance.Runtime != "runsc" || !integration.Acceptance.SignedAdmission ||
		!integration.Acceptance.SignedConnectorWork ||
		integration.Provenance.Archive.Platform != "linux/amd64" ||
		!integration.ReceiptChain.Verified || integration.ReceiptChain.Head.Sequence == 0 ||
		!integration.ConnectorReceiptChain.Verified || integration.ConnectorReceiptChain.Head.Sequence != 2 ||
		!valuesEqual(integration.Acceptance.CompletedSteps, expectedSteps) {
		t.Fatalf("invalid Hermes integration evidence authority: %#v", integration)
	}
	if feasibility.AdapterTree != integration.Provenance.BuildAttestation.Adapter.GitTree ||
		feasibility.SourceTree != integration.Provenance.BuildAttestation.Source.GitTree ||
		feasibility.SourceArchiveSHA256 != integration.Provenance.BuildAttestation.Source.ArchiveSHA256 ||
		feasibility.UpstreamRevision != integration.Provenance.BuildAttestation.Source.Revision {
		t.Fatal("Hermes feasibility and signed-integration evidence bind different source objects")
	}

	bindings := map[string]string{
		"adapter file set":    hermesAdapterFileSetSHA256(t, root),
		"builder":             sha256File(t, filepath.Join(repositoryRoot, "scripts", "build-hermes-adapter.sh")),
		"feasibility harness": sha256File(t, filepath.Join(repositoryRoot, "scripts", "hermes-feasibility.sh")),
		"acceptance harness":  sha256File(t, filepath.Join(repositoryRoot, "scripts", "hermes-steward-acceptance.sh")),
		"Dockerfile":          sha256File(t, filepath.Join(root, "Dockerfile")),
		"source inputs":       sha256File(t, filepath.Join(root, "source-inputs.sha256")),
	}
	expectedBindings := map[string]string{
		"adapter file set":    integration.Provenance.BuildAttestation.Adapter.FileSetSHA256,
		"builder":             integration.Provenance.BuildAttestation.BuildRecipe.BuilderSHA256,
		"feasibility harness": feasibility.HarnessSHA256,
		"acceptance harness":  integration.Provenance.AcceptanceScriptSHA256,
		"Dockerfile":          integration.Provenance.BuildAttestation.BuildRecipe.DockerfileSHA256,
		"source inputs":       integration.Provenance.BuildAttestation.BuildRecipe.SourceInputsSHA256,
	}
	for name, actual := range bindings {
		if actual != expectedBindings[name] {
			t.Fatalf("Hermes qualification %s digest = %s, evidence binds %s", name, actual, expectedBindings[name])
		}
	}
}

func TestHermesSecretScannerRejectsEquivalentConnectorMaterial(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	credential := filepath.Join(t.TempDir(), "connector-token")
	if err := os.WriteFile(credential, []byte("fixture-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	scanner := filepath.Join(hermesAdapterRoot(t), "fixture_secret_scan.py")
	origin := "http://127.0.0.1:18082"
	run := func(mode, material string) error {
		command := exec.Command(python, "-I", scanner, mode, credential, origin)
		command.Stdin = strings.NewReader(material)
		return command.Run()
	}
	if err := run("stream", "bounded agent material"); err != nil {
		t.Fatalf("safe agent material was rejected: %v", err)
	}
	for _, leaked := range []string{
		"fixture-secret",
		origin,
		"127.0.0.1:18082",
		`{"port":18082}`,
		`{"port": 18082}`,
		`{"port":"18082"}`,
		credential,
	} {
		if err := run("stream", leaked); err == nil {
			t.Fatalf("secret scanner accepted connector material %q", leaked)
		}
	}
	if err := run("json", `{"Config":{"Env":[]},"Mounts":[]}`); err != nil {
		t.Fatalf("safe container metadata was rejected: %v", err)
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

func TestHermesConnectorSkillUsesOnlyLogicalAuthority(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	programPath := filepath.Join(hermesAdapterRoot(t), "fixtures", "connector-skill", "connector_work.py")
	source := string(readBounded(t, programPath, 1<<20))
	for _, forbidden := range []string{"127.0.0.1:18082", "Authorization", "X-API-Key"} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("connector skill contains forbidden upstream authority %q", forbidden)
		}
	}
	program := `
import importlib.util, json, os, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("connector_work", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

calls = []
class Response:
    status = 200
    body = module.canonical_json(module.EXPECTED_RESULT)
    def getheader(self, name):
        return {"Content-Encoding": None, "Content-Length": str(len(self.body)), "Content-Type": "application/json"}.get(name)
    def read(self, maximum):
        assert maximum == module.MAX_RESPONSE_BYTES + 1
        return self.body
class Connection:
    def __init__(self, host, port, timeout):
        assert (host, port, timeout) == ("steward-relay", 8081, 10)
    def request(self, method, path, body, headers):
        assert method == "POST"
        assert path == "/v1/connectors/local-work/operations/perform"
        assert body == module.canonical_json(module.REQUEST)
        assert set(headers) == {"Accept", "Content-Length", "Content-Type", "X-Steward-Task-ID"}
        calls.append((path, headers["X-Steward-Task-ID"]))
    def getresponse(self):
        return Response()
    def close(self):
        pass

module.http.client.HTTPConnection = Connection
os.environ["STEWARD_CONNECTOR_URL"] = module.LOGICAL_BASE
status, payload = module.call("perform", "task-connector-1")
assert status == 200 and payload == module.EXPECTED_RESULT
assert calls == [("/v1/connectors/local-work/operations/perform", "task-connector-1")]
del os.environ["STEWARD_CONNECTOR_URL"]
try:
    module.call("perform", "task-connector-2")
except module.ConnectorError as error:
    assert str(error) == "logical_connector_url_unavailable"
else:
    raise AssertionError("connector skill accepted a missing logical authority")
`
	command := exec.Command(python, "-I", "-c", program, programPath)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("connector skill protocol test failed: %v\n%s", err, output)
	}
}

func TestHermesFixtureModelProtocols(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	root := hermesAdapterRoot(t)
	program := `
import http.server, importlib.util, json, sys, threading, urllib.error, urllib.request
sys.dont_write_bytecode = True
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

for mode, result in (
    ("perform", module.CONNECTOR_RESULT),
    ("replay", module.CONNECTOR_DENIALS["replay"]),
    ("forbidden", module.CONNECTOR_DENIALS["forbidden"]),
):
    output = json.dumps(result, ensure_ascii=True, separators=(",", ":"), sort_keys=True)
    envelope = json.dumps({"error": None, "exit_code": 0, "output": output}, separators=(",", ":"))
    assert module.validated_connector_result(envelope, mode) == output
    assert module.validated_connector_result(envelope.replace('"exit_code":0', '"exit_code":1'), mode) is None

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), module.Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    def complete(messages, stream):
        body = json.dumps({"messages": messages, "stream": stream}).encode()
        request = urllib.request.Request(
            f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
            data=body,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return response.headers.get_content_type(), response.read()

    def user(text):
        return [{"role": "user", "content": text}]

    content_type, wire = complete(user("STEWARD_TASK_FIXTURE"), True)
    assert content_type == "text/event-stream"
    events = [event for event in wire.decode().split("\n\n") if event]
    assert events[-1] == "data: [DONE]"
    chunk = json.loads(events[0].removeprefix("data: "))
    assert chunk["object"] == "chat.completion.chunk"
    assert chunk["choices"][0]["finish_reason"] == "stop"
    assert chunk["choices"][0]["delta"]["content"].startswith("steward-task:")

    _, wire = complete(user("STEWARD_WORKSPACE_AUDIT"), True)
    chunk = json.loads(wire.decode().split("\n\n", 1)[0].removeprefix("data: "))
    tool_call = chunk["choices"][0]["delta"]["tool_calls"][0]
    assert tool_call["index"] == 0 and tool_call["function"]["name"] == "terminal"

    connector_input = "STEWARD_CONNECTOR_WORK task=fixture-task-1"
    try:
        complete(user(connector_input), False)
    except urllib.error.HTTPError as error:
        assert error.code == 422
        assert json.load(error)["error"]["code"] == "connector_skill_not_indexed"
    else:
        raise AssertionError("connector request passed without Hermes skill discovery")

    system = {
        "role": "system",
        "content": (
            "## Skills (mandatory)\nMUST load it with skill_view(name)\n"
            f"<available_skills>\n  general [names only]: {module.CONNECTOR_SKILL_NAME}\n"
            "</available_skills>"
        ),
    }
    connector_messages = [system, *user(connector_input)]
    _, wire = complete(connector_messages, False)
    payload = json.loads(wire)
    skill_message = payload["choices"][0]["message"]
    tool_call = skill_message["tool_calls"][0]
    arguments = json.loads(tool_call["function"]["arguments"])
    assert tool_call["id"] == "call_connector_skill_perform"
    assert tool_call["function"]["name"] == "skill_view"
    assert arguments == {"name": "steward.connector-work"}

    skill_document = open(sys.argv[3], encoding="utf-8").read()
    skill_result = json.dumps({
        "success": True,
        "name": module.CONNECTOR_SKILL_NAME,
        "description": module.CONNECTOR_SKILL_DESCRIPTION,
        "content": skill_document,
        "readiness_status": "available",
        "setup_needed": False,
    })
    for non_object in ("[]", "null", json.dumps("unexpected")):
        assert module.validated_connector_skill_result(non_object) is None
    loaded_messages = connector_messages + [skill_message, {
        "role": "tool",
        "name": "skill_view",
        "tool_call_id": "call_connector_skill_perform",
        "content": skill_result,
    }]
    _, wire = complete(loaded_messages, False)
    payload = json.loads(wire)
    terminal_message = payload["choices"][0]["message"]
    tool_call = terminal_message["tool_calls"][0]
    arguments = json.loads(tool_call["function"]["arguments"])
    assert tool_call["id"] == "call_connector_perform"
    assert tool_call["function"]["name"] == "terminal"
    assert arguments == {"command": "/opt/steward/skills/steward.connector-work/connector_work.py perform fixture-task-1"}

    invalid_messages = connector_messages + [skill_message, {
        "role": "tool",
        "name": "skill_view",
        "tool_call_id": "call_connector_skill_perform",
        "content": skill_result.replace("Return its canonical JSON output unchanged.", "Return changed output."),
    }]
    try:
        complete(invalid_messages, False)
    except urllib.error.HTTPError as error:
        assert error.code == 422
        assert json.load(error)["error"]["code"] == "connector_skill_invalid"
    else:
        raise AssertionError("connector request accepted modified skill content")

    stale_workspace = user("STEWARD_WORKSPACE_AUDIT") + [
        {"role": "assistant", "content": None, "tool_calls": [{
            "id": "call_workspace_audit", "type": "function",
            "function": {"name": "terminal", "arguments": "{}"},
        }]},
        {"role": "tool", "tool_call_id": "call_workspace_audit", "content": envelope},
        {"role": "user", "content": "STEWARD_WORKSPACE_AUDIT"},
    ]
    _, wire = complete(stale_workspace, False)
    fresh = json.loads(wire)["choices"][0]["message"]
    assert fresh["tool_calls"][0]["id"] == "call_workspace_audit"

    content_type, wire = complete(user("STEWARD_TASK_FIXTURE"), False)
    assert content_type == "application/json"
    assert json.loads(wire)["object"] == "chat.completion"
finally:
    server.shutdown()
    server.server_close()
    thread.join(timeout=5)
`
	command := exec.Command(
		python,
		"-I",
		"-B",
		"-c",
		program,
		filepath.Join(root, "fixture_model.py"),
		filepath.Join(root, "fixtures", "skill", "workspace-fixture-contract.json"),
		filepath.Join(root, "fixtures", "connector-skill", "SKILL.md"),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("fixture model protocol test failed: %v\n%s", err, output)
	}
}

func TestHermesEntrypointStartsBridgeAfterHermesReadiness(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	root := hermesAdapterRoot(t)
	program := `
import importlib.util, os, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("hermes_entrypoint", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

events = []
class Process:
    def __init__(self):
        self.exited = False
    def poll(self):
        return 0 if self.exited else None
    def wait(self, timeout=None):
        events.append("wait")
        self.exited = True
        return 0
    def terminate(self):
        events.append("terminate")
        self.exited = True
    def kill(self):
        events.append("kill")
        self.exited = True

process = Process()
def popen(*args, **kwargs):
    events.append("spawn")
    return process
class Server:
    def __init__(self, *args, **kwargs):
        events.append("bind")
    def serve_forever(self):
        pass
    def shutdown(self):
        events.append("shutdown")
    def server_close(self):
        events.append("close")
class Thread:
    def __init__(self, *args, **kwargs):
        pass
    def start(self):
        events.append("thread")

module.verify_skill = lambda: None
module.seed_state = lambda model, qualification_mcp: None
module.subprocess.Popen = popen
module.wait_for_internal_api = lambda child: events.append("ready")
module.BoundedHTTPServer = Server
module.threading.Thread = Thread
module.signal.signal = lambda *args: None
os.environ["OPENAI_MODEL"] = "steward-fixture-model"
os.environ["OPENAI_BASE_URL"] = "http://steward-relay:8080/v1"
os.environ["STEWARD_HERMES_QUALIFICATION_MCP"] = "disabled"
sys.argv = [sys.argv[1], "serve"]
assert module.main() == 0
assert events == ["spawn", "ready", "bind", "thread", "wait", "shutdown", "close"], events
`
	command := exec.Command(python, "-I", "-c", program, filepath.Join(root, "entrypoint.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("entrypoint readiness ordering test failed: %v\n%s", err, output)
	}
}

func TestHermesEntrypointPublicationRecoversWithoutOverwrite(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	root := hermesAdapterRoot(t)
	program := `
import importlib.util, os, pathlib, sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("hermes_entrypoint", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

root = pathlib.Path(sys.argv[2])
name = "config.yaml"
temporary = module.publication_temp_name(name)
expected = b"authority\n"
mode = 0o600

def directory(label):
    path = root / label
    path.mkdir(mode=0o700)
    return os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY)

def write_at(directory_fd, filename, data):
    descriptor = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, mode, dir_fd=directory_fd)
    try:
        os.write(descriptor, data)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)

def expect_failure(action):
    try:
        action()
    except SystemExit:
        return
    raise AssertionError("operation unexpectedly succeeded")

def assert_absent(directory_fd, filename):
    try:
        os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        return
    raise AssertionError(f"{filename} unexpectedly exists")

# A stop during the write leaves a partial, single-link temporary file.
partial = directory("partial")
try:
    write_at(partial, temporary, b"partial")
    module.publish_exact(partial, name, expected, mode)
    content, info = module.read_regular_at(partial, name, len(expected))
    assert content == expected and info.st_nlink == 1
    assert_absent(partial, temporary)
    module.require_exact_directory_entries(partial, {name})
finally:
    os.close(partial)

# A stop after link(2) leaves two names for the same exact inode.
linked = directory("linked")
try:
    write_at(linked, temporary, expected)
    os.link(temporary, name, src_dir_fd=linked, dst_dir_fd=linked, follow_symlinks=False)
    assert os.stat(name, dir_fd=linked, follow_symlinks=False).st_nlink == 2
    module.publish_exact(linked, name, expected, mode)
    content, info = module.read_regular_at(linked, name, len(expected))
    assert content == expected and info.st_nlink == 1
    assert_absent(linked, temporary)
    module.require_exact_directory_entries(linked, {name})
finally:
    os.close(linked)

# Existing drift is reported and preserved rather than overwritten.
drifted = directory("drifted")
try:
    write_at(drifted, name, b"hostile")
    expect_failure(lambda: module.publish_exact(drifted, name, expected, mode))
    content, info = module.read_regular_at(drifted, name, len(b"hostile"))
    assert content == b"hostile" and info.st_nlink == 1
    assert_absent(drifted, temporary)
finally:
    os.close(drifted)

# Cleanup cannot unlink a reserved temporary name with another hard link.
unsafe = directory("unsafe")
try:
    write_at(unsafe, "unrelated", expected)
    os.link("unrelated", temporary, src_dir_fd=unsafe, dst_dir_fd=unsafe, follow_symlinks=False)
    expect_failure(lambda: module.publish_exact(unsafe, name, expected, mode))
    assert os.stat("unrelated", dir_fd=unsafe, follow_symlinks=False).st_nlink == 2
    assert os.stat(temporary, dir_fd=unsafe, follow_symlinks=False).st_nlink == 2
    assert_absent(unsafe, name)
finally:
    os.close(unsafe)

# Strict directory validation still rejects every unbound entry.
strict = directory("strict")
try:
    module.publish_exact(strict, name, expected, mode)
    write_at(strict, "extra", b"extra")
    expect_failure(lambda: module.require_exact_directory_entries(strict, {name}))
finally:
    os.close(strict)
`
	command := exec.Command(
		python,
		"-c",
		program,
		filepath.Join(root, "entrypoint.py"),
		t.TempDir(),
	)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("entrypoint publication recovery test failed: %v\n%s", err, output)
	}
}

func TestHermesBuilderPublicationRecoversEveryDurableState(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash is unavailable")
	}
	builder := string(readBounded(t, filepath.Join(hermesAdapterRoot(t), "..", "..", "scripts", "build-hermes-adapter.sh"), 2<<20))
	start := strings.Index(builder, "hermes_publication_pair() {")
	end := strings.Index(builder, "# END HERMES_PUBLICATION_PAIR")
	if start < 0 || end <= start {
		t.Fatal("builder publication helper markers are missing")
	}
	script := filepath.Join(t.TempDir(), "publication-helper.sh")
	program := "#!/usr/bin/env bash\nset -euo pipefail\n" + builder[start:end] + "\nhermes_publication_pair \"$@\"\n"
	if err := os.WriteFile(script, []byte(program), 0o700); err != nil {
		t.Fatal(err)
	}
	expectedRepository := "https://github.com/NousResearch/hermes-agent.git"
	expectedRevision := strings.Repeat("9", 40)
	expectedCommit := strings.Repeat("a", 40)
	expectedTree := strings.Repeat("b", 40)
	expectedBuilder := strings.Repeat("c", 64)
	authority := []string{
		expectedRepository, expectedRevision, "git-checkout", expectedCommit,
		expectedTree, "", "", expectedBuilder,
	}

	run := func(t *testing.T, operation, archive, metadata, staging string, wantSuccess bool) string {
		t.Helper()
		arguments := []string{script, operation, archive, metadata, staging, strconv.Itoa(1 << 20)}
		arguments = append(arguments, authority...)
		command := exec.Command(bash, arguments...)
		output, err := command.CombinedOutput()
		if wantSuccess && err != nil {
			t.Fatalf("publication %s failed: %v\n%s", operation, err, output)
		}
		if !wantSuccess && err == nil {
			t.Fatalf("publication %s unexpectedly succeeded: %s", operation, output)
		}
		return strings.TrimSpace(string(output))
	}

	makePair := func(t *testing.T, parent string) (string, string, string) {
		t.Helper()
		archive := filepath.Join(parent, "hermes.tar")
		metadata := archive + ".attestation.json"
		staging := filepath.Join(parent, ".hermes.tar.steward-publish")
		if err := os.Mkdir(staging, 0o700); err != nil {
			t.Fatal(err)
		}
		content := []byte("bounded archive fixture\n")
		digest := sha256.Sum256(content)
		document := map[string]any{
			"adapter": map[string]any{
				"contract":       "steward.hermes-agent.v1",
				"git_tree":       expectedTree,
				"source":         "git-checkout",
				"steward_commit": expectedCommit,
			},
			"archive": map[string]any{
				"file":       filepath.Base(archive),
				"sha256":     hex.EncodeToString(digest[:]),
				"size_bytes": len(content),
			},
			"contains_agent_content": false,
			"build_recipe": map[string]any{
				"builder_sha256": expectedBuilder,
				"id":             "steward.hermes-adapter.docker-build.v1",
				"network_scope":  "verified-host-wheel-fetch;gvisor-hooks-network-none",
			},
			"image": map[string]any{
				"config_digest":    "sha256:" + strings.Repeat("2", 64),
				"manifest_digest":  "sha256:" + strings.Repeat("1", 64),
				"platform":         "linux/amd64",
				"runtime_image_id": "sha256:" + strings.Repeat("1", 64),
			},
			"schema_version": "steward.hermes-adapter-build-attestation.v1",
			"source": map[string]any{
				"repository": expectedRepository,
				"revision":   expectedRevision,
			},
		}
		encoded, err := json.Marshal(document)
		if err != nil {
			t.Fatal(err)
		}
		encoded = append(encoded, '\n')
		if err := os.WriteFile(filepath.Join(staging, "archive.tar"), content, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(staging, "attestation.json"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		return archive, metadata, staging
	}

	t.Run("commit", func(t *testing.T) {
		archive, metadata, staging := makePair(t, t.TempDir())
		run(t, "commit", archive, metadata, staging, true)
		for _, path := range []string{archive, metadata} {
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Sys().(*syscall.Stat_t).Nlink != 1 {
				t.Fatalf("published file is not one private regular link: %s (%v, %v)", path, info, err)
			}
		}
		if _, err := os.Stat(staging); !os.IsNotExist(err) {
			t.Fatalf("staging remains after commit: %v", err)
		}
		if got := run(t, "prepare", archive, metadata, staging, true); !strings.HasPrefix(got, "recovered\n") {
			t.Fatalf("recovery without staging = %q, want recovered metadata", got)
		}
	})

	t.Run("metadata_link_only", func(t *testing.T) {
		archive, metadata, staging := makePair(t, t.TempDir())
		if err := os.Link(filepath.Join(staging, "attestation.json"), metadata); err != nil {
			t.Fatal(err)
		}
		if got := run(t, "prepare", archive, metadata, staging, true); got != "new" {
			t.Fatalf("recovery = %q, want new", got)
		}
		for _, path := range []string{archive, metadata, staging} {
			if _, err := os.Stat(path); !os.IsNotExist(err) {
				t.Fatalf("partial publication remains at %s: %v", path, err)
			}
		}
	})

	t.Run("stale_authority_without_staging", func(t *testing.T) {
		archive, metadata, staging := makePair(t, t.TempDir())
		run(t, "commit", archive, metadata, staging, true)
		authority[7] = strings.Repeat("d", 64)
		t.Cleanup(func() { authority[7] = expectedBuilder })
		run(t, "prepare", archive, metadata, staging, false)
		authority[7] = expectedBuilder
	})

	t.Run("both_links", func(t *testing.T) {
		archive, metadata, staging := makePair(t, t.TempDir())
		if err := os.Link(filepath.Join(staging, "attestation.json"), metadata); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(staging, "archive.tar"), archive); err != nil {
			t.Fatal(err)
		}
		if got := run(t, "prepare", archive, metadata, staging, true); !strings.HasPrefix(got, "recovered\n") {
			t.Fatalf("recovery = %q, want recovered metadata", got)
		}
		if _, err := os.Stat(staging); !os.IsNotExist(err) {
			t.Fatalf("staging remains after recovery: %v", err)
		}
	})

	t.Run("staging_unlinked", func(t *testing.T) {
		archive, metadata, staging := makePair(t, t.TempDir())
		if err := os.Link(filepath.Join(staging, "attestation.json"), metadata); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(filepath.Join(staging, "archive.tar"), archive); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(staging, "attestation.json")); err != nil {
			t.Fatal(err)
		}
		if err := os.Remove(filepath.Join(staging, "archive.tar")); err != nil {
			t.Fatal(err)
		}
		if got := run(t, "prepare", archive, metadata, staging, true); !strings.HasPrefix(got, "recovered\n") {
			t.Fatalf("recovery = %q, want recovered metadata", got)
		}
	})
}

func runAudit(t *testing.T, python, script, workspace string, wantSuccess bool) []byte {
	t.Helper()
	program := `
import importlib.util, json, pathlib, sys
sys.dont_write_bytecode = True
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

func decodeEvidence(t *testing.T, path string, destination any) {
	t.Helper()
	content := readBounded(t, path, 1<<20)
	decoder := json.NewDecoder(bytes.NewReader(content))
	if err := decoder.Decode(destination); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	if err := requireEOF(decoder); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
}

func sha256File(t *testing.T, path string) string {
	t.Helper()
	digest := sha256.Sum256(readBounded(t, path, 8<<20))
	return hex.EncodeToString(digest[:])
}

func validSHA256Digest(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func validSHA256Hex(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}

func validHexObjectID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded)*2 == len(value)
}

func hermesAdapterFileSetSHA256(t *testing.T, root string) string {
	t.Helper()
	var paths []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != root && !entry.IsDir() {
			paths = append(paths, path)
		}
		return nil
	}); err != nil {
		t.Fatalf("walk Hermes adapter: %v", err)
	}
	sort.Slice(paths, func(left, right int) bool {
		leftRelative, _ := filepath.Rel(root, paths[left])
		rightRelative, _ := filepath.Rel(root, paths[right])
		return filepath.ToSlash(leftRelative) < filepath.ToSlash(rightRelative)
	})
	entries := make([]map[string]any, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil {
			t.Fatalf("inspect Hermes adapter entry: %v", err)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			t.Fatal(err)
		}
		entry := map[string]any{
			"mode": int(info.Mode().Perm()),
			"path": filepath.ToSlash(relative),
		}
		switch {
		case info.Mode().IsRegular():
			digest := sha256.Sum256(readBounded(t, path, 8<<20))
			entry["sha256"] = hex.EncodeToString(digest[:])
			entry["type"] = "file"
		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				t.Fatal(err)
			}
			entry["target"] = target
			entry["type"] = "symlink"
		default:
			t.Fatalf("unsupported Hermes adapter entry type: %s", relative)
		}
		entries = append(entries, entry)
	}
	encoded, err := json.Marshal(entries)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
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
