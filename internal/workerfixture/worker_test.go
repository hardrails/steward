package workerfixture

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve worker fixture path")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func readFile(t *testing.T, path string, maximum int64) []byte {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maximum {
		t.Fatalf("unsafe fixture %s: info=%v err=%v", path, info, err)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestWorkerImagesPinReplaceableEnginesWithoutChangingGoDependencies(t *testing.T) {
	root := repositoryRoot(t)
	researchDockerfile := string(readFile(t, filepath.Join(root, "workers", "research", "Dockerfile"), 64<<10))
	codingDockerfile := string(readFile(t, filepath.Join(root, "workers", "coding", "Dockerfile"), 64<<10))
	for name, source := range map[string]string{"research": researchDockerfile, "coding": codingDockerfile} {
		for _, required := range []string{"FROM ", "@sha256:", "USER 65532:65532"} {
			if !strings.Contains(source, required) {
				t.Fatalf("%s worker Dockerfile is missing %q", name, required)
			}
		}
		if strings.Contains(source, ":latest") {
			t.Fatalf("%s worker uses a floating latest tag", name)
		}
	}
	for _, required := range []string{"npm ci --omit=dev --ignore-scripts", "unsupported coding-worker architecture", "/usr/local/bin/claude"} {
		if !strings.Contains(codingDockerfile, required) {
			t.Fatalf("coding worker build is missing %q", required)
		}
	}

	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(root, "workers", "coding", "package-lock.json"), 2<<20), &lock); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"node_modules/@openai/codex":             "0.144.6",
		"node_modules/@anthropic-ai/claude-code": "2.1.216",
	}
	if lock.LockfileVersion != 3 {
		t.Fatalf("lockfile version=%d", lock.LockfileVersion)
	}
	for path, version := range want {
		item, ok := lock.Packages[path]
		if !ok || item.Version != version || !strings.HasPrefix(item.Integrity, "sha512-") {
			t.Fatalf("package %s=%#v, want exact version %s with integrity", path, item, version)
		}
	}
}

func TestCodingWorkerUsesFixedSafeModeCLIArguments(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(repositoryRoot(t), "workers", "coding", "coding_worker.py")
	harness := `import importlib.util,json,sys
spec=importlib.util.spec_from_file_location("worker",sys.argv[1])
worker=importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
print(json.dumps({e+"-"+m:worker.command_for(e,"fixed task",m) for e in ("codex","claude-code") for m in ("read","write")},sort_keys=True))
`
	command := exec.Command(python, "-I", "-B", "-c", harness, path)
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var commands map[string][]string
	if err := json.Unmarshal(raw, &commands); err != nil {
		t.Fatal(err)
	}
	for key, arguments := range commands {
		if len(arguments) < 8 || arguments[len(arguments)-1] != "fixed task" && key[:5] == "codex" {
			t.Fatalf("%s command=%v", key, arguments)
		}
		joined := strings.Join(arguments, " ")
		for _, forbidden := range []string{"dangerously-bypass", "skip-permissions", "--continue", "--resume"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("%s command contains %q: %v", key, forbidden, arguments)
			}
		}
	}
	for _, required := range []string{"--ephemeral", "--ignore-user-config", "--ignore-rules", "--sandbox", "read-only"} {
		if !strings.Contains(strings.Join(commands["codex-read"], " "), required) {
			t.Fatalf("Codex read command is missing %q: %v", required, commands["codex-read"])
		}
	}
	for _, required := range []string{"--safe-mode", "--no-session-persistence", "--disable-slash-commands", "--permission-mode", "plan"} {
		if !strings.Contains(strings.Join(commands["claude-code-read"], " "), required) {
			t.Fatalf("Claude read command is missing %q: %v", required, commands["claude-code-read"])
		}
	}
	source := string(readFile(t, path, 1<<20))
	for _, forbidden := range []string{"shell=True", "os.system(", "subprocess.call("} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("coding worker contains unsafe execution primitive %q", forbidden)
		}
	}
	for _, required := range []string{"MAX_REQUEST = 64 << 10", "MAX_TIMEOUT = 900", "credential_output_blocked", "workspace_not_clean"} {
		if !strings.Contains(source, required) {
			t.Fatalf("coding worker is missing contract %q", required)
		}
	}
}

func TestResearchWorkerNormalizesAndRejectsPrivateSources(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(repositoryRoot(t), "workers", "research", "research_worker.py")
	harness := `import importlib.util,json,sys,urllib.parse
spec=importlib.util.spec_from_file_location("worker",sys.argv[1])
worker=importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
worker.resolve_public_addresses=lambda host,port: ["93.184.216.34"] if host != "rebind.example" else (_ for _ in ()).throw(worker.WorkerError(400,"private_source_denied","blocked"))
def fake(base,method,path,payload,token=None):
  if method=="GET": return {"results":[{"title":"Primary","url":"https://example.com/source","content":"Evidence","engine":"fixture"}]}
  return {"data":{"markdown":"# Source","metadata":{"title":"Document"}}}
worker.upstream_json=fake
worker.fetch_public_page=lambda url: (url,"Document","Source")
base=urllib.parse.urlsplit("https://service.example/prefix")
result={"search":worker.search({"query":"bounded query","limit":1},base),"extract":worker.extract({"urls":["https://example.com/source"]})}
blocked=[]
for value in ("http://127.0.0.1/x","http://169.254.169.254/latest","http://service.local/x","https://rebind.example/x"):
  try: worker.public_url(value)
  except worker.WorkerError as error: blocked.append(error.code)
result["blocked"]=blocked
print(json.dumps(result,sort_keys=True))
`
	command := exec.Command(python, "-I", "-B", "-c", harness, path)
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Search  map[string]any `json:"search"`
		Extract map[string]any `json:"extract"`
		Blocked []string       `json:"blocked"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if value.Search["schema_version"] != "steward.research-search-result.v1" ||
		value.Extract["schema_version"] != "steward.research-extract-result.v1" ||
		!bytes.Equal([]byte(strings.Join(value.Blocked, ",")), []byte("private_source_denied,private_source_denied,private_source_denied,private_source_denied")) {
		t.Fatalf("normalized result=%s", raw)
	}
	source := string(readFile(t, path, 1<<20))
	for _, required := range []string{"MAX_REQUEST = 64 << 10", "MAX_UPSTREAM = 4 << 20", "MAX_RESPONSE = 1 << 20", "hmac.compare_digest", "MAX_REDIRECTS = 5", "socket.create_connection"} {
		if !strings.Contains(source, required) {
			t.Fatalf("research worker is missing contract %q", required)
		}
	}
}

func TestResearchWorkerPinsPublicDNSAndRevalidatesRedirects(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(repositoryRoot(t), "workers", "research", "research_worker.py")
	harness := `import importlib.util,json,socket,sys,types
spec=importlib.util.spec_from_file_location("worker",sys.argv[1])
worker=importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
worker.socket.getaddrinfo=lambda host,port,type,proto:[
  (socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,"",("93.184.216.34",port)),
  (socket.AF_INET,socket.SOCK_STREAM,socket.IPPROTO_TCP,"",("127.0.0.1",port)),
]
dns="accepted"
try: worker.resolve_public_addresses("rebind.example",443)
except worker.WorkerError as error: dns=error.code
seen=[]
def destination(value):
  seen.append(value)
  if value=="https://private.example/secret": raise worker.WorkerError(400,"private_source_denied","blocked")
  return value,worker.urllib.parse.urlsplit(value),["93.184.216.34"]
class Headers:
  def get_all(self,name,default): return ["https://private.example/secret"] if name=="Location" else default
class Response:
  status=302
  headers=Headers()
class Connection:
  def close(self): pass
worker.public_destination=destination
worker.request_public_page=lambda parsed,addresses:(Response(),Connection())
redirect="accepted"
try: worker.fetch_public_page("https://public.example/start")
except worker.WorkerError as error: redirect=error.code
print(json.dumps({"dns":dns,"redirect":redirect,"seen":seen},sort_keys=True))
`
	command := exec.Command(python, "-I", "-B", "-c", harness, path)
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		DNS      string   `json:"dns"`
		Redirect string   `json:"redirect"`
		Seen     []string `json:"seen"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.DNS != "private_source_denied" || result.Redirect != "private_source_denied" ||
		strings.Join(result.Seen, ",") != "https://public.example/start,https://private.example/secret" {
		t.Fatalf("research destination enforcement=%s", raw)
	}
}
