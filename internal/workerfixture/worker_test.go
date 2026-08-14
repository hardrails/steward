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

func isolatedPythonEnvironment(t *testing.T) []string {
	t.Helper()
	environment := []string{
		"LANG=C",
		"LC_ALL=C",
		"PYTHONDONTWRITEBYTECODE=1",
	}
	for _, name := range []string{
		"HOME",
		"PATH",
		"TMPDIR",
		"TMP",
		"TEMP",
		"SYSTEMROOT",
	} {
		if value, ok := os.LookupEnv(name); ok {
			environment = append(environment, name+"="+value)
		}
	}
	for _, entry := range environment {
		name, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(strings.ToUpper(name), "GIT_") {
			t.Fatalf("isolated Python environment inherited %s", name)
		}
	}
	return environment
}

func TestWorkerImagesPinReplaceableEnginesWithoutChangingGoDependencies(t *testing.T) {
	root := repositoryRoot(t)
	researchDockerfile := string(readFile(t, filepath.Join(root, "workers", "research", "Dockerfile"), 64<<10))
	codingDockerfile := string(readFile(t, filepath.Join(root, "workers", "coding", "Dockerfile"), 64<<10))
	browserDockerfile := string(readFile(t, filepath.Join(root, "workers", "browser", "Dockerfile"), 64<<10))
	for name, source := range map[string]string{"research": researchDockerfile, "coding": codingDockerfile, "browser": browserDockerfile} {
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
	for _, required := range []string{"mcr.microsoft.com/playwright:v1.61.0-noble@sha256:", "npm ci --omit=dev --ignore-scripts"} {
		if !strings.Contains(browserDockerfile, required) {
			t.Fatalf("browser worker build is missing %q", required)
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

func TestBrowserWorkerUsesOpaqueRefsAndRejectsPrivateDestinations(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node unavailable")
	}
	root := repositoryRoot(t)
	securityPath := filepath.Join(root, "workers", "browser", "security.mjs")
	harness := `import {isPublicAddress,publicTarget,readBoundedWebBody,SourceStore} from "file://` + securityPath + `";
const blocked=[];
for (const value of ["127.0.0.1","169.254.169.254","10.0.0.1","::1","fc00::1","2001::1","2001:db8::1","2002:5db8:d822::1","3fff::1"]) blocked.push(isPublicAddress(value));
const publicV6=["2606:4700:4700::1111","2a00:1450:4009:822::200e"].map(isPublicAddress);
const lookup=async()=>[{address:"93.184.216.34",family:4}];
const accepted=await publicTarget("https://example.com/source",lookup);
let mixed="accepted";
try { await publicTarget("https://mixed.example/source",async()=>[{address:"93.184.216.34",family:4},{address:"127.0.0.1",family:4}]); }
catch(error) { mixed=error.code; }
let now=0;
const store=new SourceStore(()=>now,2,100);
const refs=store.putMany(["https://one.example","https://two.example"]);
let capacity="accepted";
try { store.putMany(["https://three.example"]); } catch(error) { capacity=error.code; }
const preserved=store.get(refs[0]);
now=101;
const replacement=store.putMany(["https://three.example"]);
let overflow="accepted";
const oversized=new Response(new Uint8Array(5),{headers:{"content-length":"5"}});
try { await readBoundedWebBody(oversized,4); } catch(error) { overflow=error.code; }
let chunkedOverflow="accepted";
const chunked=new Response(new ReadableStream({start(controller) {
  controller.enqueue(new Uint8Array([1,2,3]));
  controller.enqueue(new Uint8Array([4,5,6]));
  controller.close();
}}));
try { await readBoundedWebBody(chunked,4); } catch(error) { chunkedOverflow=error.code; }
const streamed=await readBoundedWebBody(new Response(new Uint8Array([1,2,3,4])),4);
process.stdout.write(JSON.stringify({blocked,publicV6,accepted:accepted.address,mixed,capacity,preserved,replacement:replacement.length,overflow,chunkedOverflow,streamed:streamed.length}));
`
	raw, err := exec.Command(node, "--input-type=module", "-e", harness).Output()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Blocked         []bool `json:"blocked"`
		PublicV6        []bool `json:"publicV6"`
		Accepted        string `json:"accepted"`
		Mixed           string `json:"mixed"`
		Capacity        string `json:"capacity"`
		Preserved       string `json:"preserved"`
		Replacement     int    `json:"replacement"`
		Overflow        string `json:"overflow"`
		ChunkedOverflow string `json:"chunkedOverflow"`
		Streamed        int    `json:"streamed"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Accepted != "93.184.216.34" || result.Mixed != "private_source_denied" ||
		result.Capacity != "source_capacity_exhausted" || result.Preserved != "https://one.example" ||
		result.Replacement != 1 || result.Overflow != "search_response_too_large" ||
		result.ChunkedOverflow != "search_response_too_large" || result.Streamed != 4 {
		t.Fatalf("browser destination result=%s", raw)
	}
	for _, accepted := range result.Blocked {
		if accepted {
			t.Fatalf("browser accepted a private destination: %s", raw)
		}
	}
	for _, accepted := range result.PublicV6 {
		if !accepted {
			t.Fatalf("browser rejected a public IPv6 destination: %s", raw)
		}
	}
	source := string(readFile(t, filepath.Join(root, "workers", "browser", "server.mjs"), 1<<20))
	boundaries := source + string(readFile(t, securityPath, 1<<20))
	for _, required := range []string{
		"source_ref_not_found", "serviceWorkers: \"block\"", "acceptDownloads: false",
		"--host-resolver-rules=MAP", "sameOrigin", "MAX_RESPONSE = 1 << 20",
		"readBoundedWebBody(response, MAX_SEARCH_RESPONSE)", "sources.putMany",
	} {
		if !strings.Contains(boundaries, required) {
			t.Fatalf("browser worker is missing contract %q", required)
		}
	}
	for _, forbidden := range []string{
		"page.click(", "page.fill(", "page.evaluate(", "browserType.connect(",
		"launchServer(", "node:child_process",
	} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("browser worker exposes forbidden primitive %q", forbidden)
		}
	}
	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version   string `json:"version"`
			Integrity string `json:"integrity"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(readFile(t, filepath.Join(root, "workers", "browser", "package-lock.json"), 2<<20), &lock); err != nil {
		t.Fatal(err)
	}
	for path, version := range map[string]string{
		"node_modules/playwright":      "1.61.0",
		"node_modules/playwright-core": "1.61.0",
	} {
		item := lock.Packages[path]
		if lock.LockfileVersion != 3 || item.Version != version || !strings.HasPrefix(item.Integrity, "sha512-") {
			t.Fatalf("browser dependency %s=%#v", path, item)
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
commands={e+"-"+m:worker.command_for(e,"fixed task",m) for e in ("codex","claude-code") for m in ("read","write")}
commands["boundary-codex-help"]=worker.command_for("codex","--help","write")
commands["boundary-codex-bypass"]=worker.command_for("codex","--dangerously-bypass-approvals-and-sandbox","write")
commands["boundary-claude-help"]=worker.command_for("claude-code","--help","write")
commands["boundary-claude-bypass"]=worker.command_for("claude-code","--dangerously-skip-permissions","write")
print(json.dumps(commands,sort_keys=True))
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
		if strings.HasPrefix(key, "boundary-") {
			continue
		}
		if len(arguments) < 8 {
			t.Fatalf("%s command=%v", key, arguments)
		}
		if strings.HasPrefix(key, "codex-") || strings.HasPrefix(key, "claude-code-") {
			if arguments[len(arguments)-2] != "--" || arguments[len(arguments)-1] != "fixed task" {
				t.Fatalf("%s command does not delimit task text: %v", key, arguments)
			}
		}
		joined := strings.Join(arguments, " ")
		for _, forbidden := range []string{"dangerously-bypass", "skip-permissions", "--continue", "--resume"} {
			if strings.Contains(joined, forbidden) {
				t.Fatalf("%s command contains %q: %v", key, forbidden, arguments)
			}
		}
	}
	for key, task := range map[string]string{
		"boundary-codex-help":    "--help",
		"boundary-codex-bypass":  "--dangerously-bypass-approvals-and-sandbox",
		"boundary-claude-help":   "--help",
		"boundary-claude-bypass": "--dangerously-skip-permissions",
	} {
		arguments := commands[key]
		if len(arguments) < 2 || arguments[len(arguments)-2] != "--" || arguments[len(arguments)-1] != task {
			t.Fatalf("%s command does not preserve task text after the option boundary: %v", key, arguments)
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

func TestCodingWorkerProducesReproducibleImmutableGitHandoffs(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	root := repositoryRoot(t)
	fixture := filepath.Join(root, "internal", "workerfixture", "coding_handoff_test.py")
	worker := filepath.Join(root, "workers", "coding", "coding_worker.py")
	command := exec.Command(python, "-I", "-B", "-W", "error::ResourceWarning", fixture, worker)
	command.Env = isolatedPythonEnvironment(t)
	raw, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("immutable coding handoff fixture failed: %v\n%s", err, raw)
	}
	if bytes.Contains(raw, []byte("ResourceWarning")) {
		t.Fatalf("immutable coding handoff fixture leaked a resource:\n%s", raw)
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

func TestResearchWorkerNormalizesPublicJSONAndRejectsInvalidJSON(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(repositoryRoot(t), "workers", "research", "research_worker.py")
	harness := `import importlib.util,json,sys,urllib.parse
spec=importlib.util.spec_from_file_location("worker",sys.argv[1])
worker=importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
class Headers:
  def __init__(self,content_type): self.content_type=content_type
  def get_all(self,name,default): return default
  def get(self,name,default=None): return "identity" if name=="Content-Encoding" else default
  def get_content_type(self): return self.content_type
  def get_content_charset(self): return "utf-8"
class Response:
  status=200
  def __init__(self,body,content_type): self.body=body; self.headers=Headers(content_type)
  def read(self,maximum): return self.body
class Connection:
  def close(self): pass
responses=[
  Response(b'{"z":2,"a":{"value":1}}',"application/json"),
  Response(b'{"type":"Feature"}',"application/geo+json"),
  Response(b'{bad',"application/geo+json"),
  Response((b'['*2000)+b'0'+(b']'*2000),"application/json"),
  Response(b'"\\ud800"',"application/json"),
]
worker.public_destination=lambda value:(value,urllib.parse.urlsplit(value),["93.184.216.34"])
worker.request_public_page=lambda parsed,addresses,deadline=None:(responses.pop(0),Connection())
url,title,content,media=worker.fetch_public_page("https://api.example/data",include_source_media=True)
v2=worker.extract_v2_outcome("https://api.example/feature",worker.time.monotonic()+1)
failures=[]
for suffix in ("bad","deep","surrogate"):
  try: worker.fetch_public_page("https://api.example/"+suffix)
  except worker.WorkerError as error: failures.append(error.code)
print(json.dumps({"url":url,"title":title,"content":content,"media":media,"v2":v2,"failures":failures},sort_keys=True))
`
	command := exec.Command(python, "-I", "-B", "-c", harness, path)
	command.Env = isolatedPythonEnvironment(t)
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		URL     string `json:"url"`
		Title   string `json:"title"`
		Content string `json:"content"`
		Media   string `json:"media"`
		V2      struct {
			Disposition string `json:"disposition"`
			Media       string `json:"source_media_type"`
			Content     string `json:"content"`
		} `json:"v2"`
		Failures []string `json:"failures"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.URL != "https://api.example/data" || result.Title != "" ||
		result.Content != "{\n  \"a\": {\n    \"value\": 1\n  },\n  \"z\": 2\n}" ||
		result.Media != "application/json" ||
		result.V2.Disposition != "extracted" || result.V2.Media != "application/json" ||
		result.V2.Content != "{\n  \"type\": \"Feature\"\n}" ||
		strings.Join(result.Failures, ",") != "unsupported_source,unsupported_source,unsupported_source" {
		t.Fatalf("public JSON normalization=%s", raw)
	}
}

func TestResearchWorkerV2ReturnsStrictOrderedTotalOutcomes(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	path := filepath.Join(repositoryRoot(t), "workers", "research", "research_worker.py")
	harness := `import base64,importlib.util,json,os,subprocess,sys,time
spec=importlib.util.spec_from_file_location("worker",sys.argv[1])
worker=importlib.util.module_from_spec(spec); spec.loader.exec_module(worker)
urls=["https://slow.example/report","https://rejected.example/report","https://fast.example/report"]
def start(index,url,batch,raw=None,delay=0,hang=False):
  if hang:
    arguments=[sys.executable,"-I","-c","import time; time.sleep(60)"]
  else:
    encoded=base64.b64encode(raw).decode("ascii")
    script="import base64,sys,time;time.sleep(float(sys.argv[1]));sys.stdout.buffer.write(base64.b64decode(sys.argv[2]))"
    arguments=[sys.executable,"-I","-c",script,str(delay),encoded]
  process=subprocess.Popen(arguments,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,close_fds=True,start_new_session=True)
  descriptor=process.stdout.fileno(); os.set_blocking(descriptor,False)
  return worker.V2SourceProcess(index=index,requested_url=url,process=process,deadline=min(batch,time.monotonic()+worker.V2_SOURCE_SECONDS),output=bytearray(),stdout_fd=descriptor)
def outcome(url,disposition):
  if disposition=="failed":
    return {"requested_url":url,"disposition":"failed","failure_code":"source_rejected"}
  return {"requested_url":url,"disposition":"extracted","resolved_url":url+"/final","source_media_type":"application/pdf","title":"Report","content":"bounded","content_type":"text/plain","content_truncated":False}
values={urls[0]:outcome(urls[0],"extracted"),urls[1]:outcome(urls[1],"failed"),urls[2]:outcome(urls[2],"extracted")}
def factory(index,url,batch):
  raw=json.dumps(values[url],ensure_ascii=False,separators=(",",":"),sort_keys=True).encode()
  return start(index,url,batch,raw,0.08 if url==urls[0] else 0.01)
outcomes=worker.run_v2_source_processes(urls,factory)
success_keys={"requested_url","disposition","resolved_url","source_media_type","title","content","content_type","content_truncated"}
failure_keys={"requested_url","disposition","failure_code"}
exact=set(outcomes[0])==success_keys and set(outcomes[1])==failure_keys and "message" not in outcomes[1]
def malformed(index,url,batch):
  return start(index,url,batch,b'{"unexpected":true}')
protocol="accepted"
try: worker.run_v2_source_processes([urls[0]],malformed)
except RuntimeError: protocol="rejected"
original_source,original_batch=worker.V2_SOURCE_SECONDS,worker.V2_BATCH_SECONDS
worker.V2_SOURCE_SECONDS,worker.V2_BATCH_SECONDS=0.05,0.12
hung=[f"https://hung-{index}.example/report" for index in range(10)]
started=time.monotonic()
deadline=worker.run_v2_source_processes(hung,lambda index,url,batch:start(index,url,batch,hang=True))
elapsed=time.monotonic()-started
worker.V2_SOURCE_SECONDS,worker.V2_BATCH_SECONDS=original_source,original_batch
private=worker.extract_v2({"urls":["http://127.0.0.1/private"]})["outcomes"][0]
result={"schema":"steward.research-extract-result.v2","outcomes":outcomes,"exact":exact,"protocol":protocol,"deadline_codes":[item["failure_code"] for item in deadline],"elapsed":elapsed,"private":private,"serialized":len(json.dumps({"schema_version":"steward.research-extract-result.v2","outcomes":outcomes},ensure_ascii=False,separators=(",",":"),sort_keys=True).encode())}
print(json.dumps(result,sort_keys=True))
`
	command := exec.Command(python, "-I", "-B", "-c", harness, path)
	command.Env = isolatedPythonEnvironment(t)
	raw, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Schema   string `json:"schema"`
		Outcomes []struct {
			RequestedURL     string `json:"requested_url"`
			Disposition      string `json:"disposition"`
			ResolvedURL      string `json:"resolved_url"`
			SourceMediaType  string `json:"source_media_type"`
			ContentType      string `json:"content_type"`
			ContentTruncated bool   `json:"content_truncated"`
			FailureCode      string `json:"failure_code"`
		} `json:"outcomes"`
		Exact         bool     `json:"exact"`
		Protocol      string   `json:"protocol"`
		DeadlineCodes []string `json:"deadline_codes"`
		Elapsed       float64  `json:"elapsed"`
		Private       struct {
			RequestedURL string `json:"requested_url"`
			Disposition  string `json:"disposition"`
			FailureCode  string `json:"failure_code"`
		} `json:"private"`
		Serialized int `json:"serialized"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatal(err)
	}
	if value.Schema != "steward.research-extract-result.v2" || len(value.Outcomes) != 3 ||
		value.Outcomes[0].RequestedURL != "https://slow.example/report" ||
		value.Outcomes[1].RequestedURL != "https://rejected.example/report" ||
		value.Outcomes[2].RequestedURL != "https://fast.example/report" ||
		value.Outcomes[0].Disposition != "extracted" || value.Outcomes[1].Disposition != "failed" ||
		value.Outcomes[0].ResolvedURL != "https://slow.example/report/final" ||
		value.Outcomes[0].SourceMediaType != "application/pdf" ||
		value.Outcomes[0].ContentType != "text/plain" || value.Outcomes[0].ContentTruncated ||
		value.Outcomes[1].FailureCode != "source_rejected" || !value.Exact ||
		value.Protocol != "rejected" || value.Serialized > 1<<20 {
		t.Fatalf("v2 extraction contract=%s", raw)
	}
	if len(value.DeadlineCodes) != 10 || value.Elapsed >= 1 {
		t.Fatalf("v2 deadline contract=%s", raw)
	}
	for _, code := range value.DeadlineCodes {
		if code != "source_unavailable" {
			t.Fatalf("v2 deadline returned %q: %s", code, raw)
		}
	}
	if value.Private.RequestedURL != "http://127.0.0.1/private" ||
		value.Private.Disposition != "failed" || value.Private.FailureCode != "private_source_denied" {
		t.Fatalf("v2 private destination contract=%s", raw)
	}
	source := string(readFile(t, path, 1<<20))
	for _, required := range []string{
		`MAX_V2_SOURCE_TEXT = 32 << 10`, `V2_SOURCE_SECONDS = 15`, `V2_BATCH_SECONDS = 50`,
		`V2_CLEANUP_RESERVE_SECONDS = 1`,
		`V2_MAX_CONCURRENCY = 4`, `V2_SOURCE_CHILD_MODE = "--extract-source-v2"`,
		`start_new_session=True`, `os.killpg`, `"/v2/extract"`, `"source_media_type"`,
	} {
		if !strings.Contains(source, required) {
			t.Fatalf("v2 research worker is missing contract %q", required)
		}
	}
	if strings.Contains(source, "ThreadPoolExecutor") {
		t.Fatal("v2 research worker can wait indefinitely on a thread-pool future")
	}
}
