package adapterfixture

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHermesBridgeCarriesOnlyCanonicalPerRunInferenceScope(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	const program = `
import base64, http.client, http.server, importlib.util, json, sys, threading
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("entrypoint", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
calls = []
class Upstream(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        calls.append((self.path, self.headers.get(module.INFERENCE_PERMIT_HEADER), self.headers["Authorization"], body))
        self.send_response(202)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *args): pass
upstream = http.server.HTTPServer(("127.0.0.1", 0), Upstream)
module.INTERNAL_API_PORT = upstream.server_port
bridge = module.BoundedHTTPServer(("127.0.0.1", 0), module.ServiceBridgeHandler)
servers = [upstream, bridge]
threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
for thread in threads: thread.start()
def request(values, path="/v1/runs", body=b'{"input":"work"}'):
    connection = http.client.HTTPConnection("127.0.0.1", bridge.server_port, timeout=3)
    try:
        connection.putrequest("POST", path)
        connection.putheader("Content-Length", str(len(body)))
        for value in values: connection.putheader(module.INFERENCE_PERMIT_HEADER, value)
        connection.endheaders(body)
        response = connection.getresponse()
        content = response.read()
        return response.status, content
    finally: connection.close()
try:
    # The bridge transports an envelope; only the native gateway authenticates it.
    first = base64.urlsafe_b64encode(b'first-envelope').decode().rstrip('=')
    second = base64.urlsafe_b64encode(b'second-envelope').decode().rstrip('=')
    maximum = base64.urlsafe_b64encode(b'x' * module.MAX_INFERENCE_PERMIT_BYTES).decode().rstrip('=')
    for value in (first, second, maximum):
        assert request([value])[0] == 202
        assert calls[-1][1:3] == (value, 'Bearer ' + module.INTERNAL_API_TOKEN)
    assert request([])[0] == 202 and calls[-1][1] is None
    before = len(calls)
    oversized = base64.urlsafe_b64encode(b'x' * (module.MAX_INFERENCE_PERMIT_BYTES + 1)).decode().rstrip('=')
    for values in ([first, second], [''], [first + '='], ['a'], ['Zh'], ['!!'], [oversized]):
        status, body = request(values)
        assert status == 400 and json.loads(body)['error'] == 'invalid_inference_permit', (values[:1], status)
        assert len(calls) == before
    run = 'run_' + 'a' * 32
    body = json.dumps({'run_id': run}, separators=(',', ':')).encode()
    assert request([first], '/steward/v1/run-stop', body)[0] == 202
    assert calls[-1][0] == '/v1/runs/' + run + '/stop' and calls[-1][1] is None
finally:
    for server in servers: server.shutdown(); server.server_close()
    for thread in threads: thread.join(3)
`
	command := exec.CommandContext(ctx, python, "-I", "-c", program,
		filepath.Join(hermesAdapterRoot(t), "entrypoint.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("per-run inference scope bridge: %v\n%s", err, output)
	}
}
