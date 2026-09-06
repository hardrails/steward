package adapterfixture

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestHermesStopObservationOracle(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	program := `
import json, math, pathlib, sys
source = pathlib.Path(sys.argv[1]).read_text()
oracle = source.split('# BEGIN STOP OBSERVATION ORACLE', 1)[1].split('\n', 1)[1].split('# END STOP OBSERVATION ORACLE', 1)[0]
exec(compile(oracle, sys.argv[1], 'exec'))
run = 'run_' + 'a' * 32

def trial(status='cancelled', survives=False, born=99.0, request_delay=0, active=True):
    now = [100.0]
    requests = []
    def clock():
        return now[0]
    def sleep(duration):
        assert 0 <= duration <= 0.1
        now[0] += duration
    def request(method, path, body, deadline):
        assert deadline == 105.0
        requests.append(method)
        now[0] += request_delay
        if method == 'POST':
            assert path == '/steward/v1/run-stop'
            assert body == json.dumps({'run_id': run}, separators=(',', ':')).encode()
            return {'run_id': run, 'status': 'stopping'}
        assert path == '/v1/runs/' + run and body is None
        return {'run_id': run, 'status': status}
    def process_matches(marker):
        return active if not requests else survives
    observe_stop(run, {'pid': 1, 'start': '123', 'born': born}, request, process_matches, clock, sleep)
    return now[0]

assert trial() < 105.0
for kwargs in (
    {'survives': True},  # Lying terminal status must not count as stopping work.
    {'status': 'stopping', 'survives': True},  # Ignored stop cannot wait for natural exit.
    {'status': 'completed'},
    {'status': 'failed'},
    {'status': 'unknown'},
    {'born': 96.9},  # Old marker cannot establish natural-exit headroom.
    {'born': 101.0},
    {'born': float('nan')},
    {'born': float('inf')},
    {'request_delay': 6},  # Deadline includes stop dispatch, not just polling.
    {'request_delay': 3},  # Late terminal response must not pass.
    {'active': False},
):
    try:
        trial(**kwargs)
    except AssertionError:
        pass
    else:
        raise AssertionError('invalid stop observation accepted: ' + repr(kwargs))
`
	command := exec.CommandContext(ctx, python, "-I", "-c", program,
		filepath.Join(hermesAdapterRoot(t), "..", "..", "scripts", "hermes-feasibility.sh"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Hermes stop observation oracle failed: %v\n%s", err, output)
	}
}

func TestHermesImageOwnedStopFixture(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	program := `
import importlib.util, json, pathlib, stat, sys, tempfile
from unittest import mock
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location('fixture_model', sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
with tempfile.TemporaryDirectory() as temporary:
    marker = pathlib.Path(temporary) / 'active.json'
    module.STOP_FIXTURE_MARKER = str(marker)
    proc_stat = '42 (python3) ' + ' '.join(['S'] + ['0'] * 18 + ['12345'])
    with mock.patch.object(module.pathlib.Path, 'read_text', return_value=proc_stat), mock.patch.object(module.os, 'getpid', return_value=42), mock.patch.object(module.time, 'monotonic', return_value=100.0), mock.patch.object(module.time, 'sleep') as sleep:
        module.run_stop_fixture()
        sleep.assert_called_once_with(60)
        try:
            module.run_stop_fixture()
        except FileExistsError:
            pass
        else:
            raise AssertionError('existing marker was overwritten')
    assert json.loads(marker.read_text()) == {'pid': 42, 'start': '12345', 'born': 100.0}
    assert stat.S_IMODE(marker.stat().st_mode) == 0o600
    target = pathlib.Path(temporary) / 'do-not-overwrite'
    target.write_text('preserved')
    link = pathlib.Path(temporary) / 'marker-link'
    link.symlink_to(target)
    module.STOP_FIXTURE_MARKER = str(link)
    with mock.patch.object(module.pathlib.Path, 'read_text', return_value=proc_stat), mock.patch.object(module.time, 'sleep') as sleep:
        try:
            module.run_stop_fixture()
        except FileExistsError:
            pass
        else:
            raise AssertionError('symlink marker accepted')
        sleep.assert_not_called()
    assert target.read_text() == 'preserved'
`
	command := exec.CommandContext(ctx, python, "-I", "-c", program,
		filepath.Join(hermesAdapterRoot(t), "fixture_model.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("image-owned stop fixture failed: %v\n%s", err, output)
	}
}

func TestHermesBridgeRunStopBoundary(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	program := `
import http.client, http.server, importlib.util, json, sys, threading
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("hermes_entrypoint", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

calls = []
run = "run_" + "a" * 32
stop_path = "/steward/v1/run-stop"
native_stop_path = "/v1/runs/" + run + "/stop"
stop_body = json.dumps({"run_id": run}, separators=(",", ":")).encode()
assert len(stop_body) == 49
upstream_status = 200
upstream_body = json.dumps({"run_id": run, "status": "stopping"}).encode()
oversized_response = False

class Upstream(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        calls.append((self.command, self.path, body, dict(self.headers)))
        self.send_response(upstream_status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(module.MAX_RESPONSE_BODY + 1 if oversized_response else len(upstream_body)))
        self.end_headers()
        if not oversized_response:
            self.wfile.write(upstream_body)
    def do_GET(self):
        calls.append((self.command, self.path, None, dict(self.headers)))
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(upstream_body)))
        self.end_headers()
        self.wfile.write(upstream_body)
    def log_message(self, *args):
        pass

upstream = http.server.HTTPServer(("127.0.0.1", 0), Upstream)
module.INTERNAL_API_PORT = upstream.server_port
bridge = module.BoundedHTTPServer(("127.0.0.1", 0), module.ServiceBridgeHandler)
servers = (upstream, bridge)
threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
for thread in threads:
    thread.start()

def request(method, path, body=stop_body, headers=None):
    if headers is None:
        headers = [("Content-Length", str(len(body)))]
    connection = http.client.HTTPConnection("127.0.0.1", bridge.server_port, timeout=2)
    try:
        connection.putrequest(method, path, skip_accept_encoding=True)
        for name, value in headers:
            connection.putheader(name, value)
        connection.endheaders(body)
        response = connection.getresponse()
        return response.status, response.read(module.MAX_RESPONSE_BODY + 1)
    finally:
        connection.close()

try:
    status, body = request("POST", stop_path, headers=[
        ("Content-Length", "49"), ("Authorization", "Bearer caller-secret"),
        ("Cookie", "session=caller-cookie"), ("X-Forwarded-Host", "attacker.invalid"),
    ])
    assert status == 200 and body == upstream_body, (status, body)
    assert json.loads(body)["status"] == "stopping", "stop acknowledgement was promoted to termination"
    assert len(calls) == 1, calls
    method, path, forwarded_body, headers = calls[0]
    assert (method, path, forwarded_body) == ("POST", native_stop_path, b"{}")
    assert headers["Authorization"] == "Bearer " + module.INTERNAL_API_TOKEN
    assert headers["Content-Type"] == "application/json"
    assert "Cookie" not in headers and "X-Forwarded-Host" not in headers
    assert "caller-secret" not in repr(headers)

    # A second observation still says stopping; the bridge cannot prove execution halted.
    status, body = request("GET", "/v1/runs/" + run, body=b"", headers=[])
    assert status == 200 and body == upstream_body
    count = len(calls)
    forbidden = [
        stop_path + "/", stop_path + "?all=true", stop_path + "/../stop",
        native_stop_path, stop_path.replace("run-stop", "run-%73top"),
        "/v1/runs/stop", "/v1/runs/" + run + "/approval", "/v1/runs/" + run + "/events",
    ]
    for path in forbidden:
        status, _ = request("POST", path)
        assert status == 404, (path, status)
    status, _ = request("GET", stop_path, body=b"", headers=[])
    assert status == 404
    assert len(calls) == count, "forbidden route reached Hermes"

    invalid_requests = [
        (b"", [], 411),
        (b"", [("Content-Length", "50")], 413),
        (b"", [("Content-Length", "65537")], 413),
        (b"{}", [("Content-Length", "2"), ("Content-Length", "2")], 400),
        (b"{}", [("Content-Length", "2"), ("Transfer-Encoding", "chunked")], 400),
        (b"{}", [("Content-Length", "2"), ("Expect", "100-continue")], 417),
        (b"", [("Content-Length", "0")], 400),
        (b"[]", [("Content-Length", "2")], 400),
        (b"  ", [("Content-Length", "2")], 400),
        (b"", [("Content-Length", "-1")], 400),
    ]
    for body, headers, expected in invalid_requests:
        status, _ = request("POST", stop_path, body=body, headers=headers)
        assert status == expected, (body, headers, status, expected)
    for invalid_run in ("run_" + "a" * 31, "RUN_" + "a" * 32, "run_" + "A" * 32,
                        "run_" + "g" * 32, "../other", 3, None, True):
        body = json.dumps({"run_id": invalid_run}, separators=(",", ":")).encode()
        status, _ = request("POST", stop_path, body=body)
        assert status == 400, (body, status)
    for body in (b'{"run_id": "' + run.encode() + b'"}',
                 b'{"run_id":"' + run.encode() + b'","all":true}',
                 b'{"run_id":"' + run.encode() + b'","run_id":"' + run.encode() + b'"}'):
        status, _ = request("POST", stop_path, body=body)
        assert status == 413, (body, status)
    assert len(calls) == count, "invalid stop body reached Hermes"

    # Run submissions retain their existing larger request allowance.
    status, _ = request("POST", "/v1/runs", body=b'{"input":"hello"}')
    assert status == 200 and calls[-1][2] == b'{"input":"hello"}'
    count = len(calls)
    for upstream_status in (404, 409, 503):
        upstream_body = b'{"error":"upstream-rejected"}'
        status, body = request("POST", stop_path)
        assert status == upstream_status and body == upstream_body
        count += 1
        assert len(calls) == count, "stop was retried"
    oversized_response = True
    upstream_status = 200
    status, body = request("POST", stop_path)
    assert status == 502 and json.loads(body)["error"] == "upstream_response_too_large"
    assert len(calls) == count + 1
    status, body = request("GET", "/steward/v1/negotiation", body=b"", headers=[])
    assert status == 200 and json.loads(body)["adapter_contract"] == "steward.hermes-agent.v2"
finally:
    for server in servers:
        server.shutdown()
        server.server_close()
    for thread in threads:
        thread.join(timeout=2)
`
	command := exec.CommandContext(ctx, python, "-I", "-c", program,
		filepath.Join(hermesAdapterRoot(t), "entrypoint.py"))
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("Hermes stop boundary failed: %v\n%s", err, output)
	}
}
