#!/usr/bin/env bash
# Host-safe, black-box acceptance proof for Steward Control and Executor uplink v3.
set -euo pipefail
umask 077
unset BASH_ENV CDPATH ENV PYTHONHOME PYTHONPATH
export LC_ALL=C

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)
root=$(cd "$script_dir/.." && pwd -P)

command -v python3 >/dev/null 2>&1 || {
	echo "control-acceptance: python3 is required" >&2
	exit 2
}

work=$(mktemp -d "${TMPDIR:-/tmp}/steward-control-acceptance.XXXXXX")
work=$(cd "$work" && pwd -P)
chmod 0700 "$work"
control_pid=
control_url=
keep_failed=${STEWARD_CONTROL_ACCEPTANCE_KEEP_FAILED:-NO}
[[ $keep_failed == YES || $keep_failed == NO ]] || {
	echo "control-acceptance: STEWARD_CONTROL_ACCEPTANCE_KEEP_FAILED must be YES or NO" >&2
	exit 2
}

stop_control() {
	local status=0
	local index
	[[ -n ${control_pid:-} ]] || return 0
	if kill -0 "$control_pid" 2>/dev/null; then
		kill -TERM "$control_pid" 2>/dev/null || true
		index=0
		while (( index < 100 )); do
			kill -0 "$control_pid" 2>/dev/null || break
			sleep 0.05
			((index += 1))
		done
		if kill -0 "$control_pid" 2>/dev/null; then
			kill -KILL "$control_pid" 2>/dev/null || true
			status=1
		fi
	fi
	set +e
	wait "$control_pid" 2>/dev/null
	local wait_status=$?
	set -e
	control_pid=
	if (( wait_status != 0 && wait_status != 143 )); then
		status=1
	fi
	return "$status"
}

cleanup() {
	local status=$?
	trap - EXIT HUP INT TERM
	stop_control || status=1
	if (( status != 0 )) && [[ $keep_failed == YES ]]; then
		echo "control-acceptance: retained owner-only diagnostics at $work" >&2
	else
		rm -rf -- "$work"
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Run a trusted local binary with bounded output and a wall-clock timeout. The
# process gets its own session so a timeout also terminates its descendants.
run_bounded() {
	local seconds=$1
	local directory=$2
	local stdout_path=$3
	local stderr_path=$4
	shift 4
	python3 -I - "$seconds" "$directory" "$stdout_path" "$stderr_path" "$@" <<'PY'
import os
import pathlib
import selectors
import signal
import subprocess
import sys
import time

seconds = float(sys.argv[1])
directory = sys.argv[2]
stdout_path = pathlib.Path(sys.argv[3])
stderr_path = pathlib.Path(sys.argv[4])
command = sys.argv[5:]
limit = 1 << 20

if not (0 < seconds <= 300) or not command:
    raise SystemExit("control-acceptance: invalid bounded-command request")

try:
    process = subprocess.Popen(
        command,
        cwd=directory,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
except OSError as error:
    raise SystemExit(f"control-acceptance: command could not start: {error.strerror}") from None

selector = selectors.DefaultSelector()
buffers = {}
for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
    selector.register(stream, selectors.EVENT_READ, label)
    buffers[label] = bytearray()

deadline = time.monotonic() + seconds
failure = None
while selector.get_map():
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        failure = "command exceeded its timeout"
        break
    for key, _ in selector.select(min(remaining, 0.2)):
        chunk = os.read(key.fileobj.fileno(), 65536)
        if not chunk:
            selector.unregister(key.fileobj)
            key.fileobj.close()
            continue
        target = buffers[key.data]
        target.extend(chunk)
        if len(target) > limit:
            failure = f"command {key.data} exceeded 1 MiB"
            break
    if failure:
        break

if failure:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
else:
    remaining = max(0.1, deadline - time.monotonic())
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired:
        failure = "command exceeded its timeout"
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()

stdout_path.write_bytes(buffers["stdout"])
stderr_path.write_bytes(buffers["stderr"])
if failure:
    raise SystemExit(f"control-acceptance: {failure}")
if process.returncode != 0:
    raise SystemExit(process.returncode if 0 < process.returncode < 126 else 1)
PY
}

control_bin=${STEWARD_CONTROL_BIN:-$work/steward-control}
ctl_bin=${STEWARDCTL_BIN:-$work/stewardctl}
mcp_bin=${STEWARD_MCP_BIN:-$work/steward-mcp}
if [[ ! -x $control_bin || ! -x $ctl_bin || ! -x $mcp_bin ]]; then
	command -v go >/dev/null 2>&1 || {
		echo "control-acceptance: go is required unless all binary paths are provided" >&2
		exit 2
	}
fi
if [[ ! -x $control_bin ]]; then
	run_bounded 180 "$root" "$work/build-control.stdout" "$work/build-control.stderr" \
		go build -o "$control_bin" ./cmd/steward-control
fi
if [[ ! -x $ctl_bin ]]; then
	run_bounded 180 "$root" "$work/build-ctl.stdout" "$work/build-ctl.stderr" \
		go build -o "$ctl_bin" ./cmd/stewardctl
fi
if [[ ! -x $mcp_bin ]]; then
	run_bounded 180 "$root" "$work/build-mcp.stdout" "$work/build-mcp.stderr" \
		go build -o "$mcp_bin" ./cmd/steward-mcp
fi
[[ -x $control_bin && -x $ctl_bin && -x $mcp_bin ]] || {
	echo "control-acceptance: Steward binaries are not executable" >&2
	exit 2
}

state_dir=$work/state
admin_token=$work/site-admin.token
run_bounded 30 "$work" "$work/initialize.stdout" "$work/initialize.stderr" \
	"$control_bin" -initialize -state-dir "$state_dir" -admin-token-file "$admin_token" -addr 127.0.0.1:0

python3 -I - "$work/initialize.stdout" "$work/initialize.stderr" "$admin_token" "$state_dir" <<'PY'
import os
import pathlib
import stat
import sys

stdout_path, stderr_path, token_path, state_path = map(pathlib.Path, sys.argv[1:])
if stdout_path.read_text(encoding="utf-8") != f"{token_path}\n":
    raise SystemExit("control-acceptance: initialization disclosed data instead of only the token path")
if stderr_path.read_bytes():
    raise SystemExit("control-acceptance: initialization wrote unexpected diagnostics")
token = token_path.read_bytes()
if not (16 <= len(token.rstrip(b"\n")) <= 4096) or token.count(b"\n") != 1 or not token.endswith(b"\n"):
    raise SystemExit("control-acceptance: bootstrap token file is malformed")
for path, expected_type, expected_mode in (
    (token_path, "file", 0o600),
    (state_path, "directory", 0o700),
    (state_path / "auth.key", "file", 0o600),
    (state_path / "witness.private.pem", "file", 0o600),
    (state_path / "witness.public.pem", "file", 0o644),
):
    metadata = path.lstat()
    if stat.S_ISLNK(metadata.st_mode):
        raise SystemExit(f"control-acceptance: sensitive {expected_type} is a symlink")
    type_ok = stat.S_ISREG(metadata.st_mode) if expected_type == "file" else stat.S_ISDIR(metadata.st_mode)
    if not type_ok or stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise SystemExit(f"control-acceptance: sensitive {expected_type} has unsafe type or mode")
if token_path.read_bytes().rstrip(b"\n") in stdout_path.read_bytes() + stderr_path.read_bytes():
    raise SystemExit("control-acceptance: bootstrap bearer reached process output")
PY

# Preserve the controller witness identity outside mutable controller state before
# the service first starts. Later verification must use this pinned copy, including
# after a restart, so a replaced controller key cannot authorize its own exports.
pinned_witness=$work/pinned-witness.public.pem
python3 -I - "$state_dir/witness.public.pem" "$pinned_witness" <<'PY'
import os
import pathlib
import stat
import sys

source = pathlib.Path(sys.argv[1])
destination = pathlib.Path(sys.argv[2])
metadata = source.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("control-acceptance: witness trust source is not a regular file")
raw = source.read_bytes()
if not raw or len(raw) > 1 << 20:
    raise SystemExit("control-acceptance: witness trust source is empty or oversized")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(destination, flags, 0o600)
try:
    written = 0
    while written < len(raw):
        count = os.write(descriptor, raw[written:])
        if count <= 0:
            raise SystemExit("control-acceptance: pinned witness copy was incomplete")
        written += count
    os.fsync(descriptor)
finally:
    os.close(descriptor)
if destination.read_bytes() != raw or stat.S_IMODE(destination.lstat().st_mode) != 0o600:
    raise SystemExit("control-acceptance: pinned witness copy is not exact and owner-only")
PY

extract_address() {
	python3 -I - "$1" <<'PY'
import ipaddress
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
raw = path.read_bytes()
if len(raw) > 1 << 20:
    raise SystemExit(1)
for line in raw.splitlines():
    try:
        record = json.loads(line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        continue
    if record.get("msg") != "Steward Control listening" or record.get("tls") is not False:
        continue
    address = record.get("address", "")
    host, separator, port_text = address.rpartition(":")
    if separator and host == "127.0.0.1" and ipaddress.ip_address(host).is_loopback:
        try:
            port = int(port_text)
        except ValueError:
            continue
        if 0 < port < 65536:
            print(address)
            raise SystemExit(0)
raise SystemExit(1)
PY
}

start_control() {
	local label=$1
	shift
	local address=
	local index
	"$control_bin" -state-dir "$state_dir" -addr 127.0.0.1:0 -delivery-lease 1m \
		"$@" \
		>"$work/$label.stdout" 2>"$work/$label.stderr" &
	control_pid=$!
	index=0
	while (( index < 100 )); do
		if ! kill -0 "$control_pid" 2>/dev/null; then
			echo "control-acceptance: controller exited during $label startup" >&2
			return 1
		fi
		if [[ -s $work/$label.stderr ]] && address=$(extract_address "$work/$label.stderr" 2>/dev/null); then
			break
		fi
		sleep 0.05
		((index += 1))
	done
	[[ -n $address ]] || {
		echo "control-acceptance: controller did not publish a bounded loopback address" >&2
		return 1
	}
	control_url=http://$address
}

# Run one bounded MCP stdio session. Requests and both outputs are regular
# files so bearer paths, protocol output, and diagnostics can be audited after
# the child exits.
run_mcp_session() {
	local request_path=$1
	local stdout_path=$2
	local stderr_path=$3
	shift 3
	python3 -I - "$request_path" "$stdout_path" "$stderr_path" "$@" <<'PY'
import os
import pathlib
import signal
import subprocess
import sys

request_path, stdout_path, stderr_path = map(pathlib.Path, sys.argv[1:4])
command = sys.argv[4:]
limit = 1 << 20
request = request_path.read_bytes()
if not request or len(request) > limit or not command:
    raise SystemExit("control-acceptance: invalid MCP session request")
try:
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
        close_fds=True,
    )
except OSError as error:
    raise SystemExit(f"control-acceptance: MCP process could not start: {error.strerror}") from None
try:
    stdout, stderr = process.communicate(request, timeout=30)
except subprocess.TimeoutExpired:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        stdout, stderr = process.communicate(timeout=2)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        stdout, stderr = process.communicate()
    raise SystemExit("control-acceptance: MCP session exceeded its timeout") from None
stdout_path.write_bytes(stdout)
stderr_path.write_bytes(stderr)
if len(stdout) > limit or len(stderr) > limit:
    raise SystemExit("control-acceptance: MCP session output exceeded 1 MiB")
if process.returncode != 0:
    raise SystemExit(process.returncode if 0 < process.returncode < 126 else 1)
PY
}

# Perform one bounded JSON HTTP exchange without proxies or redirects. TOKEN_KIND
# is none, raw, or json; json reads the node credential's credential member.
http_json() {
	local method=$1
	local path=$2
	local body_path=$3
	local token_kind=$4
	local token_path=$5
	local expected_status=$6
	local output_path=$7
	python3 -I - "$control_url$path" "$method" "$body_path" "$token_kind" "$token_path" \
		"$expected_status" >"$output_path" <<'PY'
import json
import pathlib
import sys
import urllib.error
import urllib.request

url, method, body_path, token_kind, token_path, expected_text = sys.argv[1:]
expected = int(expected_text)
limit = 1 << 20

if method not in {"GET", "POST", "DELETE"} or not url.startswith("http://127.0.0.1:"):
    raise SystemExit("control-acceptance: unsafe HTTP request")
if body_path:
    body = pathlib.Path(body_path).read_bytes()
    if not body or len(body) > limit:
        raise SystemExit("control-acceptance: request body is empty or exceeds 1 MiB")
    json.loads(body)
else:
    body = None

token = ""
if token_kind == "raw":
    token = pathlib.Path(token_path).read_text(encoding="utf-8").strip()
elif token_kind == "json":
    token = json.loads(pathlib.Path(token_path).read_text(encoding="utf-8")).get("credential", "")
elif token_kind != "none":
    raise SystemExit("control-acceptance: unknown token kind")
if token and (len(token) > 4096 or any(character.isspace() for character in token)):
    raise SystemExit("control-acceptance: bearer file is invalid")

request = urllib.request.Request(url, data=body, method=method)
request.add_header("Accept", "application/json")
if body is not None:
    request.add_header("Content-Type", "application/json")
if token:
    request.add_header("Authorization", f"Bearer {token}")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    response = opener.open(request, timeout=5)
except urllib.error.HTTPError as error:
    response = error
except OSError as error:
    raise SystemExit(f"control-acceptance: HTTP exchange failed: {error.__class__.__name__}") from None

with response:
    status = response.status
    content_type = response.headers.get_content_type()
    raw = response.read(limit + 1)
if status != expected:
    raise SystemExit(f"control-acceptance: HTTP status {status}, expected {expected}")
if len(raw) > limit:
    raise SystemExit("control-acceptance: HTTP response exceeds 1 MiB")
if content_type != "application/json":
    raise SystemExit("control-acceptance: HTTP response is not application/json")
try:
    value = json.loads(raw)
except (UnicodeDecodeError, json.JSONDecodeError):
    raise SystemExit("control-acceptance: HTTP response is invalid JSON") from None
if not isinstance(value, dict):
    raise SystemExit("control-acceptance: HTTP response is not one JSON object")
sys.stdout.buffer.write(raw)
PY
}

# Perform one authenticated metrics exchange without proxies or redirects and
# preserve only its bounded Prometheus text body.
http_metrics() {
	local path=$1
	local token_path=$2
	local output_path=$3
	python3 -I - "$control_url$path" "$token_path" >"$output_path" <<'PY'
import pathlib
import sys
import urllib.error
import urllib.request

url, token_path = sys.argv[1:]
limit = 1 << 20
if not url.startswith("http://127.0.0.1:"):
    raise SystemExit("control-acceptance: unsafe metrics request")
token = pathlib.Path(token_path).read_text(encoding="utf-8").strip()
if not token or len(token) > 4096 or any(character.isspace() for character in token):
    raise SystemExit("control-acceptance: metrics bearer file is invalid")
request = urllib.request.Request(url, method="GET")
request.add_header("Accept", "text/plain")
request.add_header("Authorization", f"Bearer {token}")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None

opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
try:
    response = opener.open(request, timeout=5)
except urllib.error.HTTPError as error:
    raise SystemExit(f"control-acceptance: metrics HTTP status {error.code}, expected 200") from None
except OSError as error:
    raise SystemExit(f"control-acceptance: metrics exchange failed: {error.__class__.__name__}") from None
with response:
    content_type = response.headers.get("Content-Type", "")
    cache_control = response.headers.get("Cache-Control", "")
    content_options = response.headers.get("X-Content-Type-Options", "")
    raw = response.read(limit + 1)
if response.status != 200:
    raise SystemExit(f"control-acceptance: metrics HTTP status {response.status}, expected 200")
if content_type != "text/plain; version=0.0.4; charset=utf-8":
    raise SystemExit("control-acceptance: metrics content type is not the fixed Prometheus format")
if cache_control != "no-store" or content_options != "nosniff":
    raise SystemExit("control-acceptance: metrics response omitted defensive headers")
if not raw or len(raw) > limit:
    raise SystemExit("control-acceptance: metrics response is empty or exceeds 1 MiB")
sys.stdout.buffer.write(raw)
PY
}

assert_owner_file() {
	python3 -I - "$1" <<'PY'
import pathlib
import stat
import sys

metadata = pathlib.Path(sys.argv[1]).lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != 0o600:
    raise SystemExit("control-acceptance: secret-bearing output is not an owner-only regular file")
PY
}

assert_secret_absent() {
	local kind=$1
	local secret_path=$2
	shift 2
	python3 -I - "$kind" "$secret_path" "$@" <<'PY'
import json
import pathlib
import sys

kind, secret_path, *targets = sys.argv[1:]
raw = pathlib.Path(secret_path).read_bytes()
if len(raw) > 65536:
    raise SystemExit("control-acceptance: secret source exceeds 64 KiB")
if kind == "raw":
    secret = raw.strip()
elif kind in {"enrollment_token", "credential"}:
    secret = json.loads(raw)[kind].encode("utf-8")
else:
    raise SystemExit("control-acceptance: unknown secret field")
if len(secret) < 16:
    raise SystemExit("control-acceptance: secret is unexpectedly short")
for target in targets:
    contents = pathlib.Path(target).read_bytes()
    if len(contents) > 1 << 20:
        raise SystemExit("control-acceptance: diagnostic output exceeds 1 MiB")
    if secret in contents:
        raise SystemExit("control-acceptance: bearer secret reached process output")
PY
}

start_control control-first -node-stale-after=1ns
http_json GET /v1/healthz "" none "" 200 "$work/health.json"
http_json GET /v1/readiness "" none "" 200 "$work/readiness.json"
http_json GET /metrics "" none "" 404 "$work/metrics-disabled.json"
python3 -I - "$work/health.json" "$work/readiness.json" "$work/metrics-disabled.json" <<'PY'
import json
import pathlib
import sys
if json.loads(pathlib.Path(sys.argv[1]).read_text()) != {"status": "ok"}:
    raise SystemExit("control-acceptance: health response is invalid")
if json.loads(pathlib.Path(sys.argv[2]).read_text()) != {"status": "ready"}:
    raise SystemExit("control-acceptance: readiness response is invalid")
disabled = json.loads(pathlib.Path(sys.argv[3]).read_text())
if disabled.get("error") != "not_found" or not disabled.get("message"):
    raise SystemExit("control-acceptance: metrics were not absent before explicit opt-in")
PY

tenant_id=acceptance-tenant
other_tenant_id=acceptance-other
node_id=acceptance-node
pool_id=acceptance-pool
command_id=acceptance-command
instance_id=acceptance-instance

run_bounded 30 "$work" "$work/tenant.stdout" "$work/tenant.stderr" \
	"$ctl_bin" control tenant create -control-url "$control_url" -token-file "$admin_token" -tenant-id "$tenant_id"
run_bounded 30 "$work" "$work/other-tenant.stdout" "$work/other-tenant.stderr" \
	"$ctl_bin" control tenant create -control-url "$control_url" -token-file "$admin_token" -tenant-id "$other_tenant_id"
python3 -I - "$work/tenant.stdout" "$tenant_id" "$work/other-tenant.stdout" "$other_tenant_id" <<'PY'
import json
import pathlib
import sys
for path, wanted in ((sys.argv[1], sys.argv[2]), (sys.argv[3], sys.argv[4])):
    value = json.loads(pathlib.Path(path).read_text())
    if value.get("tenant_id") != wanted or value.get("state") != "active":
        raise SystemExit("control-acceptance: tenant creation response is invalid")
PY

operator_token=$work/tenant-operator.token
run_bounded 30 "$work" "$work/operator.stdout" "$work/operator.stderr" \
	"$ctl_bin" control operator issue -control-url "$control_url" -token-file "$admin_token" \
	-request-id acceptance-operator-request -role tenant_operator -tenant-id "$tenant_id" -token-out "$operator_token"
assert_owner_file "$operator_token"
assert_secret_absent raw "$admin_token" "$work/tenant.stdout" "$work/tenant.stderr" \
	"$work/other-tenant.stdout" "$work/other-tenant.stderr" "$work/operator.stdout" "$work/operator.stderr"
assert_secret_absent raw "$operator_token" "$work/operator.stdout" "$work/operator.stderr"

# A tenant-scoped bearer must not reveal whether another tenant exists.
http_json GET "/v1/tenants/$other_tenant_id" "" raw "$operator_token" 404 "$work/cross-tenant.json"
python3 -I - "$work/cross-tenant.json" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value.get("error") != "not_found" or not value.get("message"):
    raise SystemExit("control-acceptance: tenant isolation error is invalid")
PY

# An unrelated bearer is rejected before it can enumerate controller state.
printf '%s\n' 'acceptance-invalid-bearer-value' >"$work/invalid.token"
http_json GET /v1/tenants "" raw "$work/invalid.token" 401 "$work/invalid-auth.json"
python3 -I - "$work/invalid-auth.json" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value.get("error") != "unauthorized" or not value.get("message"):
    raise SystemExit("control-acceptance: authentication error is invalid")
PY

enrollment=$work/enrollment.json
enrollment_retry=$work/enrollment-retry.json
run_bounded 30 "$work" "$work/enrollment.stdout" "$work/enrollment.stderr" \
	"$ctl_bin" control enrollment create -control-url "$control_url" -token-file "$operator_token" \
	-request-id acceptance-node-enrollment -node-id "$node_id" -tenant-ids "$tenant_id" -valid-for 5m -out "$enrollment"
run_bounded 30 "$work" "$work/enrollment-retry.stdout" "$work/enrollment-retry.stderr" \
	"$ctl_bin" control enrollment create -control-url "$control_url" -token-file "$operator_token" \
	-request-id acceptance-node-enrollment -node-id "$node_id" -tenant-ids "$tenant_id" -valid-for 5m -out "$enrollment_retry"
assert_owner_file "$enrollment"
assert_owner_file "$enrollment_retry"
cmp -s "$enrollment" "$enrollment_retry" || {
	echo "control-acceptance: exact enrollment issuance retry changed the capability" >&2
	exit 1
}
assert_secret_absent enrollment_token "$enrollment" "$work/enrollment.stdout" "$work/enrollment.stderr"

evidence_private=$work/executor-evidence.private
evidence_public=$work/executor-evidence.public
run_bounded 30 "$work" "$work/evidence-keygen.stdout" "$work/evidence-keygen.stderr" \
	"$ctl_bin" keygen -key-id acceptance-executor-evidence -private-out "$evidence_private" \
	-public-out "$evidence_public"
assert_owner_file "$evidence_private"

node_credential=$work/node-credential.json
node_credential_retry=$work/node-credential-retry.json
evidence_config=$work/executor-evidence.env
evidence_config_retry=$work/executor-evidence-retry.env
run_bounded 30 "$work" "$work/exchange.stdout" "$work/exchange.stderr" \
	"$ctl_bin" control enrollment exchange -control-url "$control_url" -enrollment "$enrollment" \
	-request-id acceptance-node-exchange -executor-evidence-private-key "$evidence_private" \
	-credential-out "$node_credential" -executor-evidence-config-out "$evidence_config"
run_bounded 30 "$work" "$work/exchange-retry.stdout" "$work/exchange-retry.stderr" \
	"$ctl_bin" control enrollment exchange -control-url "$control_url" -enrollment "$enrollment" \
	-request-id acceptance-node-exchange -executor-evidence-private-key "$evidence_private" \
	-credential-out "$node_credential_retry" -executor-evidence-config-out "$evidence_config_retry"
assert_owner_file "$node_credential"
assert_owner_file "$node_credential_retry"
assert_owner_file "$evidence_config"
assert_owner_file "$evidence_config_retry"
cmp -s "$node_credential" "$node_credential_retry" || {
	echo "control-acceptance: deterministic enrollment retry changed the node credential" >&2
	exit 1
}
cmp -s "$evidence_config" "$evidence_config_retry" || {
	echo "control-acceptance: deterministic enrollment retry changed the evidence config" >&2
	exit 1
}
python3 -I - "$node_credential" "$node_id" "$work/exchange.stdout" "$work/exchange-retry.stdout" <<'PY'
import json
import pathlib
import re
import sys
credential = json.loads(pathlib.Path(sys.argv[1]).read_text())
if credential.get("version") != 2 or credential.get("scope") != "node" or credential.get("node_id") != sys.argv[2]:
    raise SystemExit("control-acceptance: node credential is invalid")
token = credential.get("credential", "")
match = re.fullmatch(r"steward_node_v1_(node-cred-[a-f0-9]{32})_[A-Za-z0-9_-]{43}", token)
if match is None:
    raise SystemExit("control-acceptance: node credential omits its revocation identity")
credential_id = match.group(1)
if pathlib.Path(sys.argv[3]).read_text() != f"{credential_id}\n" or pathlib.Path(sys.argv[4]).read_text() != f"{credential_id}\n":
    raise SystemExit("control-acceptance: enrollment exchange did not return only the credential ID")
PY
node_credential_id=$(tr -d '\n' <"$work/exchange.stdout")
[[ $node_credential_id =~ ^node-cred-[a-f0-9]{32}$ ]] || {
	echo "control-acceptance: enrollment exchange returned an invalid credential ID" >&2
	exit 1
}
assert_secret_absent credential "$node_credential" "$work/exchange.stdout" "$work/exchange.stderr" \
	"$work/exchange-retry.stdout" "$work/exchange-retry.stderr"

# The capability is one-time: only the original request identity may recover
# the deterministically derived node credential.
set +e
run_bounded 30 "$work" "$work/exchange-replay.stdout" "$work/exchange-replay.stderr" \
	"$ctl_bin" control enrollment exchange -control-url "$control_url" -enrollment "$enrollment" \
	-request-id acceptance-different-exchange -executor-evidence-private-key "$evidence_private" \
	-credential-out "$work/replayed-node-credential.json" \
	-executor-evidence-config-out "$work/replayed-executor-evidence.env"
replay_status=$?
set -e
if (( replay_status == 0 )) || [[ -e $work/replayed-node-credential.json ||
	-e $work/replayed-executor-evidence.env ]]; then
	echo "control-acceptance: consumed enrollment accepted a different replay identity" >&2
	exit 1
fi
assert_secret_absent enrollment_token "$enrollment" "$work/exchange-replay.stdout" "$work/exchange-replay.stderr"

run_bounded 30 "$work" "$work/node-status.stdout" "$work/node-status.stderr" \
	"$ctl_bin" control node status -control-url "$control_url" -token-file "$operator_token" \
	-tenant-id "$tenant_id" -node-id "$node_id"
python3 -I - "$work/node-status.stdout" "$node_id" "$tenant_id" <<'PY'
import json
import pathlib
import sys
node = json.loads(pathlib.Path(sys.argv[1]).read_text())
if node.get("node_id") != sys.argv[2] or node.get("tenant_ids") != [sys.argv[3]] or node.get("state") != "active":
    raise SystemExit("control-acceptance: enrolled node inventory is invalid")
PY

# NodePool capacity is site authority, not tenant or workload authority. Create
# a durable intent before the node advertises membership, prove idempotent and
# optimistic revision handling, and leave the pool in revision 2 so restart
# recovery can be verified against an exact retained value.
pool_membership_private=$work/pool-membership.private
pool_membership_public=$work/pool-membership.public
run_bounded 30 "$work" "$work/pool-membership-keygen.stdout" "$work/pool-membership-keygen.stderr" \
	"$ctl_bin" keygen -key-id acceptance-pool-authority -private-out "$pool_membership_private" \
	-public-out "$pool_membership_public"
assert_owner_file "$pool_membership_private"
run_bounded 30 "$work" "$work/node-pool-create.stdout" "$work/node-pool-create.stderr" \
	"$ctl_bin" control node-pool apply -control-url "$control_url" -token-file "$admin_token" \
	-pool-id "$pool_id" -tenant-ids "$tenant_id" -architecture amd64 \
	-min-nodes 1 -desired-nodes 2 -max-nodes 3 \
	-membership-key-id acceptance-pool-authority -membership-public-key "$pool_membership_public"
run_bounded 30 "$work" "$work/node-pool-retry.stdout" "$work/node-pool-retry.stderr" \
	"$ctl_bin" control node-pool apply -control-url "$control_url" -token-file "$admin_token" \
	-pool-id "$pool_id" -tenant-ids "$tenant_id" -architecture amd64 \
	-min-nodes 1 -desired-nodes 2 -max-nodes 3 -revision 1 \
	-membership-key-id acceptance-pool-authority -membership-public-key "$pool_membership_public"
python3 -I - "$work/node-pool-create.stdout" "$work/node-pool-retry.stdout" \
	"$pool_id" "$tenant_id" <<'PY'
import json
import pathlib
import sys

for path in sys.argv[1:3]:
    status = json.loads(pathlib.Path(path).read_text())
    pool = status.get("pool", {})
    if pool.get("id") != sys.argv[3] or pool.get("tenant_ids") != [sys.argv[4]] or \
            pool.get("architecture") != "amd64" or pool.get("revision") != 1 or \
            pool.get("membership_generation") != 1 or \
            pool.get("membership_key_id") != "acceptance-pool-authority":
        raise SystemExit("control-acceptance: node-pool creation or idempotent retry changed intent")
    if status.get("registered_nodes") != 0 or status.get("ready_nodes") != 0 or \
            status.get("scale_out_needed") != 2 or status.get("scale_in_candidates") != [] or \
            status.get("conditions") != ["capacity_shortfall"]:
        raise SystemExit("control-acceptance: empty node-pool capacity observation is invalid")
PY

set +e
run_bounded 30 "$work" "$work/node-pool-tenant-denied.stdout" \
	"$work/node-pool-tenant-denied.stderr" "$ctl_bin" control node-pool list \
	-control-url "$control_url" -token-file "$operator_token"
node_pool_tenant_status=$?
set -e
if (( node_pool_tenant_status == 0 )) || [[ -s $work/node-pool-tenant-denied.stdout ]]; then
	echo "control-acceptance: tenant operator gained site node-pool visibility" >&2
	exit 1
fi

run_bounded 30 "$work" "$work/node-pool-update.stdout" "$work/node-pool-update.stderr" \
	"$ctl_bin" control node-pool apply -control-url "$control_url" -token-file "$admin_token" \
	-pool-id "$pool_id" -tenant-ids "$tenant_id" -architecture amd64 \
	-min-nodes 1 -desired-nodes 3 -max-nodes 3 -revision 1 \
	-membership-key-id acceptance-pool-authority -membership-public-key "$pool_membership_public"
set +e
run_bounded 30 "$work" "$work/node-pool-stale.stdout" "$work/node-pool-stale.stderr" \
	"$ctl_bin" control node-pool apply -control-url "$control_url" -token-file "$admin_token" \
	-pool-id "$pool_id" -tenant-ids "$tenant_id" -architecture amd64 \
	-min-nodes 1 -desired-nodes 2 -max-nodes 3 -revision 1 \
	-membership-key-id acceptance-pool-authority -membership-public-key "$pool_membership_public"
node_pool_stale_status=$?
set -e
if (( node_pool_stale_status == 0 )) || [[ -s $work/node-pool-stale.stdout ]]; then
	echo "control-acceptance: stale node-pool writer changed retained capacity" >&2
	exit 1
fi
python3 -I - "$work/node-pool-update.stdout" "$pool_id" <<'PY'
import json
import pathlib
import sys

status = json.loads(pathlib.Path(sys.argv[1]).read_text())
pool = status.get("pool", {})
if pool.get("id") != sys.argv[2] or pool.get("revision") != 2 or pool.get("membership_generation") != 1 or \
        pool.get("desired_nodes") != 3 or \
        status.get("registered_nodes") != 0 or status.get("scale_out_needed") != 3:
    raise SystemExit("control-acceptance: revised node-pool capacity is invalid")
PY

# The operations surface is authenticated, tenant projected, query strict, and
# metadata only. Exercise both its HTTP contract and the human-facing CLI
# before the node has polled so the node_never_seen finding is deterministic.
for route in /v1/operations/summary /v1/operations/attention \
	/v1/operations/timeline /v1/operations/commands /v1/operations/credentials; do
	safe_name=${route##*/}
	http_json GET "$route" "" none "" 401 "$work/operations-$safe_name-unauthorized.json"
done
run_bounded 30 "$work" "$work/operations-status.stdout" "$work/operations-status.stderr" \
	"$ctl_bin" control operations status -control-url "$control_url" -token-file "$operator_token"
http_json GET "/v1/operations/summary?tenant_id=$tenant_id" "" raw "$admin_token" 200 \
	"$work/operations-summary-admin.json"
python3 -I - "$work/operations-status.stdout" "$work/operations-summary-admin.json" \
	"$tenant_id" "$node_id" <<'PY'
import json
import pathlib
import sys

def object_keys(value):
    if isinstance(value, dict):
        for key, child in value.items():
            yield key
            yield from object_keys(child)
    elif isinstance(value, list):
        for child in value:
            yield from object_keys(child)

for path in sys.argv[1:3]:
    summary = json.loads(pathlib.Path(path).read_text())
    if summary.get("tenant_id") != sys.argv[3] or not summary.get("generated_at"):
        raise SystemExit("control-acceptance: operations summary did not retain tenant scope")
    capacity = summary.get("capacity")
    if not isinstance(capacity, list) or {entry.get("resource") for entry in capacity} != {
        "nodes", "credentials", "enrollments", "commands",
    }:
        raise SystemExit("control-acceptance: tenant operations capacity inventory is incomplete")
    if summary.get("evidence", {}).get("nodes") != 1:
        raise SystemExit("control-acceptance: tenant operations evidence count is invalid")
    if summary.get("commands", {}).get("total") != 0:
        raise SystemExit("control-acceptance: operations summary counted a command before submission")
    if summary.get("attention", {}).get("total", 0) < 1:
        raise SystemExit("control-acceptance: operations summary omitted derived attention")
    raw = pathlib.Path(path).read_text()
    if sys.argv[4] in raw:
        raise SystemExit("control-acceptance: operations summary exposed a node identity")
    forbidden = {"credential", "token", "command_dsse", "payload", "result"}
    leaked = forbidden.intersection(object_keys(summary))
    if leaked:
        raise SystemExit(f"control-acceptance: operations summary exposed {sorted(leaked)}")
PY

for route in \
	"/v1/operations/summary?tenant_id=$other_tenant_id" \
	"/v1/operations/attention?tenant_id=$other_tenant_id" \
	"/v1/operations/timeline?tenant_id=$other_tenant_id" \
	"/v1/operations/commands?tenant_id=$other_tenant_id" \
	"/v1/operations/credentials?tenant_id=$other_tenant_id"; do
	safe_name=$(printf '%s' "$route" | tr '/?=&' '-----')
	http_json GET "$route" "" raw "$operator_token" 404 "$work/$safe_name.json"
done

for route in \
	"/v1/operations/summary?unexpected=1" \
	"/v1/operations/summary?tenant_id=$tenant_id&tenant_id=$tenant_id" \
	"/v1/operations/attention?reason=" \
	"/v1/operations/attention?reason=not_a_reason" \
	"/v1/operations/attention?limit=01" \
	"/v1/operations/timeline?kind=unknown" \
	"/v1/operations/timeline?severity=urgent" \
	"/v1/operations/commands?state=unknown" \
	"/v1/operations/commands?cursor=a&cursor=b" \
	"/v1/operations/credentials?revoked=1" \
	"/v1/operations/credentials?kind=unknown"; do
	safe_name=$(printf '%s' "$route" | tr '/?=&' '-----')
	http_json GET "$route" "" raw "$admin_token" 400 "$work/$safe_name.json"
done

run_bounded 30 "$work" "$work/attention-never-seen.stdout" "$work/attention-never-seen.stderr" \
	"$ctl_bin" control attention list -control-url "$control_url" -token-file "$operator_token" \
	-reason node_never_seen -limit 1
run_bounded 30 "$work" "$work/credentials-first.stdout" "$work/credentials-first.stderr" \
	"$ctl_bin" control credential list -control-url "$control_url" -token-file "$operator_token" \
	-revoked false -limit 1
credential_cursor=$(python3 -I - "$work/attention-never-seen.stdout" \
	"$work/credentials-first.stdout" "$tenant_id" "$node_id" <<'PY'
import base64
import json
import pathlib
import sys

attention = json.loads(pathlib.Path(sys.argv[1]).read_text())
if len(attention.get("items", [])) != 1:
    raise SystemExit("control-acceptance: filtered attention page is not exactly bounded")
item = attention["items"][0]
if item.get("reason") != "node_never_seen" or item.get("tenant_id") != sys.argv[3] or item.get("node_id") != sys.argv[4]:
    raise SystemExit("control-acceptance: node-never-seen attention fact is invalid")
credentials = json.loads(pathlib.Path(sys.argv[2]).read_text())
if len(credentials.get("credentials", [])) != 1:
    raise SystemExit("control-acceptance: first credential page is not exactly bounded")
cursor = credentials.get("next_cursor", "")
try:
    decoded = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4))
except ValueError:
    raise SystemExit("control-acceptance: credential continuation cursor is invalid base64url") from None
canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode()
if not cursor or canonical != cursor or len(decoded) <= 33 or decoded[0] != 1:
    raise SystemExit("control-acceptance: credential continuation cursor is not canonical and versioned")
print(cursor)
PY
)
run_bounded 30 "$work" "$work/credentials-second.stdout" "$work/credentials-second.stderr" \
	"$ctl_bin" control credential list -control-url "$control_url" -token-file "$operator_token" \
	-revoked false -cursor "$credential_cursor" -limit 1
python3 -I - "$work/credentials-first.stdout" "$work/credentials-second.stdout" \
	"$tenant_id" "$node_id" "$node_credential" "$admin_token" "$operator_token" <<'PY'
import json
import pathlib
import sys

pages = [json.loads(pathlib.Path(path).read_text()) for path in sys.argv[1:3]]
records = [record for page in pages for record in page.get("credentials", [])]
if len(records) != 2 or len({record.get("id") for record in records}) != 2:
    raise SystemExit("control-acceptance: credential cursor repeated or skipped visible metadata")
if pages[1].get("next_cursor"):
    raise SystemExit("control-acceptance: final credential page retained a continuation cursor")
kinds = {record.get("kind") for record in records}
if kinds != {"operator", "node"}:
    raise SystemExit("control-acceptance: tenant credential inventory returned the wrong kinds")
node_records = [record for record in records if record.get("kind") == "node"]
if len(node_records) != 1 or node_records[0].get("tenant_ids") != [sys.argv[3]] or node_records[0].get("node_id") != sys.argv[4]:
    raise SystemExit("control-acceptance: tenant credential projection crossed its scope")
raw = b"".join(pathlib.Path(path).read_bytes() for path in sys.argv[1:3])
node_secret = json.loads(pathlib.Path(sys.argv[5]).read_text())["credential"].encode()
for secret_path in sys.argv[6:8]:
    if pathlib.Path(secret_path).read_bytes().strip() in raw:
        raise SystemExit("control-acceptance: credential inventory disclosed an operator bearer")
if node_secret in raw:
    raise SystemExit("control-acceptance: credential inventory disclosed a node bearer")
for forbidden in (b'"credential":', b'"token"', b'"token_mac"', b'"mac"'):
    if forbidden in raw:
        raise SystemExit("control-acceptance: credential inventory exposed secret-bearing fields")
PY

# The site authority can inspect the independently retained receipt checkpoint,
# export it under the dedicated witness key, and verify it without contacting
# the controller. A tenant-scoped operator cannot read this cross-tenant view.
run_bounded 30 "$work" "$work/evidence-status.stdout" "$work/evidence-status.stderr" \
	"$ctl_bin" control evidence status -control-url "$control_url" -token-file "$admin_token" \
	-node-id "$node_id"
python3 -I - "$work/evidence-status.stdout" "$node_id" "$enrollment" "$evidence_public" \
	"$evidence_config" <<'PY'
import base64
import hashlib
import json
import pathlib
import re
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())
node_id = sys.argv[2]
enrollment = json.loads(pathlib.Path(sys.argv[3]).read_text())
public_text = pathlib.Path(sys.argv[4]).read_text(encoding="utf-8").strip()
try:
    public = base64.b64decode(public_text, validate=True)
except ValueError:
    raise SystemExit("control-acceptance: generated evidence public key is not canonical base64") from None
if len(public) != 32 or base64.b64encode(public).decode("ascii") != public_text:
    raise SystemExit("control-acceptance: generated evidence public key is not canonical Ed25519")
public_digest = "sha256:" + hashlib.sha256(public).hexdigest()

config = {}
for line in pathlib.Path(sys.argv[5]).read_text(encoding="utf-8").splitlines():
    name, separator, content = line.partition("=")
    if not separator or not name or name in config:
        raise SystemExit("control-acceptance: evidence handoff config is ambiguous")
    config[name] = content
expected_config_keys = {
    "STEWARD_EXECUTOR_EVIDENCE_CONFIG_VERSION",
    "STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID",
    "STEWARD_EXECUTOR_EVIDENCE_NODE_ID",
    "STEWARD_EXECUTOR_EVIDENCE_RECEIPT_EPOCH",
    "STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_BASE64",
}
if set(config) != expected_config_keys:
    raise SystemExit("control-acceptance: evidence handoff config fields are incomplete")

status = value.get("status", {})
head = status.get("head", {})
claim = value.get("identity_proof", {}).get("claim", {})
controller_id = enrollment.get("controller_instance_id")
if value.get("protocol_version") != 1 or value.get("control_node_id") != node_id:
    raise SystemExit("control-acceptance: online evidence inspection identity is invalid")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", controller_id or "") or \
        value.get("controller_instance_id") != controller_id:
    raise SystemExit("control-acceptance: online evidence inspection omits the controller identity")
expected_claim = {
    "protocol_version": 1,
    "controller_instance_id": controller_id,
    "enrollment_id": enrollment.get("enrollment_id"),
    "control_node_id": node_id,
    "stream": "executor",
    "receipt_node_id": node_id,
    "receipt_epoch": 1,
    "public_key_base64": public_text,
    "public_key_sha256": public_digest,
}
for field, expected in expected_claim.items():
    if claim.get(field) != expected:
        raise SystemExit(f"control-acceptance: enrolled evidence claim changed {field}")
if config != {
    "STEWARD_EXECUTOR_EVIDENCE_CONFIG_VERSION": "1",
    "STEWARD_EXECUTOR_EVIDENCE_CONTROLLER_INSTANCE_ID": controller_id,
    "STEWARD_EXECUTOR_EVIDENCE_NODE_ID": node_id,
    "STEWARD_EXECUTOR_EVIDENCE_RECEIPT_EPOCH": "1",
    "STEWARD_EXECUTOR_EVIDENCE_PUBLIC_KEY_BASE64": public_text,
}:
    raise SystemExit("control-acceptance: Executor evidence handoff differs from the enrolled claim")
expected_head = {
    "stream": claim.get("stream"),
    "receipt_node_id": claim.get("receipt_node_id"),
    "receipt_epoch": claim.get("receipt_epoch"),
    "sequence": 0,
    "chain_hash": "sha256:" + "0" * 64,
    "public_key_sha256": claim.get("public_key_sha256"),
}
for field, expected in expected_head.items():
    if head.get(field) != expected:
        raise SystemExit(f"control-acceptance: witnessed genesis changed {field}")
if claim.get("control_node_id") != node_id or claim.get("receipt_node_id") != node_id:
    raise SystemExit("control-acceptance: online evidence inspection changed the enrolled receipt identity")
if status.get("state") != "current" or head.get("sequence") != 0:
    raise SystemExit("control-acceptance: new node does not expose its witnessed genesis checkpoint")
if not status.get("witnessed_at"):
    raise SystemExit("control-acceptance: witnessed genesis coordinate is invalid")
PY

http_json GET "/v1/nodes/$node_id/evidence" "" raw "$operator_token" 403 \
	"$work/evidence-tenant-denied.json"
http_json GET "/v1/nodes/$node_id/evidence/export" "" raw "$operator_token" 403 \
	"$work/evidence-export-tenant-denied.json"
python3 -I - "$work/evidence-tenant-denied.json" "$work/evidence-export-tenant-denied.json" <<'PY'
import json
import pathlib
import sys
for path in sys.argv[1:]:
    value = json.loads(pathlib.Path(path).read_text())
    if value.get("error") != "forbidden" or not value.get("message"):
        raise SystemExit("control-acceptance: evidence endpoint did not return the stable forbidden error")
PY

tenant_denied_export=$work/tenant-denied-evidence-witness.json
set +e
run_bounded 30 "$work" "$work/evidence-export-tenant-cli.stdout" \
	"$work/evidence-export-tenant-cli.stderr" "$ctl_bin" control evidence export \
	-control-url "$control_url" -token-file "$operator_token" -node-id "$node_id" \
	-out "$tenant_denied_export"
evidence_tenant_export_status=$?
set -e
if (( evidence_tenant_export_status == 0 )) || [[ -e $tenant_denied_export ]] || \
	[[ -s $work/evidence-export-tenant-cli.stdout ]]; then
	echo "control-acceptance: denied tenant evidence export published output" >&2
	exit 1
fi

evidence_export=$work/executor-evidence-witness.json
run_bounded 30 "$work" "$work/evidence-export.stdout" "$work/evidence-export.stderr" \
	"$ctl_bin" control evidence export -control-url "$control_url" -token-file "$admin_token" \
	-node-id "$node_id" -out "$evidence_export"
assert_owner_file "$evidence_export"
python3 -I - "$work/evidence-export.stdout" "$evidence_export" <<'PY'
import pathlib
import sys
if pathlib.Path(sys.argv[1]).read_text(encoding="utf-8") != f"{sys.argv[2]}\n":
    raise SystemExit("control-acceptance: evidence export did not return exactly its output path")
PY

run_bounded 30 "$work" "$work/keygen.stdout" "$work/keygen.stderr" \
	"$ctl_bin" keygen -key-id acceptance-tenant-command -private-out "$work/command.private" \
	-public-out "$work/command.public"
assert_owner_file "$work/command.private"
printf '%s\n' '{}' >"$work/command-payload.json"
run_bounded 30 "$work" "$work/command-issue.stdout" "$work/command-issue.stderr" \
	"$ctl_bin" executor-command issue -command-id "$command_id" -tenant-id "$tenant_id" \
	-node-id "$node_id" -instance-id "$instance_id" -kind start -claim-generation 1 \
	-instance-generation 1 -sequence 1 -valid-for 10m -payload "$work/command-payload.json" \
	-key "$work/command.private" -key-id acceptance-tenant-command -out "$work/command.dsse.json"
run_bounded 30 "$work" "$work/command-verify.stdout" "$work/command-verify.stderr" \
	"$ctl_bin" executor-command verify -in "$work/command.dsse.json" -public-key "$work/command.public" \
	-key-id acceptance-tenant-command
python3 -I - "$work/command.dsse.json" "$work/command-issue.stdout" "$work/command-verify.stdout" \
	"$command_id" "$tenant_id" "$node_id" "$instance_id" <<'PY'
import hashlib
import json
import pathlib
import sys
command_path, digest_path, verified_path, command_id, tenant_id, node_id, instance_id = sys.argv[1:]
raw = pathlib.Path(command_path).read_bytes()
if not raw or len(raw) > 1 << 20:
    raise SystemExit("control-acceptance: signed command is empty or oversized")
digest = "sha256:" + hashlib.sha256(raw).hexdigest()
if pathlib.Path(digest_path).read_text().strip() != digest:
    raise SystemExit("control-acceptance: command issuer returned the wrong exact-byte digest")
statement = json.loads(pathlib.Path(verified_path).read_text())
expected = {
    "command_id": command_id,
    "tenant_id": tenant_id,
    "node_id": node_id,
    "instance_id": instance_id,
    "kind": "start",
    "claim_generation": 1,
    "instance_generation": 1,
    "command_sequence": 1,
    "payload": {},
}
for field, wanted in expected.items():
    if statement.get(field) != wanted:
        raise SystemExit(f"control-acceptance: verified command field {field} is invalid")
if not statement.get("runtime_ref"):
    raise SystemExit("control-acceptance: verified command omits its signed runtime reference")
PY

run_bounded 30 "$work" "$work/command-submit.stdout" "$work/command-submit.stderr" \
	"$ctl_bin" control command submit -control-url "$control_url" -token-file "$operator_token" \
	-tenant-id "$tenant_id" -node-id "$node_id" -command "$work/command.dsse.json"
run_bounded 30 "$work" "$work/command-submit-retry.stdout" "$work/command-submit-retry.stderr" \
	"$ctl_bin" control command submit -control-url "$control_url" -token-file "$operator_token" \
	-tenant-id "$tenant_id" -node-id "$node_id" -command "$work/command.dsse.json"
cmp -s "$work/command-submit.stdout" "$work/command-submit-retry.stdout" || {
	echo "control-acceptance: exact command resubmission changed retained identity" >&2
	exit 1
}
python3 -I - "$work/command-submit.stdout" "$work/command-issue.stdout" "$command_id" "$tenant_id" "$node_id" <<'PY'
import json
import pathlib
import sys
command = json.loads(pathlib.Path(sys.argv[1]).read_text())
digest = pathlib.Path(sys.argv[2]).read_text().strip()
if command.get("command_id") != sys.argv[3] or command.get("tenant_id") != sys.argv[4] or command.get("node_id") != sys.argv[5]:
    raise SystemExit("control-acceptance: submitted command route is invalid")
if command.get("command_digest") != digest or command.get("state") != "pending" or not command.get("delivery_id"):
    raise SystemExit("control-acceptance: submitted command identity or state is invalid")
PY
assert_secret_absent raw "$operator_token" "$work/command-submit.stdout" "$work/command-submit.stderr" \
	"$work/command-submit-retry.stdout" "$work/command-submit-retry.stderr"

run_bounded 30 "$work" "$work/command-list-pending.stdout" "$work/command-list-pending.stderr" \
	"$ctl_bin" control command list -control-url "$control_url" -token-file "$operator_token" \
	-tenant-id "$tenant_id" -node-id "$node_id" -state pending -limit 1
python3 -I - "$work/command-list-pending.stdout" "$work/command.dsse.json" \
	"$command_id" "$tenant_id" "$node_id" <<'PY'
import base64
import json
import pathlib
import sys

page = json.loads(pathlib.Path(sys.argv[1]).read_text())
commands = page.get("commands", [])
if len(commands) != 1 or page.get("next_cursor"):
    raise SystemExit("control-acceptance: pending command inventory is not exactly bounded")
command = commands[0]
if command.get("id") != sys.argv[3] or command.get("tenant_id") != sys.argv[4] or \
        command.get("node_id") != sys.argv[5] or command.get("state") != "pending":
    raise SystemExit("control-acceptance: pending command inventory changed command identity")
raw = pathlib.Path(sys.argv[1]).read_bytes()
signed = pathlib.Path(sys.argv[2]).read_bytes()
if signed in raw or base64.b64encode(signed) in raw:
    raise SystemExit("control-acceptance: command inventory exposed signed command bytes")
for forbidden in (
    b'"command_dsse', b'"payload"', b'"result"', b'"runtime_ref"',
    b'"reported_status"', b'"error_code"',
):
    if forbidden in raw:
        raise SystemExit("control-acceptance: command inventory exposed execution content")
PY

printf '%s\n' "{\"protocol_version\":3,\"node_id\":\"$node_id\",\"credential_scope\":\"node\",\"capabilities\":[\"delivery-leases-v3\",\"signed-commands-v2\"]}" \
	>"$work/poll-request.json"
http_json POST /executor-uplink/poll "$work/poll-request.json" json "$node_credential" 200 "$work/poll-response.json"
python3 -I - "$work/poll-response.json" "$work/command.dsse.json" "$work/command-issue.stdout" \
	"$work/command-verify.stdout" "$work/report.json" "$work/future-report.json" "$command_id" <<'PY'
import base64
import copy
import hashlib
import json
import pathlib
import sys

poll_path, command_path, digest_path, statement_path, report_path, future_path, command_id = sys.argv[1:]
poll = json.loads(pathlib.Path(poll_path).read_text())
if poll.get("protocol_version") != 3 or len(poll.get("deliveries", [])) != 1:
    raise SystemExit("control-acceptance: v3 poll did not return exactly one delivery")
delivery = poll["deliveries"][0]
command = pathlib.Path(command_path).read_bytes()
digest = pathlib.Path(digest_path).read_text().strip()
try:
    transported = base64.b64decode(delivery.get("command_dsse_base64", ""), validate=True)
except ValueError:
    raise SystemExit("control-acceptance: delivery command is not canonical base64") from None
if base64.b64encode(transported).decode("ascii") != delivery.get("command_dsse_base64"):
    raise SystemExit("control-acceptance: delivery command base64 is not canonical")
if transported != command or delivery.get("command_id") != command_id:
    raise SystemExit("control-acceptance: delivery changed the exact signed command bytes or identity")
if delivery.get("command_digest") != digest or digest != "sha256:" + hashlib.sha256(command).hexdigest():
    raise SystemExit("control-acceptance: delivery command digest is invalid")
if not delivery.get("delivery_id") or not isinstance(delivery.get("delivery_generation"), int) or delivery["delivery_generation"] <= 0:
    raise SystemExit("control-acceptance: delivery lease identity is invalid")
statement = json.loads(pathlib.Path(statement_path).read_text())
report = {
    "protocol_version": 3,
    "delivery_id": delivery["delivery_id"],
    "delivery_generation": delivery["delivery_generation"],
    "command_id": delivery["command_id"],
    "command_digest": delivery["command_digest"],
    "status": "done",
    "reported_status": "success",
    "claim_generation": statement["claim_generation"],
    "result": {"runtime_ref": statement["runtime_ref"]},
}
pathlib.Path(report_path).write_text(json.dumps(report, separators=(",", ":")) + "\n", encoding="utf-8")
future = copy.deepcopy(report)
future["delivery_generation"] += 1
pathlib.Path(future_path).write_text(json.dumps(future, separators=(",", ":")) + "\n", encoding="utf-8")
PY

# Recover the leased command and its delivery fence from durable state before
# accepting the node's terminal observation.
stop_control

# Verification is genuinely offline here: the controller process is stopped and
# the verifier receives only the export plus the public key pinned before first
# startup. Exercise both signature tampering and a different valid witness key.
run_bounded 30 "$work" "$work/evidence-verify.stdout" "$work/evidence-verify.stderr" \
	"$ctl_bin" control evidence verify -in "$evidence_export" \
	-witness-public-key "$pinned_witness"
python3 -I - "$work/evidence-verify.stdout" "$work/evidence-status.stdout" \
	"$evidence_export" "$node_id" <<'PY'
import json
import pathlib
import re
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())
online = json.loads(pathlib.Path(sys.argv[2]).read_text())
export = json.loads(pathlib.Path(sys.argv[3]).read_text())
if value.get("verified") is not True or value.get("control_node_id") != sys.argv[4]:
    raise SystemExit("control-acceptance: offline witness verification did not bind the node")
if value.get("controller_instance_id") != online.get("controller_instance_id"):
    raise SystemExit("control-acceptance: offline witness verification changed the controller identity")
if value.get("state") != "current" or value.get("sequence") != 0 or not value.get("exported_at"):
    raise SystemExit("control-acceptance: offline witness verification changed the checkpoint")
digest = value.get("witness_public_key_sha256", "")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest) or digest != export.get("witness_public_key_sha256"):
    raise SystemExit("control-acceptance: offline verification omits the pinned witness digest")
if value.get("exported_at") != export.get("statement", {}).get("exported_at"):
    raise SystemExit("control-acceptance: offline verification changed the export time")
PY

tampered_export=$work/executor-evidence-witness-tampered.json
python3 -I - "$evidence_export" "$tampered_export" <<'PY'
import json
import pathlib
import sys

source = json.loads(pathlib.Path(sys.argv[1]).read_text())
source["statement"]["exported_at"] = "2999-01-01T00:00:00Z"
with pathlib.Path(sys.argv[2]).open("x", encoding="utf-8") as output:
    json.dump(source, output, indent=2)
    output.write("\n")
PY
assert_owner_file "$tampered_export"
set +e
run_bounded 30 "$work" "$work/evidence-tampered.stdout" "$work/evidence-tampered.stderr" \
	"$ctl_bin" control evidence verify -in "$tampered_export" \
	-witness-public-key "$pinned_witness"
tampered_status=$?
set -e
if (( tampered_status == 0 )) || [[ -s $work/evidence-tampered.stdout ]]; then
	echo "control-acceptance: changed signed export field passed offline verification" >&2
	exit 1
fi

wrong_state=$work/wrong-witness-state
wrong_admin=$work/wrong-witness-admin.token
run_bounded 30 "$work" "$work/wrong-witness-initialize.stdout" \
	"$work/wrong-witness-initialize.stderr" "$control_bin" -initialize \
	-state-dir "$wrong_state" -admin-token-file "$wrong_admin" -addr 127.0.0.1:0
wrong_witness_public=$wrong_state/witness.public.pem
wrong_witness_private=$wrong_state/witness.private.pem
set +e
run_bounded 30 "$work" "$work/evidence-wrong-key.stdout" "$work/evidence-wrong-key.stderr" \
	"$ctl_bin" control evidence verify -in "$evidence_export" \
	-witness-public-key "$wrong_witness_public"
wrong_key_status=$?
set -e
if (( wrong_key_status == 0 )) || [[ -s $work/evidence-wrong-key.stdout ]]; then
	echo "control-acceptance: unpinned witness key authorized an evidence export" >&2
	exit 1
fi

start_control control-recovered
http_json GET /v1/readiness "" none "" 200 "$work/recovered-readiness.json"

# Restart must preserve both the last-good evidence checkpoint and the dedicated
# witness identity. Re-export under the recovered controller and verify both
# generations with the original pinned public key.
run_bounded 30 "$work" "$work/evidence-status-recovered.stdout" \
	"$work/evidence-status-recovered.stderr" "$ctl_bin" control evidence status \
	-control-url "$control_url" -token-file "$admin_token" -node-id "$node_id"
cmp -s "$work/evidence-status.stdout" "$work/evidence-status-recovered.stdout" || {
	echo "control-acceptance: controller restart changed the retained evidence witness" >&2
	exit 1
}
evidence_export_recovered=$work/executor-evidence-witness-recovered.json
run_bounded 30 "$work" "$work/evidence-export-recovered.stdout" \
	"$work/evidence-export-recovered.stderr" "$ctl_bin" control evidence export \
	-control-url "$control_url" -token-file "$admin_token" -node-id "$node_id" \
	-out "$evidence_export_recovered"
assert_owner_file "$evidence_export_recovered"
python3 -I - "$work/evidence-export-recovered.stdout" "$evidence_export_recovered" <<'PY'
import pathlib
import sys
if pathlib.Path(sys.argv[1]).read_text(encoding="utf-8") != f"{sys.argv[2]}\n":
    raise SystemExit("control-acceptance: recovered evidence export returned extra output")
PY
run_bounded 30 "$work" "$work/evidence-verify-recovered-old.stdout" \
	"$work/evidence-verify-recovered-old.stderr" "$ctl_bin" control evidence verify \
	-in "$evidence_export" -witness-public-key "$pinned_witness"
run_bounded 30 "$work" "$work/evidence-verify-recovered.stdout" \
	"$work/evidence-verify-recovered.stderr" "$ctl_bin" control evidence verify \
	-in "$evidence_export_recovered" -witness-public-key "$pinned_witness"
python3 -I - "$evidence_export" "$evidence_export_recovered" \
	"$work/evidence-verify-recovered-old.stdout" "$work/evidence-verify-recovered.stdout" <<'PY'
import json
import pathlib
import sys

old_export = json.loads(pathlib.Path(sys.argv[1]).read_text())
new_export = json.loads(pathlib.Path(sys.argv[2]).read_text())
old_verified = json.loads(pathlib.Path(sys.argv[3]).read_text())
new_verified = json.loads(pathlib.Path(sys.argv[4]).read_text())
old_statement = dict(old_export["statement"])
new_statement = dict(new_export["statement"])
old_statement.pop("exported_at")
new_statement.pop("exported_at")
if old_statement != new_statement:
    raise SystemExit("control-acceptance: restart changed the exported evidence statement")
for field in ("witness_public_key_base64", "witness_public_key_sha256"):
    if old_export.get(field) != new_export.get(field):
        raise SystemExit("control-acceptance: restart rotated the evidence witness identity")
for field in ("verified", "controller_instance_id", "control_node_id", "state", "sequence", "finding", "witness_public_key_sha256"):
    if old_verified.get(field) != new_verified.get(field):
        raise SystemExit(f"control-acceptance: recovered verification changed {field}")
PY

# The controller restart must retain NodePool intent. Membership arrives only
# through the authenticated node uplink and changes the exact external
# reconciliation deficit without granting any new delivery authority.
run_bounded 30 "$work" "$work/node-pool-recovered.stdout" "$work/node-pool-recovered.stderr" \
	"$ctl_bin" control node-pool status -control-url "$control_url" -token-file "$admin_token" \
	-pool-id "$pool_id"
python3 -I - "$work/node-pool-recovered.stdout" "$pool_id" <<'PY'
import json
import pathlib
import sys

status = json.loads(pathlib.Path(sys.argv[1]).read_text())
pool = status.get("pool", {})
if pool.get("id") != sys.argv[2] or pool.get("revision") != 2 or pool.get("membership_generation") != 1 or \
        pool.get("membership_key_id") != "acceptance-pool-authority" or pool.get("desired_nodes") != 3 or \
        status.get("registered_nodes") != 0 or status.get("scale_out_needed") != 3:
    raise SystemExit("control-acceptance: controller restart changed node-pool intent")
PY

python3 -I - "$work/scheduling-observation.json" "$node_id" "$pool_id" <<'PY'
import hashlib
import json
import pathlib
import sys

resources = lambda memory, cpu, pids, workloads: {
    "memory_bytes": memory, "cpu_millis": cpu, "pids": pids, "workloads": workloads,
}
policy = {
    "per_workload": resources(268435456, 1000, 128, 1),
    "host": resources(2147483648, 4000, 1024, 4),
    "tenant": resources(2147483648, 4000, 1024, 4),
    "runtime_overhead": resources(67108864, 100, 32, 0),
}
policy_digest = "sha256:" + hashlib.sha256(json.dumps(policy, separators=(",", ":")).encode()).hexdigest()
runtime_assurance = {
    "schema_version": "steward.runtime-assurance.v1",
    "profile": "shared-host-hardened",
    "runtime": "docker",
    "isolation": "gvisor",
    "network": "isolated-bridge",
    "state_isolation": "ephemeral-only",
    "credential_boundary": "gateway-only",
    "host_admin_intent": False,
}
runtime_assurance_digest = "sha256:" + hashlib.sha256(
    json.dumps(runtime_assurance, separators=(",", ":")).encode()
).hexdigest()
observation = {
    "schema_version": "steward.executor-scheduling.v1",
    "node_id": sys.argv[2],
    "credential_scope": "node",
    "os": "linux",
    "architecture": "amd64",
    "isolation": "gvisor",
    "boot_identity_sha256": "sha256:" + "a" * 64,
    "scheduling_policy_sha256": policy_digest,
    "runtime_assurance": runtime_assurance,
    "runtime_assurance_sha256": runtime_assurance_digest,
    "labels": [{"key": "steward.io/node-pool", "value": sys.argv[3]}],
    "taints": [],
    "cached_image_config_digests": [],
    "policy": policy,
}
pathlib.Path(sys.argv[1]).write_text(json.dumps(observation, separators=(",", ":")) + "\n")
PY
http_json POST /executor-uplink/scheduling "$work/scheduling-observation.json" json \
	"$node_credential" 200 "$work/scheduling-observation-response.json"
run_bounded 30 "$work" "$work/node-pool-member.stdout" "$work/node-pool-member.stderr" \
	"$ctl_bin" control node-pool status -control-url "$control_url" -token-file "$admin_token" \
	-pool-id "$pool_id"
python3 -I - "$work/scheduling-observation-response.json" "$work/node-pool-member.stdout" \
	"$pool_id" "$node_id" <<'PY'
import json
import pathlib
import sys

observed = json.loads(pathlib.Path(sys.argv[1]).read_text())
status = json.loads(pathlib.Path(sys.argv[2]).read_text())
nodes = status.get("nodes", [])
if observed.get("applied") is not True or not observed.get("observed_at"):
    raise SystemExit("control-acceptance: node scheduling observation was not durably applied")
if status.get("pool", {}).get("id") != sys.argv[3] or status.get("registered_nodes") != 1 or \
        status.get("eligible_nodes") != 0 or status.get("ready_nodes") != 0 or \
        status.get("scale_out_needed") != 3 or status.get("scale_in_candidates") != [] or \
        status.get("conditions") != ["capacity_shortfall", "membership_unverified"]:
    raise SystemExit("control-acceptance: an unsigned pool label satisfied verified capacity")
if len(nodes) != 1 or nodes[0].get("node_id") != sys.argv[4] or nodes[0].get("ready") is not False or \
        nodes[0].get("eligible") is not False or nodes[0].get("reason") != "membership_missing":
    raise SystemExit("control-acceptance: unsigned node-pool projection is invalid")
PY

read -r controller_id pool_created_at pool_membership_generation < <(python3 -I - \
	"$enrollment" "$work/node-pool-recovered.stdout" <<'PY'
import json
import pathlib
import re
import sys

enrollment = json.loads(pathlib.Path(sys.argv[1]).read_text())
status = json.loads(pathlib.Path(sys.argv[2]).read_text())
controller = enrollment.get("controller_instance_id", "")
pool = status.get("pool", {})
created = pool.get("created_at", "")
generation = pool.get("membership_generation")
if not re.fullmatch(r"[A-Za-z0-9._:-]{1,160}", controller) or \
        not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[^ ]+Z", created) or \
        not isinstance(generation, int) or generation < 1:
    raise SystemExit("control-acceptance: pool membership issuance inputs are invalid")
print(controller, created, generation)
PY
)
pool_membership=$work/pool-membership.dsse.json
read -r scheduling_policy_sha256 runtime_assurance_sha256 < <(python3 -I - \
	"$work/scheduling-observation.json" <<'PY'
import json
import pathlib
import sys

observation = json.loads(pathlib.Path(sys.argv[1]).read_text())
print(observation["scheduling_policy_sha256"], observation["runtime_assurance_sha256"])
PY
)
run_bounded 30 "$work" "$work/pool-membership-issue.stdout" "$work/pool-membership-issue.stderr" \
	"$ctl_bin" control node-pool membership-issue -private-key "$pool_membership_private" \
	-key-id acceptance-pool-authority -controller-id "$controller_id" -pool-id "$pool_id" \
	-pool-membership-generation "$pool_membership_generation" -pool-created-at "$pool_created_at" \
	-node-id "$node_id" -tenant-ids "$tenant_id" -architecture amd64 \
	-boot-identity-sha256 sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
	-scheduling-policy-sha256 "$scheduling_policy_sha256" \
	-runtime-assurance-sha256 "$runtime_assurance_sha256" \
	-valid-for 1h -out "$pool_membership" -no-context
assert_owner_file "$pool_membership"
run_bounded 30 "$work" "$work/pool-membership-verify.stdout" "$work/pool-membership-verify.stderr" \
	"$ctl_bin" control node-pool membership-verify -in "$pool_membership" \
	-public-key "$pool_membership_public" -key-id acceptance-pool-authority -no-context
run_bounded 30 "$work" "$work/pool-membership-bind.stdout" "$work/pool-membership-bind.stderr" \
	"$ctl_bin" control node-pool membership-bind -control-url "$control_url" \
	-credential "$node_credential" -in "$pool_membership" -no-context
run_bounded 30 "$work" "$work/pool-membership-bind-retry.stdout" "$work/pool-membership-bind-retry.stderr" \
	"$ctl_bin" control node-pool membership-bind -control-url "$control_url" \
	-credential "$node_credential" -in "$pool_membership" -no-context
cmp -s "$work/pool-membership-bind.stdout" "$work/pool-membership-bind-retry.stdout" || {
	echo "control-acceptance: exact pool membership retry changed the retained binding" >&2
	exit 1
}
run_bounded 30 "$work" "$work/node-pool-verified-member.stdout" \
	"$work/node-pool-verified-member.stderr" "$ctl_bin" control node-pool status \
	-control-url "$control_url" -token-file "$admin_token" -pool-id "$pool_id"
python3 -I - "$work/pool-membership-verify.stdout" "$work/pool-membership-bind.stdout" \
	"$work/node-pool-verified-member.stdout" "$pool_id" "$node_id" <<'PY'
import json
import pathlib
import re
import sys

claim = json.loads(pathlib.Path(sys.argv[1]).read_text())
binding = json.loads(pathlib.Path(sys.argv[2]).read_text())
status = json.loads(pathlib.Path(sys.argv[3]).read_text())
membership = binding.get("membership", {})
nodes = status.get("nodes", [])
if claim.get("pool_id") != sys.argv[4] or claim.get("node_id") != sys.argv[5]:
    raise SystemExit("control-acceptance: offline membership verification changed identity")
if binding.get("node_id") != sys.argv[5] or membership.get("pool_id") != sys.argv[4] or \
        not re.fullmatch(r"sha256:[0-9a-f]{64}", membership.get("digest", "")):
    raise SystemExit("control-acceptance: retained membership binding is invalid")
if status.get("eligible_nodes") != 1 or status.get("ready_nodes") != 1 or \
        status.get("scale_out_needed") != 2 or status.get("conditions") != ["capacity_shortfall"]:
    raise SystemExit("control-acceptance: verified member did not satisfy exactly one unit of capacity")
if len(nodes) != 1 or nodes[0].get("eligible") is not True or nodes[0].get("ready") is not True or \
        nodes[0].get("membership_digest") != membership.get("digest"):
    raise SystemExit("control-acceptance: verified member projection is invalid")
PY

# MCP exposes the same provider-neutral observation to a site automation
# process, but deliberately offers no pool mutation or provider action tool.
python3 -I - "$work/mcp-node-pool.requests" "$pool_id" <<'PY'
import json
import pathlib
import sys

messages = [
    {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "control-acceptance", "version": "1"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "steward_control_node_pool_list", "arguments": {"limit": 1}},
    },
    {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "steward_control_node_pool_status",
            "arguments": {"pool_id": sys.argv[2]},
        },
    },
]
with pathlib.Path(sys.argv[1]).open("x", encoding="utf-8") as output:
    for message in messages:
        output.write(json.dumps(message, separators=(",", ":")) + "\n")
PY
run_mcp_session "$work/mcp-node-pool.requests" "$work/mcp-node-pool.stdout" \
	"$work/mcp-node-pool.stderr" "$mcp_bin" -control-url "$control_url" \
	-control-token-file "$admin_token"
python3 -I - "$work/mcp-node-pool.stdout" "$work/mcp-node-pool.stderr" \
	"$pool_id" "$node_id" <<'PY'
import json
import pathlib
import sys

if pathlib.Path(sys.argv[2]).read_bytes():
    raise SystemExit("control-acceptance: node-pool MCP session wrote diagnostics")
responses = {}
for line in pathlib.Path(sys.argv[1]).read_text().splitlines():
    value = json.loads(line)
    if value.get("jsonrpc") != "2.0" or value.get("id") in responses:
        raise SystemExit("control-acceptance: node-pool MCP response identity is invalid")
    responses[value.get("id")] = value
if set(responses) != {1, 2, 3} or "error" in responses[1]:
    raise SystemExit("control-acceptance: node-pool MCP lifecycle is incomplete")
structured = {}
for identifier in (2, 3):
    result = responses[identifier].get("result", {})
    content = result.get("content", [])
    if result.get("isError") is not False or len(content) != 1 or content[0].get("type") != "text":
        raise SystemExit("control-acceptance: node-pool MCP read failed")
    structured[identifier] = result.get("structuredContent")
    if json.loads(content[0].get("text", "")) != structured[identifier]:
        raise SystemExit("control-acceptance: node-pool MCP projections disagree")
listed = structured[2].get("node_pools", [])
status = structured[3]
if len(listed) != 1:
    raise SystemExit("control-acceptance: node-pool MCP list is not exactly bounded")
for observation in (listed[0], status):
    if observation.get("pool", {}).get("id") != sys.argv[3] or \
            observation.get("pool", {}).get("revision") != 2 or \
            observation.get("registered_nodes") != 1 or observation.get("eligible_nodes") != 1 or \
            observation.get("ready_nodes") != 1 or \
            observation.get("nodes", [{}])[0].get("node_id") != sys.argv[4] or \
            observation.get("nodes", [{}])[0].get("eligible") is not True or \
            observation.get("scale_out_needed") != 2:
        raise SystemExit("control-acceptance: node-pool MCP observation differs from the public API")
PY

run_bounded 30 "$work" "$work/leased-status.stdout" "$work/leased-status.stderr" \
	"$ctl_bin" control command status -control-url "$control_url" -token-file "$operator_token" \
	-tenant-id "$tenant_id" -node-id "$node_id" -command-id "$command_id"
python3 -I - "$work/leased-status.stdout" "$work/poll-response.json" <<'PY'
import json
import pathlib
import sys
status = json.loads(pathlib.Path(sys.argv[1]).read_text())
delivery = json.loads(pathlib.Path(sys.argv[2]).read_text())["deliveries"][0]
if status.get("state") != "leased" or status.get("delivery_generation") != delivery["delivery_generation"]:
    raise SystemExit("control-acceptance: restart did not recover the delivery lease")
if status.get("delivery_id") != delivery["delivery_id"] or status.get("command_digest") != delivery["command_digest"]:
    raise SystemExit("control-acceptance: restart changed the leased command identity")
PY

# A node cannot advance the controller's delivery-generation fence.
http_json POST /executor-uplink/report "$work/future-report.json" json "$node_credential" 409 "$work/future-report-response.json"
python3 -I - "$work/future-report-response.json" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value.get("error") != "conflict" or not value.get("message"):
    raise SystemExit("control-acceptance: future delivery report did not produce a stable conflict")
PY

http_json POST /executor-uplink/report "$work/report.json" json "$node_credential" 200 "$work/report-response.json"
http_json POST /executor-uplink/report "$work/report.json" json "$node_credential" 200 "$work/report-replay-response.json"
python3 -I - "$work/report-response.json" "$work/report-replay-response.json" <<'PY'
import json
import pathlib
import sys
first = json.loads(pathlib.Path(sys.argv[1]).read_text())
replay = json.loads(pathlib.Path(sys.argv[2]).read_text())
if first != {"protocol_version": 3, "applied": True}:
    raise SystemExit("control-acceptance: exact fenced terminal report was not applied")
if replay != {"protocol_version": 3, "applied": False}:
    raise SystemExit("control-acceptance: terminal report replay was not idempotently settled")
PY

run_bounded 30 "$work" "$work/terminal-status.stdout" "$work/terminal-status.stderr" \
	"$ctl_bin" control command status -control-url "$control_url" -token-file "$operator_token" \
	-tenant-id "$tenant_id" -node-id "$node_id" -command-id "$command_id"
python3 -I - "$work/terminal-status.stdout" "$work/command-issue.stdout" "$work/report.json" "$command_id" <<'PY'
import json
import pathlib
import sys
status = json.loads(pathlib.Path(sys.argv[1]).read_text())
report = json.loads(pathlib.Path(sys.argv[3]).read_text())
if status.get("command_id") != sys.argv[4] or status.get("command_digest") != pathlib.Path(sys.argv[2]).read_text().strip():
    raise SystemExit("control-acceptance: terminal status changed command identity")
if status.get("state") != "terminal" or status.get("terminal_status") != report["status"] or status.get("reported_status") != "success":
    raise SystemExit("control-acceptance: terminal status was not durably retained")
if status.get("claim_generation") != report["claim_generation"] or status.get("result") != report["result"]:
    raise SystemExit("control-acceptance: terminal result or signed claim fence was hidden or changed")
PY

run_bounded 30 "$work" "$work/command-list-terminal.stdout" "$work/command-list-terminal.stderr" \
	"$ctl_bin" control command list -control-url "$control_url" -token-file "$operator_token" \
	-tenant-id "$tenant_id" -node-id "$node_id" -state terminal -terminal-status done -limit 1
python3 -I - "$work/command-list-terminal.stdout" "$command_id" "$tenant_id" "$node_id" <<'PY'
import json
import pathlib
import sys

page = json.loads(pathlib.Path(sys.argv[1]).read_text())
commands = page.get("commands", [])
if len(commands) != 1 or page.get("next_cursor"):
    raise SystemExit("control-acceptance: terminal command filter is not exactly bounded")
command = commands[0]
if command.get("id") != sys.argv[2] or command.get("tenant_id") != sys.argv[3] or \
        command.get("node_id") != sys.argv[4] or command.get("state") != "terminal" or \
        command.get("terminal_status") != "done":
    raise SystemExit("control-acceptance: terminal command inventory changed retained metadata")
if any(field in command for field in (
        "result", "payload", "command_dsse_base64", "runtime_ref", "reported_status", "error_code",
)):
    raise SystemExit("control-acceptance: terminal command inventory exposed execution content")
PY

# Create one retained containment fact after delivery is settled, then prove the
# CLI projection is scoped, newest-first metadata rather than execution content.
run_bounded 30 "$work" "$work/node-quarantine.stdout" "$work/node-quarantine.stderr" \
	"$ctl_bin" control node quarantine -control-url "$control_url" -token-file "$admin_token" \
	-node-id "$node_id" -reason "acceptance incident containment"
run_bounded 30 "$work" "$work/incident-timeline.stdout" "$work/incident-timeline.stderr" \
	"$ctl_bin" control incident timeline -control-url "$control_url" -token-file "$operator_token" \
	-node-id "$node_id" -kind containment -severity critical -limit 1
python3 -I - "$work/incident-timeline.stdout" "$tenant_id" "$node_id" \
	"$work/command.dsse.json" "$node_credential" "$admin_token" "$operator_token" <<'PY'
import base64
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
page = json.loads(path.read_text())
events = page.get("events", [])
if len(events) != 1 or page.get("next_cursor"):
    raise SystemExit("control-acceptance: incident timeline is not exactly bounded")
event = events[0]
if not re.fullmatch(r"incident-[0-9a-f]{64}", event.get("id", "")) or \
        event.get("kind") != "containment" or event.get("action") != "node_quarantined" or \
        event.get("severity") != "critical" or event.get("scope") != "tenant" or \
        event.get("tenant_id") != sys.argv[2] or event.get("node_id") != sys.argv[3] or \
        event.get("reason") != "acceptance incident containment" or not event.get("occurred_at"):
    raise SystemExit("control-acceptance: incident timeline changed the retained containment fact")
raw = path.read_bytes()
command = pathlib.Path(sys.argv[4]).read_bytes()
node_secret = json.loads(pathlib.Path(sys.argv[5]).read_text())["credential"].encode()
for secret in (
    command, base64.b64encode(command), node_secret,
    pathlib.Path(sys.argv[6]).read_bytes().strip(),
    pathlib.Path(sys.argv[7]).read_bytes().strip(),
):
    if secret in raw:
        raise SystemExit("control-acceptance: incident timeline exposed protected bytes")
for forbidden in (b'"command_dsse', b'"payload"', b'"result"', b'"token"', b'"credential"'):
    if forbidden in raw:
        raise SystemExit("control-acceptance: incident timeline exposed an execution field")
PY

# Exercise the same read-only fleet views through a real control-only MCP
# process. Structured and text results must agree, remain tenant scoped, and
# exclude the signed command, terminal result, and all bearer material.
python3 -I - "$work/mcp-operations.requests" "$tenant_id" "$other_tenant_id" "$node_id" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
tenant_id, other_tenant_id, node_id = sys.argv[2:]
messages = [
    {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "control-acceptance", "version": "1"},
        },
    },
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {
            "name": "steward_control_operations_summary",
            "arguments": {"tenant_id": tenant_id},
        },
    },
    {
        "jsonrpc": "2.0", "id": 3, "method": "tools/call",
        "params": {
            "name": "steward_control_attention_list",
            "arguments": {"tenant_id": tenant_id, "limit": 1},
        },
    },
    {
        "jsonrpc": "2.0", "id": 4, "method": "tools/call",
        "params": {
            "name": "steward_control_command_list",
            "arguments": {
                "tenant_id": tenant_id, "node_id": node_id, "state": "terminal",
                "terminal_status": "done", "limit": 1,
            },
        },
    },
    {
        "jsonrpc": "2.0", "id": 5, "method": "tools/call",
        "params": {
            "name": "steward_control_credential_list",
            "arguments": {
                "tenant_id": tenant_id, "kind": "node", "node_id": node_id,
                "limit": 1,
            },
        },
    },
    {
        "jsonrpc": "2.0", "id": 6, "method": "tools/call",
        "params": {
            "name": "steward_control_incident_timeline",
            "arguments": {
                "tenant_id": tenant_id, "node_id": node_id,
                "kind": "containment", "severity": "critical", "limit": 1,
            },
        },
    },
    {
        "jsonrpc": "2.0", "id": 7, "method": "tools/call",
        "params": {
            "name": "steward_control_operations_summary",
            "arguments": {"tenant_id": other_tenant_id},
        },
    },
]
with path.open("x", encoding="utf-8") as output:
    for message in messages:
        output.write(json.dumps(message, separators=(",", ":")) + "\n")
PY
run_mcp_session "$work/mcp-operations.requests" "$work/mcp-operations.stdout" \
	"$work/mcp-operations.stderr" "$mcp_bin" -control-url "$control_url" \
	-control-token-file "$operator_token"
python3 -I - "$work/mcp-operations.stdout" "$work/mcp-operations.stderr" \
	"$tenant_id" "$other_tenant_id" "$node_id" "$command_id" "$node_credential" \
	"$admin_token" "$operator_token" "$work/command.dsse.json" <<'PY'
import base64
import json
import pathlib
import sys

stdout_path, stderr_path = map(pathlib.Path, sys.argv[1:3])
tenant_id, other_tenant_id, node_id, command_id = sys.argv[3:7]
if stderr_path.read_bytes():
    raise SystemExit("control-acceptance: control-only MCP session wrote diagnostics")
responses = {}
for line in stdout_path.read_text(encoding="utf-8").splitlines():
    value = json.loads(line)
    if value.get("jsonrpc") != "2.0" or value.get("id") in responses:
        raise SystemExit("control-acceptance: MCP response identity is invalid")
    responses[value.get("id")] = value
if set(responses) != {1, 2, 3, 4, 5, 6, 7} or "error" in responses[1]:
    raise SystemExit("control-acceptance: MCP lifecycle responses are incomplete")

structured = {}
for identifier in range(2, 7):
    response = responses[identifier]
    if "error" in response:
        raise SystemExit(f"control-acceptance: MCP operations tool {identifier} returned an RPC error")
    result = response.get("result", {})
    if result.get("isError") is not False:
        raise SystemExit(f"control-acceptance: MCP operations tool {identifier} returned a tool error")
    content = result.get("content")
    if not isinstance(content, list) or len(content) != 1 or content[0].get("type") != "text":
        raise SystemExit("control-acceptance: MCP operations tool omitted its bounded text projection")
    structured[identifier] = result.get("structuredContent")
    if json.loads(content[0].get("text", "")) != structured[identifier]:
        raise SystemExit("control-acceptance: MCP structured and text projections disagree")

summary = structured[2]
if summary.get("tenant_id") != tenant_id or summary.get("commands", {}).get("terminal") != 1:
    raise SystemExit("control-acceptance: MCP operations summary changed tenant or command scope")
attention = structured[3]
if not isinstance(attention.get("items"), list):
    raise SystemExit("control-acceptance: MCP attention result is not a bounded page")
for item in attention["items"]:
    if item.get("tenant_id") != tenant_id:
        raise SystemExit("control-acceptance: MCP attention result crossed tenant scope")
commands = structured[4].get("commands", [])
if len(commands) != 1 or commands[0].get("id") != command_id or \
        commands[0].get("tenant_id") != tenant_id or commands[0].get("node_id") != node_id or \
        commands[0].get("state") != "terminal" or commands[0].get("terminal_status") != "done":
    raise SystemExit("control-acceptance: MCP command inventory is invalid")
if any(field in commands[0] for field in (
        "result", "payload", "command_dsse_base64", "runtime_ref", "reported_status", "error_code",
)):
    raise SystemExit("control-acceptance: MCP command inventory exposed execution content")
credentials = structured[5].get("credentials", [])
if len(credentials) != 1 or credentials[0].get("kind") != "node" or \
        credentials[0].get("node_id") != node_id or credentials[0].get("tenant_ids") != [tenant_id]:
    raise SystemExit("control-acceptance: MCP credential inventory is invalid")
if any(field in credentials[0] for field in ("credential", "token", "token_mac", "mac")):
    raise SystemExit("control-acceptance: MCP credential inventory exposed secret-bearing fields")
timeline = structured[6].get("events", [])
if len(timeline) != 1 or timeline[0].get("action") != "node_quarantined" or \
        timeline[0].get("tenant_id") != tenant_id or timeline[0].get("node_id") != node_id or \
        timeline[0].get("reason") != "acceptance incident containment":
    raise SystemExit("control-acceptance: MCP incident timeline changed containment metadata or scope")
if any(field in timeline[0] for field in (
        "result", "payload", "command_dsse_base64", "runtime_ref", "reported_status", "error_code",
)):
    raise SystemExit("control-acceptance: MCP incident timeline exposed execution content")
denied = responses[7].get("result", {})
denied_content = denied.get("content", [])
if denied.get("isError") is not True or len(denied_content) != 1 or \
        "HTTP 404" not in denied_content[0].get("text", "") or \
        other_tenant_id in denied_content[0].get("text", ""):
    raise SystemExit("control-acceptance: MCP tenant isolation did not fail closed and redact scope")

raw = stdout_path.read_bytes()
node_secret = json.loads(pathlib.Path(sys.argv[7]).read_text())["credential"].encode()
for secret in (
    node_secret,
    pathlib.Path(sys.argv[8]).read_bytes().strip(),
    pathlib.Path(sys.argv[9]).read_bytes().strip(),
    pathlib.Path(sys.argv[10]).read_bytes(),
    base64.b64encode(pathlib.Path(sys.argv[10]).read_bytes()),
):
    if secret in raw:
        raise SystemExit("control-acceptance: MCP operations output disclosed protected bytes")
PY

http_json POST /executor-uplink/poll "$work/poll-request.json" json "$node_credential" 200 "$work/terminal-poll.json"
python3 -I - "$work/terminal-poll.json" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value != {"protocol_version": 3, "deliveries": []}:
    raise SystemExit("control-acceptance: terminal command was delivered again")
PY

run_bounded 30 "$work" "$work/node-credential-revoke.stdout" "$work/node-credential-revoke.stderr" \
	"$ctl_bin" control node-credential revoke -control-url "$control_url" -token-file "$admin_token" \
	-credential-id "$node_credential_id"
python3 -I - "$work/node-credential-revoke.stdout" "$node_credential_id" "$node_id" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value != {"credential_id": sys.argv[2], "node_id": sys.argv[3], "revoked": True}:
    raise SystemExit("control-acceptance: narrow node credential revocation response is invalid")
PY
http_json POST /executor-uplink/poll "$work/poll-request.json" json "$node_credential" 401 "$work/revoked-node-credential.json"
python3 -I - "$work/revoked-node-credential.json" <<'PY'
import json
import pathlib
import sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value.get("error") != "unauthorized":
    raise SystemExit("control-acceptance: revoked node credential remained authorized")
PY

stop_control
start_control control-metrics -enable-metrics=true
http_json GET /metrics "" none "" 401 "$work/metrics-unauthorized.json"
http_json GET /metrics "" raw "$work/invalid.token" 401 "$work/metrics-invalid-bearer.json"
http_json GET "/metrics?unknown=1" "" raw "$admin_token" 400 "$work/metrics-unknown-query.json"
http_json GET "/metrics?tenant_id=$tenant_id&tenant_id=$tenant_id" "" raw "$admin_token" 400 \
	"$work/metrics-duplicate-query.json"
http_json GET "/metrics?tenant_id=$other_tenant_id" "" raw "$operator_token" 404 \
	"$work/metrics-cross-tenant.json"
http_metrics /metrics "$admin_token" "$work/metrics-site.prom"
http_metrics /metrics "$operator_token" "$work/metrics-tenant.prom"
http_metrics "/metrics?tenant_id=$tenant_id" "$admin_token" "$work/metrics-admin-tenant.prom"
python3 -I - "$work/metrics-site.prom" "$work/metrics-tenant.prom" \
	"$work/metrics-admin-tenant.prom" "$tenant_id" "$other_tenant_id" "$node_id" \
	"$command_id" "$node_credential_id" "$node_credential" "$admin_token" "$operator_token" <<'PY'
import json
import pathlib
import re
import sys

site_path, tenant_path, admin_tenant_path = map(pathlib.Path, sys.argv[1:4])
tenant_id, other_tenant_id, node_id, command_id, credential_id = sys.argv[4:9]
allowed_labels = {"scope", "resource", "state", "status", "reason", "severity"}
required_families = {
    "steward_control_capacity_used",
    "steward_control_capacity_limit",
    "steward_control_capacity_warning",
    "steward_control_commands",
    "steward_control_evidence_nodes",
}
texts = {
    "site": site_path.read_text(encoding="utf-8"),
    "tenant": tenant_path.read_text(encoding="utf-8"),
    "admin_tenant": admin_tenant_path.read_text(encoding="utf-8"),
}
if texts["tenant"] != texts["admin_tenant"]:
    # generated_at is not exported, so two credentials selecting the same
    # tenant projection must receive exactly the same fixed-cardinality text.
    raise SystemExit("control-acceptance: metrics tenant projection depended on operator identity")
for name, text in texts.items():
    expected_scope = "site" if name == "site" else "tenant"
    samples = []
    families = set()
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"(steward_control_[a-z0-9_]+)\{([^}]*)\} ([0-9]+)", line)
        if match is None:
            raise SystemExit(f"control-acceptance: invalid or unbounded Prometheus sample: {line}")
        family, labels_text, _ = match.groups()
        labels = {}
        for label in labels_text.split(","):
            label_match = re.fullmatch(r'([a-z_]+)="([a-z0-9_]+)"', label)
            if label_match is None or label_match.group(1) in labels:
                raise SystemExit(f"control-acceptance: invalid metric label: {label}")
            labels[label_match.group(1)] = label_match.group(2)
        if not labels or not set(labels).issubset(allowed_labels) or labels.get("scope") != expected_scope:
            raise SystemExit("control-acceptance: metrics used an identifier label or changed scope")
        families.add(family)
        samples.append(line)
    if not required_families.issubset(families) or len(samples) > 128:
        raise SystemExit("control-acceptance: metrics families are incomplete or cardinality is unbounded")

raw = "".join(texts.values()).encode()
node_secret = json.loads(pathlib.Path(sys.argv[9]).read_text())["credential"].encode()
for secret in (
    tenant_id.encode(), other_tenant_id.encode(), node_id.encode(), command_id.encode(),
    credential_id.encode(), node_secret, pathlib.Path(sys.argv[10]).read_bytes().strip(),
    pathlib.Path(sys.argv[11]).read_bytes().strip(),
):
    if secret in raw:
        raise SystemExit("control-acceptance: metrics exposed an object identity or bearer")
for forbidden in (
    b"tenant_id=", b"node_id=", b"credential_id=", b"command_id=",
    b"tenant=", b"node=", b"credential=", b"command=",
):
    if forbidden in raw:
        raise SystemExit("control-acceptance: metrics exposed a high-cardinality label")
PY

run_bounded 30 "$work" "$work/node-pool-delete.stdout" "$work/node-pool-delete.stderr" \
	"$ctl_bin" control node-pool delete -control-url "$control_url" -token-file "$admin_token" \
	-pool-id "$pool_id" -revision 2
if [[ $(tr -d '\n' <"$work/node-pool-delete.stdout") != "$pool_id" ]]; then
	echo "control-acceptance: node-pool deletion returned the wrong identity" >&2
	exit 1
fi
http_json GET "/v1/node-pools/$pool_id" "" raw "$admin_token" 404 \
	"$work/node-pool-deleted.json"
python3 -I - "$work/node-pool-deleted.json" <<'PY'
import json
import pathlib
import sys

value = json.loads(pathlib.Path(sys.argv[1]).read_text())
if value.get("error") != "not_found" or not value.get("message"):
    raise SystemExit("control-acceptance: deleted node pool remained observable")
PY
stop_control
for log in "$work/control-first.stdout" "$work/control-first.stderr" \
	"$work/control-recovered.stdout" "$work/control-recovered.stderr" \
	"$work/control-metrics.stdout" "$work/control-metrics.stderr"; do
	[[ $(wc -c <"$log") -le 1048576 ]] || {
		echo "control-acceptance: controller diagnostic output exceeded 1 MiB" >&2
		exit 1
	}
done
process_outputs=("$work"/*.stdout "$work"/*.stderr)
assert_secret_absent raw "$admin_token" "${process_outputs[@]}"
assert_secret_absent raw "$operator_token" "${process_outputs[@]}"
assert_secret_absent enrollment_token "$enrollment" "${process_outputs[@]}"
assert_secret_absent credential "$node_credential" "${process_outputs[@]}"
assert_secret_absent raw "$evidence_private" "${process_outputs[@]}"
assert_secret_absent raw "$state_dir/witness.private.pem" "${process_outputs[@]}"
assert_secret_absent raw "$wrong_admin" "${process_outputs[@]}"
assert_secret_absent raw "$wrong_witness_private" "${process_outputs[@]}"
assert_secret_absent raw "$work/command.private" "${process_outputs[@]}"

echo "Steward Control acceptance passed: initialization, scoped tenancy, operations HTTP/CLI/MCP, independently signed NodePool eligibility, retained incident chronology, secret-free inventories, opt-in fixed-cardinality metrics, deterministic enrollment, witnessed evidence export, offline verification, exact signed delivery, restart recovery, fencing, and terminal retention verified."
