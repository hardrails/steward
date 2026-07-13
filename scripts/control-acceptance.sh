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
if [[ ! -x $control_bin || ! -x $ctl_bin ]]; then
	command -v go >/dev/null 2>&1 || {
		echo "control-acceptance: go is required unless both binary paths are provided" >&2
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
[[ -x $control_bin && -x $ctl_bin ]] || {
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
	local address=
	local index
	"$control_bin" -state-dir "$state_dir" -addr 127.0.0.1:0 -delivery-lease 1m \
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

start_control control-first
http_json GET /v1/healthz "" none "" 200 "$work/health.json"
http_json GET /v1/readiness "" none "" 200 "$work/readiness.json"
python3 -I - "$work/health.json" "$work/readiness.json" <<'PY'
import json
import pathlib
import sys
if json.loads(pathlib.Path(sys.argv[1]).read_text()) != {"status": "ok"}:
    raise SystemExit("control-acceptance: health response is invalid")
if json.loads(pathlib.Path(sys.argv[2]).read_text()) != {"status": "ready"}:
    raise SystemExit("control-acceptance: readiness response is invalid")
PY

tenant_id=acceptance-tenant
other_tenant_id=acceptance-other
node_id=acceptance-node
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

node_credential=$work/node-credential.json
node_credential_retry=$work/node-credential-retry.json
run_bounded 30 "$work" "$work/exchange.stdout" "$work/exchange.stderr" \
	"$ctl_bin" control enrollment exchange -control-url "$control_url" -enrollment "$enrollment" \
	-request-id acceptance-node-exchange -credential-out "$node_credential"
run_bounded 30 "$work" "$work/exchange-retry.stdout" "$work/exchange-retry.stderr" \
	"$ctl_bin" control enrollment exchange -control-url "$control_url" -enrollment "$enrollment" \
	-request-id acceptance-node-exchange -credential-out "$node_credential_retry"
assert_owner_file "$node_credential"
assert_owner_file "$node_credential_retry"
cmp -s "$node_credential" "$node_credential_retry" || {
	echo "control-acceptance: deterministic enrollment retry changed the node credential" >&2
	exit 1
}
python3 -I - "$node_credential" "$node_id" "$work/exchange.stdout" "$work/exchange-retry.stdout" <<'PY'
import json
import pathlib
import sys
credential = json.loads(pathlib.Path(sys.argv[1]).read_text())
if credential.get("version") != 2 or credential.get("scope") != "node" or credential.get("node_id") != sys.argv[2]:
    raise SystemExit("control-acceptance: node credential is invalid")
token = credential.get("credential", "")
prefix, separator, _ = token.rpartition("_")
credential_id = prefix.removeprefix("steward_node_v1_") if separator else ""
if not credential_id.startswith("node-cred-"):
    raise SystemExit("control-acceptance: node credential omits its revocation identity")
if pathlib.Path(sys.argv[3]).read_text() != f"{credential_id}\n" or pathlib.Path(sys.argv[4]).read_text() != f"{credential_id}\n":
    raise SystemExit("control-acceptance: enrollment exchange did not return only the credential ID")
PY
node_credential_id=$(tr -d '\n' <"$work/exchange.stdout")
[[ $node_credential_id =~ ^node-cred-[A-Za-z0-9._-]+$ ]] || {
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
	-request-id acceptance-different-exchange -credential-out "$work/replayed-node-credential.json"
replay_status=$?
set -e
if (( replay_status == 0 )) || [[ -e $work/replayed-node-credential.json ]]; then
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
start_control control-recovered
http_json GET /v1/readiness "" none "" 200 "$work/recovered-readiness.json"
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
for log in "$work/control-first.stdout" "$work/control-first.stderr" \
	"$work/control-recovered.stdout" "$work/control-recovered.stderr"; do
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
assert_secret_absent raw "$work/command.private" "${process_outputs[@]}"

echo "Steward Control acceptance passed: initialization, scoped tenancy, deterministic enrollment, exact signed delivery, restart recovery, fencing, and terminal retention verified."
