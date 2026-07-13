#!/usr/bin/env bash
# Signed-admission proof that Hermes executes bundled workspace and connector skills through Steward.
# HERMES_INTEGRATION_EVIDENCE_OUT optionally writes owner-only, metadata-only success evidence.
# HERMES_BUILD_ATTESTATION selects builder metadata; the archive's sibling attestation is the default.
set -euo pipefail
umask 077
unset CDPATH PYTHONHOME PYTHONPATH
PATH=/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

command -v readlink >/dev/null 2>&1 || { echo "hermes-steward-acceptance: readlink is required" >&2; exit 2; }
script_path=$(readlink -f "${BASH_SOURCE[0]}")
root=$(cd "$(dirname "$script_path")/.." && pwd -P)
release_root=
if [[ -x $root/steward-executor && -x $root/steward-gateway && -x $root/steward-relay && -x $root/stewardctl ]]; then
	release_root=$root
elif [[ -x $root/../steward-executor && -x $root/../steward-gateway && -x $root/../steward-relay && -x $root/../stewardctl ]]; then
	release_root=$(cd "$root/.." && pwd -P)
fi
if [[ $# -eq 1 && $1 == --check-layout ]]; then
	[[ -n $release_root ]] || { echo "hermes-steward-acceptance: no packaged Steward binaries found" >&2; exit 1; }
	printf '%s\n' "$release_root"
	exit 0
fi
[[ $# -eq 0 ]] || { echo "usage: hermes-steward-acceptance.sh [--check-layout]" >&2; exit 2; }

: "${HERMES_ARCHIVE:?set HERMES_ARCHIVE to a builder-produced Hermes adapter .tar}"
evidence_out=${HERMES_INTEGRATION_EVIDENCE_OUT:-}
build_attestation=${HERMES_BUILD_ATTESTATION:-}
[[ ${STEWARD_ACCEPT_DISPOSABLE_HOST_RISK:-} == YES ]] || {
	echo "hermes-steward-acceptance: set STEWARD_ACCEPT_DISPOSABLE_HOST_RISK=YES only on a disposable host" >&2
	exit 2
}
for command in base64 curl docker python3; do
	command -v "$command" >/dev/null 2>&1 || { echo "hermes-steward-acceptance: $command is required" >&2; exit 2; }
done
docker info --format '{{json .Runtimes}}' | grep -q '"runsc"' || {
	echo "hermes-steward-acceptance: Docker runtime runsc is required" >&2
	exit 2
}
[[ -f $HERMES_ARCHIVE && ! -L $HERMES_ARCHIVE ]] || {
	echo "hermes-steward-acceptance: HERMES_ARCHIVE must be a regular file" >&2
	exit 2
}

work=$(mktemp -d /tmp/steward-hermes-integration.XXXXXX)
executor_bin=${EXECUTOR_BIN:-${release_root:+$release_root/steward-executor}}
gateway_bin=${GATEWAY_BIN:-${release_root:+$release_root/steward-gateway}}
relay_bin=${RELAY_BIN:-${release_root:+$release_root/steward-relay}}
ctl_bin=${STEWARDCTL_BIN:-${release_root:+$release_root/stewardctl}}
executor_bin=${executor_bin:-$work/steward-executor}
gateway_bin=${gateway_bin:-$work/steward-gateway}
relay_bin=${relay_bin:-$work/steward-relay}
ctl_bin=${ctl_bin:-$work/stewardctl}
if [[ ! -x $executor_bin || ! -x $gateway_bin || ! -x $relay_bin || ! -x $ctl_bin ]]; then
	command -v go >/dev/null 2>&1 || {
		echo "hermes-steward-acceptance: go is required unless all binary paths are provided" >&2
		exit 2
	}
fi
run_id=${STEWARD_ACCEPTANCE_RUN_ID:-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')}
[[ $run_id =~ ^[a-f0-9]{16}$ ]] || { echo "hermes-steward-acceptance: invalid STEWARD_ACCEPTANCE_RUN_ID" >&2; exit 2; }
connector_id=local-work
connector_operation=perform
connector_origin=http://127.0.0.1:18082
connector_task_id=hermes-$run_id-work
connector_forbidden_task_id=hermes-$run_id-forbidden
tenant_id=hermes-$run_id
instance_id=agent-$run_id
lineage_id=lineage-$run_id
node_id=node-$run_id
repository=local/hermes-agent
runtime_ref=
state_volume=
imported_image_digests=()
debug_keep=${HERMES_DEBUG_KEEP_FAILED_WORK:-NO}
[[ $debug_keep == YES || $debug_keep == NO ]] || { echo "hermes-steward-acceptance: HERMES_DEBUG_KEEP_FAILED_WORK must be YES or NO" >&2; exit 2; }
: >"$work/steps"

mark() {
	printf '%s\n' "$1" >>"$work/steps"
}

prepare_evidence_provenance() {
	[[ -n $evidence_out ]] || return 0
	local attestation=$build_attestation
	if [[ -z $attestation && ( -e $HERMES_ARCHIVE.attestation.json || -L $HERMES_ARCHIVE.attestation.json ) ]]; then
		attestation=$HERMES_ARCHIVE.attestation.json
	fi
	if [[ -z $attestation ]]; then
		echo "hermes-steward-acceptance: evidence output requires the adapter build attestation" >&2
		return 1
	fi
	python3 -I - "$work/provenance.json" "$HERMES_ARCHIVE" "$manifest_digest" "$config_digest" \
		"$image_os" "$image_arch" "$image_variant" "$attestation" "$root" \
		"$root/scripts/hermes-steward-acceptance.sh" \
		executor "$executor_bin" gateway "$gateway_bin" relay "$relay_bin" ctl "$ctl_bin" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import subprocess
import sys

(
    output_path,
    archive_path,
    manifest_digest,
    config_digest,
    image_os,
    image_arch,
    image_variant,
    attestation_path,
    source_root,
    script_path,
    *binary_fields,
) = sys.argv[1:]

VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+:/@ -]{0,255}")


def hash_file(path: pathlib.Path) -> tuple[str, int]:
    opened = path.open("rb")
    try:
        before = os.fstat(opened.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0:
            raise SystemExit(f"hermes-steward-acceptance: provenance input is not a regular file: {path.name}")
        digest = hashlib.sha256()
        observed = 0
        while True:
            chunk = opened.read(1 << 20)
            if not chunk:
                break
            observed += len(chunk)
            digest.update(chunk)
        after = os.fstat(opened.fileno())
        if observed != before.st_size or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise SystemExit(f"hermes-steward-acceptance: provenance input changed while hashing: {path.name}")
        return digest.hexdigest(), observed
    finally:
        opened.close()


def read_regular_nofollow(path: pathlib.Path, maximum: int) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum:
            raise SystemExit("hermes-steward-acceptance: build attestation is not a bounded regular file")
        data = bytearray()
        while len(data) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(descriptor)
        named = os.stat(path, follow_symlinks=False)
        identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
        if len(data) != before.st_size or len(data) > maximum or identity(before) != identity(after) or identity(after) != identity(named):
            raise SystemExit("hermes-steward-acceptance: build attestation changed while being read")
        return bytes(data)
    finally:
        os.close(descriptor)


archive = pathlib.Path(archive_path).resolve(strict=True)
archive_sha256, archive_size = hash_file(archive)
expected_platform = f"{image_os}/{image_arch}" + (f"/{image_variant}" if image_variant else "")

if len(binary_fields) != 8:
    raise SystemExit("hermes-steward-acceptance: internal binary provenance input is incomplete")
binaries = {}
for index in range(0, len(binary_fields), 2):
    name = binary_fields[index]
    path = pathlib.Path(binary_fields[index + 1]).resolve(strict=True)
    digest, _ = hash_file(path)
    completed = subprocess.run([str(path), "-version"], check=True, capture_output=True, text=True, timeout=10)
    version = completed.stdout.strip()
    if completed.stderr or VERSION.fullmatch(version) is None:
        raise SystemExit(f"hermes-steward-acceptance: invalid {name} version output")
    binaries[name] = {"sha256": digest, "version": version}

source = None
source_path = pathlib.Path(source_root)
if (source_path / ".git").exists():
    environment = dict(os.environ)
    for name in (
        "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_CEILING_DIRECTORIES", "GIT_COMMON_DIR",
        "GIT_CONFIG_COUNT", "GIT_CONFIG_PARAMETERS", "GIT_DIR", "GIT_EXEC_PATH",
        "GIT_INDEX_FILE", "GIT_NAMESPACE", "GIT_OBJECT_DIRECTORY", "GIT_SHALLOW_FILE",
        "GIT_TEMPLATE_DIR", "GIT_WORK_TREE",
    ):
        environment.pop(name, None)
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_GLOBAL"] = "/dev/null"
    environment["GIT_NO_REPLACE_OBJECTS"] = "1"

    def git(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                "git",
                "-c", "core.fsmonitor=false",
                "-c", "core.hooksPath=/dev/null",
                "-C", str(source_path),
                *arguments,
            ],
            check=check,
            capture_output=True,
            text=True,
            timeout=10,
            env=environment,
        )

    commit = git("rev-parse", "HEAD").stdout.strip()
    tree = git("rev-parse", "HEAD^{tree}").stdout.strip()
    worktree = git("diff", "--no-ext-diff", "--no-textconv", "--quiet", "--", check=False).returncode
    index = git("diff", "--cached", "--no-ext-diff", "--no-textconv", "--quiet", "--", check=False).returncode
    if not re.fullmatch(r"[a-f0-9]{40,64}", commit) or not re.fullmatch(r"[a-f0-9]{40,64}", tree) or worktree not in (0, 1) or index not in (0, 1):
        raise SystemExit("hermes-steward-acceptance: source provenance cannot be determined")
    source = {"commit": commit, "tracked_dirty": worktree == 1 or index == 1, "tree": tree}

script_sha256, _ = hash_file(pathlib.Path(script_path).resolve(strict=True))
build = None
if attestation_path:
    attestation_file = pathlib.Path(attestation_path)
    encoded = read_regular_nofollow(attestation_file, 64 << 10)
    try:
        document = json.loads(encoded)
    except (TypeError, ValueError) as error:
        raise SystemExit("hermes-steward-acceptance: build attestation is invalid JSON") from error
    if (
        not isinstance(document, dict)
        or document.get("schema_version") != "steward.hermes-adapter-build-attestation.v1"
        or document.get("contains_agent_content") is not False
        or not isinstance(document.get("archive"), dict)
        or document["archive"].get("sha256") != archive_sha256
        or document["archive"].get("size_bytes") != archive_size
        or not isinstance(document.get("image"), dict)
        or document["image"].get("manifest_digest") != manifest_digest
        or document["image"].get("config_digest") != config_digest
        or document["image"].get("runtime_image_id") not in {manifest_digest, config_digest}
        or document["image"].get("platform") != expected_platform
        or not isinstance(document.get("adapter"), dict)
        or document["adapter"].get("contract") != "steward.hermes-agent.v1"
        or not isinstance(document.get("source"), dict)
        or not isinstance(document.get("build_recipe"), dict)
    ):
        raise SystemExit("hermes-steward-acceptance: build attestation does not bind the accepted archive")

    def selected(mapping: dict, names: tuple[str, ...]) -> dict:
        result = {name: mapping[name] for name in names if name in mapping}
        if any(not isinstance(value, (str, int, bool)) for value in result.values()):
            raise SystemExit("hermes-steward-acceptance: build attestation contains invalid provenance fields")
        return result

    build = {
        "adapter": selected(
            document["adapter"],
            ("contract", "file_set_sha256", "git_tree", "release_manifest_sha256", "release_version", "source", "steward_commit"),
        ),
        "attestation_sha256": hashlib.sha256(encoded).hexdigest(),
        "build_recipe": selected(
            document["build_recipe"],
            (
                "base_image", "build_isolation", "builder_sha256", "dockerfile_sha256", "id",
                "network_scope", "source_inputs_sha256", "upstream_build_hooks_in_final_assembly",
            ),
        ),
        "schema_version": document["schema_version"],
        "source": selected(document["source"], ("archive_sha256", "git_tree", "repository", "revision")),
    }

payload = {
    "acceptance_script_sha256": script_sha256,
    "archive": {
        "config_digest": config_digest,
        "file": archive.name,
        "manifest_digest": manifest_digest,
        "platform": expected_platform,
        "sha256": archive_sha256,
        "size_bytes": archive_size,
    },
    "binaries": binaries,
    "build_attestation": build,
    "steward_source": source,
}
pathlib.Path(output_path).write_text(json.dumps(payload, separators=(",", ":"), sort_keys=True) + "\n", encoding="utf-8")
PY
}

write_success_evidence() {
	[[ -n $evidence_out ]] || return 0
	python3 -I - "$evidence_out" "$work/provenance.json" "$work/evidence-head.json" \
		"$work/steps" "$work/receipts.public" "$work/connector-evidence-head.json" \
		"$work/connectors.public" "$node_id/gateway" <<'PY' || return
import datetime
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

destination = pathlib.Path(sys.argv[1]).absolute()
provenance_path = pathlib.Path(sys.argv[2])
head_path = pathlib.Path(sys.argv[3])
steps_path = pathlib.Path(sys.argv[4])
public_key_path = pathlib.Path(sys.argv[5])
connector_head_path = pathlib.Path(sys.argv[6])
connector_public_key_path = pathlib.Path(sys.argv[7])
connector_node_id = sys.argv[8]
expected_steps = [
    "image_imported",
    "executor_ready",
    "generation_1_admitted",
    "generation_1_started",
    "generation_1_ready",
    "state_volume_observed",
    "workspace_seeded",
    "generation_1_skill_passed",
    "generation_1_connector_skill_passed",
    "connector_replay_denied",
    "connector_forbidden_denied",
    "connector_fixture_effect_verified",
    "connector_secret_absence_verified",
    "generation_1_destroyed",
    "generation_2_admitted",
    "generation_2_started",
    "generation_2_ready",
    "generation_2_skill_passed",
    "generation_2_destroyed",
    "state_purged",
    "evidence_chain_verified",
    "connector_evidence_chain_verified",
    "acceptance_complete",
]


def read_small_json(path: pathlib.Path) -> object:
    data = path.read_bytes()
    if not data or len(data) > 1 << 20:
        raise SystemExit("hermes-steward-acceptance: success evidence input is empty or oversized")
    try:
        return json.loads(data)
    except (TypeError, ValueError) as error:
        raise SystemExit("hermes-steward-acceptance: success evidence input is invalid JSON") from error


steps = steps_path.read_text(encoding="ascii").splitlines()
if steps != expected_steps:
    raise SystemExit("hermes-steward-acceptance: completed acceptance step set is invalid")
provenance = read_small_json(provenance_path)
verification = read_small_json(head_path)
if not isinstance(provenance, dict) or not isinstance(verification, dict) or verification.get("valid") is not True:
    raise SystemExit("hermes-steward-acceptance: success evidence metadata is invalid")
head = verification.get("head")
if (
    not isinstance(head, dict)
    or not isinstance(head.get("sequence"), int)
    or head["sequence"] <= 0
    or re.fullmatch(r"sha256:[a-f0-9]{64}", str(head.get("chain_hash", ""))) is None
):
    raise SystemExit("hermes-steward-acceptance: verified receipt-chain head is invalid")
public_key = public_key_path.read_bytes()
public_stat = public_key_path.stat()
if not stat.S_ISREG(public_stat.st_mode) or not public_key or len(public_key) > 1024:
    raise SystemExit("hermes-steward-acceptance: receipt public key is invalid")
connector_verification = read_small_json(connector_head_path)
connector_head = connector_verification.get("head") if isinstance(connector_verification, dict) else None
if (
    not isinstance(connector_verification, dict)
    or connector_verification.get("valid") is not True
    or connector_verification.get("kind") != "connector"
    or not isinstance(connector_head, dict)
    or set(connector_head) != {"chain_hash", "epoch", "key_id", "node_id", "sequence"}
    or connector_head.get("node_id") != connector_node_id
    or connector_head.get("epoch") != 1
    or connector_head.get("sequence") != 2
    or re.fullmatch(r"sha256:[a-f0-9]{64}", str(connector_head.get("chain_hash", ""))) is None
    or re.fullmatch(r"sha256:[a-f0-9]{64}", str(connector_head.get("key_id", ""))) is None
):
    raise SystemExit("hermes-steward-acceptance: verified connector receipt-chain head is invalid")
connector_public_key = connector_public_key_path.read_bytes()
connector_public_stat = connector_public_key_path.stat()
if not stat.S_ISREG(connector_public_stat.st_mode) or not connector_public_key or len(connector_public_key) > 1024:
    raise SystemExit("hermes-steward-acceptance: connector receipt public key is invalid")

payload = {
    "acceptance": {
        "completed_steps": steps,
        "runtime": "runsc",
        "signed_admission": True,
        "signed_connector_work": True,
    },
    "completed_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    "contains_agent_content": False,
    "overall": "passed",
    "provenance": provenance,
    "receipt_chain": {
        "head": head,
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "verified": True,
    },
    "connector_receipt_chain": {
        "head": connector_head,
        "public_key_sha256": hashlib.sha256(connector_public_key).hexdigest(),
        "verified": True,
    },
    "schema_version": "steward.hermes-integration-evidence.v1",
}
encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n"
if len(encoded) > 1 << 20:
    raise SystemExit("hermes-steward-acceptance: success evidence exceeds 1 MiB")

parent = destination.parent
if os.path.lexists(destination):
    raise SystemExit("hermes-steward-acceptance: evidence output already exists")
if not parent.is_dir() or parent.is_symlink() or parent.resolve() != parent:
    raise SystemExit("hermes-steward-acceptance: evidence output parent must be a real directory")
directory_flags = os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0)
directory_fd = os.open(parent, directory_flags)
temporary = f".{destination.name}.tmp-{os.getpid()}"
temporary_created = False
try:
    file_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    file_fd = os.open(temporary, file_flags, 0o600, dir_fd=directory_fd)
    temporary_created = True
    try:
        written = 0
        while written < len(encoded):
            written += os.write(file_fd, encoded[written:])
        os.fchmod(file_fd, 0o600)
        os.fsync(file_fd)
    finally:
        os.close(file_fd)
    os.link(temporary, destination.name, src_dir_fd=directory_fd, dst_dir_fd=directory_fd, follow_symlinks=False)
    os.unlink(temporary, dir_fd=directory_fd)
    temporary_created = False
    os.fsync(directory_fd)
finally:
    if temporary_created:
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
    os.close(directory_fd)
PY
	printf 'Hermes integration evidence: %s\n' "$evidence_out"
}

cleanup() {
	local status=$?
	if [[ $status -ne 0 && $debug_keep == YES ]]; then
		for container in $(docker ps -aq --filter "label=io.hardrails.tenant=$tenant_id" --filter "label=io.hardrails.instance=$instance_id"); do
			docker logs "$container" >"$work/docker-$container.log" 2>&1 || true
			docker inspect "$container" >"$work/docker-$container.inspect.json" 2>&1 || true
		done
	fi
	if [[ -n ${runtime_ref:-} && -n ${token:-} ]]; then
		curl -sS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null 2>&1 || true
	fi
	[[ -n ${executor_pid:-} ]] && kill "$executor_pid" 2>/dev/null || true
	[[ -n ${gateway_pid:-} ]] && kill "$gateway_pid" 2>/dev/null || true
	[[ -n ${model_pid:-} ]] && kill "$model_pid" 2>/dev/null || true
	[[ -n ${connector_fixture_pid:-} ]] && kill "$connector_fixture_pid" 2>/dev/null || true
	docker ps -aq --filter label=io.hardrails.relay.managed=true \
		--filter "label=io.hardrails.tenant=$tenant_id" \
		--filter "label=io.hardrails.instance=$instance_id" | xargs -r docker rm -f >/dev/null 2>&1 || true
	docker network ls -q --filter label=io.hardrails.network.managed=true \
		--filter "label=io.hardrails.tenant=$tenant_id" \
		--filter "label=io.hardrails.instance=$instance_id" | xargs -r docker network rm >/dev/null 2>&1 || true
	[[ -n ${state_volume:-} ]] && docker volume rm "$state_volume" >/dev/null 2>&1 || true
	[[ -n ${relay_tag:-} ]] && docker image rm "$relay_tag" >/dev/null 2>&1 || true
	for image_digest in "${imported_image_digests[@]}"; do
		docker image rm "$image_digest" >/dev/null 2>&1 || true
	done
	if [[ $status -eq 0 || $debug_keep == NO ]]; then
		rm -rf "$work"
	else
		echo "hermes-steward-acceptance: preserved diagnostics at $work" >&2
	fi
	exit "$status"
}
trap cleanup EXIT

if [[ -n $evidence_out ]]; then
	python3 -I - "$evidence_out" "$work" <<'PY'
import os
import pathlib
import sys

destination = pathlib.Path(sys.argv[1]).absolute()
work = pathlib.Path(sys.argv[2]).resolve()
parent = destination.parent
if os.path.lexists(destination):
    raise SystemExit("hermes-steward-acceptance: evidence output already exists")
if not parent.is_dir() or parent.is_symlink() or parent.resolve() != parent:
    raise SystemExit("hermes-steward-acceptance: evidence output parent must be a real directory")
try:
    destination.relative_to(work)
except ValueError:
    pass
else:
    raise SystemExit("hermes-steward-acceptance: evidence output cannot be inside the temporary workspace")
PY
fi

for entry in executor:steward-executor gateway:steward-gateway relay:steward-relay ctl:stewardctl; do
	variable=${entry%%:*}_bin
	package=${entry#*:}
	path=${!variable}
	[[ -x $path ]] || (cd "$root" && go build -o "$path" "./cmd/$package")
done

image_json=$($ctl_bin image inspect -archive "$HERMES_ARCHIVE")
mapfile -t image_values < <(python3 -I -c '
import json,sys
p=json.load(sys.stdin)
print(p["manifest_digest"])
print(p["config_digest"])
print(p["platform"]["os"])
print(p["platform"]["architecture"])
print(p["platform"].get("variant", ""))
' <<<"$image_json")
(( ${#image_values[@]} == 5 )) || { echo "hermes-steward-acceptance: incomplete archive identity" >&2; exit 1; }
manifest_digest=${image_values[0]}
config_digest=${image_values[1]}
image_os=${image_values[2]}
image_arch=${image_values[3]}
image_variant=${image_values[4]}
[[ $image_os == linux && $manifest_digest =~ ^sha256:[a-f0-9]{64}$ && $config_digest =~ ^sha256:[a-f0-9]{64}$ ]] || {
	echo "hermes-steward-acceptance: invalid archive identity" >&2
	exit 1
}
prepare_evidence_provenance

install -m 0755 "$relay_bin" "$work/steward-relay"
printf '%s\n' 'FROM scratch' 'COPY steward-relay /steward-relay' 'USER 65532:65532' 'ENTRYPOINT ["/steward-relay"]' >"$work/Relayfile"
relay_tag=steward-hermes-relay-acceptance:$run_id
docker build --network=none --pull=false --provenance=false -q -f "$work/Relayfile" -t "$relay_tag" "$work" >/dev/null
relay_image=$(docker image inspect --format '{{.Id}}' "$relay_tag")

python3 -I - "$root/adapters/hermes-agent/fixture_model.py" <<'PY' >"$work/model.log" 2>&1 &
import http.server
import importlib.util
import sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("fixture_model", sys.argv[1])
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
http.server.ThreadingHTTPServer(("127.0.0.1", 18080), module.Handler).serve_forever()
PY
model_pid=$!
for _ in $(seq 1 30); do
	curl -fsS http://127.0.0.1:18080/v1/models >/dev/null 2>&1 && break
	kill -0 "$model_pid" 2>/dev/null || { echo "hermes-steward-acceptance: model fixture exited" >&2; exit 1; }
	sleep 1
done
curl -fsS http://127.0.0.1:18080/v1/models >/dev/null

printf '%s\n' service-secret >"$work/service-token"
connector_secret=hermes-connector-$(od -An -N24 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$connector_secret" >"$work/connector-token"
"$ctl_bin" keygen -key-id connector-receipts -private-out "$work/connectors.private" \
	-public-out "$work/connectors.public" >/dev/null
python3 -I "$root/adapters/hermes-agent/fixture_connector.py" "$work/connector-token" \
	>"$work/connector-fixture.log" 2>&1 &
connector_fixture_pid=$!
for _ in $(seq 1 30); do
	curl -fsS "$connector_origin/health" >/dev/null 2>&1 && break
	kill -0 "$connector_fixture_pid" 2>/dev/null || { echo "hermes-steward-acceptance: connector fixture exited" >&2; exit 1; }
	sleep 1
done
curl -fsS "$connector_origin/health" >/dev/null
gid=$(id -g nobody 2>/dev/null || getent group nogroup | cut -d: -f3)
mkdir -p "$work/gateway" "$work/grants"
printf '%s\n' "{
  \"version\":1,
  \"control_socket\":\"$work/gateway/control.sock\",
  \"service_address\":\"127.0.0.1:18091\",
  \"service_token_file\":\"$work/service-token\",
  \"state_file\":\"$work/gateway-state.json\",
  \"grant_root\":\"$work/grants\",
  \"executor_gid\":$gid,
  \"relay_gid\":$gid,
  \"routes\":[{\"id\":\"local-openai\",\"base_url\":\"http://127.0.0.1:18080/v1\",\"max_concurrent\":2}],
  \"connector_receipt_file\":\"$work/connector-receipts.ndjson\",
  \"connector_receipt_key_file\":\"$work/connectors.private\",
  \"connector_receipt_node_id\":\"$node_id/gateway\",
  \"connector_receipt_epoch\":1,
  \"connector_receipt_tenant_budgets\":[{\"tenant_id\":\"$tenant_id\",\"bytes\":4194304}],
  \"connectors\":[{
    \"id\":\"$connector_id\",\"base_url\":\"$connector_origin\",\"credential_file\":\"$work/connector-token\",
    \"credential_mode\":\"bearer\",\"allow_insecure_http\":true,\"allowed_cidrs\":[\"127.0.0.0/8\"],
    \"max_concurrent\":1,\"max_request_bytes\":4096,\"max_response_bytes\":4096,
    \"max_seconds\":10,\"max_calls_per_grant\":1,
    \"operations\":[{\"id\":\"$connector_operation\",\"method\":\"POST\",\"path\":\"/v1/work/execute\"}]
  }]
}" >"$work/gateway.json"
"$gateway_bin" -config "$work/gateway.json" >"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 30); do [[ -S $work/gateway/control.sock ]] && break; sleep 1; done
[[ -S $work/gateway/control.sock ]] || { echo "hermes-steward-acceptance: Gateway did not become ready" >&2; exit 1; }
unset connector_secret

"$ctl_bin" keygen -key-id site-root -private-out "$work/site.private" -public-out "$work/site.public" >/dev/null
"$ctl_bin" keygen -key-id publisher -private-out "$work/publisher.private" -public-out "$work/publisher.public" >/dev/null
"$ctl_bin" keygen -key-id receipts -private-out "$work/receipts.private" -public-out "$work/receipts.public" >/dev/null
publisher_public=$(tr -d '\n' <"$work/publisher.public")
platform="\"os\":\"$image_os\",\"architecture\":\"$image_arch\""
[[ -z $image_variant ]] || platform+=",\"variant\":\"$image_variant\""
printf '%s\n' "{
  \"schema_version\":\"steward.admission.v1\",\"policy_id\":\"hermes-acceptance\",\"policy_epoch\":1,
  \"publishers\":[{\"key_id\":\"publisher\",\"public_key\":\"$publisher_public\",\"revoked\":false,
    \"allowed_profiles\":[{\"id\":\"hermes-v1\",\"version\":\"v1\"}],
    \"allowed_repositories\":[\"$repository\"],\"allowed_manifest_digests\":[\"$manifest_digest\"],
    \"resource_ceiling\":{\"memory_bytes\":536870912,\"cpu_millis\":1000,\"pids\":128}}],
  \"tenants\":[{\"tenant_id\":\"$tenant_id\",\"publisher_key_ids\":[\"publisher\"],
    \"resource_ceiling\":{\"memory_bytes\":536870912,\"cpu_millis\":1000,\"pids\":128},
    \"inference_route_ids\":[\"local-openai\"],\"inference_model_aliases\":[\"steward-fixture-model\"],
    \"service_ids\":[\"hermes-api\"],\"connector_ids\":[\"$connector_id\"]}]
}" >"$work/policy.json"
"$ctl_bin" policy sign -in "$work/policy.json" -out "$work/policy.dsse.json" -key "$work/site.private" -key-id site-root >/dev/null
printf '%s\n' "{
  \"schema_version\":\"steward.admission.v1\",\"capsule_id\":\"hermes-workspace-audit\",\"publisher_key_id\":\"publisher\",
  \"profile\":{\"id\":\"hermes-v1\",\"version\":\"v1\"},
  \"image\":{\"repository\":\"$repository\",\"manifest_digest\":\"$manifest_digest\",\"config_digest\":\"$config_digest\",\"platform\":{$platform}},
  \"command\":[\"serve\"],\"resources\":{\"memory_bytes\":536870912,\"cpu_millis\":1000,\"pids\":128},
  \"capabilities\":{\"state\":true,\"inference\":true,\"service\":true,\"egress\":false,\"connector\":true},
  \"state\":{\"schema_version\":\"v1\",\"path\":\"/opt/data\"},\"service\":{\"id\":\"hermes-api\",\"port\":8766}
}" >"$work/capsule.json"
capsule_digest=$("$ctl_bin" capsule sign -in "$work/capsule.json" -out "$work/capsule.dsse.json" -key "$work/publisher.private" -key-id publisher)
capsule_base64=$(base64 <"$work/capsule.dsse.json" | tr -d '\n')

import_result=$("$ctl_bin" image import -archive "$HERMES_ARCHIVE" -capsule "$work/capsule.dsse.json" \
	-policy "$work/policy.dsse.json" -site-root-public-key "$work/site.public" -site-root-key-id site-root)
image_imported=$(python3 -I -c 'import json,sys; p=json.load(sys.stdin); assert p["image"]["manifest_digest"]==sys.argv[1] and p["image"]["config_digest"]==sys.argv[2] and type(p.get("imported")) is bool; print("true" if p["imported"] else "false")' \
	"$manifest_digest" "$config_digest" <<<"$import_result")
if [[ $image_imported == true ]]; then
	imported_image_digests=("$manifest_digest")
	[[ $config_digest == "$manifest_digest" ]] || imported_image_digests+=("$config_digest")
fi
mark image_imported

token=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
printf '%s\n' "$token" >"$work/token"
"$executor_bin" -initialize-admission-fence -admission-fence-file "$work/fences.bin" >/dev/null
"$executor_bin" -token-file "$work/token" -admission-policy-file "$work/policy.dsse.json" \
	-admission-site-root-public-key-file "$work/site.public" -admission-site-root-key-id site-root \
	-admission-node-id "$node_id" -admission-allow-host-admin-intent -admission-fence-file "$work/fences.bin" \
	-admission-journal-file "$work/journal.bin" -admission-evidence-file "$work/evidence.bin" \
	-admission-evidence-key-file "$work/receipts.private" -allow-unquotaed-state-on-dedicated-host \
	-gateway-control-socket "$work/gateway/control.sock" -gateway-grant-root "$work/grants" \
	-relay-image "$relay_image" -relay-gid "$gid" >"$work/executor.log" 2>&1 &
executor_pid=$!
for _ in $(seq 1 30); do
	kill -0 "$executor_pid" 2>/dev/null || { echo "hermes-steward-acceptance: Executor exited" >&2; exit 1; }
	curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:8090/v1/readiness >/dev/null 2>&1 && break
	sleep 1
done
curl -fsS -H "Authorization: Bearer $token" http://127.0.0.1:8090/v1/readiness >/dev/null
mark executor_ready

admit() {
	local generation=$1 disposition=$2
	printf '%s\n' "{\"capsule_dsse_base64\":\"$capsule_base64\",\"intent\":{\"tenant_id\":\"$tenant_id\",\"node_id\":\"$node_id\",\"instance_id\":\"$instance_id\",\"lineage_id\":\"$lineage_id\",\"generation\":$generation,\"capsule_digest\":\"$capsule_digest\",\"resources\":{\"memory_bytes\":536870912,\"cpu_millis\":1000,\"pids\":128},\"capabilities\":{\"state\":true,\"inference\":true,\"service\":true,\"egress\":false,\"connector\":true},\"state_disposition\":\"$disposition\",\"inference_route_id\":\"local-openai\",\"model_alias\":\"steward-fixture-model\",\"service_id\":\"hermes-api\",\"connector_ids\":[\"$connector_id\"]}}" | \
		curl -sS -X POST http://127.0.0.1:8090/v1/admissions -H 'Content-Type: application/json' -H "Authorization: Bearer $token" --data-binary @-
}

extract_admission() {
	python3 -I -c 'import json,sys; p=json.load(sys.stdin); print(p["runtime_ref"]); print(p["grant_id"])'
}

require_admission() {
	python3 -I -c 'import json,sys; p=json.load(sys.stdin); ok=isinstance(p.get("runtime_ref"),str) and isinstance(p.get("grant_id"),str); print(json.dumps(p,separators=(",",":")),file=sys.stderr) if not ok else None; raise SystemExit(0 if ok else 1)'
}

run_workspace_audit() {
	local grant=$1 expected=$2 session=$3 response run_ref terminal status
	[[ $expected =~ ^sha256:[a-f0-9]{64}$ && $session =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || return 1
	response=$(python3 -I -c 'import json,sys; print(json.dumps({"input":"STEWARD_WORKSPACE_AUDIT","session_id":sys.argv[1]},separators=(",",":")))' \
		"$session" | curl -fsS -X POST "http://127.0.0.1:18091/v1/services/$grant/v1/runs" \
		-H 'Authorization: Bearer service-secret' -H 'Content-Type: application/json' --data-binary @-)
	run_ref=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin)["run_id"])' <<<"$response")
	[[ $run_ref =~ ^run_[a-f0-9]{32}$ ]] || return 1
	status=
	for _ in $(seq 1 180); do
		terminal=$(curl -fsS -H 'Authorization: Bearer service-secret' \
			"http://127.0.0.1:18091/v1/services/$grant/v1/runs/$run_ref")
		status=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' <<<"$terminal")
		[[ $status == completed ]] && break
		[[ $status == failed || $status == cancelled ]] && return 1
		sleep 1
	done
	[[ $status == completed ]] || return 1
	python3 -I -c 'import json,sys; p=json.load(sys.stdin); assert isinstance(p.get("output"),str) and sys.argv[1] in p["output"]' \
		"$expected" <<<"$terminal"
}

run_hermes_input() {
	local grant=$1 input=$2 session=$3 response run_ref terminal status
	response=$(python3 -I -c 'import json,sys; print(json.dumps({"input":sys.argv[1],"session_id":sys.argv[2]},separators=(",",":")))' \
		"$input" "$session" | curl -fsS -X POST "http://127.0.0.1:18091/v1/services/$grant/v1/runs" \
		-H 'Authorization: Bearer service-secret' -H 'Content-Type: application/json' --data-binary @-)
	run_ref=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin)["run_id"])' <<<"$response")
	[[ $run_ref =~ ^run_[a-f0-9]{32}$ ]] || return 1
	status=
	for _ in $(seq 1 180); do
		terminal=$(curl -fsS -H 'Authorization: Bearer service-secret' \
			"http://127.0.0.1:18091/v1/services/$grant/v1/runs/$run_ref")
		status=$(python3 -I -c 'import json,sys; print(json.load(sys.stdin).get("status",""))' <<<"$terminal")
		[[ $status == completed ]] && break
		[[ $status == failed || $status == cancelled ]] && return 1
		sleep 1
	done
	[[ $status == completed ]] || return 1
	printf '%s\n' "$terminal"
}

run_connector_assertion() {
	local grant=$1 marker=$2 mode=$3 terminal
	terminal=$(run_hermes_input "$grant" "$marker" "steward-connector-$run_id-$mode")
	python3 -I - "$mode" "$root/adapters/hermes-agent/fixtures/connector-skill/connector-fixture-contract.json" \
		"$terminal" <<'PY'
import json
import pathlib
import sys

mode = sys.argv[1]
contract = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
terminal = json.loads(sys.argv[3])
if terminal.get("status") != "completed" or not isinstance(terminal.get("output"), str):
    raise SystemExit("hermes-steward-acceptance: connector skill did not complete")
try:
    output = json.loads(terminal["output"])
except (TypeError, ValueError) as error:
    raise SystemExit("hermes-steward-acceptance: connector skill output is invalid JSON") from error
if mode == "perform":
    expected = contract["response"]
elif mode == "replay":
    expected = {
        "error": "connector_task_replayed",
        "schema_version": "steward.connector-work.denial.v1",
        "status": 409,
    }
elif mode == "forbidden":
    expected = {
        "error": "connector_denied",
        "schema_version": "steward.connector-work.denial.v1",
        "status": 403,
    }
else:
    raise SystemExit("hermes-steward-acceptance: invalid connector assertion mode")
if output != expected:
    raise SystemExit("hermes-steward-acceptance: connector skill returned an unexpected result")
PY
}

assert_agent_excludes_connector_material() {
	local runtime=$1 scanner=$root/adapters/hermes-agent/fixture_secret_scan.py inspect_file path presence
	inspect_file=$work/docker-$runtime.material-inspect.json
	docker inspect "$runtime" >"$inspect_file"
	python3 -I "$scanner" json "$work/connector-token" "$connector_origin" <"$inspect_file"
	python3 -I - "$inspect_file" <<'PY'
import json
import pathlib
import sys

documents = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
if not isinstance(documents, list) or len(documents) != 1 or not isinstance(documents[0], dict):
    raise SystemExit("hermes-steward-acceptance: agent container metadata is invalid")
container = documents[0]
host = container.get("HostConfig")
mounts = container.get("Mounts")
if (
    not isinstance(host, dict)
    or host.get("ReadonlyRootfs") is not True
    or set((host.get("Tmpfs") or {}).keys()) != {"/tmp"}
    or not isinstance(mounts, list)
    or len(mounts) != 1
    or not isinstance(mounts[0], dict)
    or mounts[0].get("Type") != "volume"
    or mounts[0].get("Destination") != "/opt/data"
    or mounts[0].get("RW") is not True
):
    raise SystemExit("hermes-steward-acceptance: agent writable mount topology is unexpected")
PY
	docker export "$runtime" | \
		python3 -I "$scanner" stream "$work/connector-token" "$connector_origin"
	for path in /opt/data /tmp /workspace /dev/shm; do
		presence=$(docker exec "$runtime" /opt/hermes/.venv/bin/python -I -c \
			'import os,stat,sys; p=sys.argv[1]; print("absent" if not os.path.lexists(p) else "directory" if stat.S_ISDIR(os.lstat(p).st_mode) else "unsafe")' "$path")
		case $presence in
		absent) continue ;;
		directory) ;;
		*) echo "hermes-steward-acceptance: agent scan path is unsafe: $path" >&2; return 1 ;;
		esac
		docker cp "$runtime:$path/." - | \
			python3 -I "$scanner" stream "$work/connector-token" "$connector_origin"
	done
}

wait_for_hermes() {
	local grant=$1 runtime=$2
	for _ in $(seq 1 120); do
		if curl -fsS -H 'Authorization: Bearer service-secret' \
			"http://127.0.0.1:18091/v1/services/$grant/health" >/dev/null 2>&1; then
			return 0
		fi
		[[ $(docker inspect --format '{{.State.Running}}' "$runtime" 2>/dev/null) == true ]] || return 1
		sleep 1
	done
	return 1
}

admission_response=$(admit 1 new)
require_admission <<<"$admission_response"
mapfile -t admission < <(extract_admission <<<"$admission_response")
runtime_ref=${admission[0]}
grant_id=${admission[1]}
connector_runtime_ref=$runtime_ref
connector_grant_id=$grant_id
mapfile -t connector_bindings < <(python3 -I -c '
import json,sys
p=json.load(sys.stdin)
print(p["policy_digest"])
print(p["route_policy_digest"])
' <<<"$admission_response")
connector_policy_digest=${connector_bindings[0]}
connector_route_policy_digest=${connector_bindings[1]}
[[ $connector_policy_digest =~ ^sha256:[a-f0-9]{64}$ && $connector_route_policy_digest =~ ^sha256:[a-f0-9]{64}$ ]] || {
	echo "hermes-steward-acceptance: admission omitted connector policy bindings" >&2
	exit 1
}
mark generation_1_admitted
curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$runtime_ref/start" -H "Authorization: Bearer $token" >/dev/null
mark generation_1_started
[[ $(docker inspect --format '{{.HostConfig.Runtime}}' "$runtime_ref") == runsc ]]
[[ $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$runtime_ref") == true ]]
wait_for_hermes "$grant_id" "$runtime_ref"
mark generation_1_ready
state_volume=$(docker inspect --format '{{range .Mounts}}{{if eq .Destination "/opt/data"}}{{.Name}}{{end}}{{end}}' "$runtime_ref")
[[ -n $state_volume ]]
mark state_volume_observed
docker exec -u 65532:65532 "$runtime_ref" sh -c 'mkdir -p /opt/data/workspace/nested && printf "alpha\n" > /opt/data/workspace/alpha.txt && printf "beta\n" > /opt/data/workspace/nested/beta.txt'
mark workspace_seeded
curl -fsS -H 'Authorization: Bearer service-secret' "http://127.0.0.1:18091/v1/services/$grant_id/health" | \
	python3 -I -c 'import json,sys; p=json.load(sys.stdin); assert p.get("status")=="ok" and p.get("platform")=="hermes-agent"'
generation_1_workspace_digest=$(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1],encoding="utf-8"))["manifest_digest"])' \
	"$root/adapters/hermes-agent/fixtures/skill/workspace-fixture-contract.json")
run_workspace_audit "$grant_id" "$generation_1_workspace_digest" "steward-integration-$run_id-generation-1"
mark generation_1_skill_passed
run_connector_assertion "$grant_id" "STEWARD_CONNECTOR_WORK task=$connector_task_id" perform
mark generation_1_connector_skill_passed
run_connector_assertion "$grant_id" "STEWARD_CONNECTOR_REPLAY task=$connector_task_id" replay
mark connector_replay_denied
run_connector_assertion "$grant_id" "STEWARD_CONNECTOR_FORBIDDEN task=$connector_forbidden_task_id" forbidden
mark connector_forbidden_denied
connector_fixture_status=$(curl -fsS "$connector_origin/status")
python3 -I - "$root/adapters/hermes-agent/fixtures/connector-skill/connector-fixture-contract.json" \
	"$connector_fixture_status" <<'PY'
import hashlib
import json
import pathlib
import sys

status = json.loads(sys.argv[2])
contract = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
request = json.dumps(contract["request"], separators=(",", ":"), sort_keys=True).encode()
if status != {
    "authenticated_calls": 1,
    "request_sha256": hashlib.sha256(request).hexdigest(),
    "status": "ok",
}:
    raise SystemExit("hermes-steward-acceptance: connector fixture observed unexpected effects")
PY
mark connector_fixture_effect_verified
assert_agent_excludes_connector_material "$runtime_ref"
mark connector_secret_absence_verified
docker exec -u 65532:65532 "$runtime_ref" sh -c 'printf "generation-two\n" > /opt/data/workspace/generation-two.txt'
generation_2_workspace_digest=$(python3 -I - "$root/adapters/hermes-agent/fixtures/skill/workspace-fixture-contract.json" <<'PY'
import hashlib
import json
import pathlib
import sys

contract = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
content = b"generation-two\n"
entries = list(contract["entries"])
entries.append({"path": "generation-two.txt", "sha256": hashlib.sha256(content).hexdigest(), "size": len(content)})
body = {
    "entries": sorted(entries, key=lambda item: item["path"].encode("utf-8")),
    "file_count": len(entries),
    "root": "workspace",
    "schema_version": "steward.workspace-audit.result.v1",
    "total_bytes": contract["total_bytes"] + len(content),
}
canonical = json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode()
print("sha256:" + hashlib.sha256(b"steward.workspace-audit.manifest.v1\x00" + canonical).hexdigest())
PY
)
curl -fsS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null
runtime_ref=
mark generation_1_destroyed

admission_response=$(admit 2 resume)
require_admission <<<"$admission_response"
mapfile -t admission < <(extract_admission <<<"$admission_response")
runtime_ref=${admission[0]}
grant_id=${admission[1]}
mark generation_2_admitted
curl -fsS -X POST "http://127.0.0.1:8090/v1/workloads/$runtime_ref/start" -H "Authorization: Bearer $token" >/dev/null
mark generation_2_started
wait_for_hermes "$grant_id" "$runtime_ref"
mark generation_2_ready
run_workspace_audit "$grant_id" "$generation_2_workspace_digest" "steward-integration-$run_id-generation-2"
mark generation_2_skill_passed
curl -fsS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null
runtime_ref=
mark generation_2_destroyed
curl -fsS -X POST http://127.0.0.1:8090/v1/state/purge -H 'Content-Type: application/json' \
	-H "Authorization: Bearer $token" \
	--data-binary "{\"tenant_id\":\"$tenant_id\",\"node_id\":\"$node_id\",\"lineage_id\":\"$lineage_id\",\"generation\":2}" >/dev/null
state_volume=
mark state_purged
"$ctl_bin" evidence verify -in "$work/evidence.bin" -public-key "$work/receipts.public" \
	-node-id "$node_id" -epoch 1 -json >"$work/evidence-head.json"
python3 -I - "$work/evidence-head.json" "$node_id" <<'PY'
import json
import pathlib
import re
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
head = document.get("head") if isinstance(document, dict) else None
if (
    set(document) != {"head", "valid"}
    or document.get("valid") is not True
    or not isinstance(head, dict)
    or set(head) != {"chain_hash", "epoch", "key_id", "node_id", "sequence"}
    or head.get("node_id") != sys.argv[2]
    or head.get("epoch") != 1
    or not isinstance(head.get("sequence"), int)
    or head["sequence"] <= 0
    or re.fullmatch(r"sha256:[a-f0-9]{64}", str(head.get("chain_hash", ""))) is None
    or re.fullmatch(r"[a-f0-9]{32}", str(head.get("key_id", ""))) is None
):
    raise SystemExit("hermes-steward-acceptance: evidence verification result is invalid")
PY
mark evidence_chain_verified
"$ctl_bin" evidence verify -kind connector -in "$work/connector-receipts.ndjson" \
	-public-key "$work/connectors.public" -node-id "$node_id/gateway" -epoch 1 \
	-expected-sequence 2 -json >"$work/connector-evidence-head.json"
python3 -I - "$work/connector-receipts.ndjson" "$work/connector-token" "$connector_origin" \
	"$root/adapters/hermes-agent/fixtures/connector-skill/connector-fixture-contract.json" \
	"$tenant_id" "$instance_id" "$connector_runtime_ref" "$capsule_digest" "$connector_policy_digest" \
	"$connector_route_policy_digest" "$connector_grant_id" "$connector_task_id" "$node_id/gateway" <<'PY'
import base64
import hashlib
import json
import pathlib
import stat
import sys

(
    ledger_path,
    token_path,
    origin,
    contract_path,
    tenant_id,
    instance_id,
    runtime_ref,
    capsule_digest,
    policy_digest,
    route_policy_digest,
    grant_id,
    task_id,
    node_id,
) = sys.argv[1:]
ledger_file = pathlib.Path(ledger_path)
ledger_stat = ledger_file.stat()
raw = ledger_file.read_bytes()
if (
    not stat.S_ISREG(ledger_stat.st_mode)
    or stat.S_IMODE(ledger_stat.st_mode) != 0o600
    or not 0 < len(raw) <= 256 << 10
    or len(raw) != ledger_stat.st_size
):
    raise SystemExit("hermes-steward-acceptance: connector receipt ledger is not a bounded owner-only file")
secret = pathlib.Path(token_path).read_bytes().strip()
netloc = origin.removeprefix("http://")
_host, separator, port = netloc.rpartition(":")
forbidden_material = (
    secret,
    origin.encode(),
    netloc.encode(),
    f":{port}".encode(),
    f": {port}".encode(),
    f"={port}".encode(),
    f'"{port}"'.encode(),
    str(pathlib.Path(token_path).resolve()).encode(),
    task_id.encode(),
)
if not secret or not separator or any(material in raw for material in forbidden_material):
    raise SystemExit("hermes-steward-acceptance: connector receipt ledger contains secret call material")
lines = raw.splitlines()
if len(lines) != 2:
    raise SystemExit("hermes-steward-acceptance: connector receipt ledger must contain one complete call")
receipts = []
for line in lines:
    if not 0 < len(line) <= 128 << 10:
        raise SystemExit("hermes-steward-acceptance: connector receipt line is oversized")
    envelope = json.loads(line)
    if set(envelope) != {"payload", "payloadType", "signatures"} or envelope["payloadType"] != "application/vnd.steward.connector-receipt.v1+json":
        raise SystemExit("hermes-steward-acceptance: connector receipt envelope is invalid")
    payload = base64.b64decode(envelope["payload"], validate=True)
    receipts.append(json.loads(payload))

contract = json.loads(pathlib.Path(contract_path).read_text(encoding="utf-8"))
request = json.dumps(contract["request"], separators=(",", ":"), sort_keys=True).encode()
response = json.dumps(contract["response"], separators=(",", ":"), sort_keys=True).encode()
task_hash = hashlib.sha256()
task_hash.update(b"steward-gateway-connector-call-v1\x00")
for value in (tenant_id, instance_id, task_id, contract["connector_id"], contract["operation_id"]):
    task_hash.update(value.encode())
    task_hash.update(b"\x00")
task_digest = "sha256:" + task_hash.hexdigest()

for index, receipt in enumerate(receipts, 1):
    if (
        set(receipt) != {"epoch", "event", "node_id", "observed_at", "previous_hash", "schema_version", "sequence"}
        or receipt.get("schema_version") != "steward.connector-receipt.v1"
        or receipt.get("node_id") != node_id
        or receipt.get("epoch") != 1
        or receipt.get("sequence") != index
        or not isinstance(receipt.get("observed_at"), str)
    ):
        raise SystemExit("hermes-steward-acceptance: connector receipt provenance is invalid")
    event = receipt["event"]
    if (
        event.get("tenant_id") != tenant_id
        or event.get("runtime_ref") != runtime_ref
        or event.get("capsule_digest") != capsule_digest
        or event.get("policy_digest") != policy_digest
        or event.get("route_policy_digest") != route_policy_digest
        or event.get("generation") != 1
        or event.get("grant_id") != grant_id
        or event.get("connector_id") != contract["connector_id"]
        or event.get("operation_id") != contract["operation_id"]
        or event.get("task_digest") != task_digest
        or event.get("request_bytes") != len(request)
        or event.get("error_code", "") != ""
    ):
        raise SystemExit("hermes-steward-acceptance: connector receipt is not bound to the admitted call")

authorize, terminal = (receipt["event"] for receipt in receipts)
if (
    authorize.get("phase") != "authorize"
    or authorize.get("outcome") != "allowed"
    or authorize.get("response_bytes") != 0
    or "http_status" in authorize
    or terminal.get("phase") != "terminal"
    or terminal.get("outcome") != "responded"
    or terminal.get("http_status") != 200
    or terminal.get("response_bytes") != len(response)
):
    raise SystemExit("hermes-steward-acceptance: connector receipt phases do not prove a completed upstream response")
PY
mark connector_evidence_chain_verified
mark acceptance_complete
write_success_evidence
echo "Hermes Steward acceptance passed: signed import, gVisor, Gateway inference, service and connector work, replay denial, resume, purge, and receipts verified."
