#!/usr/bin/env bash
# Signed-admission and tenant-task proof that Hermes executes bundled workspace and connector skills through Steward.
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
task_key_id=tenant-task
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
    "service_task_replay_verified",
    "generation_1_connector_skill_passed",
    "connector_replay_denied",
    "connector_forbidden_denied",
    "connector_fixture_effect_verified",
    "connector_secret_absence_verified",
    "tenant_task_private_key_agent_absence_verified",
    "generation_1_destroyed",
    "generation_2_admitted",
    "generation_2_started",
    "generation_2_ready",
    "generation_2_skill_passed",
    "generation_2_destroyed",
    "state_purged",
    "evidence_chain_verified",
    "connector_evidence_chain_verified",
    "service_task_audit_verified",
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
    or not isinstance(connector_head.get("sequence"), int)
    or connector_head["sequence"] < 4
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
        "signed_service_tasks": True,
        "task_private_key_agent_absence_verified": True,
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
printf %s "$connector_secret" >"$work/connector-token"
"$ctl_bin" keygen -key-id connector-receipts -private-out "$work/connectors.private" \
	-public-out "$work/connectors.public" >/dev/null
"$ctl_bin" keygen -key-id "$task_key_id" -private-out "$work/task.private" \
	-public-out "$work/task.public" >/dev/null
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
"$ctl_bin" gateway service set -config "$work/gateway.json" -service-id hermes-api \
	-operation hermes.run=POST:/v1/runs -max-request-bytes 65536 -max-response-bytes 1048576 \
	-lifecycle hermes.run=/v1/runs/ -status-max-seconds 15 -poll-interval 1s \
	-max-seconds 120 -max-permit-seconds 300 >"$work/service-setup.json"
"$ctl_bin" gateway service trust -config "$work/gateway.json" -node-id "$node_id" \
	-tenant-id "$tenant_id" >"$work/service-trust.json"
"$ctl_bin" gateway validate -config "$work/gateway.json" >/dev/null
"$gateway_bin" -config "$work/gateway.json" >"$work/gateway.log" 2>&1 &
gateway_pid=$!
for _ in $(seq 1 30); do [[ -S $work/gateway/control.sock ]] && break; sleep 1; done
[[ -S $work/gateway/control.sock ]] || { echo "hermes-steward-acceptance: Gateway did not become ready" >&2; exit 1; }
unset connector_secret

"$ctl_bin" keygen -key-id site-root -private-out "$work/site.private" -public-out "$work/site.public" >/dev/null
"$ctl_bin" keygen -key-id publisher -private-out "$work/publisher.private" -public-out "$work/publisher.public" >/dev/null
"$ctl_bin" keygen -key-id receipts -private-out "$work/receipts.private" -public-out "$work/receipts.public" >/dev/null
publisher_public=$(tr -d '\n' <"$work/publisher.public")
task_public=$(tr -d '\n' <"$work/task.public")
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
    \"service_ids\":[\"hermes-api\"],\"connector_ids\":[\"$connector_id\"],
    \"task_keys\":[{\"key_id\":\"$task_key_id\",\"public_key\":\"$task_public\",\"service_ids\":[\"hermes-api\"]}]}]
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
	local intent_path=$work/intent-g$generation.json
	local request_path=$work/admission-request-g$generation.json
	local response_path=$work/admission-g$generation.json
	printf '%s\n' "{\"tenant_id\":\"$tenant_id\",\"node_id\":\"$node_id\",\"instance_id\":\"$instance_id\",\"lineage_id\":\"$lineage_id\",\"generation\":$generation,\"capsule_digest\":\"$capsule_digest\",\"resources\":{\"memory_bytes\":536870912,\"cpu_millis\":1000,\"pids\":128},\"capabilities\":{\"state\":true,\"inference\":true,\"service\":true,\"egress\":false,\"connector\":true},\"state_disposition\":\"$disposition\",\"inference_route_id\":\"local-openai\",\"model_alias\":\"steward-fixture-model\",\"service_id\":\"hermes-api\",\"connector_ids\":[\"$connector_id\"]}" >"$intent_path"
	python3 -I - "$intent_path" "$capsule_base64" <<'PY' >"$request_path"
import json
import pathlib
import sys

intent = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
print(json.dumps({"capsule_dsse_base64": sys.argv[2], "intent": intent}, separators=(",", ":")))
PY
	curl -sS -X POST http://127.0.0.1:8090/v1/admissions -H 'Content-Type: application/json' \
		-H "Authorization: Bearer $token" --data-binary "@$request_path" >"$response_path"
	cat "$response_path"
}

extract_admission() {
	python3 -I -c 'import json,sys; p=json.load(sys.stdin); print(p["runtime_ref"]); print(p["grant_id"])'
}

require_admission() {
	python3 -I -c 'import json,sys; p=json.load(sys.stdin); ok=isinstance(p.get("runtime_ref"),str) and isinstance(p.get("grant_id"),str); print(json.dumps(p,separators=(",",":")),file=sys.stderr) if not ok else None; raise SystemExit(0 if ok else 1)'
}

run_workspace_audit() {
	local generation=$1 expected=$2 session=$3 replay=${4:-no} terminal
	[[ $expected =~ ^sha256:[a-f0-9]{64}$ && $session =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || return 1
	terminal=$(run_signed_hermes "$generation" "workspace-g$generation" \
		"STEWARD_WORKSPACE_AUDIT" "$session" "$replay")
	python3 -I -c 'import json,sys; p=json.load(sys.stdin); assert isinstance(p.get("output"),str) and sys.argv[1] in p["output"]' \
		"$expected" <<<"$terminal"
}

run_signed_hermes() {
	local generation=$1 label=$2 input=$3 session=$4 replay=${5:-no}
	local request_path=$work/task-$label.request.json
	local bundle_path=$work/task-$label.bundle.json
	local issue_path=$work/task-$label.issue.json
	local terminal_path=$work/task-$label.terminal.json
	[[ $generation =~ ^[12]$ && $label =~ ^[a-z0-9][a-z0-9-]{0,63}$ && \
		$session =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]] || return 1
	[[ $replay == yes || $replay == no ]] || return 1
	python3 -I -c 'import json,sys; print(json.dumps({"input":sys.argv[1],"session_id":sys.argv[2]},separators=(",",":")))' \
		"$input" "$session" >"$request_path"
	"$ctl_bin" task issue -admission "$work/admission-g$generation.json" \
		-intent "$work/intent-g$generation.json" -trust "$work/service-trust.json" \
		-request "$request_path" -operation-id hermes.run -key "$work/task.private" \
		-key-id "$task_key_id" -out "$bundle_path" >"$issue_path"
	if [[ $replay == yes ]]; then
		"$ctl_bin" task submit -bundle "$bundle_path" -gateway-url http://127.0.0.1:18091 \
			-token-file "$work/service-token" >"$work/task-$label.first.json"
		"$ctl_bin" task submit -bundle "$bundle_path" -gateway-url http://127.0.0.1:18091 \
			-token-file "$work/service-token" >"$work/task-$label.replay.json"
		python3 -I - "$work/task-$label.first.json" "$work/task-$label.replay.json" "$issue_path" <<'PY'
import json
import pathlib
import re
import sys

first = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
replay = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
issue = json.loads(pathlib.Path(sys.argv[3]).read_text(encoding="utf-8"))
if (
    set(first) != {"task_digest", "permit_digest", "run_id", "receipt"}
    or set(replay) != set(first)
    or first["task_digest"] != replay["task_digest"]
    or first["permit_digest"] != replay["permit_digest"]
    or first["run_id"] != replay["run_id"]
    or first["permit_digest"] != issue.get("permit_digest")
    or re.fullmatch(r"sha256:[a-f0-9]{64}", str(first.get("task_digest", ""))) is None
    or re.fullmatch(r"run_[a-f0-9]{32}", str(first.get("run_id", ""))) is None
    or first.get("receipt") != "recorded"
    or replay.get("receipt") != "replayed"
):
    raise SystemExit("hermes-steward-acceptance: identical task bundle did not replay one durable dispatch")
PY
		: >"$work/service-task-replay.verified"
	else
		"$ctl_bin" task submit -bundle "$bundle_path" -gateway-url http://127.0.0.1:18091 \
			-token-file "$work/service-token" >"$work/task-$label.submit.json"
	fi
	"$ctl_bin" task wait -bundle "$bundle_path" -gateway-url http://127.0.0.1:18091 \
		-token-file "$work/service-token" -wait-timeout 3m -result-out "$terminal_path" \
		>"$work/task-$label.wait.json"
	python3 -I - "$work/task-$label.wait.json" "$terminal_path" <<'PY'
import hashlib
import json
import pathlib
import re
import sys

status = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
raw = pathlib.Path(sys.argv[2]).read_bytes()
terminal = json.loads(raw)
if (
    status.get("schema_version") != "steward.task-status.v1"
    or status.get("phase") != "terminal"
    or status.get("state") != "agent_reported_completed"
    or status.get("task_status") != "agent_reported_completed"
    or status.get("observed_status") != "completed"
    or status.get("response_bytes") != len(raw)
    or status.get("result_digest") != "sha256:" + hashlib.sha256(raw).hexdigest()
    or status.get("run_id") != terminal.get("run_id")
    or terminal.get("status") != "completed"
    or re.fullmatch(r"run_[a-f0-9]{32}", str(terminal.get("run_id", ""))) is None
):
    raise SystemExit("hermes-steward-acceptance: terminal result is not bound to verified lifecycle evidence")
PY
	cat "$terminal_path"
}

run_connector_assertion() {
	local generation=$1 label=$2 marker=$3 mode=$4 terminal
	terminal=$(run_signed_hermes "$generation" "$label" "$marker" "steward-connector-$run_id-$mode")
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

scan_agent_sensitive_material() {
	local mode=$1
	python3 -I -c '
import base64, json, os, pathlib, stat, sys
mode, key_path_text, connector_path_text, service_path_text, executor_path_text, origin = sys.argv[1:]
if mode not in {"json", "stream"}:
    raise SystemExit("hermes-steward-acceptance: invalid agent-material scan mode")


def read_owner_file(path: pathlib.Path) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077 or not 0 < info.st_size <= 16384:
        raise SystemExit(f"hermes-steward-acceptance: sensitive host file is unsafe: {path.name}")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        parts = []
        observed = 0
        while observed <= 16384:
            chunk = os.read(descriptor, min(65536, 16385 - observed))
            if not chunk:
                break
            parts.append(chunk)
            observed += len(chunk)
        final = os.fstat(descriptor)
        named = path.lstat()
    finally:
        os.close(descriptor)
    data = b"".join(parts)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if len(data) != info.st_size or identity(info) != identity(opened) or identity(opened) != identity(final) or identity(final) != identity(named):
        raise SystemExit(f"hermes-steward-acceptance: sensitive host file changed while being read: {path.name}")
    return data


def common_encodings(value: bytes) -> tuple[bytes, ...]:
    if not value:
        return ()
    encoded = [
        value,
        base64.b64encode(value),
        base64.b64encode(value).rstrip(b"="),
        base64.urlsafe_b64encode(value),
        base64.urlsafe_b64encode(value).rstrip(b"="),
        base64.b32encode(value),
        base64.b32encode(value).rstrip(b"="),
        value.hex().encode(),
        value.hex().upper().encode(),
    ]
    try:
        text = value.decode("ascii")
    except UnicodeDecodeError:
        pass
    else:
        encoded.append(json.dumps(text, ensure_ascii=True)[1:-1].encode())
    return tuple(encoded)


key_path = pathlib.Path(key_path_text)
key = read_owner_file(key_path)
lines = key.splitlines()
if lines[:1] != [b"-----BEGIN PRIVATE KEY-----"] or lines[-1:] != [b"-----END PRIVATE KEY-----"] or len(lines) < 3:
    raise SystemExit("hermes-steward-acceptance: task signing key is not one PKCS#8 PEM block")
try:
    der = base64.b64decode(b"".join(lines[1:-1]), validate=True)
except ValueError as error:
    raise SystemExit("hermes-steward-acceptance: task signing key PEM is invalid") from error
if len(der) < 32 or b"\x04\x20" not in der or not der.endswith(b"\x04\x20" + der[-32:]):
    raise SystemExit("hermes-steward-acceptance: task signing key is not canonical Ed25519 PKCS#8")
seed = der[-32:]
escaped_key = json.dumps(key.decode("ascii"), ensure_ascii=True)[1:-1].encode()
escaped_trimmed_key = json.dumps(key.rstrip(b"\n").decode("ascii"), ensure_ascii=True)[1:-1].encode()
patterns = []
for value in (key, key.rstrip(b"\n"), der, seed):
    patterns.extend(common_encodings(value))
patterns.extend((escaped_key, escaped_trimmed_key, os.fsencode(key_path.resolve(strict=True))))
for token_path_text in (connector_path_text, service_path_text, executor_path_text):
    token_path = pathlib.Path(token_path_text)
    raw_token = read_owner_file(token_path)
    token = raw_token.strip()
    if not token or b"\n" in token or b"\r" in token:
        raise SystemExit(f"hermes-steward-acceptance: sensitive bearer value is invalid: {token_path.name}")
    patterns.extend(common_encodings(raw_token))
    patterns.extend(common_encodings(token))
    patterns.append(os.fsencode(token_path.resolve(strict=True)))
netloc = origin.removeprefix("http://")
_host, separator, port = netloc.rpartition(":")
if not separator or not port.isascii() or not port.isdigit():
    raise SystemExit("hermes-steward-acceptance: connector origin is invalid")
patterns.extend((
    origin.encode(), netloc.encode(), f":{port}".encode(), f": {port}".encode(),
    f"={port}".encode(), ("\"" + port + "\"").encode(),
))
patterns = tuple(dict.fromkeys(pattern for pattern in patterns if pattern))
limit = (1 << 20) if mode == "json" else (2 << 30)
overlap = max(map(len, patterns)) - 1
carry = b""
total = 0
while True:
    chunk = sys.stdin.buffer.read(1 << 20)
    if not chunk:
        break
    total += len(chunk)
    if total > limit:
        raise SystemExit("hermes-steward-acceptance: agent material exceeds sensitive-material scan limit")
    combined = carry + chunk
    if any(pattern in combined for pattern in patterns):
        raise SystemExit("hermes-steward-acceptance: sensitive host authority or bearer material reached the untrusted agent")
    carry = combined[-overlap:] if overlap else b""
if total == 0:
    raise SystemExit("hermes-steward-acceptance: agent material stream is empty")
' "$mode" "$work/task.private" "$work/connector-token" "$work/service-token" "$work/token" "$connector_origin"
}

assert_agent_excludes_sensitive_material() {
	local runtime=$1 inspect_file path presence
	inspect_file=$work/docker-$runtime.material-inspect.json
	docker inspect "$runtime" >"$inspect_file"
	scan_agent_sensitive_material json <"$inspect_file"
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
	docker export "$runtime" | scan_agent_sensitive_material stream
	for path in /opt/data /tmp /workspace /dev/shm; do
		presence=$(docker exec "$runtime" /opt/hermes/.venv/bin/python -I -c \
			'import os,stat,sys; p=sys.argv[1]; print("absent" if not os.path.lexists(p) else "directory" if stat.S_ISDIR(os.lstat(p).st_mode) else "unsafe")' "$path")
		case $presence in
		absent) continue ;;
		directory) ;;
		*) echo "hermes-steward-acceptance: agent scan path is unsafe: $path" >&2; return 1 ;;
		esac
		docker cp "$runtime:$path/." - | scan_agent_sensitive_material stream
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
run_workspace_audit 1 "$generation_1_workspace_digest" "steward-integration-$run_id-generation-1" yes
mark generation_1_skill_passed
[[ -f $work/service-task-replay.verified ]]
mark service_task_replay_verified
run_connector_assertion 1 connector-perform "STEWARD_CONNECTOR_WORK task=$connector_task_id" perform
mark generation_1_connector_skill_passed
run_connector_assertion 1 connector-replay "STEWARD_CONNECTOR_REPLAY task=$connector_task_id" replay
mark connector_replay_denied
run_connector_assertion 1 connector-forbidden "STEWARD_CONNECTOR_FORBIDDEN task=$connector_forbidden_task_id" forbidden
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
assert_agent_excludes_sensitive_material "$runtime_ref"
mark connector_secret_absence_verified
mark tenant_task_private_key_agent_absence_verified
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
[[ $(docker inspect --format '{{.HostConfig.Runtime}}' "$runtime_ref") == runsc ]]
[[ $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$runtime_ref") == true ]]
wait_for_hermes "$grant_id" "$runtime_ref"
mark generation_2_ready
run_workspace_audit 2 "$generation_2_workspace_digest" "steward-integration-$run_id-generation-2"
mark generation_2_skill_passed
assert_agent_excludes_sensitive_material "$runtime_ref"
curl -fsS -X DELETE "http://127.0.0.1:8090/v1/workloads/$runtime_ref" -H "Authorization: Bearer $token" >/dev/null
runtime_ref=
mark generation_2_destroyed
curl -fsS -X POST http://127.0.0.1:8090/v1/state/purge -H 'Content-Type: application/json' \
	-H "Authorization: Bearer $token" \
	--data-binary "{\"tenant_id\":\"$tenant_id\",\"node_id\":\"$node_id\",\"lineage_id\":\"$lineage_id\",\"generation\":2}" >/dev/null
volume_inventory=$(docker volume ls --quiet)
if grep -Fqx -- "$state_volume" <<<"$volume_inventory"; then
	echo "hermes-steward-acceptance: state purge left the lineage volume present" >&2
	exit 1
fi
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
	-json >"$work/connector-evidence-head.json"
mapfile -t gateway_receipt_head < <(python3 -I -c '
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
head = document["head"]
print(head["sequence"])
print(head["chain_hash"])
' "$work/connector-evidence-head.json")
[[ ${#gateway_receipt_head[@]} -eq 2 && ${gateway_receipt_head[0]} =~ ^[1-9][0-9]*$ && \
	${gateway_receipt_head[1]} =~ ^sha256:[a-f0-9]{64}$ ]]
"$ctl_bin" task audit -in "$work/task-workspace-g1.bundle.json" -public-key "$work/task.public" \
	-key-id "$task_key_id" -receipts "$work/connector-receipts.ndjson" \
	-receipt-public-key "$work/connectors.public" -receipt-node-id "$node_id/gateway" -receipt-epoch 1 \
	-request "$work/task-workspace-g1.request.json" -expected-sequence "${gateway_receipt_head[0]}" \
	-expected-chain-hash "${gateway_receipt_head[1]}" >"$work/service-task-audit.json"
python3 -I - "$work/connector-receipts.ndjson" "$work/connector-evidence-head.json" \
	"$work/service-task-audit.json" "$work" "$work/connector-token" "$work/service-token" \
	"$work/token" "$work/task.private" "$connector_origin" \
	"$root/adapters/hermes-agent/fixtures/connector-skill/connector-fixture-contract.json" \
	"$tenant_id" "$instance_id" "$connector_runtime_ref" "$capsule_digest" "$connector_policy_digest" \
	"$connector_route_policy_digest" "$connector_grant_id" "$connector_task_id" "$connector_forbidden_task_id" \
	"$node_id/gateway" "$task_key_id" <<'PY'
import base64
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

(
    ledger_path,
    head_path,
    task_audit_path,
    work_path,
    token_path,
    service_token_path,
    executor_token_path,
    task_private_path,
    origin,
    contract_path,
    tenant_id,
    instance_id,
    runtime_ref,
    capsule_digest,
    policy_digest,
    route_policy_digest,
    grant_id,
    connector_task_id,
    connector_forbidden_task_id,
    node_id,
    task_key_id,
) = sys.argv[1:]
work = pathlib.Path(work_path)


def read_owner_file(path: pathlib.Path, maximum: int) -> bytes:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != 0o600 or not 0 < info.st_size <= maximum:
        raise SystemExit(f"hermes-steward-acceptance: owner-only task artifact is unsafe: {path.name}")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        parts = []
        observed = 0
        while observed <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - observed))
            if not chunk:
                break
            parts.append(chunk)
            observed += len(chunk)
        final = os.fstat(descriptor)
        named = path.lstat()
    finally:
        os.close(descriptor)
    data = b"".join(parts)
    identity = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    if len(data) != info.st_size or identity(info) != identity(opened) or identity(opened) != identity(final) or identity(final) != identity(named):
        raise SystemExit(f"hermes-steward-acceptance: task artifact changed while being read: {path.name}")
    return data


ledger_file = pathlib.Path(ledger_path)
ledger_stat = ledger_file.stat()
raw = ledger_file.read_bytes()
if (
    not stat.S_ISREG(ledger_stat.st_mode)
    or stat.S_IMODE(ledger_stat.st_mode) != 0o600
    or not 0 < len(raw) <= 4 << 20
    or len(raw) != ledger_stat.st_size
):
    raise SystemExit("hermes-steward-acceptance: connector receipt ledger is not a bounded owner-only file")
secret = pathlib.Path(token_path).read_bytes().strip()
service_token = pathlib.Path(service_token_path).read_bytes().strip()
executor_token = pathlib.Path(executor_token_path).read_bytes().strip()
task_private = read_owner_file(pathlib.Path(task_private_path), 16384)
task_private_lines = task_private.splitlines()
try:
    task_private_der = base64.b64decode(b"".join(task_private_lines[1:-1]), validate=True)
except ValueError as error:
    raise SystemExit("hermes-steward-acceptance: task private key PEM is invalid") from error
if (
    task_private_lines[:1] != [b"-----BEGIN PRIVATE KEY-----"]
    or task_private_lines[-1:] != [b"-----END PRIVATE KEY-----"]
    or len(task_private_der) < 32
    or not task_private_der.endswith(b"\x04\x20" + task_private_der[-32:])
):
    raise SystemExit("hermes-steward-acceptance: task private key is not canonical Ed25519 PKCS#8")
task_private_seed = task_private_der[-32:]
task_private_escaped = json.dumps(task_private.decode("ascii"), ensure_ascii=True)[1:-1].encode()
task_private_trimmed_escaped = json.dumps(task_private.rstrip(b"\n").decode("ascii"), ensure_ascii=True)[1:-1].encode()
netloc = origin.removeprefix("http://")
_host, separator, port = netloc.rpartition(":")
forbidden_material = [
    secret,
    service_token,
    executor_token,
    task_private,
    task_private_der,
    task_private_seed,
    base64.b64encode(task_private),
    base64.b64encode(task_private_der),
    base64.b64encode(task_private_seed),
    base64.b64encode(task_private_seed).rstrip(b"="),
    task_private_der.hex().encode(),
    task_private_seed.hex().encode(),
    task_private_seed.hex().upper().encode(),
    task_private_escaped,
    task_private_trimmed_escaped,
    origin.encode(),
    netloc.encode(),
    f":{port}".encode(),
    f": {port}".encode(),
    f"={port}".encode(),
    f'"{port}"'.encode(),
    str(pathlib.Path(token_path).resolve()).encode(),
    str(pathlib.Path(service_token_path).resolve()).encode(),
    str(pathlib.Path(executor_token_path).resolve()).encode(),
    str(pathlib.Path(task_private_path).resolve()).encode(),
    connector_task_id.encode(),
    connector_forbidden_task_id.encode(),
]
issue_by_permit = {}


def service_task_digest(task_id: str) -> str:
    digest = hashlib.sha256()
    digest.update(b"steward-task-permit-spend-v1\x00")
    for value in (tenant_id, instance_id, task_id):
        encoded = value.encode()
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return "sha256:" + digest.hexdigest()


for issue_path in sorted(work.glob("task-*.issue.json")):
    issue = json.loads(read_owner_file(issue_path, 4096))
    if set(issue) != {"bundle_path", "permit_digest", "request_digest", "task_id"}:
        raise SystemExit("hermes-steward-acceptance: task issue metadata is invalid")
    stem = issue_path.name.removesuffix(".issue.json")
    request_path = work / f"{stem}.request.json"
    bundle_path = work / f"{stem}.bundle.json"
    terminal_path = work / f"{stem}.terminal.json"
    submit_path = work / f"{stem}.submit.json"
    replay_path = work / f"{stem}.replay.json"
    request = read_owner_file(request_path, 65536)
    read_owner_file(bundle_path, 128 << 10)
    terminal_raw = read_owner_file(terminal_path, 1 << 20)
    terminal_document = json.loads(terminal_raw)
    dispatch_paths = [path for path in (submit_path, replay_path) if path.exists()]
    if len(dispatch_paths) != 1:
        raise SystemExit("hermes-steward-acceptance: task has no unique durable dispatch metadata")
    dispatch = json.loads(read_owner_file(dispatch_paths[0], 4096))
    if (
        not request
        or len(request) > 65536
        or issue.get("bundle_path") != str(bundle_path)
        or re.fullmatch(r"sha256:[a-f0-9]{64}", str(issue.get("permit_digest", ""))) is None
        or re.fullmatch(r"sha256:[a-f0-9]{64}", str(issue.get("request_digest", ""))) is None
        or issue.get("request_digest") != "sha256:" + hashlib.sha256(request).hexdigest()
        or re.fullmatch(r"task-[a-f0-9]{32}", str(issue.get("task_id", ""))) is None
        or issue["permit_digest"] in issue_by_permit
        or set(dispatch) != {"task_digest", "permit_digest", "run_id", "receipt"}
        or dispatch.get("permit_digest") != issue["permit_digest"]
        or dispatch.get("receipt") not in {"recorded", "replayed"}
        or dispatch.get("run_id") != terminal_document.get("run_id")
        or terminal_document.get("status") != "completed"
    ):
        raise SystemExit("hermes-steward-acceptance: task issue binding is invalid")
    request_document = json.loads(request)
    if set(request_document) != {"input", "session_id"} or not isinstance(request_document["input"], str):
        raise SystemExit("hermes-steward-acceptance: exact task request is invalid")
    output = terminal_document.get("output")
    if not isinstance(output, str):
        raise SystemExit("hermes-steward-acceptance: completed task has no string output")
    forbidden_material.extend((
        request,
        request_document["input"].encode(),
        issue["task_id"].encode(),
        terminal_raw,
        output.encode(),
    ))
    issue_by_permit[issue["permit_digest"]] = (
        issue,
        len(request),
        service_task_digest(issue["task_id"]),
        dispatch["run_id"],
        len(terminal_raw),
        "sha256:" + hashlib.sha256(terminal_raw).hexdigest(),
    )
if len(issue_by_permit) != 5:
    raise SystemExit("hermes-steward-acceptance: expected five independently signed Hermes task bundles")
if (
    not secret
    or not service_token
    or not executor_token
    or not task_private
    or not separator
    or any(material and material in raw for material in forbidden_material)
):
    raise SystemExit("hermes-steward-acceptance: Gateway receipt ledger contains task bodies, task IDs, prompts, or secrets")
lines = raw.splitlines()
if len(lines) != 2 + 3 * len(issue_by_permit):
    raise SystemExit("hermes-steward-acceptance: mixed Gateway receipt ledger has an unexpected record count")
receipts = []
previous = "sha256:" + "0" * 64
for index, line in enumerate(lines, 1):
    if not 0 < len(line) <= 128 << 10:
        raise SystemExit("hermes-steward-acceptance: connector receipt line is oversized")
    envelope = json.loads(line)
    payload_type = envelope.get("payloadType")
    schemas = {
        "application/vnd.steward.connector-receipt.v1+json": "steward.connector-receipt.v1",
        "application/vnd.steward.connector-receipt.v4+json": "steward.connector-receipt.v4",
    }
    if set(envelope) != {"payload", "payloadType", "signatures"} or payload_type not in schemas:
        raise SystemExit("hermes-steward-acceptance: connector receipt envelope is invalid")
    payload = base64.b64decode(envelope["payload"], validate=True)
    if base64.b64encode(payload).decode() != envelope["payload"]:
        raise SystemExit("hermes-steward-acceptance: connector receipt payload is not canonical base64")
    receipt = json.loads(payload)
    receipt_keys = {"epoch", "event", "node_id", "observed_at", "previous_hash", "schema_version", "sequence"}
    if payload_type.endswith(".v4+json"):
        receipt_keys |= {"task_sequence", "previous_task_hash"}
    if (
        set(receipt) != receipt_keys
        or receipt.get("schema_version") != schemas[payload_type]
        or receipt.get("node_id") != node_id
        or receipt.get("epoch") != 1
        or receipt.get("sequence") != index
        or receipt.get("previous_hash") != previous
        or not isinstance(receipt.get("observed_at"), str)
    ):
        raise SystemExit("hermes-steward-acceptance: Gateway receipt provenance is invalid")
    current_hash = hashlib.sha256(b"steward-connector-ledger-v1\x00" + line).hexdigest()
    previous = "sha256:" + current_hash
    receipts.append((payload_type, receipt, previous))

head_document = json.loads(pathlib.Path(head_path).read_text(encoding="utf-8"))
head = head_document.get("head") if isinstance(head_document, dict) else None
if (
    set(head_document) != {"head", "kind", "valid"}
    or head_document.get("valid") is not True
    or head_document.get("kind") != "connector"
    or not isinstance(head, dict)
    or head.get("node_id") != node_id
    or head.get("epoch") != 1
    or head.get("sequence") != len(lines)
    or head.get("chain_hash") != previous
):
    raise SystemExit("hermes-steward-acceptance: verified dynamic Gateway receipt head is invalid")

contract = json.loads(pathlib.Path(contract_path).read_text(encoding="utf-8"))
request = json.dumps(contract["request"], separators=(",", ":"), sort_keys=True).encode()
response = json.dumps(contract["response"], separators=(",", ":"), sort_keys=True).encode()
task_hash = hashlib.sha256()
task_hash.update(b"steward-gateway-connector-call-v1\x00")
for value in (tenant_id, instance_id, connector_task_id, contract["connector_id"], contract["operation_id"]):
    task_hash.update(value.encode())
    task_hash.update(b"\x00")
task_digest = "sha256:" + task_hash.hexdigest()

connector_receipts = [receipt for payload_type, receipt, _ in receipts if payload_type.endswith(".v1+json")]
if len(connector_receipts) != 2:
    raise SystemExit("hermes-steward-acceptance: mixed ledger must contain one complete legacy connector call")
for receipt in connector_receipts:
    if (
        (event := receipt["event"]).get("tenant_id") != tenant_id
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

authorize, terminal = (receipt["event"] for receipt in connector_receipts)
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

admissions = {}
for generation in (1, 2):
    admission = json.loads((work / f"admission-g{generation}.json").read_text(encoding="utf-8"))
    admissions[admission["grant_id"]] = (generation, admission)
service_receipts = [(receipt, receipt_hash) for payload_type, receipt, receipt_hash in receipts if payload_type.endswith(".v4+json")]
if len(service_receipts) != 3 * len(issue_by_permit):
    raise SystemExit("hermes-steward-acceptance: mixed ledger omits a service-task lifecycle phase")
service_by_permit = {}
for receipt, receipt_hash in service_receipts:
    event = receipt["event"]
    admitted = admissions.get(event.get("grant_id"))
    binding = issue_by_permit.get(event.get("permit_digest"))
    if admitted is None or binding is None:
        raise SystemExit("hermes-steward-acceptance: service-task receipt has no exact admission or task bundle")
    generation, admission = admitted
    issue, request_bytes, expected_task_digest, run_id, terminal_bytes, terminal_digest = binding
    if (
        event.get("kind") != "service_task"
        or event.get("tenant_id") != tenant_id
        or event.get("runtime_ref") != admission.get("runtime_ref")
        or event.get("capsule_digest") != capsule_digest
        or event.get("policy_digest") != admission.get("policy_digest")
        or event.get("route_policy_digest") != admission.get("route_policy_digest")
        or event.get("generation") != generation
        or event.get("grant_id") != admission.get("grant_id")
        or event.get("connector_id") != ""
        or event.get("service_id") != "hermes-api"
        or event.get("operation_id") != "hermes.run"
        or re.fullmatch(r"sha256:[a-f0-9]{64}", str(event.get("operation_policy_digest", ""))) is None
        or event.get("task_digest") != expected_task_digest
        or event.get("authority_key_id") != task_key_id
        or event.get("request_digest") != issue["request_digest"]
        or event.get("request_bytes") != request_bytes
        or event.get("task_protocol") != "steward.task-lifecycle.v1"
        or event.get("error_code", "") != ""
    ):
        raise SystemExit("hermes-steward-acceptance: service-task receipt is not bound to the signed task and admission")
    service_by_permit.setdefault(event["permit_digest"], []).append((receipt, receipt_hash))
if set(service_by_permit) != set(issue_by_permit):
    raise SystemExit("hermes-steward-acceptance: service-task receipts do not cover every issued task")
for permit_digest, records in service_by_permit.items():
    if len(records) != 3:
        raise SystemExit("hermes-steward-acceptance: a task permit has an incomplete lifecycle")
    authorized_record, dispatched_record, completed_record = records
    authorized, dispatched, completed = (
        authorized_record[0]["event"],
        dispatched_record[0]["event"],
        completed_record[0]["event"],
    )
    issue, request_bytes, expected_task_digest, run_id, terminal_bytes, terminal_digest = issue_by_permit[permit_digest]
    zero_hash = "sha256:" + "0" * 64
    if (
        authorized_record[0].get("task_sequence") != 1
        or authorized_record[0].get("previous_task_hash") != zero_hash
        or dispatched_record[0].get("task_sequence") != 2
        or dispatched_record[0].get("previous_task_hash") != authorized_record[1]
        or completed_record[0].get("task_sequence") != 3
        or completed_record[0].get("previous_task_hash") != dispatched_record[1]
        or authorized.get("phase") != "authorize"
        or authorized.get("outcome") != "allowed"
        or authorized.get("response_bytes") != 0
        or "http_status" in authorized
        or authorized.get("run_id", "") != ""
        or authorized.get("task_status", "") != ""
        or authorized.get("result_digest", "") != ""
        or dispatched.get("phase") != "dispatch"
        or dispatched.get("outcome") != "responded"
        or dispatched.get("http_status") != 202
        or not 0 < dispatched.get("response_bytes", 0) <= 1 << 20
        or dispatched.get("run_id") != run_id
        or dispatched.get("task_status", "") != ""
        or dispatched.get("result_digest", "") != ""
        or completed.get("phase") != "terminal"
        or completed.get("outcome") != "responded"
        or completed.get("http_status") != 200
        or completed.get("response_bytes") != terminal_bytes
        or completed.get("run_id") != run_id
        or completed.get("task_status") != "agent_reported_completed"
        or completed.get("result_digest") != terminal_digest
        or re.fullmatch(r"run_[a-f0-9]{32}", str(run_id)) is None
        or any(authorized.get(name) != event.get(name) for event in (dispatched, completed) for name in (
            "tenant_id", "runtime_ref", "capsule_digest", "policy_digest", "route_policy_digest",
            "generation", "grant_id", "service_id", "operation_id", "operation_policy_digest",
            "task_digest", "authority_key_id", "permit_digest", "request_digest", "request_bytes", "task_protocol",
        ))
    ):
        raise SystemExit("hermes-steward-acceptance: service-task receipts do not prove one recoverable lifecycle")

audit = json.loads(pathlib.Path(task_audit_path).read_text(encoding="utf-8"))
workspace_issue = json.loads((work / "task-workspace-g1.issue.json").read_text(encoding="utf-8"))
replayed_run = json.loads((work / "task-workspace-g1.replay.json").read_text(encoding="utf-8"))
if (
    audit.get("valid") is not True
    or audit.get("permit_digest") != workspace_issue["permit_digest"]
    or audit.get("request_digest") != workspace_issue["request_digest"]
    or audit.get("permit_key_id") != task_key_id
    or not isinstance(audit.get("authorization"), dict)
    or not isinstance(audit.get("dispatch"), dict)
    or not isinstance(audit.get("terminal"), dict)
    or audit["authorization"].get("event", {}).get("phase") != "authorize"
    or audit["dispatch"].get("event", {}).get("phase") != "dispatch"
    or audit["terminal"].get("event", {}).get("phase") != "terminal"
    or audit["terminal"].get("event", {}).get("run_id") != replayed_run.get("run_id")
    or [audit[name].get("task_sequence") for name in ("authorization", "dispatch", "terminal")] != [1, 2, 3]
    or audit.get("head") != head
):
    raise SystemExit("hermes-steward-acceptance: offline task audit did not bind the exact request to the mixed ledger")
PY
mark connector_evidence_chain_verified
mark service_task_audit_verified
mark acceptance_complete
write_success_evidence
echo "Hermes Steward acceptance passed: signed import, gVisor, tenant-signed service work, connector work, exact replay, resume, purge, and mixed receipts verified."
