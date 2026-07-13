#!/usr/bin/env bash
# Build the exact pinned Hermes adapter into a new Docker image archive.
# This is a build-time tool. It never starts the resulting image and records no
# prompts, responses, secrets, or other agent content.
set -euo pipefail
umask 077

readonly expected_repository=https://github.com/NousResearch/hermes-agent.git
readonly expected_revision=095b9eed3801c251796df93f48a8f2a527ff6e70
readonly default_build_timeout=3600
readonly default_clone_timeout=600
readonly default_save_timeout=900
readonly default_min_free_bytes=$((4 * 1024 * 1024 * 1024))
readonly default_max_archive_bytes=$((8 * 1024 * 1024 * 1024))
readonly sandbox_memory_bytes=$((4 * 1024 * 1024 * 1024))
readonly sandbox_output_bytes=$((2 * 1024 * 1024 * 1024))
readonly sandbox_pids=512
readonly sandbox_cpus=1

usage() {
	cat <<'USAGE'
Usage:
  scripts/build-hermes-adapter.sh [options]

Builds Steward's exact pinned Hermes adapter and publishes a new .tar archive
plus a canonical, metadata-only .attestation.json sidecar.

Options:
  --output FILE.tar       New archive to create (required in non-interactive mode)
  --source-dir DIR        Use an already-present exact checkout; no source download
  --non-interactive       Do not prompt; fail if required input is missing
  --keep-image            Keep the temporary local Docker image after saving
  --build-timeout SEC     Docker build timeout (300..14400; default 3600)
  --clone-timeout SEC     Online fetch timeout (30..3600; default 600)
  --save-timeout SEC      Docker save timeout (30..3600; default 900)
  --min-free-bytes BYTES  Required free host space (1 GiB..1 TiB; default 4 GiB)
  --max-archive-bytes N   Refuse an archive over this size (1 GiB..64 GiB; default 8 GiB)
  -h, --help              Show this help

Without --source-dir, the builder fetches only the pinned upstream commit into a
temporary directory. Upstream build hooks run only inside a bounded gVisor
sandbox with a read-only source mount and no Docker socket. Network access is
build-time only; the resulting runtime is not started and remains suitable for
offline import and execution.
USAGE
}

die() {
	echo "build-hermes-adapter: $*" >&2
	exit 1
}

usage_error() {
	echo "build-hermes-adapter: $*" >&2
	usage >&2
	exit 2
}

progress() {
	echo "==> $*" >&2
}

require_command() {
	command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

safe_git() {
	local repository=$1
	shift
	env -u GIT_CONFIG_COUNT -u GIT_CONFIG_PARAMETERS \
		GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
		git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C "$repository" "$@"
}

safe_git_timeout() {
	local duration=$1 repository=$2
	shift 2
	timeout "$duration" env -u GIT_CONFIG_COUNT -u GIT_CONFIG_PARAMETERS \
		GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null GIT_NO_REPLACE_OBJECTS=1 \
		git -c core.fsmonitor=false -c core.hooksPath=/dev/null -C "$repository" "$@"
}

validate_integer_range() {
	local name=$1 value=$2 minimum=$3 maximum=$4
	[[ $value =~ ^[1-9][0-9]{0,15}$ ]] || usage_error "$name must be a canonical positive integer"
	local decimal=$((10#$value))
	(( decimal >= minimum && decimal <= maximum )) || usage_error "$name must be between $minimum and $maximum"
}

sha256_file() {
	python3 - "$1" <<'PY'
import hashlib
import pathlib
import sys

digest = hashlib.sha256()
with pathlib.Path(sys.argv[1]).open("rb") as stream:
    for chunk in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

file_size() {
	python3 - "$1" <<'PY'
import os
import sys
print(os.stat(sys.argv[1], follow_symlinks=False).st_size)
PY
}

canonical_file_set_digest() {
	python3 - "$1" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

root = pathlib.Path(sys.argv[1])
entries = []
for path in sorted(root.rglob("*"), key=lambda item: item.relative_to(root).as_posix()):
    relative = path.relative_to(root).as_posix()
    info = os.lstat(path)
    mode = stat.S_IMODE(info.st_mode)
    if stat.S_ISDIR(info.st_mode):
        continue
    if stat.S_ISREG(info.st_mode):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        entries.append({"mode": mode, "path": relative, "sha256": digest, "type": "file"})
    elif stat.S_ISLNK(info.st_mode):
        entries.append({"mode": mode, "path": relative, "target": os.readlink(path), "type": "symlink"})
    else:
        raise SystemExit(f"unsupported adapter entry type: {relative}")
encoded = json.dumps(entries, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode()
print(hashlib.sha256(encoded).hexdigest())
PY
}

check_free_space() {
	local path=$1 label=$2 available_kib available_bytes
	available_kib=$(df -Pk -- "$path" | awk 'NR == 2 { print $4 }')
	[[ $available_kib =~ ^[0-9]+$ ]] || die "could not determine free space for $label"
	available_bytes=$((available_kib * 1024))
	(( available_bytes >= min_free_bytes )) || die "$label has $available_bytes free bytes; at least $min_free_bytes are required"
}

source_dir=
output=
non_interactive=false
keep_image=false
build_timeout=$default_build_timeout
clone_timeout=$default_clone_timeout
save_timeout=$default_save_timeout
min_free_bytes=$default_min_free_bytes
max_archive_bytes=$default_max_archive_bytes

while (( $# > 0 )); do
	case $1 in
	--output)
		(( $# >= 2 )) || usage_error "--output requires a value"
		output=$2
		shift 2
		;;
	--output=*) output=${1#*=}; shift ;;
	--source-dir)
		(( $# >= 2 )) || usage_error "--source-dir requires a value"
		source_dir=$2
		shift 2
		;;
	--source-dir=*) source_dir=${1#*=}; shift ;;
	--non-interactive) non_interactive=true; shift ;;
	--keep-image) keep_image=true; shift ;;
	--build-timeout)
		(( $# >= 2 )) || usage_error "--build-timeout requires a value"
		build_timeout=$2
		shift 2
		;;
	--build-timeout=*) build_timeout=${1#*=}; shift ;;
	--clone-timeout)
		(( $# >= 2 )) || usage_error "--clone-timeout requires a value"
		clone_timeout=$2
		shift 2
		;;
	--clone-timeout=*) clone_timeout=${1#*=}; shift ;;
	--save-timeout)
		(( $# >= 2 )) || usage_error "--save-timeout requires a value"
		save_timeout=$2
		shift 2
		;;
	--save-timeout=*) save_timeout=${1#*=}; shift ;;
	--min-free-bytes)
		(( $# >= 2 )) || usage_error "--min-free-bytes requires a value"
		min_free_bytes=$2
		shift 2
		;;
	--min-free-bytes=*) min_free_bytes=${1#*=}; shift ;;
	--max-archive-bytes)
		(( $# >= 2 )) || usage_error "--max-archive-bytes requires a value"
		max_archive_bytes=$2
		shift 2
		;;
	--max-archive-bytes=*) max_archive_bytes=${1#*=}; shift ;;
	-h|--help) usage; exit 0 ;;
	--) shift; (( $# == 0 )) || usage_error "positional arguments are not accepted" ;;
	-*) usage_error "unknown option: $1" ;;
	*) usage_error "positional arguments are not accepted: $1" ;;
	esac
done

validate_integer_range --build-timeout "$build_timeout" 300 14400
validate_integer_range --clone-timeout "$clone_timeout" 30 3600
validate_integer_range --save-timeout "$save_timeout" 30 3600
validate_integer_range --min-free-bytes "$min_free_bytes" $((1024 * 1024 * 1024)) $((1024 * 1024 * 1024 * 1024))
validate_integer_range --max-archive-bytes "$max_archive_bytes" $((1024 * 1024 * 1024)) $((64 * 1024 * 1024 * 1024))

if ! $non_interactive && [[ ! -t 0 || ! -t 1 ]]; then
	usage_error "no interactive terminal; pass --non-interactive"
fi
if [[ -z $output ]]; then
	$non_interactive && usage_error "--output is required with --non-interactive"
	default_output=$PWD/hermes-agent-adapter-${expected_revision:0:12}.tar
	read -r -p "Output archive [$default_output]: " output
	output=${output:-$default_output}
fi
[[ $output != *$'\n'* && $output != *$'\r'* ]] || usage_error "output path must not contain a newline"
[[ $(basename -- "$output") != .tar && $output == *.tar ]] || usage_error "output must be a named .tar archive"

for command in docker git python3 sha256sum tar timeout df awk od; do
	require_command "$command"
done

script_path=$(python3 - "${BASH_SOURCE[0]}" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
)
payload_root=$(cd "$(dirname "$script_path")/.." && pwd -P)
source_checkout_root=$(safe_git "$payload_root" rev-parse --show-toplevel 2>/dev/null || true)
if [[ -n $source_checkout_root ]]; then
	source_checkout_root=$(cd "$source_checkout_root" && pwd -P)
fi
adapter_source=
build_commit=
adapter_tree=
release_version=
release_manifest_sha256=
if [[ $source_checkout_root == "$payload_root" && -f $payload_root/adapters/hermes-agent/adapter.json ]]; then
	adapter_source=git-checkout
	root=$payload_root
	adapter_path=$root/adapters/hermes-agent
	safe_git "$root" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "Steward source root is not a Git checkout"
	build_commit=$(safe_git "$root" rev-parse HEAD)
	safe_git "$root" ls-files --error-unmatch scripts/build-hermes-adapter.sh >/dev/null 2>&1 \
		|| die "builder must be checked in before it can produce an attestation"
	committed_builder_blob=$(safe_git "$root" rev-parse "$build_commit:scripts/build-hermes-adapter.sh")
	current_builder_blob=$(safe_git "$root" hash-object --no-filters "$script_path")
	[[ $current_builder_blob == "$committed_builder_blob" ]] || die "builder differs from the committed Steward source"
	adapter_tree=$(safe_git "$root" rev-parse "$build_commit:adapters/hermes-agent")
elif [[ -f $payload_root/release.json && -f $payload_root/adapters/hermes-agent/adapter.json ]]; then
	adapter_source=release-payload
	root=$payload_root
	adapter_path=$payload_root/adapters/hermes-agent
	release_manifest=$payload_root/release.json
elif [[ -f $(dirname "$payload_root")/release.json && -f $payload_root/adapters/hermes-agent/adapter.json ]]; then
	adapter_source=release-payload
	root=$(dirname "$payload_root")
	adapter_path=$payload_root/adapters/hermes-agent
	release_manifest=$root/release.json
else
	die "Hermes adapter is absent from the Steward source or release payload"
fi
if [[ $adapter_source == release-payload ]]; then
	[[ -f $release_manifest && ! -L $release_manifest ]] || die "packaged builder requires an immutable release.json"
	release_version=$(python3 - "$adapter_path" "$script_path" "$release_manifest" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

adapter, script, manifest_path = map(pathlib.Path, sys.argv[1:])
if manifest_path.stat().st_size > 1 << 20:
    raise SystemExit("packaged release manifest is oversized")
manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
version = manifest.get("version") if isinstance(manifest, dict) else None
files = manifest.get("files") if isinstance(manifest, dict) else None
if (
    not isinstance(manifest, dict)
    or manifest.get("schema") != "steward.release.v2"
    or manifest.get("os") != "linux"
    or not isinstance(version, str)
    or re.fullmatch(r"v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?", version) is None
    or not isinstance(files, dict)
):
    raise SystemExit("packaged release manifest is invalid")

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

actual = set()
for path in sorted(adapter.rglob("*")):
    info = os.lstat(path)
    if stat.S_ISDIR(info.st_mode):
        continue
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        raise SystemExit(f"packaged adapter contains an unsafe entry: {path.relative_to(adapter)}")
    actual.add("integration/adapters/hermes-agent/" + path.relative_to(adapter).as_posix())
expected = {name for name in files if name.startswith("integration/adapters/hermes-agent/")}
if actual != expected:
    raise SystemExit("packaged adapter inventory differs from release.json")
builder_name = "integration/scripts/build-hermes-adapter.sh"
for name, path in [(name, adapter / name.removeprefix("integration/adapters/hermes-agent/")) for name in actual]:
    expected_digest = files.get(name)
    if not isinstance(expected_digest, str) or digest(path) != expected_digest:
        raise SystemExit(f"packaged release digest mismatch: {name}")
if not isinstance(files.get(builder_name), str) or digest(script) != files[builder_name]:
    raise SystemExit(f"packaged release digest mismatch: {builder_name}")
print(version)
PY
)
	release_manifest_sha256=$(sha256_file "$release_manifest")
fi
[[ -f $adapter_path/adapter.json && -f $adapter_path/Dockerfile ]] || die "Hermes adapter payload is incomplete"

output=$(python3 - "$output" <<'PY'
import os
import sys
print(os.path.abspath(sys.argv[1]))
PY
)
output_parent=$(dirname -- "$output")
mkdir -p -- "$output_parent"
[[ -d $output_parent && ! -L $output_parent ]] || die "output parent must be a real directory"
attestation=$output.attestation.json
[[ ! -e $output && ! -L $output ]] || die "output archive already exists: $output"
[[ ! -e $attestation && ! -L $attestation ]] || die "attestation already exists: $attestation"

docker info >/dev/null 2>&1 || die "Docker Engine is unavailable"
docker info --format '{{json .Runtimes}}' | python3 -c 'import json,sys; raise SystemExit(0 if "runsc" in json.load(sys.stdin) else 1)' \
	|| die "Docker runtime runsc is not registered"

tmp_base=${TMPDIR:-/tmp}
[[ -d $tmp_base ]] || die "temporary directory root does not exist: $tmp_base"
[[ $tmp_base != *:* && $tmp_base != *,* ]] || die "temporary directory root must not contain ':' or ','"
check_free_space "$tmp_base" "temporary filesystem"
check_free_space "$output_parent" "output filesystem"

work=$(mktemp -d "$tmp_base/steward-hermes-build.XXXXXX")
publish_dir=$(mktemp -d "$output_parent/.steward-hermes-publish.XXXXXX")
image_tag=steward-hermes-adapter-build:${expected_revision:0:12}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
image_owned=false
sandbox_name=
sandbox_network=

cleanup() {
	local status=$?
	trap - EXIT INT TERM
	if $image_owned && { (( status != 0 )) || ! $keep_image; }; then
		docker image rm "$image_tag" >/dev/null 2>&1 || true
	fi
	[[ -z $sandbox_name ]] || docker rm -f "$sandbox_name" >/dev/null 2>&1 || true
	[[ -z $sandbox_network ]] || docker network rm "$sandbox_network" >/dev/null 2>&1 || true
	rm -rf -- "$work"
	rm -rf -- "$publish_dir"
	exit "$status"
}
on_signal() {
	exit 130
}
trap cleanup EXIT
trap on_signal INT TERM

if [[ -z $source_dir ]]; then
	progress "Fetching pinned Hermes source $expected_revision"
	source_dir=$work/source
	git init -q "$source_dir"
	safe_git "$source_dir" remote add origin "$expected_repository"
	safe_git_timeout "$clone_timeout" "$source_dir" fetch --depth=1 --no-tags origin "$expected_revision"
	safe_git "$source_dir" checkout -q --detach FETCH_HEAD
else
	[[ -d $source_dir ]] || die "source directory does not exist: $source_dir"
	source_dir=$(cd "$source_dir" && pwd -P)
fi

actual_revision=$(safe_git "$source_dir" rev-parse HEAD 2>/dev/null || true)
[[ $actual_revision == "$expected_revision" ]] || die "source revision mismatch: expected $expected_revision"
source_tree=$(safe_git "$source_dir" rev-parse "$expected_revision^{tree}")

mkdir -p "$work/context/upstream" "$work/context/adapter"
safe_git "$source_dir" archive --format=tar --output="$work/source.tar" "$expected_revision"
if [[ $adapter_source == git-checkout ]]; then
	safe_git "$root" archive --format=tar --output="$work/adapter.tar" "$build_commit:adapters/hermes-agent"
else
	tar -cf "$work/adapter.tar" -C "$adapter_path" .
fi
source_archive_sha256=$(sha256_file "$work/source.tar")
tar -xf "$work/source.tar" -C "$work/context/upstream"
tar -xf "$work/adapter.tar" -C "$work/context/adapter"
adapter_file_set_sha256=$(canonical_file_set_digest "$work/context/adapter")

mapfile -t adapter_values < <(python3 - "$work/context/adapter/adapter.json" <<'PY'
import json
import pathlib
import sys

document = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
bases = document.get("base_images")
if not isinstance(bases, list) or len(bases) != 1 or not isinstance(bases[0], dict):
    raise SystemExit("adapter must define exactly one base image")
print(document.get("upstream", {}).get("repository", ""))
print(document.get("upstream", {}).get("revision", ""))
print(bases[0].get("reference", ""))
PY
)
(( ${#adapter_values[@]} == 3 )) || die "adapter metadata is invalid"
[[ ${adapter_values[0]} == "$expected_repository" ]] || die "adapter repository pin drift"
[[ ${adapter_values[1]} == "$expected_revision" ]] || die "adapter revision pin drift"
base_image_reference=${adapter_values[2]}
[[ $base_image_reference =~ @sha256:[a-f0-9]{64}$ ]] || die "adapter base image is not digest-pinned"
dockerfile_base=$(awk -F= '/^ARG UV_IMAGE=/{print substr($0, index($0, "=") + 1); exit}' "$work/context/adapter/Dockerfile")
[[ $dockerfile_base == "$base_image_reference" ]] || die "Dockerfile base image differs from adapter metadata"

(cd "$work/context/upstream" && sha256sum -c "$work/context/adapter/source-inputs.sha256") >/dev/null \
	|| die "pinned Hermes source inputs failed verification"
build_recipe_sha256=$(sha256_file "$work/context/adapter/Dockerfile")
source_inputs_sha256=$(sha256_file "$work/context/adapter/source-inputs.sha256")
builder_sha256=$(sha256_file "$script_path")

if ! $non_interactive; then
	echo >&2
	echo "Pinned source: $expected_revision" >&2
	echo "Source mode:   $([[ $source_dir == "$work/source" ]] && echo online-temporary || echo offline-checkout)" >&2
	echo "Output:        $output" >&2
	echo "Base image:    $base_image_reference" >&2
	read -r -p "Build and publish this archive? [y/N] " answer
	[[ $answer == y || $answer == Y || $answer == yes || $answer == YES ]] || die "cancelled"
fi

# The sandbox runs as the fixed non-root runtime UID. Expose only traversal to
# the private temporary parent and read-only access to the two explicit bind
# roots; all other build state remains owner-only.
chmod 0711 "$work" "$work/context"
chmod 0555 "$work/context/upstream" "$work/context/adapter"

progress "Building Hermes dependencies inside bounded gVisor sandbox (timeout ${build_timeout}s)"
sandbox_name=steward-hermes-build-sandbox-${expected_revision:0:12}-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
sandbox_network=$sandbox_name-network
docker network create --label io.hardrails.steward.hermes-build=true "$sandbox_network" >/dev/null
sandbox_command='set -eu
mkdir -p /tmp/build /tmp/home
cp -R /input/upstream/. /tmp/build/
chmod -R u+rwX /tmp/build
cd /tmp/build
sha256sum -c /input/adapter/source-inputs.sha256
uv sync --frozen --no-install-project --extra mcp --extra homeassistant
uv pip install --no-cache-dir --no-deps .
tar -cf /output/venv.tar .venv
'
docker create --name "$sandbox_name" \
	--runtime runsc --network "$sandbox_network" --read-only --cap-drop ALL \
	--security-opt no-new-privileges:true --pids-limit "$sandbox_pids" \
	--memory "$sandbox_memory_bytes" --memory-swap "$sandbox_memory_bytes" --cpus "$sandbox_cpus" \
	--tmpfs "/tmp:rw,nosuid,nodev,size=$sandbox_memory_bytes" \
	--tmpfs "/output:rw,noexec,nosuid,nodev,size=$sandbox_output_bytes" \
	--user 65532:65532 --workdir /tmp \
	--env HOME=/tmp/home --env UV_CACHE_DIR=/tmp/uv-cache --env UV_LINK_MODE=copy \
	--log-driver local --log-opt max-size=1m --log-opt max-file=1 --log-opt compress=false \
	--mount "type=bind,source=$work/context/upstream,target=/input/upstream,readonly" \
	--mount "type=bind,source=$work/context/adapter,target=/input/adapter,readonly" \
	--entrypoint /bin/sh "$base_image_reference" -ceu "$sandbox_command" >/dev/null
docker start "$sandbox_name" >/dev/null
sandbox_status=$(timeout "$build_timeout" docker wait "$sandbox_name") || die "gVisor build sandbox timed out"
[[ $sandbox_status == 0 ]] || {
	docker logs --tail 200 "$sandbox_name" >&2 || true
	die "gVisor build sandbox failed with status $sandbox_status"
}
docker cp "$sandbox_name:/output/venv.tar" "$work/venv.tar"
venv_archive_size=$(python3 - "$work/venv.tar" <<'PY'
import os
import stat
import sys

info = os.lstat(sys.argv[1])
if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
    raise SystemExit("gVisor build artifact is not a single-link regular file")
print(info.st_size)
PY
)
(( venv_archive_size > 0 && venv_archive_size <= sandbox_output_bytes )) || die "gVisor build artifact is empty or oversized"

mkdir -p "$work/final-context/adapter" "$work/final-context/upstream" "$work/final-context/artifact/venv"
cp -a "$work/context/adapter"/. "$work/final-context/adapter/"
install -m 0444 "$work/context/upstream/LICENSE" "$work/final-context/upstream/LICENSE"
python3 - "$work/venv.tar" "$sandbox_output_bytes" <<'PY'
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
limit = int(sys.argv[2])
with tarfile.open(archive_path, mode="r:") as archive:
    members = archive.getmembers()
    if not members or len(members) > 100000:
        raise SystemExit("gVisor build artifact has an invalid member count")
    normalized = {}
    symlinks = set()
    total = 0
    for member in members:
        raw = member.name.removeprefix("./")
        path = pathlib.PurePosixPath(raw)
        if not raw or path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
            raise SystemExit("gVisor build artifact contains an unsafe path")
        if path.parts[0] != ".venv" or path in normalized:
            raise SystemExit("gVisor build artifact escaped or duplicated its root")
        if not (member.isdir() or member.isfile() or member.issym()) or member.mode & 0o7000:
            raise SystemExit("gVisor build artifact contains an unsafe member type or mode")
        if member.isfile():
            if member.size < 0 or member.size > limit:
                raise SystemExit("gVisor build artifact member is oversized")
            total += member.size
            if total > limit:
                raise SystemExit("gVisor build artifact expands beyond its limit")
        if member.issym():
            if not member.linkname or len(member.linkname.encode("utf-8")) > 4096 or "\x00" in member.linkname:
                raise SystemExit("gVisor build artifact contains an unsafe symlink")
            symlinks.add(path)
        normalized[path] = member
    for path in normalized:
        if any(pathlib.PurePosixPath(*path.parts[:index]) in symlinks for index in range(1, len(path.parts))):
            raise SystemExit("gVisor build artifact places content below a symlink")
PY
tar --no-same-owner -xf "$work/venv.tar" -C "$work/final-context/artifact/venv"
mkdir -p "$work/final-context/artifact/state/home"
chmod 0700 "$work/final-context/artifact/state" "$work/final-context/artifact/state/home"
printf 'docker\n' >"$work/final-context/artifact/install_method"
chmod 0444 "$work/final-context/artifact/install_method"

docker image inspect "$image_tag" >/dev/null 2>&1 && die "temporary image tag already exists"
progress "Assembling pinned Hermes adapter without upstream build hooks (timeout ${build_timeout}s)"
image_owned=true
timeout "$build_timeout" docker build --network=none --pull=false --provenance=false \
	--build-arg "HERMES_SOURCE_REVISION=$expected_revision" \
	-f "$work/final-context/adapter/Dockerfile" -t "$image_tag" "$work/final-context"

runtime_image_id=$(docker image inspect --format '{{.Id}}' "$image_tag")
image_user=$(docker image inspect --format '{{.Config.User}}' "$image_tag")
image_volumes=$(docker image inspect --format '{{json .Config.Volumes}}' "$image_tag")
image_os=$(docker image inspect --format '{{.Os}}' "$image_tag")
image_arch=$(docker image inspect --format '{{.Architecture}}' "$image_tag")
image_source_revision=$(docker image inspect --format '{{index .Config.Labels "io.hardrails.steward.hermes.source-revision"}}' "$image_tag")
[[ $runtime_image_id =~ ^sha256:[a-f0-9]{64}$ ]] || die "built image has an invalid runtime identity digest"
[[ $image_user == 65532:65532 ]] || die "built image user is $image_user, not 65532:65532"
[[ $image_volumes == null || $image_volumes == '{}' ]] || die "built image declares a volume"
[[ -n $image_os && -n $image_arch ]] || die "built image platform is incomplete"
[[ $image_source_revision == "$expected_revision" ]] || die "built image source revision label is invalid"
image_platform=$image_os/$image_arch

check_free_space "$output_parent" "output filesystem"
archive_tmp=$publish_dir/archive.tar
progress "Saving bounded image archive (timeout ${save_timeout}s)"
timeout "$save_timeout" docker save "$image_tag" | python3 -c '
import os
import pathlib
import sys

destination = pathlib.Path(sys.argv[1])
limit = int(sys.argv[2])
written = 0
with destination.open("xb") as stream:
    while True:
        chunk = sys.stdin.buffer.read(1024 * 1024)
        if not chunk:
            break
        written += len(chunk)
        if written > limit:
            raise SystemExit("Docker archive exceeds configured size limit")
        stream.write(chunk)
    stream.flush()
    os.fsync(stream.fileno())
if written == 0:
    raise SystemExit("Docker produced an empty archive")
' "$archive_tmp" "$max_archive_bytes"

mapfile -t archive_image_values < <(python3 - "$archive_tmp" "$image_tag" "$runtime_image_id" "$image_os" "$image_arch" <<'PY'
import hashlib
import json
import re
import sys
import tarfile

archive_path, expected_tag, runtime_id, expected_os, expected_arch = sys.argv[1:]
digest = re.compile(r"sha256:[a-f0-9]{64}")
blob = re.compile(r"blobs/sha256/([a-f0-9]{64})")

with tarfile.open(archive_path, mode="r:") as archive:
    members = archive.getmembers()
    if len(members) > 512 or len({member.name for member in members}) != len(members):
        raise SystemExit("Docker archive has an invalid member inventory")
    if any(not (member.isfile() or member.isdir()) for member in members):
        raise SystemExit("Docker archive contains a non-file member")
    by_name = {member.name: member for member in members}

    def read(name, maximum):
        member = by_name.get(name)
        if member is None or not member.isfile() or member.size < 0 or member.size > maximum:
            raise SystemExit(f"Docker archive member is missing or oversized: {name}")
        stream = archive.extractfile(member)
        if stream is None:
            raise SystemExit(f"Docker archive member cannot be read: {name}")
        content = stream.read(maximum + 1)
        if len(content) != member.size or len(content) > maximum:
            raise SystemExit(f"Docker archive member changed size: {name}")
        return content

    legacy = json.loads(read("manifest.json", 1 << 20))
    if not isinstance(legacy, list) or len(legacy) != 1 or not isinstance(legacy[0], dict):
        raise SystemExit("Docker archive must contain exactly one image")
    image = legacy[0]
    if image.get("RepoTags") != [expected_tag]:
        raise SystemExit("Docker archive tag differs from the temporary build tag")
    config_path = image.get("Config")
    match = blob.fullmatch(config_path) if isinstance(config_path, str) else None
    if match is None:
        raise SystemExit("Docker archive config path is invalid")
    config_bytes = read(config_path, 1 << 20)
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    if config_digest != "sha256:" + match.group(1):
        raise SystemExit("Docker archive config digest is invalid")
    config = json.loads(config_bytes)
    if (
        not isinstance(config, dict)
        or config.get("os") != expected_os
        or config.get("architecture") != expected_arch
        or not isinstance(config.get("config"), dict)
        or config["config"].get("User") != "65532:65532"
        or config["config"].get("Volumes") not in (None, {})
    ):
        raise SystemExit("Docker archive config contract is invalid")

    index = json.loads(read("index.json", 1 << 20))
    descriptors = index.get("manifests") if isinstance(index, dict) else None
    if not isinstance(descriptors, list) or len(descriptors) != 1 or not isinstance(descriptors[0], dict):
        raise SystemExit("Docker archive OCI index is invalid")
    manifest_digest = descriptors[0].get("digest")
    if not isinstance(manifest_digest, str) or digest.fullmatch(manifest_digest) is None:
        raise SystemExit("Docker archive manifest digest is invalid")
    manifest_path = "blobs/sha256/" + manifest_digest.removeprefix("sha256:")
    manifest_bytes = read(manifest_path, 1 << 20)
    if "sha256:" + hashlib.sha256(manifest_bytes).hexdigest() != manifest_digest:
        raise SystemExit("Docker archive manifest content does not match its digest")
    manifest = json.loads(manifest_bytes)
    descriptor = manifest.get("config") if isinstance(manifest, dict) else None
    if not isinstance(descriptor, dict) or descriptor.get("digest") != config_digest:
        raise SystemExit("Docker archive manifest does not bind the config digest")
    annotation = descriptors[0].get("annotations", {}).get("config.digest")
    if annotation is not None and annotation != config_digest:
        raise SystemExit("Docker archive index config annotation is inconsistent")
    if runtime_id not in {manifest_digest, config_digest}:
        raise SystemExit("Docker runtime image identity is not bound by the archive")

print(manifest_digest)
print(config_digest)
PY
)
(( ${#archive_image_values[@]} == 2 )) || die "Docker archive image identity is incomplete"
image_manifest_digest=${archive_image_values[0]}
image_config_digest=${archive_image_values[1]}

archive_sha256=$(sha256_file "$archive_tmp")
archive_size=$(file_size "$archive_tmp")
attestation_tmp=$publish_dir/attestation.json
python3 - "$attestation_tmp" "$(basename -- "$output")" "$expected_repository" "$expected_revision" "$source_tree" \
	"$source_archive_sha256" "$adapter_source" "$build_commit" "$adapter_tree" "$release_version" \
	"$release_manifest_sha256" "$adapter_file_set_sha256" "$build_recipe_sha256" \
	"$source_inputs_sha256" "$builder_sha256" "$base_image_reference" "$image_manifest_digest" \
	"$image_config_digest" "$runtime_image_id" "$image_platform" \
	"$archive_sha256" "$archive_size" <<'PY'
import json
import os
import pathlib
import sys

(
    destination, archive_name, repository, revision, source_tree, source_archive,
    adapter_source, steward_commit, adapter_tree, release_version, release_manifest,
    adapter_files, dockerfile, source_inputs, builder,
    base_image, manifest_digest, config_digest, runtime_image_id, platform, archive_digest, archive_size,
) = sys.argv[1:]
adapter = {
    "contract": "steward.hermes-agent.v1",
    "file_set_sha256": adapter_files,
    "source": adapter_source,
}
if adapter_source == "git-checkout":
    adapter["git_tree"] = adapter_tree
    adapter["steward_commit"] = steward_commit
elif adapter_source == "release-payload":
    adapter["release_manifest_sha256"] = release_manifest
    adapter["release_version"] = release_version
else:
    raise SystemExit("invalid adapter source")
payload = {
    "adapter": adapter,
    "archive": {
        "file": archive_name,
        "sha256": archive_digest,
        "size_bytes": int(archive_size),
    },
    "build_recipe": {
        "base_image": base_image,
        "build_isolation": "gvisor-runsc",
        "builder_sha256": builder,
        "dockerfile_sha256": dockerfile,
        "id": "steward.hermes-adapter.docker-build.v1",
        "network_scope": "gvisor-build-sandbox-only",
        "pull_newer_base": False,
        "runtime_executed": False,
        "source_inputs_sha256": source_inputs,
        "upstream_build_hooks_in_final_assembly": False,
    },
    "contains_agent_content": False,
    "image": {
        "config_digest": config_digest,
        "declared_volumes": False,
        "manifest_digest": manifest_digest,
        "platform": platform,
        "runtime_image_id": runtime_image_id,
        "user": "65532:65532",
    },
    "schema_version": "steward.hermes-adapter-build-attestation.v1",
    "source": {
        "archive_sha256": source_archive,
        "git_tree": source_tree,
        "repository": repository,
        "revision": revision,
    },
}
encoded = json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode() + b"\n"
path = pathlib.Path(destination)
with path.open("xb") as stream:
    stream.write(encoded)
    stream.flush()
    os.fsync(stream.fileno())
PY

python3 - "$archive_tmp" "$output" "$attestation_tmp" "$attestation" <<'PY'
import os
import pathlib
import sys

archive_source, archive_destination, metadata_source, metadata_destination = map(pathlib.Path, sys.argv[1:])
published_archive = False
published_metadata = False
try:
    os.link(archive_source, archive_destination, follow_symlinks=False)
    published_archive = True
    os.link(metadata_source, metadata_destination, follow_symlinks=False)
    published_metadata = True
    directory_fd = os.open(archive_destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
except Exception:
    if published_metadata:
        try:
            if os.stat(metadata_source).st_ino == os.stat(metadata_destination).st_ino:
                metadata_destination.unlink()
        except OSError:
            pass
    if published_archive:
        try:
            if os.stat(archive_source).st_ino == os.stat(archive_destination).st_ino:
                archive_destination.unlink()
        except OSError:
            pass
    raise
PY

progress "Hermes adapter archive created"
echo "Archive:     $output"
echo "Attestation: $attestation"
echo "Image:       $image_manifest_digest ($image_platform)"
echo "Config:      $image_config_digest"
echo "Archive SHA: $archive_sha256"
